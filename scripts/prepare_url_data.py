"""Prepare the UCI PhiUSIIL URL data for the optional URL model.

Reads only the URL and label columns, maps UCI labels (1=legitimate,
0=phishing) to internal labels (1=phishing, 0=legitimate), applies the
versioned preprocessing/privacy policy, audits duplicates and contradictions,
and writes domain-grouped train/val/test partitions plus a manifest.

Output stays OUTSIDE git (default /workspace/url_ml_data/prepared). Logs print
only aggregated counts, never raw URLs.

Quarantine policy: rows whose *model text* (canonical URL) appears with both
labels are all removed (contradictory: contradictory_texts distinct texts,
contradictory_rows_quarantined rows incl. duplicates); exact/canonical
duplicates with one label keep the first occurrence (duplicates_dropped counts
every later occurrence, including those of contradictory texts).
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scamshield.url_ml_preprocessing import (  # noqa: E402
    PREPROCESSING_VERSION, RULES_BASELINE_COMMIT, UCI_TO_INTERNAL, prepare_url,
)

DEFAULT_SEED = 20261017


def map_label(value):
    """UCI label string -> internal label (1 phishing, 0 legitimate) or None."""
    if value is None:
        return None
    v = str(value).strip()
    if v not in ("0", "1"):
        return None
    return UCI_TO_INTERNAL[int(v)]


def _h(seed, s: str) -> float:
    d = hashlib.sha256(f"{seed}\x00{s}".encode("utf-8", "surrogatepass")).digest()
    return int.from_bytes(d[:8], "big") / 2 ** 64


def _bucket(reason: str) -> str:
    for key in ("reserved", "login", "e-mail", "token", "scheme", "too long", "single", "empty", "error"):
        if key in reason:
            return key
    return "other"


def audit_and_prepare(rows):
    """rows: iterable of {"url", "label" (internal 0/1), optional "src_row"}."""
    stats = collections.Counter()
    by_text: dict = {}
    order = []
    for i, r in enumerate(rows):
        stats["input_rows"] += 1
        p = prepare_url(r["url"])
        if p["status"] != "ok":
            stats["excluded_" + _bucket(p["reason"])] += 1
            continue
        t = p["text"]
        if t in by_text:
            by_text[t]["labels"].add(r["label"])
            by_text[t]["count"] += 1
            stats["duplicates_dropped"] += 1
            continue
        by_text[t] = {"text": t, "group": p["group"], "label": r["label"],
                      "labels": {r["label"]}, "count": 1, "src_row": r.get("src_row", i)}
        order.append(t)
    out = []
    for t in order:
        e = by_text[t]
        if len(e["labels"]) > 1:
            stats["contradictory_texts"] += 1
            stats["contradictory_rows_quarantined"] += e["count"]
            continue
        out.append({"text": t, "group": e["group"], "label": e["label"], "src_row": e["src_row"]})
    stats["kept"] = len(out)
    return out, dict(stats)


def split_groups(rows, *, seed=DEFAULT_SEED, val_frac=0.1, test_frac=0.1):
    parts = {"train": [], "val": [], "test": []}
    for r in rows:
        u = _h(seed, r["group"])
        k = "test" if u < test_frac else "val" if u < test_frac + val_frac else "train"
        parts[k].append(r)
    return parts


def sample_rows(rows, n, *, seed=DEFAULT_SEED):
    """Class-aware, domain-diverse deterministic sample of n rows."""
    if n >= len(rows):
        return list(rows)
    by_label = collections.defaultdict(list)
    for r in rows:
        by_label[r["label"]].append(r)
    total = len(rows)
    labels = sorted(by_label)
    quotas = {lab: round(n * len(by_label[lab]) / total) for lab in labels}
    quotas[labels[-1]] = n - sum(quotas[lab] for lab in labels[:-1])
    out = []
    for lab in labels:
        rank = collections.Counter()
        keyed = []
        for r in sorted(by_label[lab], key=lambda r: _h(seed, r["text"])):
            keyed.append((rank[r["group"]], _h(seed, r["text"]), r))
            rank[r["group"]] += 1
        keyed.sort(key=lambda k: (k[0], k[1]))
        out.extend(k[2] for k in keyed[:quotas[lab]])
    out.sort(key=lambda r: _h(seed + 1, r["text"]))
    return out


def read_uci_csv(path):
    stats = collections.Counter()
    rows = []
    csv.field_size_limit(1 << 24)
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for i, rec in enumerate(reader):
            url = rec.get("URL")
            lab = map_label(rec.get("label"))
            if not url or not url.strip():
                stats["missing_url"] += 1
                continue
            if lab is None:
                stats["invalid_label"] += 1
                continue
            rows.append({"url": url, "label": lab, "src_row": i})
    return rows, dict(stats)


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=True) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="/workspace/url_ml_data/PhiUSIIL_Phishing_URL_Dataset.csv")
    ap.add_argument("--out", default="/workspace/url_ml_data/prepared")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--val-frac", type=float, default=0.1)
    ap.add_argument("--test-frac", type=float, default=0.1)
    ap.add_argument("--source-sha256", default="")
    ap.add_argument("--retrieved-at", default="")
    a = ap.parse_args(argv)
    t0 = time.perf_counter()
    rows, read_stats = read_uci_csv(a.csv)
    raw_counts = collections.Counter(r["label"] for r in rows)
    prepared, stats = audit_and_prepare(rows)
    parts = split_groups(prepared, seed=a.seed, val_frac=a.val_frac, test_frac=a.test_frac)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {}
    for k, v in parts.items():
        _write_jsonl(out / f"{k}.jsonl", v)
        summary[k] = {"rows": len(v), "phishing": sum(r["label"] for r in v),
                      "legitimate": sum(1 - r["label"] for r in v),
                      "groups": len({r["group"] for r in v})}
    manifest = {
        "dataset": "UCI PhiUSIIL Phishing URL Dataset (id 967)",
        "license": "CC BY 4.0",
        "source_csv": Path(a.csv).name,
        "source_zip_sha256": a.source_sha256,
        "retrieved_at": a.retrieved_at,
        "columns_used": ["URL", "label"],
        "label_mapping": "UCI 1=legitimate,0=phishing -> internal 1=phishing,0=legitimate",
        "preprocessing_version": PREPROCESSING_VERSION,
        "rules_commit": RULES_BASELINE_COMMIT,
        "seed": a.seed, "val_frac": a.val_frac, "test_frac": a.test_frac,
        "split": "domain-grouped by offline registrable-domain approximation (sha256(seed, group))",
        "read_stats": read_stats,
        "raw_label_counts": {"phishing": raw_counts[1], "legitimate": raw_counts[0]},
        "audit": stats,
        "partitions": summary,
        "prepare_seconds": round(time.perf_counter() - t0, 2),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({k: manifest[k] for k in ("read_stats", "raw_label_counts", "audit", "partitions", "prepare_seconds")}, indent=1))


if __name__ == "__main__":
    main()
