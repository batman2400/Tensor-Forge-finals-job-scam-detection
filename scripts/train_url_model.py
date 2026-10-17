"""Train the optional URL model (char TF-IDF 3-5 + logistic regression).

Uses the domain-grouped partitions written by prepare_url_data.py. The model
(C) and decision threshold are chosen on the VALIDATION partition only; the
test partition is scored once at the end. Prints/writes aggregated numbers
only (no raw URLs). Artifacts are written outside git (artifacts/ is ignored).

Threshold objective (precision-prioritised): the lowest threshold whose
validation precision >= --precision-target (maximises recall under that
precision); if no threshold reaches the target, the max-F1 threshold.
"""
from __future__ import annotations

import argparse
import json
import resource
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import numpy as np  # noqa: E402
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score  # noqa: E402

from scamshield import url_ml  # noqa: E402
from scamshield.url_ml_preprocessing import RULES_BASELINE_COMMIT  # noqa: E402

sys.path.insert(0, str(REPO / "scripts"))
from prepare_url_data import sample_rows, DEFAULT_SEED  # noqa: E402


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def choose_threshold(y, s, target):
    p, r, t = precision_recall_curve(y, s)
    p, r = p[:-1], r[:-1]
    ok = np.where(p >= target)[0]
    if len(ok):
        i = ok[np.argmax(r[ok])]
        return float(t[i]), f"max recall s.t. validation precision >= {target}"
    f1 = 2 * p * r / np.maximum(p + r, 1e-12)
    i = int(np.argmax(f1))
    return float(t[i]), "max validation F1 (precision target unreachable)"


def metrics(y, s, thr):
    y = np.asarray(y)
    pred = s >= thr
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"n": int(len(y)), "phishing": int(y.sum()), "legitimate": int((1 - y).sum()),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(2 * prec * rec / (prec + rec), 4) if prec + rec else 0.0,
            "fpr": round(fp / (fp + tn), 4) if fp + tn else 0.0,
            "pr_auc": round(float(average_precision_score(y, s)), 4),
            "roc_auc": round(float(roc_auc_score(y, s)), 4)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="/workspace/url_ml_data/prepared")
    ap.add_argument("--out", default=str(REPO / "artifacts" / "url_ml"))
    ap.add_argument("--deliver", default="/workspace/url_ml_delivery")
    ap.add_argument("--train-rows", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED)
    ap.add_argument("--max-features", type=int, default=2 ** 18)
    ap.add_argument("--C-grid", default="1,4,16")
    ap.add_argument("--precision-target", type=float, default=0.99)
    a = ap.parse_args(argv)
    d = Path(a.data)
    manifest = json.loads((d / "manifest.json").read_text())
    train_all, val, test = load(d / "train.jsonl"), load(d / "val.jsonl"), load(d / "test.jsonl")
    train = sample_rows(train_all, a.train_rows, seed=a.seed)
    Xtr, ytr = [r["text"] for r in train], np.array([r["label"] for r in train])
    Xva, yva = [r["text"] for r in val], np.array([r["label"] for r in val])
    Xte, yte = [r["text"] for r in test], np.array([r["label"] for r in test])

    grid = []
    best = None
    t_all = time.perf_counter()
    for C in [float(c) for c in a.C_grid.split(",")]:
        t0 = time.perf_counter()
        m = url_ml.build_pipeline(max_features=a.max_features, C=C, seed=a.seed)
        m.fit(Xtr, ytr)
        fit_s = time.perf_counter() - t0
        col = list(m.classes_).index(1)
        sva = m.predict_proba(Xva)[:, col]
        ap_va = float(average_precision_score(yva, sva))
        grid.append({"C": C, "val_pr_auc": round(ap_va, 4), "fit_seconds": round(fit_s, 2)})
        if best is None or ap_va > best[0]:
            best = (ap_va, C, m, sva, fit_s)
    search_s = time.perf_counter() - t_all
    _, C, model, sva, fit_s = best
    thr, objective = choose_threshold(yva, sva, a.precision_target)
    col = list(model.classes_).index(1)
    t0 = time.perf_counter()
    ste = model.predict_proba(Xte)[:, col]
    test_pred_s = time.perf_counter() - t0
    version = f"urlml-lr-char35-{len(train)}-{time.strftime('%Y%m%d%H%M')}"
    report = {
        "model_version": version,
        "train_rows": len(train), "train_phishing": int(ytr.sum()),
        "train_groups": len({r["group"] for r in train}),
        "train_partition_rows_available": len(train_all),
        "C_grid": grid, "C": C,
        "vocab_size": len(model.named_steps["tfidf"].vocabulary_),
        "threshold": round(thr, 6), "threshold_objective": objective,
        "validation": metrics(yva, sva, thr),
        "test": metrics(yte, ste, thr),
        "timing": {"fit_seconds_chosen": round(fit_s, 2), "grid_search_seconds": round(search_s, 2),
                   "test_predict_seconds": round(test_pred_s, 3),
                   "test_predict_ms_per_url": round(1000 * test_pred_s / max(len(Xte), 1), 4)},
    }
    meta = {"model_version": version, "threshold": round(thr, 6),
            "threshold_objective": objective, "rules_commit": RULES_BASELINE_COMMIT,
            "dataset": {k: manifest.get(k) for k in ("dataset", "license", "source_zip_sha256", "retrieved_at", "seed")},
            "training": {"rows": len(train), "C": C, "max_features": a.max_features,
                         "vectorizer": "TfidfVectorizer(char, 3-5, lowercase=False, min_df=2, sublinear_tf, float32)",
                         "classifier": "LogisticRegression(liblinear)"},
            "eval_summary": {"validation": report["validation"], "test": report["test"]}}
    out = Path(a.out)
    meta = url_ml.save_artifact(model, meta, out)
    # end-to-end latency through the public batch API (includes preprocessing)
    url_ml._CACHE.clear()
    t0 = time.perf_counter(); url_ml.load_model(out); load_s = time.perf_counter() - t0
    sample = [r["text"] for r in test[:1000]]
    t0 = time.perf_counter(); res = url_ml.predict_urls(sample, model_dir=out)
    e2e = time.perf_counter() - t0
    report["timing"].update({"load_seconds": round(load_s, 3),
                             "predict_urls_1000_seconds": round(e2e, 3),
                             "predict_urls_ms_per_url": round(e2e, 3)})
    report["predict_urls_status_counts_1000"] = {s: sum(r["status"] == s for r in res) for s in ("scored", "unavailable", "not_evaluated")}
    report["model_bytes"] = meta["model_bytes"]
    report["peak_rss_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1)
    report["data_manifest"] = {k: manifest[k] for k in ("read_stats", "raw_label_counts", "audit", "partitions")}
    (out / "eval_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    if a.deliver:
        dd = Path(a.deliver) / version
        dd.mkdir(parents=True, exist_ok=True)
        for f in (url_ml.MODEL_FILE, url_ml.META_FILE, "eval_report.json"):
            shutil.copy2(out / f, dd / f)
        report["delivered_to"] = str(dd)
    print(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
