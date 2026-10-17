"""Merge raw generated batches into processed splits and remove leakage.

Inputs  (data/raw/):  train_*.jsonl, test_*.jsonl, shifted_*.jsonl   (+ data/seed/seed.jsonl -> train)
Outputs (data/processed/):
    train.jsonl           training data
    test.jsonl            held-out test set (generated separately, near-duplicates of train removed)
    shifted.jsonl         held-out shifted set, used only for evaluation
    shifted_stream.jsonl  shifted replay for the drift demo; near-duplicates of shifted.jsonl are removed first
"""
import hashlib
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402

from scamshield import config  # noqa: E402
from scamshield.conversation import to_model_text  # noqa: E402
from scamshield.data import read_jsonl, write_jsonl  # noqa: E402

NEAR_DUP_SIM = 0.9


def norm_hash(row: dict) -> str:
    text = re.sub(r"\W+", " ", to_model_text(row["messages"]).lower()).strip()
    return hashlib.sha1(text.encode()).hexdigest()


def load(prefix: str) -> list[dict]:
    rows = []
    for path in sorted(config.RAW_DIR.glob(f"{prefix}_*.jsonl")):
        rows += read_jsonl(path)
    return rows


def valid(row: dict) -> bool:
    return row.get("label") in (0, 1) and isinstance(row.get("messages"), list) and len(row["messages"]) >= 2


def dedupe(rows: list[dict], seen: set) -> list[dict]:
    out = []
    for r in rows:
        h = norm_hash(r)
        if h not in seen:
            seen.add(h)
            out.append(r)
    return out


def drop_near_duplicates(rows: list[dict], reference: list[dict]) -> list[dict]:
    if not rows or not reference:
        return rows
    vec = TfidfVectorizer(ngram_range=(1, 2)).fit([to_model_text(r["messages"]) for r in reference + rows])
    ref = vec.transform([to_model_text(r["messages"]) for r in reference])
    cand = vec.transform([to_model_text(r["messages"]) for r in rows])
    max_sim = (cand @ ref.T).max(axis=1).toarray().ravel()
    kept = [r for r, s in zip(rows, max_sim) if s < NEAR_DUP_SIM]
    print(f"  near-duplicate filter removed {len(rows) - len(kept)}")
    return kept


def split_shifted(shifted: list[dict], rng: random.Random) -> tuple[list[dict], list[dict]]:
    """Keep the eval half fixed, then drop stream rows that are near-duplicates of it.

    A random half would let near-copies sit in both the replay/retrain stream and the held-out
    shifted eval, which inflates any later before/after comparison.
    """
    rows = list(shifted)
    rng.shuffle(rows)
    half = len(rows) // 2
    eval_rows = rows[half:]
    stream = drop_near_duplicates(rows[:half], eval_rows)
    return stream, eval_rows


def summary(name: str, rows: list[dict]) -> None:
    scams = sum(r["label"] for r in rows)
    print(f"{name:15s} n={len(rows):4d} scam={scams} legit={len(rows) - scams}")


def main():
    seen: set = set()
    seed = read_jsonl(config.SEED_PATH) if config.SEED_PATH.exists() else []
    train = dedupe([r for r in load("train") + seed if valid(r)], seen)
    test = drop_near_duplicates(dedupe([r for r in load("test") if valid(r)], seen), train)
    shifted = drop_near_duplicates(dedupe([r for r in load("shifted") if valid(r)], seen), train)
    shifted = drop_near_duplicates(shifted, test)

    rng = random.Random(42)
    stream, shifted_eval = split_shifted(shifted, rng)

    for name, rows in [("train", train), ("test", test), ("shifted", shifted_eval), ("shifted_stream", stream)]:
        for i, r in enumerate(rows):
            r.setdefault("id", f"{name}-{i}")
        write_jsonl(config.PROCESSED_DIR / f"{name}.jsonl", rows)
        summary(name, rows)


if __name__ == "__main__":
    main()
