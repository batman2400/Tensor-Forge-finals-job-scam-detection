"""Dataset loading. One JSON object per line:

{"id": str, "label": 0|1, "category": str, "lang": "en"|"singlish",
 "source": str, "messages": [{"sender": str, "text": str}]}
"""
import json
from pathlib import Path

from . import config
from .conversation import to_model_text


def read_jsonl(path: Path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def load_split(name: str) -> list[dict]:
    """name: train | test | shifted. Falls back to the hand-written seed set for train."""
    path = config.PROCESSED_DIR / f"{name}.jsonl"
    if path.exists():
        return read_jsonl(path)
    if name == "train" and config.SEED_PATH.exists():
        print(f"[data] {path} missing, using seed data")
        return read_jsonl(config.SEED_PATH)
    raise FileNotFoundError(path)


def texts_labels(rows: list[dict]) -> tuple[list[str], list[int]]:
    return [to_model_text(r["messages"]) for r in rows], [int(r["label"]) for r in rows]
