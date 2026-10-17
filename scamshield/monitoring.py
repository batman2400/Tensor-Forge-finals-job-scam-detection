"""Prediction logging (SQLite), drift signals, and the human-review queue."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    model_version TEXT,
    score REAL NOT NULL,
    label TEXT NOT NULL,
    confidence REAL NOT NULL,
    novelty REAL NOT NULL,
    unfamiliar INTEGER NOT NULL,
    uncertain INTEGER NOT NULL,
    link_flags INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,          -- auto | review | reviewed
    review_reason TEXT,
    text TEXT,                     -- stored only for items routed to review
    review_label INTEGER
);
"""


@contextmanager
def _db():
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def log_prediction(*, source, model_version, score, label, confidence, novelty, unfamiliar,
                   uncertain, link_flags, review_reason, text) -> int:
    status = "review" if review_reason else "auto"
    with _db() as conn:
        cur = conn.execute(
            """INSERT INTO predictions (ts, source, model_version, score, label, confidence, novelty,
               unfamiliar, uncertain, link_flags, status, review_reason, text)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (datetime.now(timezone.utc).isoformat(), source, model_version, score, label, confidence,
             novelty, int(unfamiliar), int(uncertain), link_flags, status, review_reason,
             text if review_reason else None),
        )
        return cur.lastrowid


def _is_holdout_source(source: str | None) -> bool:
    """Held-out replays may be logged for monitoring. They must not be reviewed into training."""
    source = source or ""
    return source.startswith("replay:test") or source.startswith("heldout:")


def recent(limit: int = 200, model_version: str | None = None) -> list[dict]:
    with _db() as conn:
        if model_version:
            rows = conn.execute(
                """SELECT id, ts, source, model_version, score, label, confidence, novelty, unfamiliar, uncertain, status
                   FROM predictions WHERE model_version = ? ORDER BY id DESC LIMIT ?""",
                (model_version, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT id, ts, source, model_version, score, label, confidence, novelty, unfamiliar, uncertain, status
                   FROM predictions ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
    return [dict(r) for r in reversed(rows)]


def drift_status(reference: dict, window: int = config.DRIFT_WINDOW, model_version: str | None = None) -> dict:
    rows = recent(window, model_version=model_version)
    n = len(rows)
    status = {
        "window_size": n,
        "model_version": model_version,
        "reference": reference,
        "alerts": [],
        "drift": False,
    }
    ref_version = (reference or {}).get("model_version")
    if model_version and ref_version and ref_version != model_version:
        status["reference_mismatch"] = True
        return status
    if n == 0:
        return status
    current = {
        "mean_confidence": sum(r["confidence"] for r in rows) / n,
        "unfamiliar_rate": sum(r["unfamiliar"] for r in rows) / n,
        "uncertain_rate": sum(r["uncertain"] for r in rows) / n,
        "scam_rate": sum(r["label"] == "scam" for r in rows) / n,
    }
    status["current"] = current
    if n < config.DRIFT_MIN_SAMPLES or not reference:
        return status

    alerts = []
    if reference["mean_confidence"] - current["mean_confidence"] > config.CONFIDENCE_DROP_ALERT:
        alerts.append(f"Mean confidence fell from {reference['mean_confidence']:.2f} to {current['mean_confidence']:.2f}")
    if current["unfamiliar_rate"] - reference["unfamiliar_rate"] > config.UNFAMILIAR_RISE_ALERT:
        alerts.append(f"Unfamiliar inputs rose from {reference['unfamiliar_rate']:.0%} to {current['unfamiliar_rate']:.0%}")
    if current["uncertain_rate"] - reference["uncertain_rate"] > config.UNCERTAIN_RISE_ALERT:
        alerts.append(f"Uncertain predictions rose from {reference['uncertain_rate']:.0%} to {current['uncertain_rate']:.0%}")
    status["alerts"] = alerts
    status["drift"] = bool(alerts)
    return status


def review_queue(limit: int = 100) -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            """SELECT id, ts, source, score, label, confidence, novelty, review_reason, text
               FROM predictions WHERE status = 'review'
               AND source NOT LIKE 'replay:test%' AND source NOT LIKE 'heldout:%'
               ORDER BY id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def submit_review(prediction_id: int, review_label: int) -> bool:
    with _db() as conn:
        row = conn.execute(
            "SELECT source, status FROM predictions WHERE id = ?", (prediction_id,)
        ).fetchone()
        if row is None or row["status"] != "review" or _is_holdout_source(row["source"]):
            return False
        cur = conn.execute(
            "UPDATE predictions SET status = 'reviewed', review_label = ? WHERE id = ? AND status = 'review'",
            (review_label, prediction_id),
        )
        return cur.rowcount == 1


def reviewed_examples() -> list[tuple[str, int]]:
    """Human labels eligible for a later retrain. Held-out test replays are excluded.

    Stored chats keep speaker names so a reviewer can read them. Training text drops those
    names, same as texts_labels(), so a reviewed chat is not a different format from the seed set.
    """
    from .conversation import parse_conversation, to_model_text

    with _db() as conn:
        rows = conn.execute(
            """SELECT text, review_label FROM predictions
               WHERE status = 'reviewed' AND text IS NOT NULL
               AND source NOT LIKE 'replay:test%' AND source NOT LIKE 'heldout:%'"""
        ).fetchall()
    examples = []
    for row in rows:
        messages = parse_conversation(row["text"])
        if not messages:
            continue
        examples.append((to_model_text(messages), int(row["review_label"])))
    return examples


def reset() -> None:
    with _db() as conn:
        conn.execute("DELETE FROM predictions")
