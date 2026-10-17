"""Score the confirmation batches on a temporary database.

The working prediction log is not opened. The shifted stream is not replayed.
The limit must already be frozen on the saved model.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield import config, monitoring  # noqa: E402
from scamshield.data import read_jsonl, texts_labels  # noqa: E402
from scamshield.model import Detector  # noqa: E402
from scamshield.training import save_report  # noqa: E402

CONFIRM = config.ROOT / "data" / "confirm"


def _replay(detector: Detector, filename: str, source: str) -> dict:
    path = Path(filename)
    if not path.is_file():
        path = CONFIRM / filename
    rows = read_jsonl(path)
    texts, labels = texts_labels(rows)
    if len(texts) < config.DRIFT_WINDOW:
        raise SystemExit(f"{filename} has {len(texts)} chats; the limit is built for {config.DRIFT_WINDOW}")
    scores = detector.predict_proba(texts)
    novelty = detector.novelty(texts)
    real_db = config.DB_PATH
    temp_db = Path(tempfile.mkdtemp()) / "confirm.db"
    if temp_db.resolve() == real_db.resolve():
        raise SystemExit("temporary database resolved to the working log")
    config.DB_PATH = temp_db
    try:
        for score, distance, label in zip(scores, novelty, labels):
            score = float(score)
            monitoring.log_prediction(
                source=source,
                model_version=detector.version,
                score=score,
                label="scam" if score >= config.SCAM_THRESHOLD else "legit",
                confidence=float(max(score, 1.0 - score)),
                novelty=float(distance),
                unfamiliar=bool(distance > detector.novelty_threshold),
                uncertain=bool(config.UNCERTAIN_LOW <= score <= config.UNCERTAIN_HIGH),
                link_flags=0,
                review_reason=None,
                text=None,
            )
        # The limit assumes a window of DRIFT_WINDOW, so use the first window only.
        status = monitoring.drift_status(
            detector.reference, window=config.DRIFT_WINDOW, model_version=detector.version
        )
    finally:
        config.DB_PATH = real_db
    current = status["current"]
    correct = sum((float(score) >= config.SCAM_THRESHOLD) == bool(label) for score, label in zip(scores, labels))
    return {
        "source": source,
        "n": len(texts),
        "accuracy": correct / len(texts),
        "drift": status["drift"],
        "alerts": status["alerts"],
        "advisory": status.get("advisory") or [],
        "mean_novelty": current["mean_novelty"],
        "mean_confidence": current["mean_confidence"],
        "unfamiliar_rate": current["unfamiliar_rate"],
        "uncertain_rate": current["uncertain_rate"],
        "temporary_db": str(temp_db),
    }


def main() -> None:
    legit_name = sys.argv[1] if len(sys.argv) > 1 else "legit.jsonl"
    shifted_name = sys.argv[2] if len(sys.argv) > 2 else "shifted.jsonl"
    report_name = sys.argv[3] if len(sys.argv) > 3 else "confirm_drift"
    detector = Detector.load()
    reference = detector.reference
    report = {
        "pipeline_version": detector.version,
        "fit_version": getattr(detector, "fit_version", ""),
        "novelty_mean_alert": reference.get("novelty_mean_alert"),
        "mean_novelty_validation": reference.get("mean_novelty"),
        "novelty_limit": reference.get("novelty_limit"),
        "novelty_assumptions": reference.get("novelty_assumptions"),
        "working_log": str(config.DB_PATH),
        "development_stream_replayed": False,
        "drift_policy": reference.get("drift_policy") or config.DRIFT_POLICY,
        "threshold_changed": False,
        "legit_control": _replay(detector, legit_name, "confirm:legit"),
        "shifted_confirm": _replay(detector, shifted_name, "confirm:shifted"),
    }
    save_report(report, report_name)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
