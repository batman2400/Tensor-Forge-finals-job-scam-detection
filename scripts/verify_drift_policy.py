"""Show the frozen drift policy on the loaded pipeline.

Temporary databases only. The working prediction log is not opened.
Thresholds are not changed.

The three checks are:

- a window above the mean-unfamiliarity limit, and inside the other three cuts,
  returns the advisory and does not queue a chat that has no individual reason
- each original signal, on its own, sets the drift alert
- an uncertain chat, an unfamiliar chat, and a high-risk link still reach review
  while that advisory window is the only batch signal
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield import config, monitoring  # noqa: E402
from scamshield.conversation import to_display_text, to_model_text  # noqa: E402
from scamshield.data import load_split  # noqa: E402
from scamshield.model import Detector  # noqa: E402
from scamshield.service import infer_claimed_company, safe_check_urls  # noqa: E402


def _temp_db(working: Path) -> Path:
    path = Path(tempfile.mkdtemp()) / "verify.db"
    if path.resolve() == working.resolve():
        raise RuntimeError("temporary database resolved to the working log")
    config.DB_PATH = path
    return path


def _log_window(version: str, rows: list[dict]) -> None:
    for row in rows:
        monitoring.log_prediction(
            source="verify",
            model_version=version,
            score=float(row["score"]),
            label="scam" if row["score"] >= config.SCAM_THRESHOLD else "legit",
            confidence=float(row["confidence"]),
            novelty=float(row["novelty"]),
            unfamiliar=bool(row["unfamiliar"]),
            uncertain=bool(row["uncertain"]),
            link_flags=0,
            review_reason=None,
            text=None,
        )


def _flags(detector: Detector, text: str) -> dict:
    messages_text = text
    from scamshield.conversation import parse_conversation

    messages = parse_conversation(messages_text)
    model_text = to_model_text(messages)
    score = float(detector.predict_proba([model_text])[0])
    novelty = float(detector.novelty([model_text])[0])
    company = infer_claimed_company(messages_text)
    links = safe_check_urls(messages_text, claimed_company=company) or []
    return {
        "score": score,
        "novelty": novelty,
        "unfamiliar": novelty > detector.novelty_threshold,
        "uncertain": config.UNCERTAIN_LOW <= score <= config.UNCERTAIN_HIGH,
        "high_link": any(link.get("risk") == "high" for link in links),
    }


def _pick_examples(detector: Detector) -> dict[str, str]:
    rows = load_split("test")
    model_texts = [to_model_text(row["messages"]) for row in rows]
    scores = detector.predict_proba(model_texts)
    novelty = detector.novelty(model_texts)
    picked: dict[str, str] = {}
    for row, score, distance in zip(rows, scores, novelty):
        score = float(score)
        distance = float(distance)
        uncertain = config.UNCERTAIN_LOW <= score <= config.UNCERTAIN_HIGH
        unfamiliar = distance > detector.novelty_threshold
        text = to_display_text(row["messages"])
        flags = _flags(detector, text) if (uncertain or unfamiliar or score >= config.DRIFT_FALLBACK_THRESHOLD) else None
        if flags is None:
            continue
        if uncertain and not flags["unfamiliar"] and not flags["high_link"] and "uncertain" not in picked:
            picked["uncertain"] = text
        elif unfamiliar and not flags["uncertain"] and not flags["high_link"] and "unfamiliar" not in picked:
            picked["unfamiliar"] = text
        elif (
            score >= config.DRIFT_FALLBACK_THRESHOLD
            and not flags["uncertain"]
            and not flags["unfamiliar"]
            and not flags["high_link"]
            and "plain" not in picked
        ):
            picked["plain"] = text
        if len(picked) == 3:
            break
    legit = (config.DEMO_DIR / "legit_recruitment.txt").read_text(encoding="utf-8")
    picked["high_link"] = legit + "\nRecruiter: Register here: https://brightpath-careers.tasks-portal.example/join"
    missing = [name for name in ("uncertain", "unfamiliar", "plain", "high_link") if name not in picked]
    if missing:
        raise RuntimeError(f"could not isolate example chats: {missing}")
    return picked


def _slim(status: dict) -> dict:
    current = status.get("current") or {}
    return {
        "drift": status["drift"],
        "alerts": status["alerts"],
        "advisory": status["advisory"],
        "window_size": status["window_size"],
        "mean_novelty": current.get("mean_novelty"),
        "mean_confidence": current.get("mean_confidence"),
        "unfamiliar_rate": current.get("unfamiliar_rate"),
        "uncertain_rate": current.get("uncertain_rate"),
    }


def _analyze(client, text: str) -> dict:
    response = client.post("/analyze", json={"text": text, "source": "verify"})
    if response.status_code != 200:
        raise RuntimeError(f"analyze failed: {response.status_code} {response.text}")
    body = response.json()
    return {
        "score": body["score"],
        "drift_active": body["drift_active"],
        "advisory": body.get("advisory") or [],
        "routed_to_review": body["routed_to_review"],
        "review_reason": body["review_reason"],
        "prediction_id": body["prediction_id"],
    }


def run() -> dict:
    working = config.DB_PATH
    detector = Detector.load()
    reference = detector.reference
    version = detector.version
    if reference.get("model_version") != version:
        raise RuntimeError("saved reference is not stamped with the loaded pipeline")
    if reference.get("drift_policy") != config.DRIFT_POLICY:
        raise RuntimeError("loaded model is not on the frozen drift policy")
    limit = float(reference["novelty_mean_alert"])
    threshold = float(detector.novelty_threshold)
    if not limit < threshold:
        raise RuntimeError("no gap between the advisory limit and the individual unfamiliarity cut")
    examples = _pick_examples(detector)
    isolated = {name: _flags(detector, text) for name, text in examples.items()}
    from fastapi.testclient import TestClient
    from scamshield.api import app

    client = TestClient(app)
    failures: list[str] = []

    def expect(ok: bool, message: str) -> None:
        if not ok:
            failures.append(message)

    for name, flags in isolated.items():
        if name == "uncertain":
            expect(flags["uncertain"] and not flags["unfamiliar"] and not flags["high_link"], f"uncertain example is mixed: {flags}")
        elif name == "unfamiliar":
            expect(flags["unfamiliar"] and not flags["uncertain"] and not flags["high_link"], f"unfamiliar example is mixed: {flags}")
        elif name == "plain":
            expect(
                flags["score"] >= config.DRIFT_FALLBACK_THRESHOLD
                and not flags["uncertain"] and not flags["unfamiliar"] and not flags["high_link"],
                f"plain example would not show broad routing: {flags}",
            )
        elif name == "high_link":
            expect(flags["high_link"] and not flags["uncertain"] and not flags["unfamiliar"], f"link example is mixed: {flags}")

    # Mean unfamiliarity sits between the advisory limit and the individual cut.
    advisory_novelty = (limit + threshold) / 2
    advisory_rows = [
        {"score": 0.08, "confidence": reference["mean_confidence"], "novelty": advisory_novelty,
         "unfamiliar": False, "uncertain": False}
        for _ in range(config.DRIFT_MIN_SAMPLES)
    ]
    try:
        _temp_db(working)
        _log_window(version, advisory_rows)
        advisory = _slim(client.get("/monitoring").json())
        plain = _analyze(client, examples["plain"])
        uncertain = _analyze(client, examples["uncertain"])
        unfamiliar = _analyze(client, examples["unfamiliar"])
        high_link = _analyze(client, examples["high_link"])
        queue = client.get("/review").json()
    except Exception:
        config.DB_PATH = working
        raise
    queued_reasons = {item["review_reason"] for item in queue}

    expect(advisory["drift"] is False, "advisory window raised a drift alert")
    expect(advisory["alerts"] == [], f"advisory window alerts: {advisory['alerts']}")
    expect(advisory["advisory"] == [config.ADVISORY_NOVELTY_MESSAGE], "advisory text missing")
    expect(advisory["mean_novelty"] > limit, "advisory window was not above the frozen limit")
    expect(plain["drift_active"] is False and plain["routed_to_review"] is False,
           f"plain chat was broadly routed during advisory: {plain}")
    expect(plain["advisory"] == [config.ADVISORY_NOVELTY_MESSAGE], "plain chat hid the advisory")
    expect(uncertain["drift_active"] is False and uncertain["review_reason"] == "uncertain",
           f"uncertain chat: {uncertain}")
    expect(unfamiliar["drift_active"] is False and unfamiliar["review_reason"] == "unfamiliar",
           f"unfamiliar chat: {unfamiliar}")
    expect(high_link["drift_active"] is False and high_link["review_reason"] == "high-risk-link",
           f"high-risk link: {high_link}")
    expect(queued_reasons == {"uncertain", "unfamiliar", "high-risk-link"},
           f"review queue reasons: {sorted(queued_reasons)}")
    expect(plain["prediction_id"] not in {item["id"] for item in queue}, "plain chat entered the queue")

    # Each original signal on its own. Mean unfamiliarity stays at or under the limit,
    # so the advisory is not what raises the alert.
    quiet_novelty = limit - 0.05
    signal_rows = {
        "confidence_drop": [
            {"score": 0.30, "confidence": reference["mean_confidence"] - config.CONFIDENCE_DROP_ALERT - 0.02,
             "novelty": quiet_novelty, "unfamiliar": False, "uncertain": False}
            for _ in range(config.DRIFT_MIN_SAMPLES)
        ],
        "unfamiliar_rise": [],
        "uncertain_rise": [],
    }
    unfamiliar_count = 5
    for i in range(config.DRIFT_MIN_SAMPLES):
        high_novelty = threshold + 0.005
        signal_rows["unfamiliar_rise"].append({
            "score": 0.20,
            "confidence": reference["mean_confidence"],
            "novelty": high_novelty if i < unfamiliar_count else quiet_novelty,
            "unfamiliar": i < unfamiliar_count,
            "uncertain": False,
        })
        signal_rows["uncertain_rise"].append({
            "score": 0.50 if i < 4 else 0.10,
            "confidence": reference["mean_confidence"],
            "novelty": quiet_novelty,
            "unfamiliar": False,
            "uncertain": i < 4,
        })
    signals = {}
    fallback = None
    try:
        for name, rows in signal_rows.items():
            _temp_db(working)
            _log_window(version, rows)
            status = _slim(client.get("/monitoring").json())
            signals[name] = status
            if name == "confidence_drop":
                fallback = _analyze(client, examples["plain"])
            mean_novelty = sum(row["novelty"] for row in rows) / len(rows)
            expect(mean_novelty <= limit, f"{name} also crossed the advisory limit ({mean_novelty})")
            expect(status["drift"] is True, f"{name} did not raise a drift alert")
            expect(status["advisory"] == [], f"{name} also raised the advisory: {status['advisory']}")
    except Exception:
        config.DB_PATH = working
        raise
    expect(any("confidence" in item.lower() for item in signals["confidence_drop"]["alerts"]),
           f"confidence alert missing: {signals['confidence_drop']['alerts']}")
    expect(any("Unfamiliar" in item for item in signals["unfamiliar_rise"]["alerts"]),
           f"unfamiliar alert missing: {signals['unfamiliar_rise']['alerts']}")
    expect(any("Uncertain" in item for item in signals["uncertain_rise"]["alerts"]),
           f"uncertain alert missing: {signals['uncertain_rise']['alerts']}")
    expect(fallback["drift_active"] is True and fallback["review_reason"] == "drift-fallback",
           f"same plain chat was not broadly routed under a real alert: {fallback}")

    config.DB_PATH = working
    return {
        "pipeline_version": version,
        "drift_policy": reference.get("drift_policy"),
        "novelty_mean_alert": limit,
        "novelty_threshold": threshold,
        "working_log": str(working),
        "working_log_used": False,
        "thresholds_changed": False,
        "example_flags": isolated,
        "advisory_only": advisory,
        "plain_during_advisory": plain,
        "uncertain_during_advisory": uncertain,
        "unfamiliar_during_advisory": unfamiliar,
        "high_link_during_advisory": high_link,
        "signals": signals,
        "plain_during_confidence_alert": fallback,
        "failures": failures,
    }


def main() -> None:
    report = run()
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = config.REPORT_DIR / "verify_drift_policy.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
