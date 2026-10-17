import logging

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import config, monitoring
from .conversation import to_display_text
from .data import read_jsonl
from .service import Analyzer, infer_claimed_company, safe_check_urls
from .training import retrain_with_reviews

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scamshield")

app = FastAPI(title="ScamShield LK", version="0.1.0")
analyzer = Analyzer()

REPLAY_SETS = {"test": "test.jsonl", "shifted": "shifted_stream.jsonl", "drift": "drift_demo.jsonl"}


class AnalyzeRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000)
    source: str = "live"
    claimed_company: str | None = None
    expected_domain: str | None = None


class ReviewRequest(BaseModel):
    label: int = Field(..., ge=0, le=1)


class ReplayRequest(BaseModel):
    dataset: str = "shifted"
    limit: int = Field(60, ge=1, le=1000)


def _require_model():
    if not analyzer.ready:
        raise HTTPException(503, "No trained model. Run: python scripts/train.py")


@app.get("/health")
def health():
    detector = analyzer.detector
    return {
        "status": "ok",
        "model_loaded": analyzer.ready,
        "model_version": detector.version if analyzer.ready else None,
        "fit_version": (getattr(detector, "fit_version", "") or detector.version) if analyzer.ready else None,
        "drift_policy": detector.reference.get("drift_policy") if analyzer.ready else None,
    }


@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    _require_model()
    try:
        result = analyzer.analyze(
            req.text, source=req.source, claimed_company=req.claimed_company,
            expected_domain=req.expected_domain,
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    log.info("prediction id=%s label=%s score=%.3f review=%s",
             result["prediction_id"], result["label"], result["score"], result["review_reason"])
    return result


@app.post("/links")
def links(req: AnalyzeRequest):
    company = req.claimed_company or infer_claimed_company(req.text)
    try:
        from .links import canonical_expected_domain

        adviser_domain = canonical_expected_domain(req.expected_domain)
    except ValueError as e:
        raise HTTPException(422, str(e))
    result = safe_check_urls(req.text, claimed_company=company, expected_domain=adviser_domain)
    if result is None:
        raise HTTPException(503, "Link checker disabled or unavailable")
    return result


@app.post("/replay")
def replay(req: ReplayRequest):
    """Feed a stored dataset through the live pipeline to demonstrate monitoring."""
    _require_model()
    if req.dataset not in REPLAY_SETS:
        raise HTTPException(400, f"dataset must be one of {list(REPLAY_SETS)}")
    if req.dataset == "drift":
        path = config.DEMO_DIR / REPLAY_SETS[req.dataset]
    else:
        path = config.PROCESSED_DIR / REPLAY_SETS[req.dataset]
    if not path.exists():
        raise HTTPException(404, f"{path.name} not found; run scripts/prepare_data.py")
    rows = read_jsonl(path)[: req.limit]
    correct = routed = 0
    # Test replay is a control. The drift sample is unfamiliar writing used only
    # to move the monitoring window. Neither is queued for review.
    allow_review = req.dataset == "shifted"
    for row in rows:
        r = analyzer.analyze(
            to_display_text(row["messages"]), source=f"replay:{req.dataset}", timeline=False,
            allow_review=allow_review,
        )
        if req.dataset != "drift":
            correct += int((r["label"] == "scam") == bool(row["label"]))
        routed += int(r["routed_to_review"])
    drift = monitoring.drift_status(analyzer.detector.reference, model_version=analyzer.detector.version)
    if drift["drift"]:
        log.warning("DRIFT ALERT: %s", "; ".join(drift["alerts"]))
    elif drift.get("advisory"):
        log.info("DRIFT ADVISORY: %s", "; ".join(drift["advisory"]))
    result = {"dataset": req.dataset, "n": len(rows), "routed_to_review": routed,
              "eligible_for_retrain": req.dataset == "shifted", "drift": drift}
    if req.dataset != "drift":
        result["accuracy"] = correct / max(len(rows), 1)
    return result


@app.get("/monitoring")
def monitoring_status():
    _require_model()
    return monitoring.drift_status(analyzer.detector.reference, model_version=analyzer.detector.version)


@app.get("/predictions")
def predictions(limit: int = 200):
    return monitoring.recent(limit)


@app.get("/review")
def review_queue():
    return monitoring.review_queue()


@app.post("/review/{prediction_id}")
def submit_review(prediction_id: int, req: ReviewRequest):
    if not monitoring.submit_review(prediction_id, req.label):
        raise HTTPException(404, "not in review queue")
    return {"ok": True}


@app.post("/retrain")
def retrain():
    reviewed = monitoring.reviewed_examples()
    if not reviewed:
        raise HTTPException(400, "No reviewed examples yet")
    result = retrain_with_reviews(reviewed)
    analyzer.reload()
    log.info("retrained with %d reviewed examples -> %s", len(reviewed), analyzer.detector.version)
    return result


@app.post("/admin/reset-logs")
def reset_logs():
    monitoring.reset()
    return {"ok": True}
