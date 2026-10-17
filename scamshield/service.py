"""Analysis pipeline shared by the API: model verdict, indicators, links, logging, and review routing."""
import logging

from . import config, monitoring
from .conversation import parse_conversation, to_display_text, to_model_text
from .indicators import find_indicators
from .model import Detector

log = logging.getLogger("scamshield")


def infer_claimed_company(text: str) -> str | None:
    """Return a demo company named in the chat, if one is listed in official_domains.json."""
    try:
        from .links import official_domains
    except Exception:
        return None
    lowered = text.lower()
    for name in sorted(official_domains(), key=len, reverse=True):
        if name.lower() in lowered:
            return name
    return None


def safe_check_urls(text: str, claimed_company: str | None = None) -> list[dict] | None:
    """Link checking is optional: None means disabled or failed, and the verdict never depends on it."""
    if not config.ENABLE_LINK_CHECK:
        return None
    try:
        from .links import check_urls

        return check_urls(text, claimed_company=claimed_company)
    except Exception:
        log.exception("link checker failed; continuing without it")
        return None


class Analyzer:
    def __init__(self):
        self.detector: Detector | None = None
        self.reload()

    def reload(self) -> None:
        self.detector = Detector.load() if config.MODEL_PATH.exists() else None

    @property
    def ready(self) -> bool:
        return self.detector is not None

    def analyze(self, text: str, source: str = "live", timeline: bool = True,
                claimed_company: str | None = None, allow_review: bool = True) -> dict:
        messages = parse_conversation(text)
        if not messages:
            raise ValueError("empty conversation")
        d = self.detector

        model_text = to_model_text(messages)
        score = float(d.predict_proba([model_text])[0])
        novelty = float(d.novelty([model_text])[0])
        # Score on the side the model chose: max(p, 1-p). Not the distance from 0.5.
        confidence = max(score, 1 - score)
        unfamiliar = novelty > d.novelty_threshold
        uncertain = config.UNCERTAIN_LOW <= score <= config.UNCERTAIN_HIGH
        company = claimed_company or infer_claimed_company(text)
        links = safe_check_urls(text, claimed_company=company)
        risky_links = sum(1 for link in links or [] if link.get("risk") != "low")

        drift = monitoring.drift_status(d.reference, model_version=d.version)
        reasons = []
        if uncertain:
            reasons.append("uncertain")
        if unfamiliar:
            reasons.append("unfamiliar")
        if drift["drift"] and score >= config.DRIFT_FALLBACK_THRESHOLD and not reasons:
            reasons.append("drift-fallback")
        review_reason = ",".join(reasons) or None
        if not allow_review:
            review_reason = None

        label = "scam" if score >= config.SCAM_THRESHOLD else "legit"
        verdict = "Scam signal detected" if label == "scam" else "No strong scam signal detected"
        prediction_id = monitoring.log_prediction(
            source=source, model_version=d.version, score=score, label=label, confidence=confidence,
            novelty=novelty, unfamiliar=unfamiliar, uncertain=uncertain, link_flags=risky_links,
            review_reason=review_reason, text=to_display_text(messages),
        )

        result = {
            "prediction_id": prediction_id,
            "model_version": d.version,
            "label": label,
            "verdict": verdict,
            "claimed_company": company,
            "score": score,
            "confidence": confidence,
            "novelty": novelty,
            "unfamiliar": unfamiliar,
            "uncertain": uncertain,
            "routed_to_review": review_reason is not None,
            "review_reason": review_reason,
            "drift_active": drift["drift"],
            "indicators": find_indicators(model_text),
            "links": links,
        }
        if timeline:
            prefixes = [to_model_text(messages[: i + 1]) for i in range(len(messages))]
            scores = d.predict_proba(prefixes)
            result["timeline"] = [
                {"index": i, "sender": m["sender"], "text": m["text"], "cumulative_score": float(s),
                 "indicators": find_indicators(m["text"])}
                for i, (m, s) in enumerate(zip(messages, scores))
            ]
        return result
