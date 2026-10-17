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


def safe_check_urls(text: str, claimed_company: str | None = None,
                    expected_domain: str | None = None) -> list[dict] | None:
    """Link checking is optional. None means disabled or failed.

    The model verdict does not depend on the result. A high-risk link is a
    separate review reason (see ``review_reasons``). ``expected_domain`` is
    used only when the caller passes it.
    """
    if not config.ENABLE_LINK_CHECK:
        return None
    try:
        from .links import check_urls

        return check_urls(text, claimed_company=claimed_company, expected_domain=expected_domain)
    except Exception:
        log.exception("link checker failed; continuing without it")
        return None


def review_reasons(*, uncertain: bool, unfamiliar: bool, drift: bool, score: float,
                   links: list[dict] | None, allow_review: bool,
                   credential: bool = False) -> str | None:
    """Reasons to queue a chat. The model score is left as it is.

    A link with risk ``high`` (IP, company mismatch, look-alike, or .apk)
    adds ``high-risk-link``. Medium flags stay notes and do not queue the chat.
    ``credential`` is an explicit password, PIN, or one-time-code request. It
    queues the chat and does not change the score. ``drift`` is the batch alert
    from the three original signals. The mean-unfamiliarity advisory is not a
    reason and is not passed in here. ``allow_review=False`` is the held-out
    test replay: nothing is queued.
    """
    reasons = []
    if uncertain:
        reasons.append("uncertain")
    if unfamiliar:
        reasons.append("unfamiliar")
    if credential:
        reasons.append("credential-request")
    if any(link.get("risk") == "high" for link in links or []):
        reasons.append("high-risk-link")
    if drift and score >= config.DRIFT_FALLBACK_THRESHOLD and not reasons:
        reasons.append("drift-fallback")
    if not allow_review:
        return None
    return ",".join(reasons) or None


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
                claimed_company: str | None = None, expected_domain: str | None = None,
                allow_review: bool = True) -> dict:
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
        from .links import canonical_expected_domain

        company = claimed_company or infer_claimed_company(text)
        adviser_domain = canonical_expected_domain(expected_domain)
        links = safe_check_urls(text, claimed_company=company, expected_domain=adviser_domain)
        risky_links = sum(1 for link in links or [] if link.get("risk") != "low")

        from .context import explicit_credential_request

        credential = explicit_credential_request(model_text)
        drift = monitoring.drift_status(d.reference, model_version=d.version)
        review_reason = review_reasons(
            uncertain=uncertain, unfamiliar=unfamiliar, drift=drift["drift"], score=score,
            links=links, allow_review=allow_review, credential=credential,
        )

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
            "expected_domain": adviser_domain,
            "expected_domain_note": (
                "Adviser-provided. This tool did not look it up or verify it."
                if adviser_domain else None
            ),
            "score": score,
            "confidence": confidence,
            "novelty": novelty,
            "unfamiliar": unfamiliar,
            "uncertain": uncertain,
            "routed_to_review": review_reason is not None,
            "review_reason": review_reason,
            "credential_request": credential,
            "drift_active": drift["drift"],
            "drift_alerts": drift.get("alerts") or [],
            "advisory": drift.get("advisory") or [],
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
