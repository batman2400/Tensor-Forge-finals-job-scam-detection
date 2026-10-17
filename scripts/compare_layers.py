"""Compare raw scores, final verdicts, and review routing. Does not open the working log.

The classification threshold is left where it is. This script does not train.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield import config  # noqa: E402
from scamshield.context import adjust_score, explicit_credential_request  # noqa: E402
from scamshield.conversation import to_model_text  # noqa: E402
from scamshield.data import read_jsonl  # noqa: E402
from scamshield.model import Detector  # noqa: E402
from scamshield.service import review_reasons  # noqa: E402


def layers(detector: Detector, rows: list[dict]) -> dict:
    texts = [to_model_text(row["messages"]) for row in rows]
    raw_scores = detector.clf.predict_proba(detector._encode(texts))[:, 1]
    novelty = detector.novelty(texts)
    raw_hit = 0
    final_hit = 0
    raw_fp = 0
    final_fp = 0
    reviewed = 0
    silent = 0
    missed = []
    lifted = []
    for row, text, raw_score, distance in zip(rows, texts, raw_scores, novelty):
        raw_score = float(raw_score)
        final = float(adjust_score(text, raw_score))
        label = int(row["label"])
        raw_pred = raw_score >= config.SCAM_THRESHOLD
        final_pred = final >= config.SCAM_THRESHOLD
        raw_hit += int(raw_pred == bool(label))
        final_hit += int(final_pred == bool(label))
        raw_fp += int(label == 0 and raw_pred)
        final_fp += int(label == 0 and final_pred)
        uncertain = config.UNCERTAIN_LOW <= final <= config.UNCERTAIN_HIGH
        unfamiliar = float(distance) > detector.novelty_threshold
        credential = explicit_credential_request(text)
        reason = review_reasons(
            uncertain=uncertain, unfamiliar=unfamiliar, drift=False, score=final,
            links=None, allow_review=True, credential=credential,
        )
        reviewed += int(reason is not None)
        if label == 1 and not final_pred and reason is None:
            silent += 1
        if label == 1 and not final_pred:
            missed.append({
                "id": row.get("id"),
                "lang": row.get("lang"),
                "category": row.get("category"),
                "raw": round(raw_score, 3),
                "final": round(final, 3),
                "review_reason": reason,
            })
        if raw_pred != final_pred:
            lifted.append({
                "id": row.get("id"),
                "lang": row.get("lang"),
                "category": row.get("category"),
                "label": label,
                "raw": round(raw_score, 3),
                "final": round(final, 3),
                "review_reason": reason,
            })
    n = len(rows)
    scams = sum(int(row["label"]) == 1 for row in rows)
    caught = scams - len(missed)
    return {
        "n": n,
        "scams": scams,
        "legitimate": n - scams,
        "raw_correct": raw_hit,
        "final_correct": final_hit,
        "raw_accuracy": raw_hit / n,
        "final_accuracy": final_hit / n,
        "raw_false_positives": raw_fp,
        "final_false_positives": final_fp,
        "scam_recall_raw": (caught + sum(1 for item in missed if item["raw"] >= config.SCAM_THRESHOLD)) / scams if scams else None,
        "scam_recall_final": caught / scams if scams else None,
        "reviewed": reviewed,
        "review_rate": reviewed / n,
        "silent_scam_misses": silent,
        "rule_changed_the_label": lifted,
        "misses": missed,
        "threshold": config.SCAM_THRESHOLD,
    }


def main() -> None:
    detector = Detector.load()
    sets = {
        "development_new_tactics": "data/confirm/policy_shifted.jsonl",
        "development_onboarding": "data/confirm/policy_legit.jsonl",
        "fresh_scenarios": "data/confirm/fresh_scenarios.jsonl",
    }
    report = {
        "model_version": detector.version,
        "fit_version": detector.fit_version,
        "threshold": config.SCAM_THRESHOLD,
        "threshold_changed": False,
        "working_log_used": False,
        "note": (
            "Raw is the classifier probability. Final is that probability after the context rules. "
            "Review is uncertain, unfamiliar, or an explicit credential request. "
            "Drift fallback is not included. The development batches were inspected before this fit. "
            "fresh_scenarios.jsonl was scored once and was not used to train or to move the threshold."
        ),
        "sets": {},
    }
    for name, path in sets.items():
        report["sets"][name] = layers(detector, read_jsonl(path))
        item = report["sets"][name]
        print(
            f"{name}: raw {item['raw_correct']}/{item['n']} "
            f"final {item['final_correct']}/{item['n']} "
            f"fp {item['final_false_positives']} "
            f"recall {item['scam_recall_final']} "
            f"review {item['reviewed']}/{item['n']} "
            f"silent {item['silent_scam_misses']} "
            f"rule_flips {len(item['rule_changed_the_label'])}"
        )
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = config.REPORT_DIR / "layer_comparison.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("wrote", out)


if __name__ == "__main__":
    main()
