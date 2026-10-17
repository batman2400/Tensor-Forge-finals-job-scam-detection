"""Training, evaluation, and retraining with human-reviewed labels."""
import json
import shutil

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from . import config
from .data import load_split, texts_labels
from .model import Detector


def evaluate(detector: Detector, rows: list[dict]) -> dict:
    texts, y = texts_labels(rows)
    y = np.array(y)
    p = detector.predict_proba(texts)
    pred = (p >= config.SCAM_THRESHOLD).astype(int)
    conf = np.maximum(p, 1 - p)
    novelty = detector.novelty(texts)
    uncertain = (p >= config.UNCERTAIN_LOW) & (p <= config.UNCERTAIN_HIGH)
    unfamiliar = novelty > detector.novelty_threshold
    matrix = confusion_matrix(y, pred, labels=[0, 1])
    result = {
        "n": int(len(y)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "confusion_matrix": matrix.tolist(),
        # Legitimate chats scored as a scam signal. Rows are true label 0 then 1.
        "false_positives": int(matrix[0][1]),
        "mean_confidence": float(conf.mean()),
        "uncertain_rate": float(uncertain.mean()),
        "unfamiliar_rate": float(unfamiliar.mean()),
        # Standing review rule on a frozen set: uncertain score or unfamiliar chat.
        # Drift fallback is extra and only applies while a live alert is already on.
        "review_rate": float((uncertain | unfamiliar).mean()),
    }
    if len(set(y.tolist())) == 2:
        result["roc_auc"] = float(roc_auc_score(y, p))
    return result


def train(kind: str = config.MODEL_KIND, extra: list[tuple[str, int]] | None = None, seed: int = 42) -> Detector:
    """Fit the model that will be deployed, then measure its reference on examples it did not see.

    Reviewed extras are added only to the fit split. They never enter the validation slice, and the
    validation slice is never folded back into the deployed model. A second model trained on 100% of
    the data would not match these reference numbers.
    """
    texts, y = texts_labels(load_split("train"))
    tr_t, va_t, tr_y, _ = train_test_split(texts, y, test_size=0.2, stratify=y, random_state=seed)
    tr_t, tr_y = list(tr_t), list(tr_y)
    va_t = list(va_t)
    if extra:
        tr_t += [t for t, _ in extra]
        tr_y += [label for _, label in extra]

    detector = Detector(kind).fit(tr_t, tr_y)
    val_novelty = detector.novelty(va_t)
    threshold = float(np.quantile(val_novelty, 0.95))
    val_p = detector.predict_proba(va_t)
    detector.novelty_threshold = threshold
    detector.reference = {
        "model_version": detector.version,
        "n_validation": len(va_t),
        "mean_confidence": float(np.maximum(val_p, 1 - val_p).mean()),
        "uncertain_rate": float(((val_p >= config.UNCERTAIN_LOW) & (val_p <= config.UNCERTAIN_HIGH)).mean()),
        "unfamiliar_rate": float((val_novelty > threshold).mean()),
    }
    return detector


def evaluate_all(detector: Detector) -> dict:
    report = {"model_version": detector.version, "kind": detector.kind, "reference": detector.reference}
    for split in ("test", "shifted"):
        try:
            report[split] = evaluate(detector, load_split(split))
        except FileNotFoundError:
            report[split] = None
    return report


def save_report(report: dict, name: str) -> None:
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with open(config.REPORT_DIR / f"{name}.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def retrain_with_reviews(reviewed: list[tuple[str, int]]) -> dict:
    """Retraining trigger: add human-reviewed cases, retrain, and keep the old model as a fallback."""
    old = Detector.load() if config.MODEL_PATH.exists() else None
    before = evaluate_all(old) if old else None
    new = train(kind=old.kind if old else config.MODEL_KIND, extra=reviewed)
    after = evaluate_all(new)
    if config.MODEL_PATH.exists():
        shutil.copy(config.MODEL_PATH, config.MODEL_PATH.with_name("model_prev.joblib"))
    new.save()
    result = {"reviewed_examples": len(reviewed), "before": before, "after": after}
    save_report(result, "retrain")
    return result
