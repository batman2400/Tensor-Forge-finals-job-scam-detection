"""Training, evaluation, and retraining with human-reviewed labels."""
import json
import shutil
from datetime import datetime, timezone

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


def validation_split(seed: int = 42) -> tuple[list[str], list[str], list[int]]:
    """The deployed fit split and the 20% slice it must not see."""
    texts, y = texts_labels(load_split("train"))
    tr_t, va_t, tr_y, _ = train_test_split(texts, y, test_size=0.2, stratify=y, random_state=seed)
    return list(tr_t), list(va_t), list(tr_y)


def window_prediction_limit(values: np.ndarray, window: int, alpha: float) -> dict:
    """Upper limit for the mean of a future window, not a confidence interval for the past mean.

    If ``n`` validation scores are i.i.d. normal and a future window is ``window`` further
    i.i.d. draws from that same distribution, then

        mean + t_{n-1, 1-alpha} * sd * sqrt(1/window + 1/n)

    is an upper prediction limit for that future average. The ``1/n`` term is the
    uncertainty in the validation mean. A confidence interval for the validation mean
    would use ``sqrt(1/n)`` alone and would not be a limit for a new window.

    This nominal tail probability is not a measured false-alarm rate. A live window is
    not a random sample, and choosing mean unfamiliarity after seeing a stream uses up
    the nominal rate.
    """
    from scipy.stats import t as student_t

    values = np.asarray(values, dtype=float)
    n = int(values.shape[0])
    if n < 2 or window < 1 or not 0 < alpha < 1:
        raise ValueError("prediction limit needs two or more scores, a positive window, and alpha in (0, 1)")
    mean = float(values.mean())
    sd = float(values.std(ddof=1))
    df = n - 1
    critical = float(student_t.ppf(1.0 - alpha, df))
    scale = sd * float(np.sqrt(1.0 / window + 1.0 / n))
    return {
        "mean": mean,
        "sd": sd,
        "df": df,
        "critical": critical,
        "limit": mean + critical * scale,
    }


def set_reference(detector: Detector, va_t: list[str]) -> None:
    """Measure the drift reference on the validation slice. Does not refit."""
    val_novelty = np.asarray(detector.novelty(va_t), dtype=float)
    detector.novelty_threshold = float(np.quantile(val_novelty, 0.95))
    val_p = detector.predict_proba(va_t)
    limit = window_prediction_limit(val_novelty, config.DRIFT_WINDOW, config.NOVELTY_MEAN_ALPHA)
    fit_version = getattr(detector, "fit_version", "") or detector.version
    detector.reference = {
        "model_version": detector.version,
        "fit_version": fit_version,
        "n_validation": len(va_t),
        "mean_confidence": float(np.maximum(val_p, 1 - val_p).mean()),
        "uncertain_rate": float(((val_p >= config.UNCERTAIN_LOW) & (val_p <= config.UNCERTAIN_HIGH)).mean()),
        "unfamiliar_rate": float((val_novelty > detector.novelty_threshold).mean()),
        "mean_novelty": limit["mean"],
        "novelty_sd": limit["sd"],
        "novelty_df": limit["df"],
        "novelty_alpha": config.NOVELTY_MEAN_ALPHA,
        "novelty_critical": limit["critical"],
        "novelty_mean_alert": limit["limit"],
        "novelty_limit": (
            "one-sided Student-t prediction limit for the mean of a future "
            f"window of {config.DRIFT_WINDOW}"
        ),
        "novelty_role": "advisory",
        "drift_policy": config.DRIFT_POLICY,
        "novelty_assumptions": (
            "i.i.d. normal validation scores; the future window is the same size "
            "and the same distribution; nominal tail probability only. Not a "
            "measured false-alarm rate. Mean unfamiliarity was chosen after the "
            "shifted stream was inspected, so that stream is development data. "
            "Under three-signal-alert-v1 this limit is an advisory. It does not "
            "raise the drift alert and does not route a chat to review by itself."
        ),
    }


def stamp_pipeline(detector: Detector) -> None:
    """Give the current rules and reference their own id. The fitted weights keep theirs."""
    fit = getattr(detector, "fit_version", "") or detector.version
    fit = fit.split("+pipeline-")[0]
    detector.fit_version = fit
    detector.version = f"{fit}+pipeline-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"


def train(kind: str = config.MODEL_KIND, extra: list[tuple[str, int]] | None = None, seed: int = 42) -> Detector:
    """Fit the model that will be deployed, then measure its reference on examples it did not see.

    Reviewed extras are added only to the fit split. They never enter the validation slice, and the
    validation slice is never folded back into the deployed model. A second model trained on 100% of
    the data would not match these reference numbers.
    """
    tr_t, va_t, tr_y = validation_split(seed)
    if extra:
        tr_t += [t for t, _ in extra]
        tr_y += [label for _, label in extra]

    reviewed = _reviewed_extras()
    if reviewed:
        tr_t += [text for text, _ in reviewed]
        tr_y += [label for _, label in reviewed]
    detector = Detector(kind).fit(tr_t, tr_y)
    # The reference has to name the same pipeline id the live window will use.
    stamp_pipeline(detector)
    set_reference(detector, va_t)
    return detector


def _reviewed_extras() -> list[tuple[str, int]]:
    """Hand-reviewed chats added only to the fit. They are not a test set."""
    path = config.DATA_DIR / "seed" / "reviewed_tactics.jsonl"
    if not path.exists():
        return []
    from .data import read_jsonl

    rows = read_jsonl(path)
    texts, labels = texts_labels(rows)
    return list(zip(texts, labels))


def refresh_saved_reference() -> dict:
    """Recompute the saved reference from the current scorer. The fitted weights stay as they are."""
    detector = Detector.load()
    stamp_pipeline(detector)
    _, va_t, _ = validation_split()
    set_reference(detector, va_t)
    detector.save()
    report = evaluate_all(detector)
    path = config.REPORT_DIR / "metrics.json"
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    existing["deployed_kind"] = existing.get("deployed_kind", detector.kind)
    existing[detector.kind] = report
    save_report(existing, "metrics")
    return report


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
