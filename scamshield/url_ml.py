"""Optional URL ML model: char TF-IDF + logistic regression (observation only).

* scikit-learn / joblib are imported lazily; importing this module needs only
  the stdlib. If they are missing, every URL is ``unavailable``.
* The artifact is loaded once from a trusted, configured directory and reused.
  Never pass user-supplied model files: joblib/pickle can execute code.
* Directory: ``model_dir`` argument, else env ``SCAMSHIELD_URL_ML_DIR``, else
  ``<repo>/artifacts/url_ml`` (resolved from this file, not the cwd).
* Results never fabricate a 0 score or a "safe" verdict; failures are per-URL
  ``unavailable`` / ``not_evaluated`` with ``phishing_score: None``. Output order
  and length always match the input.
* No network access.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
from pathlib import Path

from scamshield.url_ml_preprocessing import (
    INTERNAL_CLASS_NAMES,
    PHISHING_CLASS,
    PREPROCESSING_VERSION,
    prepare_url,
)

__all__ = ["predict_urls", "load_model", "reload_model", "model_available",
           "default_model_dir", "build_pipeline", "save_artifact",
           "phishing_column", "MODEL_FILE", "META_FILE", "SCHEMA_VERSION"]

MODEL_FILE = "url_model.joblib"
META_FILE = "url_model_meta.json"
SCHEMA_VERSION = 1
MAX_BATCH = 1000

_LOCK = threading.Lock()
_CACHE: dict = {}


class ModelUnavailable(Exception):
    pass


def default_model_dir() -> Path:
    env = os.environ.get("SCAMSHIELD_URL_ML_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return Path(__file__).resolve().parent.parent / "artifacts" / "url_ml"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _major_minor(v: str) -> str:
    return ".".join(str(v).split(".")[:2])


def phishing_column(classes) -> int:
    """Index of the phishing class in ``classes_`` (never assume position)."""
    cl = [int(c) for c in classes]
    if sorted(cl) != [0, 1]:
        raise ModelUnavailable(f"unexpected classes {cl}")
    return cl.index(PHISHING_CLASS)


def _validate_meta(meta: dict) -> None:
    if not isinstance(meta, dict):
        raise ModelUnavailable("metadata is not an object")
    if meta.get("schema_version") != SCHEMA_VERSION:
        raise ModelUnavailable("metadata schema version mismatch")
    if meta.get("preprocessing_version") != PREPROCESSING_VERSION:
        raise ModelUnavailable("preprocessing version mismatch")
    cm = meta.get("class_mapping") or {}
    if str(cm.get("phishing")) != str(PHISHING_CLASS) or str(cm.get("legitimate")) != "0":
        raise ModelUnavailable("class mapping mismatch")
    thr = meta.get("threshold")
    if not isinstance(thr, (int, float)) or not (0.0 <= thr <= 1.0):
        raise ModelUnavailable("invalid threshold")
    if not meta.get("model_version") or not meta.get("model_sha256"):
        raise ModelUnavailable("metadata incomplete")


def _load(model_dir: Path):
    meta_path = model_dir / META_FILE
    model_path = model_dir / MODEL_FILE
    if not meta_path.is_file() or not model_path.is_file():
        raise ModelUnavailable("model artifact not found")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ModelUnavailable(f"metadata unreadable ({type(exc).__name__})")
    _validate_meta(meta)
    if _sha256(model_path) != meta["model_sha256"]:
        raise ModelUnavailable("model file checksum mismatch")
    try:
        import joblib
        import sklearn
    except ImportError:
        raise ModelUnavailable("scikit-learn/joblib not installed")
    want = (meta.get("dependencies") or {}).get("scikit-learn")
    if want and _major_minor(want) != _major_minor(sklearn.__version__):
        raise ModelUnavailable("scikit-learn version incompatible with artifact")
    try:
        model = joblib.load(model_path)
    except Exception as exc:
        raise ModelUnavailable(f"model file unreadable ({type(exc).__name__})")
    if not hasattr(model, "predict_proba") or not hasattr(model, "classes_"):
        raise ModelUnavailable("model has no predict_proba/classes_")
    col = phishing_column(model.classes_)
    return {"model": model, "meta": meta, "col": col}


def load_model(model_dir=None, *, reload: bool = False) -> dict:
    """Load (once) and return {"model", "meta", "col"}; raises ModelUnavailable.

    A failed load is cached too; call ``reload_model()`` after fixing it.
    """
    d = Path(model_dir).resolve() if model_dir is not None else default_model_dir()
    key = str(d)
    with _LOCK:
        if reload:
            _CACHE.pop(key, None)
        if key not in _CACHE:
            try:
                _CACHE[key] = _load(d)
            except ModelUnavailable as exc:
                _CACHE[key] = exc
            except Exception as exc:
                _CACHE[key] = ModelUnavailable(f"model load failed ({type(exc).__name__})")
        val = _CACHE[key]
    if isinstance(val, Exception):
        raise val
    return val


def reload_model(model_dir=None) -> bool:
    if model_dir is None:
        with _LOCK:
            _CACHE.clear()
    try:
        load_model(model_dir, reload=True)
        return True
    except ModelUnavailable:
        return False


def model_available(model_dir=None) -> bool:
    try:
        load_model(model_dir)
        return True
    except ModelUnavailable:
        return False


def _row(url, status, score=None, version=None, reason="", above=None):
    return {"url": url, "status": status, "phishing_score": score,
            "above_threshold": above, "model_version": version, "reason": reason}


def predict_urls(urls, *, model_dir=None) -> list[dict]:
    """Score a batch of URLs. One result per input, same order. Never raises."""
    try:
        items = list(urls)
    except TypeError:
        return []
    if not items:
        return []
    try:
        bundle = load_model(model_dir)
    except ModelUnavailable as exc:
        bundle, why = None, str(exc)
    meta = bundle["meta"] if bundle else {}
    version = meta.get("model_version")
    out: list = [None] * len(items)
    todo_idx, todo_text = [], []
    for i, u in enumerate(items):
        if i >= MAX_BATCH:
            out[i] = _row(u, "not_evaluated", version=version, reason="batch limit exceeded")
            continue
        prep = prepare_url(u)
        if prep["status"] != "ok":
            out[i] = _row(u, "not_evaluated", version=version, reason=prep["reason"])
        elif bundle is None:
            out[i] = _row(u, "unavailable", reason=f"URL model unavailable: {why}")
        else:
            todo_idx.append(i)
            todo_text.append(prep["text"])
    if todo_idx:
        try:
            proba = bundle["model"].predict_proba(todo_text)
            scores = [float(row[bundle["col"]]) for row in proba]
            if len(scores) != len(todo_idx):
                raise ValueError("length mismatch")
        except Exception as exc:
            scores = None
            fail = f"URL model scoring failed ({type(exc).__name__})"
        thr = float(meta["threshold"])
        for k, i in enumerate(todo_idx):
            if scores is None:
                out[i] = _row(items[i], "unavailable", version=version, reason=fail)
                continue
            s = scores[k]
            if not math.isfinite(s) or not (0.0 <= s <= 1.0):
                out[i] = _row(items[i], "unavailable", version=version, reason="non-finite score")
            else:
                above = s >= thr
                out[i] = _row(items[i], "scored", round(s, 6), version,
                              "URL text resembles phishing URLs in the training data" if above
                              else "URL text does not resemble phishing URLs in the training data (not a safety verdict)",
                              above)
    return out


# ---- training helpers (used by scripts/train_url_model.py and tests) -------

def build_pipeline(*, max_features=2 ** 18, C=4.0, min_df=2, class_weight=None, seed=0):
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    import numpy as np
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), lowercase=False,
                                  min_df=min_df, max_features=max_features,
                                  sublinear_tf=True, dtype=np.float32)),
        ("clf", LogisticRegression(C=C, max_iter=2000, solver="liblinear",
                                   class_weight=class_weight, random_state=seed)),
    ])


def save_artifact(model, meta: dict, model_dir) -> dict:
    """Write model + metadata atomically-ish; returns the final metadata."""
    import joblib
    import sklearn, numpy, scipy
    d = Path(model_dir)
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / (MODEL_FILE + ".tmp")
    joblib.dump(model, tmp, compress=3)
    os.replace(tmp, d / MODEL_FILE)
    meta = dict(meta)
    meta.update({
        "schema_version": SCHEMA_VERSION,
        "preprocessing_version": PREPROCESSING_VERSION,
        "class_mapping": {"legitimate": 0, "phishing": PHISHING_CLASS},
        "class_names": INTERNAL_CLASS_NAMES,
        "model_sha256": _sha256(d / MODEL_FILE),
        "model_bytes": (d / MODEL_FILE).stat().st_size,
        "dependencies": {"scikit-learn": sklearn.__version__, "numpy": numpy.__version__,
                         "scipy": scipy.__version__, "joblib": joblib.__version__},
    })
    (d / META_FILE).write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
    return meta
