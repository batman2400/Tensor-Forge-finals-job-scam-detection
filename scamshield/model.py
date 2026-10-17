"""Conversation-level scam detector with a novelty (unfamiliarity) score."""
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import normalize

from . import config

_ENCODERS: dict = {}
_EMBED_CACHE: dict[str, np.ndarray] = {}
_EMBED_CACHE_MAX = 20000


def _sentence_encoder(name: str):
    if name not in _ENCODERS:
        from sentence_transformers import SentenceTransformer

        encoder = SentenceTransformer(name)
        # Conversations exceed the default 128 tokens; the payment request is usually near the end.
        encoder.max_seq_length = 512
        _ENCODERS[name] = encoder
    return _ENCODERS[name]


class Detector:
    def __init__(self, kind: str = config.MODEL_KIND, embed_model: str = config.EMBED_MODEL):
        if kind not in ("embed", "tfidf"):
            raise ValueError(f"unknown model kind: {kind}")
        self.kind = kind
        self.embed_model = embed_model
        self.word_vec: TfidfVectorizer | None = None
        self.char_vec: TfidfVectorizer | None = None
        self.clf = LogisticRegression(max_iter=2000, class_weight="balanced", C=2.0)
        self.train_vectors = None
        self.novelty_threshold: float = 1.0
        self.reference: dict = {}
        # fit_version identifies the fitted classifier. version identifies the
        # whole scoring pipeline (weights, context rules, and drift reference).
        self.fit_version = ""
        self.version = ""

    def _encode(self, texts: list[str], fit: bool = False):
        if self.kind == "embed":
            missing = list({t for t in texts if t not in _EMBED_CACHE})
            if missing:
                if len(_EMBED_CACHE) > _EMBED_CACHE_MAX:
                    _EMBED_CACHE.clear()
                vectors = _sentence_encoder(self.embed_model).encode(
                    missing, normalize_embeddings=True, batch_size=16, show_progress_bar=False
                )
                _EMBED_CACHE.update(zip(missing, vectors))
            return np.vstack([_EMBED_CACHE[t] for t in texts])
        if fit:
            self.word_vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=1)
            self.char_vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, min_df=2)
            word, char = self.word_vec.fit_transform(texts), self.char_vec.fit_transform(texts)
        else:
            word, char = self.word_vec.transform(texts), self.char_vec.transform(texts)
        return normalize(sparse.hstack([word, char]).tocsr())

    def fit(self, texts: list[str], labels: list[int]) -> "Detector":
        X = self._encode(texts, fit=True)
        self.clf.fit(X, labels)
        self.train_vectors = X
        self.fit_version = f"{self.kind}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}"
        self.version = self.fit_version
        return self

    def predict_proba(self, texts: list[str]) -> np.ndarray:
        raw = self.clf.predict_proba(self._encode(texts))[:, 1]
        # Refusals, questions, and payment lines the word weights misread.
        from .context import adjust_score

        return np.array([adjust_score(text, float(score)) for text, score in zip(texts, raw)], dtype=float)

    def novelty(self, texts: list[str]) -> np.ndarray:
        """1 - cosine similarity to the nearest training example (0 = seen before, 1 = nothing similar)."""
        sims = self._encode(texts) @ self.train_vectors.T
        sims = sims.toarray() if sparse.issparse(sims) else np.asarray(sims)
        return 1.0 - sims.max(axis=1)

    def save(self, path: Path = config.MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path = config.MODEL_PATH) -> "Detector":
        return joblib.load(path)
