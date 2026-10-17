import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
# Does not override variables already set by the shell or by Docker.
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SEED_PATH = DATA_DIR / "seed" / "seed.jsonl"
DEMO_DIR = DATA_DIR / "demo"

ARTIFACT_DIR = Path(os.getenv("ARTIFACT_DIR", ROOT / "artifacts"))
MODEL_PATH = ARTIFACT_DIR / "model.joblib"
REPORT_DIR = ROOT / "reports"
DB_PATH = Path(os.getenv("DB_PATH", ROOT / "logs" / "predictions.db"))

MODEL_KIND = os.getenv("MODEL_KIND", "tfidf")  # "embed" or "tfidf"
EMBED_MODEL = os.getenv(
    "EMBED_MODEL", "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
)

SCAM_THRESHOLD = float(os.getenv("SCAM_THRESHOLD", 0.5))
UNCERTAIN_LOW = float(os.getenv("UNCERTAIN_LOW", 0.35))
UNCERTAIN_HIGH = float(os.getenv("UNCERTAIN_HIGH", 0.65))
# Under an active drift alert, anything at or above this score goes to human review.
DRIFT_FALLBACK_THRESHOLD = float(os.getenv("DRIFT_FALLBACK_THRESHOLD", 0.2))

DRIFT_WINDOW = int(os.getenv("DRIFT_WINDOW", 40))
DRIFT_MIN_SAMPLES = int(os.getenv("DRIFT_MIN_SAMPLES", 15))
CONFIDENCE_DROP_ALERT = float(os.getenv("CONFIDENCE_DROP_ALERT", 0.10))
UNFAMILIAR_RISE_ALERT = float(os.getenv("UNFAMILIAR_RISE_ALERT", 0.20))
UNCERTAIN_RISE_ALERT = float(os.getenv("UNCERTAIN_RISE_ALERT", 0.15))
# Nominal tail probability for a future window average, under an i.i.d. normal
# model with the validation mean and spread estimated. This is not a measured
# false-alarm rate on live traffic. Crossing this limit is an advisory, not a
# drift alert, and it does not route a chat to review by itself.
NOVELTY_MEAN_ALPHA = float(os.getenv("NOVELTY_MEAN_ALPHA", "0.01"))
# Frozen after the matched confirmation pair. Do not retune the three cuts or
# this role after seeing a later batch.
DRIFT_POLICY = "three-signal-alert-v1"
ADVISORY_NOVELTY_MESSAGE = "Input patterns differ from the reference—monitor closely"

ENABLE_LINK_CHECK = os.getenv("ENABLE_LINK_CHECK", "true").lower() == "true"

API_URL = os.getenv("API_URL", "http://localhost:8000")
