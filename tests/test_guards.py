"""Guards for held-out evaluation, drift windows, and link risk."""
import random
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from scamshield import config, monitoring, training  # noqa: E402
from scamshield.links import _risk, check_urls  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

import prepare_data  # noqa: E402


def _row(text: str, label: int = 1) -> dict:
    return {
        "label": label,
        "messages": [
            {"sender": "Recruiter", "text": text},
            {"sender": "Candidate", "text": "ok"},
        ],
    }


def _log(**overrides):
    fields = dict(
        source="live", model_version="m1", score=0.4, label="legit", confidence=0.6,
        novelty=0.2, unfamiliar=False, uncertain=True, link_flags=0,
        review_reason="uncertain", text="Recruiter: hello",
    )
    fields.update(overrides)
    return monitoring.log_prediction(**fields)


class EvaluationGuards(unittest.TestCase):
    def setUp(self):
        self._old_db = config.DB_PATH
        config.DB_PATH = Path(tempfile.mkdtemp()) / "predictions.db"

    def tearDown(self):
        config.DB_PATH = self._old_db

    def test_test_replay_cannot_enter_retraining(self):
        held = _log(source="replay:test", text="held out conversation")
        live = _log(source="replay:shifted", text="shifted stream conversation")
        self.assertFalse(monitoring.submit_review(held, 1))
        self.assertTrue(monitoring.submit_review(live, 1))
        with monitoring._db() as conn:
            conn.execute(
                "UPDATE predictions SET status = 'reviewed', review_label = 1 WHERE id = ?",
                (held,),
            )
        texts = [text for text, _ in monitoring.reviewed_examples()]
        self.assertIn("shifted stream conversation", texts)
        self.assertNotIn("held out conversation", texts)
        self.assertEqual([item["id"] for item in monitoring.review_queue()], [])

    def test_reviewed_text_uses_training_normalization(self):
        pid = _log(source="live", text="Recruiter: pay the deposit fee\nCandidate: ok I will")
        self.assertTrue(monitoring.submit_review(pid, 1))
        self.assertEqual(
            [text for text, _ in monitoring.reviewed_examples()],
            ["pay the deposit fee\nok I will"],
        )

    def test_drift_window_ignores_other_model_versions(self):
        for _ in range(4):
            _log(model_version="old", review_reason=None, uncertain=False, confidence=0.2)
        for _ in range(3):
            _log(model_version="new", review_reason=None, uncertain=False, confidence=0.9)
        reference = {
            "model_version": "new",
            "mean_confidence": 0.8,
            "unfamiliar_rate": 0.0,
            "uncertain_rate": 0.0,
        }
        status = monitoring.drift_status(reference, model_version="new")
        self.assertEqual(status["window_size"], 3)
        self.assertFalse(status["drift"])
        mismatched = monitoring.drift_status(
            {**reference, "model_version": "old"}, model_version="new"
        )
        self.assertTrue(mismatched["reference_mismatch"])
        self.assertFalse(mismatched["drift"])

    def test_reference_is_measured_on_the_deployed_model(self):
        rows = []
        for i in range(20):
            label = i % 2
            stem = "pay a deposit fee before you can withdraw the earnings " if label else "interview on tuesday please bring your university id "
            rows.append(_row(stem + "case " + str(i), label))
        original_load = training.load_split
        seen = {}
        original_fit = training.Detector.fit

        def record_fit(self, texts, labels):
            seen["texts"] = list(texts)
            return original_fit(self, texts, labels)

        training.load_split = lambda name: rows if name == "train" else []
        training.Detector.fit = record_fit
        try:
            detector = training.train(kind="tfidf", seed=0)
        finally:
            training.load_split = original_load
            training.Detector.fit = original_fit
        texts, y = training.texts_labels(rows)
        _, va_t, _, _ = train_test_split(texts, y, test_size=0.2, stratify=y, random_state=0)
        self.assertTrue(set(va_t).isdisjoint(seen["texts"]))
        self.assertEqual(detector.reference["model_version"], detector.version)
        self.assertEqual(detector.reference["n_validation"], len(va_t))


class SplitAndLinks(unittest.TestCase):
    def test_stream_drops_near_duplicates_of_eval(self):
        scam = " ".join(["please pay the tax clearance fee to withdraw your earnings today"] * 6)
        near = scam + " thanks"
        other = "the interview is tuesday at the colombo branch office bring university identification"
        kept = prepare_data.drop_near_duplicates([_row(near), _row(other, 0)], [_row(scam)])
        self.assertEqual(len(kept), 1)
        self.assertIn("interview", kept[0]["messages"][0]["text"])
        stream, eval_rows = prepare_data.split_shifted(
            [_row(scam), _row(near), _row(other, 0), _row("salary is paid after the signed contract on friday", 0)],
            random.Random(0),
        )
        self.assertEqual(len(prepare_data.drop_near_duplicates(stream, eval_rows)), len(stream))

    def test_weak_flags_stay_medium_and_mismatch_is_high(self):
        self.assertEqual(
            _risk([{"code": "SHORTENER", "reason": ""}, {"code": "CHAT_REDIRECT", "reason": ""}]),
            "medium",
        )
        ip = check_urls("pay at http://203.0.113.10/fee")
        self.assertEqual(ip[0]["risk"], "high")
        self.assertEqual(ip[0]["flags"][0]["code"], "IP_HOST")
        bad = check_urls(
            "https://brightpath-careers.tasks-portal.example/join",
            claimed_company="Bright Path Careers",
        )
        self.assertEqual(bad[0]["risk"], "high")
        self.assertIn("CLAIMED_COMPANY_MISMATCH", [f["code"] for f in bad[0]["flags"]])
        ok = check_urls(
            "https://careers.lakview.example/assessment",
            claimed_company="Lakview Solutions",
        )
        self.assertEqual(ok[0]["flags"], [])
        self.assertEqual(ok[0]["risk"], "low")


if __name__ == "__main__":
    unittest.main()
