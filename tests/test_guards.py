"""Guards for held-out evaluation, drift windows, and link risk."""
import random
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from scamshield import config, monitoring, training  # noqa: E402
from scamshield.links import UNVERIFIED_NOTICE, _risk, canonical_expected_domain, check_urls  # noqa: E402
from scamshield.service import infer_claimed_company, review_reasons  # noqa: E402
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
        self.assertGreater(detector.reference["novelty_mean_alert"], detector.reference["mean_novelty"])
        self.assertEqual(detector.reference["drift_policy"], config.DRIFT_POLICY)
        self.assertEqual(detector.reference["novelty_role"], "advisory")

    def test_prediction_limit_is_for_a_future_window_mean(self):
        rng = np.random.default_rng(0)
        values = rng.normal(0.70, 0.05, size=137)
        limit = training.window_prediction_limit(values, window=40, alpha=0.01)
        mean = float(values.mean())
        sd = float(values.std(ddof=1))
        from scipy.stats import t as student_t

        critical = float(student_t.ppf(0.99, 136))
        future = mean + critical * sd * np.sqrt(1 / 40 + 1 / 137)
        mean_only = mean + critical * sd / np.sqrt(137)
        known_mean = mean + critical * sd / np.sqrt(40)
        self.assertAlmostEqual(limit["limit"], future, places=8)
        self.assertGreater(limit["limit"], mean_only)
        self.assertGreater(limit["limit"], known_mean)

    def test_older_pipeline_rows_stay_out_of_the_new_window(self):
        for _ in range(20):
            _log(model_version="tfidf-fit", novelty=0.99, unfamiliar=True, uncertain=False,
                 confidence=0.2, review_reason=None)
        reference = {
            "model_version": "tfidf-fit+pipeline-new",
            "mean_confidence": 0.9,
            "unfamiliar_rate": 0.0,
            "uncertain_rate": 0.0,
            "mean_novelty": 0.70,
            "novelty_mean_alert": 0.74,
        }
        status = monitoring.drift_status(reference, model_version="tfidf-fit+pipeline-new")
        self.assertEqual(status["window_size"], 0)
        self.assertFalse(status["drift"])
        self.assertIn("Older rows", status["note"])

    def test_mean_novelty_is_advisory_and_does_not_alert(self):
        for _ in range(15):
            _log(novelty=0.80, unfamiliar=False, uncertain=False, confidence=0.9, review_reason=None)
        reference = {
            "model_version": "m1",
            "mean_confidence": 0.9,
            "unfamiliar_rate": 0.0,
            "uncertain_rate": 0.0,
            "mean_novelty": 0.72,
            "novelty_mean_alert": 0.74,
            "drift_policy": config.DRIFT_POLICY,
        }
        status = monitoring.drift_status(reference, model_version="m1")
        self.assertFalse(status["drift"])
        self.assertEqual(status["alerts"], [])
        self.assertEqual(status["advisory"], [config.ADVISORY_NOVELTY_MESSAGE])
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=status["drift"], score=0.40,
            links=None, allow_review=True,
        ))
        quiet = monitoring.drift_status({**reference, "novelty_mean_alert": 0.90}, model_version="m1")
        self.assertFalse(quiet["drift"])
        self.assertEqual(quiet["advisory"], [])

    def test_original_signals_still_raise_the_drift_alert(self):
        reference = {
            "model_version": "signals",
            "mean_confidence": 0.90,
            "unfamiliar_rate": 0.05,
            "uncertain_rate": 0.01,
            "mean_novelty": 0.70,
            "novelty_mean_alert": 0.99,
        }
        for _ in range(15):
            _log(model_version="signals", novelty=0.70, unfamiliar=False, uncertain=False,
                 confidence=0.70, review_reason=None)
        dropped = monitoring.drift_status(reference, model_version="signals")
        self.assertTrue(dropped["drift"])
        self.assertTrue(any("confidence" in item.lower() for item in dropped["alerts"]))
        self.assertEqual(dropped["advisory"], [])

        for _ in range(15):
            _log(model_version="signals-unfamiliar", novelty=0.70, unfamiliar=True, uncertain=False,
                 confidence=0.90, review_reason=None)
        unfamiliar = monitoring.drift_status(
            {**reference, "model_version": "signals-unfamiliar"}, model_version="signals-unfamiliar"
        )
        self.assertTrue(unfamiliar["drift"])
        self.assertTrue(any("Unfamiliar" in item for item in unfamiliar["alerts"]))

        for _ in range(15):
            _log(model_version="signals-uncertain", novelty=0.70, unfamiliar=False, uncertain=True,
                 confidence=0.90, review_reason=None)
        uncertain = monitoring.drift_status(
            {**reference, "model_version": "signals-uncertain"}, model_version="signals-uncertain"
        )
        self.assertTrue(uncertain["drift"])
        self.assertTrue(any("Uncertain" in item for item in uncertain["alerts"]))


class SplitAndLinks(unittest.TestCase):
    def test_matched_batches_share_length_language_and_shape(self):
        from scamshield.conversation import to_model_text
        from scamshield.data import read_jsonl

        def load(name: str) -> list[dict]:
            return read_jsonl(config.ROOT / "data" / "confirm" / name)

        legit, shifted = load("matched_legit.jsonl"), load("matched_shifted.jsonl")
        self.assertEqual(len(legit), config.DRIFT_WINDOW)
        self.assertEqual(len(shifted), config.DRIFT_WINDOW)

        def shape(rows: list[dict]) -> tuple[int, int, int]:
            counts = sorted(len(to_model_text(r["messages"]).split()) for r in rows)
            langs = {r["lang"] for r in rows}
            messages = {len(r["messages"]) for r in rows}
            self.assertEqual(langs, {"en", "singlish"})
            self.assertEqual(messages, {8})
            self.assertEqual(sum(r["lang"] == "en" for r in rows), 20)
            return counts[0], counts[len(counts) // 2], counts[-1]

        legit_span, shifted_span = shape(legit), shape(shifted)
        self.assertLess(abs(legit_span[1] - shifted_span[1]), 15)
        self.assertGreater(legit_span[0], 130)
        self.assertLess(shifted_span[2], 190)
        legit_text = {to_model_text(r["messages"]) for r in legit}
        shifted_text = {to_model_text(r["messages"]) for r in shifted}
        self.assertTrue(legit_text.isdisjoint(shifted_text))
        dev = set()
        for name in ("train.jsonl", "test.jsonl", "shifted.jsonl", "shifted_stream.jsonl"):
            dev.update(to_model_text(r["messages"]) for r in read_jsonl(config.PROCESSED_DIR / name))
        self.assertTrue(legit_text.isdisjoint(dev))
        self.assertTrue(shifted_text.isdisjoint(dev))

    def test_policy_batches_were_shaped_before_scoring(self):
        from scamshield.conversation import to_model_text
        from scamshield.data import read_jsonl

        def load(name: str) -> list[dict]:
            return read_jsonl(config.ROOT / "data" / "confirm" / name)

        legit, shifted = load("policy_legit.jsonl"), load("policy_shifted.jsonl")
        self.assertEqual(len(legit), config.DRIFT_WINDOW)
        self.assertEqual(len(shifted), config.DRIFT_WINDOW)
        pretexts = {"courier", "seat", "biometric", "kit", "referral"}
        self.assertTrue(pretexts <= {row["category"].removeprefix("policy-shifted-") for row in shifted})

        def shape(rows: list[dict]) -> tuple[int, int, int]:
            counts = sorted(len(to_model_text(r["messages"]).split()) for r in rows)
            self.assertEqual({r["lang"] for r in rows}, {"en", "singlish"})
            self.assertEqual({len(r["messages"]) for r in rows}, {8})
            self.assertEqual(sum(r["lang"] == "en" for r in rows), 20)
            return counts[0], counts[len(counts) // 2], counts[-1]

        legit_span, shifted_span = shape(legit), shape(shifted)
        self.assertLess(abs(legit_span[1] - shifted_span[1]), 15)
        self.assertGreaterEqual(legit_span[0], 140)
        self.assertLessEqual(shifted_span[2], 185)
        self.assertLessEqual(legit_span[2], 185)
        texts = {to_model_text(r["messages"]) for r in legit + shifted}
        self.assertEqual(len(texts), 80)
        earlier = set()
        for name in (
            "legit.jsonl", "shifted.jsonl", "matched_legit.jsonl", "matched_shifted.jsonl",
        ):
            earlier.update(to_model_text(r["messages"]) for r in load(name))
        for name in ("train.jsonl", "test.jsonl", "shifted.jsonl", "shifted_stream.jsonl"):
            earlier.update(to_model_text(r["messages"]) for r in read_jsonl(config.PROCESSED_DIR / name))
        self.assertTrue(texts.isdisjoint(earlier))

    def test_confirmation_batches_are_not_the_development_stream(self):
        from scamshield.conversation import to_model_text
        from scamshield.data import read_jsonl

        confirm_dir = config.ROOT / "data" / "confirm"
        confirm = []
        for name in ("legit.jsonl", "shifted.jsonl"):
            rows = read_jsonl(confirm_dir / name)
            self.assertGreaterEqual(len(rows), config.DRIFT_WINDOW)
            confirm += [to_model_text(row["messages"]) for row in rows]
        dev = []
        for name in ("train.jsonl", "test.jsonl", "shifted.jsonl", "shifted_stream.jsonl"):
            dev += [to_model_text(row["messages"]) for row in read_jsonl(config.PROCESSED_DIR / name)]
        self.assertTrue(set(confirm).isdisjoint(dev))
        self.assertEqual(len(set(confirm)), len(confirm))

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

    def test_high_link_in_a_legit_chat_is_a_review_reason(self):
        text = (config.DEMO_DIR / "legit_recruitment.txt").read_text(encoding="utf-8")
        text += "\nRecruiter: Register here: https://brightpath-careers.tasks-portal.example/join"
        links = check_urls(text, claimed_company=infer_claimed_company(text))
        self.assertTrue(any(link["risk"] == "high" for link in links))
        reason = review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=links, allow_review=True,
        )
        self.assertEqual(reason, "high-risk-link")

    def test_official_link_and_medium_link_do_not_queue(self):
        legit = (config.DEMO_DIR / "legit_recruitment.txt").read_text(encoding="utf-8")
        official = check_urls(legit, claimed_company=infer_claimed_company(legit))
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=official, allow_review=True,
        ))
        short = check_urls("See https://bit.ly/abc today")
        self.assertEqual(short[0]["risk"], "medium")
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=short, allow_review=True,
        ))

    def test_held_out_replay_does_not_queue_a_high_link(self):
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=[{"risk": "high"}], allow_review=False,
        ))

    def test_a_domain_in_the_chat_is_not_treated_as_verified(self):
        text = "Recruiter: Apply at https://northwind.example/jobs today."
        res = check_urls(text)
        self.assertEqual(res[0]["risk"], "low")
        self.assertEqual(res[0]["flags"], [])
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=res, allow_review=True,
        ))
        self.assertIn("not been verified", UNVERIFIED_NOTICE)

    def test_adviser_domain_is_a_separate_check(self):
        self.assertEqual(canonical_expected_domain(" https://www.Northwind.example/careers "), "northwind.example")
        with self.assertRaises(ValueError):
            canonical_expected_domain("not a domain")
        matched = check_urls(
            "https://careers.northwind.example/apply",
            expected_domain="northwind.example",
        )
        self.assertEqual(matched[0]["flags"], [])
        self.assertEqual(matched[0]["risk"], "low")
        form = check_urls(
            "Fill https://docs.google.com/forms/d/e/abc/viewform",
            claimed_company="Lakview Solutions",
            expected_domain="lakview.example",
        )
        self.assertEqual(form[0]["risk"], "high")
        self.assertIn("ADVISER_DOMAIN_MISMATCH", [f["code"] for f in form[0]["flags"]])
        reason = form[0]["flags"][0]["reason"].lower()
        self.assertIn("adviser-provided", reason)
        self.assertIn("did not look it up or verify", reason)
        self.assertIn("recruiting platforms or forms", reason)
        chat = check_urls("https://wa.me/94770000000")
        self.assertEqual(chat[0]["risk"], "medium")
        self.assertIn("real recruiters sometimes use", chat[0]["flags"][0]["reason"].lower())
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=chat, allow_review=True,
        ))
        self.assertEqual(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.1,
            links=form, allow_review=True,
        ), "high-risk-link")

    def test_loaded_pipeline_shows_advisory_alert_and_individual_review(self):
        import verify_drift_policy

        report = verify_drift_policy.run()
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["drift_policy"], config.DRIFT_POLICY)
        self.assertFalse(report["advisory_only"]["drift"])
        self.assertEqual(report["advisory_only"]["advisory"], [config.ADVISORY_NOVELTY_MESSAGE])
        self.assertFalse(report["plain_during_advisory"]["routed_to_review"])
        self.assertTrue(all(report["signals"][name]["drift"] for name in (
            "confidence_drop", "unfamiliar_rise", "uncertain_rise",
        )))
        self.assertEqual(report["uncertain_during_advisory"]["review_reason"], "uncertain")
        self.assertEqual(report["unfamiliar_during_advisory"]["review_reason"], "unfamiliar")
        self.assertEqual(report["high_link_during_advisory"]["review_reason"], "high-risk-link")
        self.assertEqual(report["plain_during_confidence_alert"]["review_reason"], "drift-fallback")
        self.assertFalse(report["working_log_used"])

    def test_individual_review_reasons_do_not_depend_on_the_batch_alert(self):
        self.assertEqual(review_reasons(
            uncertain=True, unfamiliar=False, drift=False, score=0.50,
            links=None, allow_review=True,
        ), "uncertain")
        self.assertEqual(review_reasons(
            uncertain=False, unfamiliar=True, drift=False, score=0.90,
            links=None, allow_review=True,
        ), "unfamiliar")
        self.assertEqual(review_reasons(
            uncertain=False, unfamiliar=False, drift=True, score=0.40,
            links=None, allow_review=True,
        ), "drift-fallback")
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.40,
            links=None, allow_review=True,
        ))

    def test_high_link_joins_other_review_reasons(self):
        reason = review_reasons(
            uncertain=True, unfamiliar=False, drift=True, score=0.5,
            links=[{"risk": "high"}], allow_review=True,
        )
        self.assertEqual(reason, "uncertain,high-risk-link")

    def test_a_credential_request_is_its_own_review_reason(self):
        self.assertEqual(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.54,
            links=None, allow_review=True, credential=True,
        ), "credential-request")
        self.assertEqual(review_reasons(
            uncertain=True, unfamiliar=False, drift=False, score=0.54,
            links=None, allow_review=True, credential=True,
        ), "uncertain,credential-request")
        self.assertIsNone(review_reasons(
            uncertain=False, unfamiliar=False, drift=False, score=0.54,
            links=None, allow_review=False, credential=True,
        ))


if __name__ == "__main__":
    unittest.main()
