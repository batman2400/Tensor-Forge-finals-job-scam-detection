"""Verdicts the word weights got wrong, and the frozen chats they already got right."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scamshield import config  # noqa: E402
from scamshield.context import adjust_score, explicit_credential_request  # noqa: E402
from scamshield.conversation import parse_conversation, to_model_text  # noqa: E402
from scamshield.data import read_jsonl, texts_labels  # noqa: E402
from scamshield.indicators import find_indicators  # noqa: E402
from scamshield.model import Detector  # noqa: E402

FEE_DENIAL = (
    "Recruiter: This internship does not have a registration fee, training fee, or deposit. "
    "If anyone asks you to top up a wallet, that message is not from us.\n"
    "Candidate: Good to know. When is the interview?"
)
ADVISER = (
    "Candidate: A recruiter told me to rate hotels, then top up Rs. 15,000 and pay a tax clearance fee "
    "before I can withdraw. I did not pay.\n"
    "Recruiter: That pattern is a task scam. Do not send money, do not join their Telegram, and do not share an OTP."
)
STUDENT = (
    "Candidate: Machan a job chat asked me to deposit 10000 to unlock tasks. Is that normal or a scam?\n"
    "Recruiter: Do not deposit. Real employers do not ask you to pay to start."
)
COMMISSION = (
    "Recruiter: This is a commission sales role for a software product. You earn after a customer signs. "
    "There is no starter kit and no upfront payment.\n"
    "Candidate: Is there a base salary?\n"
    "Recruiter: A small base plus commission, paid monthly by the company after you join."
)
COURIER = (
    "Recruiter: Bike courier shift in Kandy. You can earn about Rs. 3000 a day after deliveries. "
    "The company pays you. You do not buy anything.\n"
    "Candidate: Do I need my own bike?\n"
    "Recruiter: Yes. Fuel is reimbursed weekly. No deposit."
)
STORY = (
    "Candidate: Yesterday someone promised Rs 6000 a day for liking videos, then asked for a deposit. I blocked them.\n"
    "Recruiter: You did the right thing. Report it and do not pay."
)
PLAIN_SEND = (
    "Recruiter: Before we continue, send 15000 to the account I share so your place is held.\n"
    "Candidate: Is that required?\n"
    "Recruiter: Yes, today."
)
BURIED = (
    "Recruiter: Thanks for applying. The interview is Thursday at 3 pm at our Colombo branch. "
    "Please also transfer 8000 today to confirm the seat.\n"
    "Candidate: I can come on Thursday."
)
LONG_DENIAL = (
    "Recruiter: We will never ask for a registration fee, a deposit, a top up, USDT, or a tax to withdraw. "
    "The interview is Friday.\n"
    "Candidate: Thank you."
)
MIXED_DENIAL = (
    "We never charge a registration fee, but you must transfer Rs 8000 to activate your tasks."
)
WAGE_TRANSFER = "We will transfer Rs 45000 to your account as your monthly salary."
SCAM_LESSON = (
    "Our security workshop explains why criminals say pay the deposit fee before you can withdraw."
)
VIP_DESK = (
    "Recruiter: We are hiring a receptionist for the VIP guest desk at a hotel. "
    "Experience is preferred. Interview on Monday. Salary is monthly, no joining fee.\n"
    "Candidate: I can attend."
)


def _codes(text: str) -> list[str]:
    messages = parse_conversation(text)
    return [item["code"] for item in find_indicators(to_model_text(messages))]


class ContextRules(unittest.TestCase):
    def test_refusal_and_report_stay_under_the_line(self):
        for text in (FEE_DENIAL, ADVISER, STUDENT, COMMISSION, COURIER, STORY, LONG_DENIAL, VIP_DESK):
            self.assertLess(adjust_score(text, 0.90), 0.35, text[:60])

    def test_payment_instruction_crosses_the_line(self):
        for text in (PLAIN_SEND, BURIED):
            self.assertGreaterEqual(adjust_score(text, 0.10), 0.65, text[:60])

    def test_a_real_fee_is_not_treated_as_a_refusal(self):
        text = "Pay the registration fee of Rs 5000 before we start your tasks. Then you can withdraw daily."
        self.assertGreaterEqual(adjust_score(text, 0.20), 0.65)

    def test_a_demand_in_the_same_sentence_as_a_denial_stays_a_demand(self):
        self.assertGreaterEqual(adjust_score(MIXED_DENIAL, 0.10), 0.65)
        split = (
            "We never charge a registration fee. "
            "But you must transfer Rs 8000 to activate your tasks."
        )
        self.assertGreaterEqual(adjust_score(split, 0.10), 0.65)

    def test_a_wage_transfer_and_a_scam_lesson_stay_under_the_line(self):
        self.assertLess(adjust_score(WAGE_TRANSFER, 0.90), 0.35)
        self.assertLess(adjust_score(SCAM_LESSON, 0.90), 0.35)
        self.assertNotIn("PAY_TO_HOLD", _codes(WAGE_TRANSFER))
        self.assertNotIn("DEPOSIT_TOPUP", _codes(SCAM_LESSON))

    def test_refusal_does_not_light_the_phrase_it_denies(self):
        self.assertNotIn("UPFRONT_FEE", _codes(FEE_DENIAL))
        self.assertNotIn("DEPOSIT_TOPUP", _codes(FEE_DENIAL))
        self.assertNotIn("DEPOSIT_TOPUP", _codes(COURIER))
        self.assertNotIn("DEPOSIT_TOPUP", _codes(STORY))
        self.assertNotIn("UPFRONT_FEE", _codes(VIP_DESK))
        self.assertNotIn("COMMISSION_LEVELS", _codes(VIP_DESK))
        self.assertNotIn("COMMISSION_LEVELS", _codes(COMMISSION))
        self.assertNotIn("PAY_TO_WITHDRAW", _codes(ADVISER))
        self.assertNotIn("HIGH_EASY_PAY", _codes(COURIER))

    def test_a_report_phrase_does_not_hide_a_payment_to_the_reader(self):
        reported = "They asked me to tell you to pay Rs 10000 to unlock your earnings."
        self.assertEqual(adjust_score(reported, 0.66), 0.66)
        self.assertLess(adjust_score(ADVISER, 0.90), 0.35)
        self.assertLess(adjust_score(STUDENT, 0.90), 0.35)
        self.assertLess(adjust_score(STORY, 0.90), 0.35)

    def test_a_credential_request_keeps_the_classifier_score(self):
        request = "To receive your earnings, give me your banking password and the one-time code."
        advice = "Do not share an OTP. Never send your banking password to a recruiter."
        lesson = "Our security workshop explains why criminals ask people to share an OTP."
        self.assertTrue(explicit_credential_request(request))
        self.assertEqual(adjust_score(request, 0.54), 0.54)
        self.assertFalse(explicit_credential_request(advice))
        self.assertFalse(explicit_credential_request(lesson))
        self.assertLess(adjust_score(advice, 0.90), 0.5)
        self.assertLess(adjust_score(lesson, 0.90), 0.5)
        self.assertNotIn("SENSITIVE_INFO", _codes(advice))
        self.assertIn("SENSITIVE_INFO", _codes(request))

    def test_scam_phrases_the_list_used_to_miss(self):
        fee = "Pay Rs 5000 registration to start work-from-home product rating today."
        freeze = "Your task account is frozen. Transfer Rs. 20,000 to unfreeze it and receive the salary shown on the app."
        insurance = "Before the payout we need the payout insurance of Rs. 12,000. It is the last step."
        kit = "To begin the reseller role you must buy the starter kit for Rs. 25,000."
        self.assertIn("UPFRONT_FEE", _codes(fee))
        self.assertIn("ACCOUNT_FREEZE", _codes(freeze))
        self.assertIn("PAYOUT_INSURANCE", _codes(insurance))
        self.assertIn("STARTER_KIT", _codes(kit))
        self.assertIn("PAY_TO_HOLD", _codes(PLAIN_SEND))
        self.assertIn("PAY_TO_HOLD", _codes(BURIED))


@unittest.skipUnless(config.MODEL_PATH.exists(), "saved model is not in artifacts/")
class SavedModelVerdicts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.detector = Detector.load()

    def _score(self, text: str) -> float:
        messages = parse_conversation(text)
        return float(self.detector.predict_proba([to_model_text(messages)])[0])

    def test_the_eight_wrong_verdicts(self):
        legit = {
            "fee denial": FEE_DENIAL,
            "adviser": ADVISER,
            "student": STUDENT,
            "commission": COMMISSION,
            "courier": COURIER,
            "story": STORY,
        }
        for name, text in legit.items():
            self.assertLess(self._score(text), 0.5, name)
        self.assertLess(self._score(LONG_DENIAL), 0.35)
        self.assertGreaterEqual(self._score(PLAIN_SEND), 0.5)
        self.assertGreaterEqual(self._score(BURIED), 0.65)
        self.assertGreaterEqual(self._score(MIXED_DENIAL), 0.65)
        self.assertLess(self._score(WAGE_TRANSFER), 0.5)
        self.assertLess(self._score(SCAM_LESSON), 0.5)

    def test_demo_files_stay_on_their_sides(self):
        legit = self._score((config.DEMO_DIR / "legit_recruitment.txt").read_text(encoding="utf-8"))
        scam = self._score((config.DEMO_DIR / "task_scam.txt").read_text(encoding="utf-8"))
        self.assertLess(legit, 0.2)
        self.assertGreater(scam, 0.85)
        greeting = (
            "Hi! I'm Ruwani from Bright Path Careers. We found your profile and have a flexible "
            "part-time online job for students."
        )
        self.assertLess(self._score(greeting), 0.5)

    def test_window_limit_matches_the_validation_prediction_formula(self):
        from scamshield.training import set_reference, validation_split, window_prediction_limit

        _, va_t, _ = validation_split()
        set_reference(self.detector, va_t)
        limit = window_prediction_limit(
            self.detector.novelty(va_t), config.DRIFT_WINDOW, config.NOVELTY_MEAN_ALPHA
        )
        ref = self.detector.reference
        self.assertAlmostEqual(ref["novelty_mean_alert"], limit["limit"], places=6)
        self.assertIn("prediction limit", ref["novelty_limit"])
        self.assertIn("Not a measured false-alarm rate", ref["novelty_assumptions"])
        stream_texts, _ = texts_labels(read_jsonl(config.PROCESSED_DIR / "shifted_stream.jsonl"))
        self.assertTrue(set(va_t).isdisjoint(stream_texts))

    def test_frozen_labels_do_not_flip(self):
        for name in ("test", "shifted", "shifted_stream", "train"):
            path = config.PROCESSED_DIR / f"{name}.jsonl"
            rows = read_jsonl(path)
            texts, labels = texts_labels(rows)
            scores = self.detector.predict_proba(texts)
            wrong = [
                (i, int(label), float(score))
                for i, (label, score) in enumerate(zip(labels, scores))
                if (score >= 0.5) != bool(label)
            ]
            self.assertEqual(wrong, [], name)


if __name__ == "__main__":
    unittest.main()
