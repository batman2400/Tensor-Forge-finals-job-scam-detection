"""Review scan: labels, realism, and personal data. Uses fixtures only."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import review_data  # noqa: E402


def _chat(label: int, recruiter: list[str], candidate: str = "Ok, tell me more.", lang: str = "en", n_pad: int = 6) -> dict:
    messages = []
    for text in recruiter:
        messages.append({"sender": "Recruiter", "text": text})
        messages.append({"sender": "Candidate", "text": candidate})
    while len(messages) < n_pad:
        messages.append({"sender": "Candidate", "text": "Thanks, I will think about it."})
    return {
        "label": label,
        "split": "train",
        "category": "fixture",
        "lang": lang,
        "messages": messages,
    }


def _codes(findings: list[dict], severity: str | None = None) -> set[str]:
    return {item["code"] for item in findings if severity is None or item["severity"] == severity}


class ReviewData(unittest.TestCase):
    def test_placeholder_phone_and_example_link_are_clean(self):
        row = _chat(1, [
            "Call the agent on 07X-XXX-XXXX or +94 7X-XXX-XXXX.",
            "Register at https://jobs.example/apply and email hr@jobs.example.",
            "Then deposit Rs. 5,000 as a refundable registration fee.",
        ])
        codes = _codes(review_data.review_row(row, 1, "train", 1), "error")
        self.assertEqual(codes, set())

    def test_real_phone_nic_bank_and_link(self):
        row = _chat(1, [
            "WhatsApp me on 0771234567 or +94 77 123 4567.",
            "NIC 123456789V and new NIC 199912345678.",
            "Send the fee to account number 801234567890 at Bank of Ceylon.",
            "Form: https://bit.ly/join-now",
            "Please deposit Rs. 5,000.",
        ])
        codes = _codes(review_data.review_row(row, 4, "train", 1), "error")
        self.assertIn("real_phone", codes)
        self.assertIn("nic", codes)
        self.assertIn("bank_account", codes)
        self.assertIn("real_organisation", codes)
        self.assertIn("off_example_link", codes)

    def test_ordinary_commercial_bank_account_is_not_a_named_bank(self):
        row = _chat(1, ["Can I withdraw Rs. 1,200 to my commercial bank account? Please deposit Rs. 5,000."])
        codes = _codes(review_data.review_row(row, 1, "train", 1), "error")
        self.assertNotIn("real_organisation", codes)

    def test_lkr_after_the_amount_still_counts_as_a_payment(self):
        styles = [
            "Habai 4,000 LKR transfer karanna ona.",
            "You must remit 68,000 LKR for the permit today.",
            "The audit system requires a prepaid order bond of Rs. 4,000.",
            "You pre-fund a booking voucher of Rs. 15,000.",
            "The starter kit costs Rs. 5,200.",
            "Oya 5,000 LKR recharge karahama return ekka add wenawa.",
            "All remote workers must obtain the Starter Work Kit for Rs. 3,200.",
        ]
        for text in styles:
            row = _chat(1, [text])
            self.assertNotIn("scam_without_payment", _codes(review_data.review_row(row, 1, "train", 1)), text)

    def test_legit_denial_is_not_a_payment_ask(self):
        row = _chat(0, [
            "The internship pays Rs. 40,000 a month.",
            "We do not ask for any fee or deposit. Training is company-paid.",
            "Please bring your CV to the interview.",
        ])
        codes = _codes(review_data.review_row(row, 1, "train", 0))
        self.assertNotIn("legit_asks_for_money", codes)
        self.assertNotIn("real_phone", codes)

    def test_legit_row_that_asks_for_money(self):
        row = _chat(0, ["Please deposit Rs. 5,000 to unlock the job."])
        codes = _codes(review_data.review_row(row, 2, "train", 0))
        self.assertIn("legit_asks_for_money", codes)

    def test_scam_without_a_payment_request(self):
        row = _chat(1, ["The interview is Tuesday at our office. Please bring your CV."])
        codes = _codes(review_data.review_row(row, 3, "train", 1))
        self.assertIn("scam_without_payment", codes)

    def test_bad_sender_and_file_label(self):
        row = _chat(0, ["Please deposit Rs. 2,000 as a registration fee."])
        row["messages"][0]["sender"] = "HR"
        codes = _codes(review_data.review_row(row, 1, "train", 1), "error")
        self.assertIn("bad_sender", codes)
        self.assertIn("label_file_mismatch", codes)

    def test_shifted_pretext_in_train_is_a_warning(self):
        row = _chat(1, ["Pay the tax clearance fee of Rs. 8,000 before withdrawal."])
        codes = _codes(review_data.review_row(row, 1, "train", 1))
        self.assertIn("shifted_pretext", codes)

    def test_unrealistic_singlish_and_duplicate_and_partial_line(self):
        scam = _chat(1, ["Deposit Rs. 3,000 as a registration fee."], lang="singlish")
        self.assertIn("unrealistic_singlish", _codes(review_data.review_row(scam, 1, "train", 1)))

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "train_scam.jsonl"
            line = json.dumps(scam, ensure_ascii=False)
            path.write_text(line + "\n" + line + "\n" + "{\"label\": 1", encoding="utf-8")
            report = review_data.review_file(path)
            codes = _codes(report["findings"])
            self.assertIn("duplicate", codes)
            self.assertIn("trailing_partial", codes)
            self.assertNotIn("bad_json", codes)
            self.assertEqual(report["rows"], 2)


if __name__ == "__main__":
    unittest.main()
