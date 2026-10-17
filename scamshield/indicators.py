"""Rule-based indicators used to explain a prediction. They do not decide the verdict."""
import re

from .context import sentence_is_inert, sentence_is_wage

INDICATORS = [
    ("UPFRONT_FEE", "Asks for a fee before work starts",
     r"\b(registration|joining|processing|training|activation|security|onboarding)\s+(fee|charge|amount|payment|deposit)\b"
     r"|\b(pay|send|transfer)\b.{0,30}\bregistration\b"
     r"|\bregistration\b.{0,20}\b(rs\.?|lkr|\d{3,})\b"),
    ("DEPOSIT_TOPUP", "Asks you to deposit or top up money",
     r"\b(top[\s-]?up|recharge|deposit|reload)\b"),
    ("PAY_TO_HOLD", "Asks you to send money to hold a place or confirm a seat",
     r"\b(send|transfer|pay)\b.{0,40}\d[\d,]{2,}.{0,40}\b(account|seat|place|hold|confirm)\b"),
    ("PAY_TO_WITHDRAW", "Payment required to withdraw or release earnings",
     r"\b(withdraw(al)?|release|unlock|cash\s?out)\b.{0,60}\b(fee|tax|pay|deposit|charge|top[\s-]?up)\b"),
    ("ACCOUNT_FREEZE", "Account freeze that is lifted only after a payment",
     r"\b(frozen|freeze|unfreeze)\b.{0,50}\b(fee|pay|transfer|deposit|rs\.?|lkr|\d{3,})\b"
     r"|\b(pay|transfer|deposit)\b.{0,40}\b(unfreeze|frozen)\b"),
    ("PAYOUT_INSURANCE", "Insurance payment required before a payout",
     r"\bpayout insurance\b|\binsurance\b.{0,25}\b(fee|deposit|rs\.?|lkr|\d{3,})\b"),
    ("STARTER_KIT", "Must buy a starter kit before work",
     r"\bstarter kit\b"),
    ("TASK_EARNINGS", "Paid for simple online tasks (likes, ratings, reviews)",
     r"\b(like|rate|rating|review|subscribe|follow)\b.{0,30}\b(videos?|products?|hotels?|pages?|channels?|apps?)\b"),
    ("HIGH_EASY_PAY", "Unusually high pay for little effort",
     r"(\b(rs\.?|lkr|usd)\s?\d[\d,]*|\$\s?\d[\d,]*).{0,20}\b(per|a|/)\s*(day|task|hour)\b|\bearn\b.{0,30}\b(daily|per day|from home)\b"),
    ("OFF_PLATFORM", "Moves the conversation to Telegram/WhatsApp",
     r"\b(telegram|whatsapp|t\.me|wa\.me|signal app)\b"),
    ("URGENCY", "Pressure to act quickly",
     r"\b(urgent(ly)?|immediately|limited (slots|seats|spots)|today only|within \d+ (minutes|mins|hours))\b"),
    ("COMMISSION_LEVELS", "VIP tasks, merchant orders, or commission levels",
     r"\b(vip\s+(task|level|member)s?|level\s*\d|merchant|prepaid task|combo task|lucky order)\b"),
    ("CRYPTO", "Payment in crypto",
     r"\b(usdt|crypto|binance|bitcoin|btc|trc20|wallet address)\b"),
    ("NO_SCREENING", "No interview or experience needed",
     r"\bno (interview|experience|qualifications?)\s*(is\s*)?(needed|required)?\b"),
    ("SENSITIVE_INFO", "Requests a password, PIN, or one-time code",
     r"\b(otp|one[- ]time code|pin number|nic (number|copy)|bank(?:ing)? (login|password))\b"),
    ("SINGLISH_PAYMENT", "Payment request in Singlish",
     r"\b(salli|gewanna|gewala|gewanna one|deposit karanna|top up karanna|danna one)\b"),
]

_COMPILED = [(code, label, re.compile(pattern, re.IGNORECASE)) for code, label, pattern in INDICATORS]


def find_indicators(text: str) -> list[dict]:
    found = []
    for code, label, regex in _COMPILED:
        for match in regex.finditer(text):
            # "No deposit" and "we do not charge a fee" are not requests.
            if sentence_is_inert(text, match.start()):
                continue
            # "Rs. 3,000 a day" on a courier shift is a wage, not a scam pitch.
            if code == "HIGH_EASY_PAY" and sentence_is_wage(text, match.start()):
                continue
            found.append({"code": code, "label": label, "match": match.group(0)})
            break
    return found
