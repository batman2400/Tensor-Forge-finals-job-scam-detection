"""Rule-based indicators used to explain a prediction. They do not decide the verdict."""
import re

INDICATORS = [
    ("UPFRONT_FEE", "Asks for a fee before work starts",
     r"\b(registration|joining|processing|training|activation|security|onboarding)\s+(fee|charge|amount|payment|deposit)\b"),
    ("DEPOSIT_TOPUP", "Asks you to deposit or top up money",
     r"\b(top[\s-]?up|recharge|deposit|reload)\b"),
    ("PAY_TO_WITHDRAW", "Payment required to withdraw or release earnings",
     r"\b(withdraw(al)?|release|unlock|cash\s?out)\b.{0,60}\b(fee|tax|pay|deposit|charge|top[\s-]?up)\b"),
    ("TASK_EARNINGS", "Paid for simple online tasks (likes, ratings, reviews)",
     r"\b(like|rate|rating|review|subscribe|follow)\b.{0,30}\b(videos?|products?|hotels?|pages?|channels?|apps?)\b"),
    ("HIGH_EASY_PAY", "Unusually high pay for little effort",
     r"(\b(rs\.?|lkr|usd)\s?\d[\d,]*|\$\s?\d[\d,]*).{0,20}\b(per|a|/)\s*(day|task|hour)\b|\bearn\b.{0,30}\b(daily|per day|from home)\b"),
    ("OFF_PLATFORM", "Moves the conversation to Telegram/WhatsApp",
     r"\b(telegram|whatsapp|t\.me|wa\.me|signal app)\b"),
    ("URGENCY", "Pressure to act quickly",
     r"\b(urgent(ly)?|immediately|limited (slots|seats|spots)|today only|within \d+ (minutes|mins|hours))\b"),
    ("COMMISSION_LEVELS", "Commission, VIP levels or 'merchant' tasks",
     r"\b(commission|vip|level \d|merchant|prepaid task|combo task|lucky order)\b"),
    ("CRYPTO", "Payment in crypto",
     r"\b(usdt|crypto|binance|bitcoin|btc|trc20|wallet address)\b"),
    ("NO_SCREENING", "No interview or experience needed",
     r"\bno (interview|experience|qualifications?)\s*(is\s*)?(needed|required)?\b"),
    ("SENSITIVE_INFO", "Requests sensitive details (OTP, PIN, NIC, bank login)",
     r"\b(otp|pin number|nic (number|copy)|bank (login|password))\b"),
    ("SINGLISH_PAYMENT", "Payment request in Singlish",
     r"\b(salli|gewanna|gewala|gewanna one|deposit karanna|top up karanna|danna one)\b"),
]

_COMPILED = [(code, label, re.compile(pattern, re.IGNORECASE)) for code, label, pattern in INDICATORS]


def find_indicators(text: str) -> list[dict]:
    found = []
    for code, label, regex in _COMPILED:
        match = regex.search(text)
        if match:
            found.append({"code": code, "label": label, "match": match.group(0)})
    return found
