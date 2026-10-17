"""Generate synthetic recruitment conversations with Gemini.

Usage:
    python scripts/generate_data.py --split train   --label 1 --n 300
    python scripts/generate_data.py --split train   --label 0 --n 300
    python scripts/generate_data.py --split test    --label 1 --n 80
    python scripts/generate_data.py --split test    --label 0 --n 80
    python scripts/generate_data.py --split shifted --label 1 --n 100
    python scripts/generate_data.py --split shifted --label 0 --n 100

Requires GEMINI_API_KEY in the environment or .env. Output: data/raw/{split}_{scam|legit}.jsonl (appends).
The train and test splits use different prompt wordings and personas to reduce leakage.
"""
import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from scamshield import config  # noqa: E402

load_dotenv(config.ROOT / ".env")
MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
BATCH = 8

SCAM_PRETEXTS = {
    "train_test": [
        "registration or joining fee before starting a part-time job",
        "training kit or 'starter pack' fee for a work-from-home job",
        "task wallet top-up to unlock product-rating tasks",
        "hotel or restaurant review tasks that later require a prepaid deposit",
        "liking YouTube videos or following pages for money, then a 'merchant task' deposit",
        "data-entry job asking for a refundable security deposit",
        "overseas job offer asking for visa or processing fees",
        "earnings shown in an app dashboard but a fee is required to withdraw",
    ],
    "shifted": [
        "VIP level upgrade required to keep receiving higher-paying tasks",
        "'tax clearance' or 'government levy' must be paid before withdrawing earnings",
        "USDT / crypto wallet activation fee to receive salary",
        "account frozen due to 'wrong operation', unlock fee required",
        "payout 'insurance' or 'guarantee deposit' required before release",
        "combo/lucky order made the balance negative, candidate must top up to recover",
    ],
}

LEGIT_SCENARIOS = [
    "scheduling a first-round interview for a software internship",
    "HR asking for CV, certificates and references after shortlisting",
    "job offer with salary details; bank account requested only for payroll after contract signing",
    "freelance graphic design gig paid after delivery through an invoice",
    "retail store part-time job, asking candidate to come for an in-person interview",
    "graduate trainee programme with an online aptitude test link on the company's own domain",
    "background check consent and start-date discussion",
    "recruiter rejecting a candidate politely and suggesting other openings",
    "call centre job explaining shifts, transport allowance and training (company-paid)",
    "tuition teaching job discussing schedule and per-hour pay after classes",
]

STYLE = {
    "train": "Write natural chat messages as they would appear on WhatsApp or Telegram.",
    "test": "Make them feel like real screenshots transcribed to text, with varied tone, typos and message lengths.",
    "shifted": "Use mostly Sri Lankan Singlish (romanized Sinhala mixed with English, e.g. 'machan', 'oyata', "
               "'karanna', 'salli', 'aniwa'), as young Sri Lankans actually type.",
}

RULES = """Rules (mandatory):
- This is synthetic training data for a fraud-DETECTION classifier that protects Sri Lankan job seekers.
- Use fictional people and fictional company names only. Never use real companies, banks or government agencies.
- No real phone numbers (write 07X-XXX-XXXX), no NIC numbers, no real bank account numbers.
- Any links must use the reserved .example domain (e.g. https://abc-careers.example/apply).
- Speakers are always "Recruiter" and "Candidate".
- 6 to 14 messages per conversation, varied length and tone.
Return ONLY a JSON array. Each item: {"category": str, "lang": "en" or "singlish",
 "messages": [{"sender": "Recruiter"|"Candidate", "text": str}]}"""


def build_prompt(split: str, label: int, n: int, rng: random.Random) -> str:
    style = STYLE[split]
    if label == 1:
        pool = SCAM_PRETEXTS["shifted" if split == "shifted" else "train_test"]
        topics = rng.sample(pool, k=min(3, len(pool)))
        task = (f"Write {n} different conversations where a fake recruiter runs an online task-job scam. "
                f"The scam should build gradually: friendly offer, simple tasks, promised or shown earnings, "
                f"then a money request. Use these pretexts (spread across conversations): {topics}.")
    else:
        topics = rng.sample(LEGIT_SCENARIOS, k=3)
        task = (f"Write {n} different conversations between a genuine recruiter and a candidate in Sri Lanka. "
                f"Never ask the candidate to pay anything. Include realistic details that could look "
                f"suspicious out of context (salary amounts, bank details for payroll, links on the company's "
                f"own .example domain). Scenarios: {topics}.")
    if split == "test":
        task = "You are helping build an evaluation set. " + task
    return f"{task}\n{style}\n{RULES}"


def api_keys() -> list[str]:
    keys = []
    # Newer keys first so a fresh quota is used before keys that already returned 429.
    names = [f"GEMINI_API_KEY_{i}" for i in range(9, 1, -1)] + ["GEMINI_API_KEY"]
    for name in names:
        value = os.getenv(name, "").strip()
        if value and value not in keys:
            keys.append(value)
    if not keys:
        raise SystemExit("Set GEMINI_API_KEY in .env. Extra keys can go in GEMINI_API_KEY_2 through GEMINI_API_KEY_9.")
    return keys


def _fail_batch(exc: Exception, keys: list[str]) -> None:
    detail = str(exc).splitlines()[0][:160]
    for key in keys:
        if key:
            detail = detail.replace(key, "[key]")
    print(f"  batch failed ({type(exc).__name__}: {detail}); switching key, retry in 10s")


def generate(client, prompt: str) -> list[dict]:
    from google.genai import types

    resp = client.models.generate_content(
        model=MODEL, contents=prompt,
        config=types.GenerateContentConfig(response_mime_type="application/json", temperature=1.0),
    )
    items = json.loads(resp.text)
    return items if isinstance(items, list) else []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", required=True, choices=["train", "test", "shifted"])
    parser.add_argument("--label", required=True, type=int, choices=[0, 1])
    parser.add_argument("--n", type=int, default=40)
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    from google import genai

    keys = api_keys()
    clients = [genai.Client(api_key=key) for key in keys]
    key_i = 0
    rng = random.Random(args.seed)
    out = config.RAW_DIR / f"{args.split}_{'scam' if args.label else 'legit'}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)

    written = 0
    failures = 0
    while written < args.n:
        prompt = build_prompt(args.split, args.label, min(BATCH, args.n - written), rng)
        try:
            items = generate(clients[key_i], prompt)
        except Exception as e:  # rate limits, refusals, bad JSON
            _fail_batch(e, keys)
            failures += 1
            key_i = (key_i + 1) % len(clients)
            if failures >= 3 * len(clients):
                raise SystemExit(
                    f"Stopped after {failures} failed batches across {len(clients)} keys. "
                    "All loaded keys are failing. Check the Gemini quota."
                )
            time.sleep(10)
            continue
        accepted = 0
        with open(out, "a", encoding="utf-8") as f:
            for item in items:
                if not isinstance(item, dict):
                    continue
                messages = item.get("messages")
                if not isinstance(messages, list) or not messages:
                    continue
                item.update({"label": args.label, "split": args.split, "source": f"{MODEL}:prompt-v1-{args.split}"})
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
                accepted += 1
                written += 1
        if accepted == 0:
            failures += 1
            key_i = (key_i + 1) % len(clients)
            print("  batch returned no usable chats; switching key, retry in 10s")
            if failures >= 3 * len(clients):
                raise SystemExit(
                    f"Stopped after {failures} failed batches across {len(clients)} keys. "
                    "All loaded keys are failing. Check the Gemini quota."
                )
            time.sleep(10)
            continue
        failures = 0
        print(f"  {out.name}: {written}/{args.n}")
        time.sleep(2)


if __name__ == "__main__":
    main()
