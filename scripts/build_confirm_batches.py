"""Write the confirmation batches. These chats are not the shifted stream.

Run this before scoring. Do not edit the batches after looking at their novelty.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield.data import write_jsonl  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "data" / "confirm"

FILLS = [
    ("Nadeera", "Malini", "Riverstone Mills", "Galle", "store counter", "Tuesday", "10:30", "64000", "7800"),
    ("Isuru", "Devika", "Gal Oya Textiles", "Kandy", "cutting assistant", "Wednesday", "09:00", "58000", "12500"),
    ("Harini", "Sajith", "Hantana Books", "Matara", "shop assistant", "Thursday", "14:00", "52000", "9600"),
    ("Pavithra", "Niluka", "Nilwala Clinics", "Negombo", "reception desk", "Friday", "11:15", "61000", "15400"),
    ("Chamodi", "Ruwan", "Maskeliya Tea Desk", "Hatton", "leaf clerk", "Monday", "08:30", "49000", "11200"),
    ("Tharushi", "Ashan", "Kelani Print Room", "Colombo", "binder", "Tuesday", "13:00", "56000", "18600"),
    ("Dinithi", "Farhan", "Yala Guest House", "Tissamaharama", "housekeeping", "Wednesday", "15:30", "47000", "14300"),
    ("Sanduni", "Pradeep", "Maha Oya Motors", "Kurunegala", "parts counter", "Thursday", "10:00", "63000", "22100"),
]


def chat(lines: list[str], label: int, category: str, index: int) -> dict:
    messages = []
    for i, text in enumerate(lines):
        messages.append({"sender": "Recruiter" if i % 2 == 0 else "Candidate", "text": text})
    return {
        "id": f"confirm-{category}-{index}",
        "label": label,
        "category": category,
        "lang": "en",
        "source": "confirm-batch-frozen-before-scoring",
        "messages": messages,
    }


def legit_lines(fill: tuple) -> list[str]:
    name, hr, company, city, role, day, time, salary, _fee = fill
    return [
        f"Hello {name}, this is {hr} from {company} in {city}. Your interview for the {role} post is on {day} at {time} at our branch.",
        "Thank you. Should I bring anything besides my CV?",
        f"Bring your NIC copy and the certificates you already sent. The meeting at the {city} branch has no charge.",
        "Do I pay anything for a uniform, a medical, or a seat?",
        f"No. {company} does not take a registration fee or a deposit. If you join, the monthly salary is LKR {salary}, paid by our payroll to your bank after the contract is signed.",
        f"I will be at the {city} branch on {day}.",
    ]


def shifted_lines(fill: tuple, kind: int) -> list[str]:
    name, hr, company, city, role, day, time, salary, fee = fill
    openings = [
        f"Hello {name}, {hr} from {company}. Your {role} task account is ready, and the VIP level upgrade is the next step.",
        f"Hi {name}, {hr} here from {company} in {city}. The {role} balance can be withdrawn after one clearance step.",
        f"{name}, this is {hr} at {company}. The {role} wallet will not pay out until the activation transfer is done.",
        f"Hello {name}. {company} froze the {role} earnings screen. I am {hr}, and the unlock is a separate payment.",
    ]
    asks = [
        f"Transfer LKR {fee} today as the VIP upgrade fee, or the {salary} task balance stays locked.",
        f"The tax clearance before withdrawal is LKR {fee}. Send it to the account I share so the {day} payout is released.",
        f"Activate the USDT wallet with a transfer of LKR {fee}. Without that, the {role} commission cannot move.",
        f"The account is frozen. Pay the unlock fee of LKR {fee} before {time} on {day} and the shown salary is released.",
        f"Payout insurance of LKR {fee} is required before {company} releases the {role} earnings.",
        f"Top up LKR {fee} to open the next task set. The {city} desk will not start the {role} work until that transfer arrives.",
        f"Buy the starter kit for LKR {fee} before any {role} shift. The kit fee is not taken from the LKR {salary} wage.",
        f"The overseas {role} file needs a visa processing fee of LKR {fee} today. The {city} office cannot submit it without the transfer.",
    ]
    return [
        openings[kind % 4],
        "What do I have to do before the work starts?",
        asks[kind],
        "Can the company deduct that after I am paid?",
        f"No. The LKR {fee} has to reach us first. Reply with the transfer receipt before {time}.",
        "I need to think about that amount.",
    ]


def main() -> None:
    legit, shifted = [], []
    for index, fill in enumerate(FILLS):
        for copy in range(5):
            n = index * 5 + copy
            # A fifth rewording pass keeps five chats from sharing one sentence list.
            variant = fill
            if copy:
                name, hr, company, city, role, day, time, salary, fee = fill
                variant = (
                    f"{name} {copy + 1}",
                    hr,
                    company,
                    city,
                    role,
                    day,
                    time,
                    str(int(salary) + copy * 500),
                    str(int(fee) + copy * 250),
                )
            legit.append(chat(legit_lines(variant), 0, "legit-control", n))
            shifted.append(chat(shifted_lines(variant, n % 8), 1, "shifted-confirm", n))
    OUT.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT / "legit.jsonl", legit)
    write_jsonl(OUT / "shifted.jsonl", shifted)
    print(f"wrote {len(legit)} legit and {len(shifted)} shifted chats to {OUT}")


if __name__ == "__main__":
    main()
