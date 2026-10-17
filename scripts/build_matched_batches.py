"""Fresh legitimate and shifted chats with the same length, language, and shape.

Word counts are checked here. The drift model is not loaded.
Do not change the frozen prediction limit after scoring these files.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield.conversation import to_model_text  # noqa: E402
from scamshield.data import write_jsonl  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "data" / "confirm"

NAMES = [
    "Anuda", "Bimsara", "Chathuri", "Dilshan", "Erandi", "Fazil", "Gayani", "Hasini",
    "Iresh", "Janani", "Kasun", "Lakmini", "Madusha", "Nethmi", "Oshadi", "Piyumi",
    "Rashmi", "Sachini", "Thisara", "Udari", "Vindya", "Waruna", "Yasiru", "Zeena",
    "Amaya", "Bhagya", "Chamara", "Dulani", "Esandi", "Farook", "Gayan", "Hiruni",
    "Imesh", "Jayani", "Kavindu", "Lasini", "Mihiri", "Nadun", "Oneli", "Pasindu",
]
HRS = ["Nelum", "Suresh", "Dilani", "Arjun", "Mala", "Farah", "Ruwanthi", "Jagath"]
COMPANIES = [
    "Riverstone Mills", "Gal Oya Textiles", "Hantana Books", "Nilwala Clinics",
    "Maskeliya Tea Desk", "Kelani Print Room", "Yala Guest House", "Maha Oya Motors",
    "Sitawaka Timber", "Deduru Stores", "Kalu Ganga Prints", "Walawe Pantry",
]
CITIES = ["Galle", "Matara", "Hatton", "Negombo", "Kurunegala", "Ratnapura", "Badulla", "Jaffna"]
ROLES = [
    "stores clerk", "counter assistant", "packing hand", "reception cover",
    "invoice typist", "shelf stacker", "dispatch helper", "tea taster trainee",
]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["9:00", "10:30", "11:15", "14:00", "15:30"]
SALARIES = ["47000", "52000", "56000", "61000", "64000", "68000", "72000", "76000"]
FEES = ["7500", "9800", "12400", "15600", "18200", "21500", "24800", "27300"]
PRETEXTS = ["vip", "tax", "usdt", "freeze", "insurance"]


def slot(i: int) -> dict:
    return {
        "name": NAMES[i],
        "hr": HRS[i % len(HRS)],
        "company": COMPANIES[i % len(COMPANIES)],
        "city": CITIES[i % len(CITIES)],
        "role": ROLES[i % len(ROLES)],
        "day": DAYS[i % len(DAYS)],
        "time": TIMES[i % len(TIMES)],
        "salary": SALARIES[i % len(SALARIES)],
        "fee": FEES[i % len(FEES)],
        "floor": str((i % 4) + 1),
        "code": f"RF{700 + i}",
    }


def words(lines: list[str]) -> int:
    return len(" ".join(lines).split())


def legit_en(s: dict) -> list[str]:
    return [
        f"Hello {s['name']}, this is {s['hr']} from {s['company']} in {s['city']}. I am calling about your application for the {s['role']} opening at our branch.",
        f"Hello {s['hr']}, thank you for calling. I sent the application last week and I am still interested in the {s['role']} post.",
        f"The interview is on {s['day']} at {s['time']} at the {s['city']} office, floor {s['floor']}. Bring a printed CV and a copy of your NIC.",
        "I can attend. Is there any form charge or uniform payment before the interview?",
        f"No. {s['company']} does not charge a registration fee, a deposit, or a kit cost. You only meet the supervisor.",
        "If I am selected, how is the monthly pay arranged?",
        f"The salary is LKR {s['salary']} a month, paid by payroll into your bank account after the contract is signed.",
        f"Thank you. I will bring the CV and the NIC copy, and I will be at the {s['city']} office on {s['day']} at {s['time']}.",
    ]


def legit_si(s: dict) -> list[str]:
    return [
        f"Hello {s['name']}, mama {s['hr']} {s['company']} eken, {s['city']} branch eken. Oya apply karapu {s['role']} vacancy ekata interview ekak denna katha karanna call kale.",
        f"Hello {s['hr']}, thanks for the call. Application eka last week eke yawala thibba. {s['role']} post eka mata thama interest.",
        f"Interview eka {s['day']} {s['time']} ta. {s['city']} office eke floor {s['floor']} ekata enna, reception eke mama hamuwela inna. Printed CV ekak saha NIC copy ekak genna.",
        "Mama {day} enna puluwan. Form ekakata, uniform ekakata, nathnam interview eka kalin monava hari gewanna ona da?".format(day=s["day"]),
        f"Naha. {s['company']} registration fee ekak, deposit ekak, nathnam kit cost ekak ganne ne. Supervisor kenek ekka katha baha. Oya lagana papers witharai ona.",
        "Ehenam hari. Select unoth monthly pay eka kohomada, saha mula wade dawasa kawadada?",
        f"Salary eka LKR {s['salary']} monthly. Contract eka sign unata passe company payroll eken oyage bank account ekata yanawa. Mula dawasa {s['day']} walata passe sumana eke balanawa.",
        f"Thanks. CV ekai NIC copy ekai genna {s['city']} office ekata {s['day']} {s['time']} ta ennan.",
    ]


def scam_ask_en(s: dict, pretext: str) -> str:
    fee, salary, day, time = s["fee"], s["salary"], s["day"], s["time"]
    asks = {
        "vip": f"Before the balance opens you have to transfer LKR {fee} as the VIP level upgrade fee. Until that arrives the LKR {salary} task total stays locked.",
        "tax": f"Withdrawal needs a tax clearance of LKR {fee}. Send it before {time} on {day} so the ledger can release the LKR {salary} balance.",
        "usdt": f"The USDT wallet is not active yet. Transfer LKR {fee} as the activation amount, or the LKR {salary} commission cannot move to your wallet.",
        "freeze": f"The task account is frozen. The unlock fee is LKR {fee}, and it has to be paid before {time} on {day} or the LKR {salary} screen stays blocked.",
        "insurance": f"Payout insurance of LKR {fee} is required before we release the earnings. Without that transfer the LKR {salary} figure on the app is only a display.",
    }
    return asks[pretext]


def scam_ask_si(s: dict, pretext: str) -> str:
    fee, salary, day, time = s["fee"], s["salary"], s["day"], s["time"]
    asks = {
        "vip": f"Balance eka open wenna kalin LKR {fee} VIP level upgrade fee ekak transfer karanna one. Eka enakan LKR {salary} task total eka lock wei.",
        "tax": f"Withdrawal ekata tax clearance LKR {fee} one. {day} {time} ta kalin ewannam ledger eka LKR {salary} balance eka release karanawa.",
        "usdt": f"USDT wallet eka thama active ne. Activation amount eka LKR {fee} transfer karanna. Nathi nam LKR {salary} commission eka wallet ekata yanne ne.",
        "freeze": f"Task account eka frozen. Unlock fee eka LKR {fee}. {day} {time} ta kalin gewwoth nathi nam LKR {salary} screen eka block wei.",
        "insurance": f"Earnings release karanna kalin payout insurance LKR {fee} one. Eka transfer nokaroth app eke LKR {salary} eka display ekak witharai.",
    }
    return asks[pretext]


def scam_en(s: dict, pretext: str) -> list[str]:
    return [
        f"Hello {s['name']}, this is {s['hr']} from {s['company']} in {s['city']}. I am calling about your application for the {s['role']} task opening on our work app.",
        f"Hello {s['hr']}, thank you for calling. I sent the application last week and I am still interested in the {s['role']} post.",
        f"The next step is on {s['day']} at {s['time']}. Open the task screen and note reference {s['code']}.",
        "I can do that. Is there any wallet payment I must send before the work starts?",
        scam_ask_en(s, pretext),
        "Can the company take that from the first salary instead of asking me to send money today?",
        f"No. The LKR {s['fee']} has to arrive first, and the receipt must show {s['code']}. Then the screen pays the LKR {s['salary']} balance.",
        f"I need to think about sending LKR {s['fee']} before any pay. I will look at the screen again before {s['time']} on {s['day']}.",
    ]


def scam_si(s: dict, pretext: str) -> list[str]:
    return [
        f"Hello {s['name']}, mama {s['hr']} {s['company']} eken, {s['city']} branch eken. Oya apply karapu {s['role']} task opening ekata work app eke katha karanna call kale.",
        f"Hello {s['hr']}, thanks for the call. Application eka last week eke yawala thibba. {s['role']} post eka mata thama interest.",
        f"Next step eka {s['day']} {s['time']} ta. Task screen eka open karala reference {s['code']} balanna. Account eka ivarai karana kota NIC copy eka lagin thiyanna.",
        "Mama eka karanna puluwan. Form charge ekak, wallet payment ekak, nathnam wade patan ganna kalin monava hari ewanna ona da?",
        scam_ask_si(s, pretext),
        "Company eka eka first salary eken kapala ganna puluwan da? Ada salli ewanna ona da?",
        f"Naha. LKR {s['fee']} kalin account ekata enna one, receipt eke {s['code']} pennanna one. Match unama screen eke LKR {s['salary']} balance eka thamai payout wenne.",
        f"LKR {s['fee']} pay ekakata kalin ewanna ona de mata hithanna one. {s['day']} {s['time']} ta kalin screen eka aye balannan.",
    ]


def build(i: int, label: int) -> dict:
    s = slot(i)
    lang = "en" if i < 20 else "singlish"
    pretext = PRETEXTS[i % len(PRETEXTS)]
    if label == 0 and lang == "en":
        lines = legit_en(s)
        category = "matched-legit-interview"
    elif label == 0:
        lines = legit_si(s)
        category = "matched-legit-interview"
    elif lang == "en":
        lines = scam_en(s, pretext)
        category = f"matched-shifted-{pretext}"
    else:
        lines = scam_si(s, pretext)
        category = f"matched-shifted-{pretext}"
    messages = [
        {"sender": "Recruiter" if n % 2 == 0 else "Candidate", "text": text}
        for n, text in enumerate(lines)
    ]
    return {
        "id": f"matched-{'legit' if label == 0 else 'shifted'}-{i}",
        "label": label,
        "category": category,
        "lang": lang,
        "source": "matched-confirm-frozen-limit",
        "messages": messages,
    }


def main() -> None:
    legit = [build(i, 0) for i in range(40)]
    shifted = [build(i, 1) for i in range(40)]
    OUT.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT / "matched_legit.jsonl", legit)
    write_jsonl(OUT / "matched_shifted.jsonl", shifted)

    def stats(rows: list[dict]) -> None:
        counts = [len(to_model_text(r["messages"]).split()) for r in rows]
        msgs = [len(r["messages"]) for r in rows]
        langs = {}
        for r in rows:
            langs[r["lang"]] = langs.get(r["lang"], 0) + 1
        ordered = sorted(counts)
        print(
            rows[0]["category"],
            "n", len(rows),
            "langs", langs,
            "msgs", min(msgs), max(msgs),
            "words median", ordered[len(ordered) // 2],
            "min", ordered[0],
            "max", ordered[-1],
        )

    stats(legit)
    stats(shifted)


if __name__ == "__main__":
    main()
