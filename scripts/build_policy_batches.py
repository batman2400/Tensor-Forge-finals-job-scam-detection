"""Fresh chats for the frozen three-signal drift policy.

Scenarios were chosen before any score. This file does not load the detector.
Do not edit the written chats after they are scored.

Both batches: 40 chats, 8 messages, 20 English and 20 Singlish, word counts in
the same band as the training chats (about 140 to 185).

Legitimate control: a branch onboarding call. The recruiter names the bus stop,
the shirt colour, the person at reception, and the payroll week. There is no
fee. This is a harmless format change from an interview-slot chat.

Shifted tactics: the same application frame, then one payment the earlier
matched pair did not use: a courier bond, a training-seat fee, a biometric
card charge, a night-shift kit purchase, or a referral-wallet load.

Earlier confirm files stay as development evidence and are not rewritten here.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield.conversation import to_model_text  # noqa: E402
from scamshield.data import write_jsonl  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "data" / "confirm"
REPORT = Path(__file__).resolve().parent.parent / "reports"

NAMES = [
    "Akeel", "Binuri", "Chanuka", "Devmini", "Eshan", "Fathima", "Geetha", "Harindu",
    "Ishara", "Janith", "Kavisha", "Lahiru", "Menura", "Nisal", "Ovin", "Prabashi",
    "Ruwani", "Senuri", "Tharushi", "Upeksha", "Vidura", "Wishmi", "Yohan", "Zainab",
    "Ashan", "Biyuni", "Chamodi", "Dineth", "Eshani", "Fazna", "Gimhan", "Hansani",
    "Isuru", "Jaliya", "Keshani", "Lihini", "Movin", "Nadeesha", "Oshini", "Pawan",
]
HRS = ["Nalini", "Sampath", "Iffath", "Chamath", "Roshani", "Dilan", "Sajini", "Harsha"]
COMPANIES = [
    "Malwathu Prints", "Kirindi Stores", "Gin Ganga Bakery", "Maduru Books",
    "Kumbuk Guest Inn", "Bentota Linen", "Haputale Wool Desk", "Chilaw Salt Room",
    "Minneriya Timber", "Nikaweratiya Pantry", "Balangoda Clay", "Tangalle Nets",
]
CITIES = ["Ambalangoda", "Bandarawela", "Chilaw", "Dambulla", "Embilipitiya", "Hambantota", "Kalutara", "Monaragala"]
ROLES = [
    "linen folder", "bread counter hand", "ticket clerk", "wool sorter",
    "net mender", "clay packer", "pantry runner", "salt-room helper",
]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
TIMES = ["8:30", "9:45", "11:00", "13:15", "16:00"]
SALARIES = ["45500", "49000", "53500", "58000", "62500", "67000", "71500", "75000"]
FEES = ["6400", "8700", "10900", "13200", "16400", "19100", "22600", "25400"]
PRETEXTS = ["courier", "seat", "biometric", "kit", "referral"]
STOPS = ["the clock tower", "the bus stand", "the post office", "the market gate"]
COLOURS = ["white", "light blue", "grey", "navy"]


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
        "stop": STOPS[i % len(STOPS)],
        "colour": COLOURS[i % len(COLOURS)],
        "week": str((i % 3) + 1),
        "code": f"OB{400 + i}",
    }


def legit_en(s: dict) -> list[str]:
    return [
        f"Hello {s['name']}, {s['hr']} from {s['company']} in {s['city']}. Your {s['role']} application is here. I am calling to set the first morning.",
        f"Hello {s['hr']}. I applied last week and I still want the {s['role']} post. Please tell me where to come and what to bring.",
        f"Come on {s['day']} at {s['time']}. The branch is a short walk from {s['stop']}. Ask for {s['hr']} at reception and wear a {s['colour']} shirt.",
        "I can come. Do I pay anything for the shirt, the file, or a seat before that morning?",
        f"No. {s['company']} does not take a fee, a deposit, or a kit charge. The shirt is your own, and the file is opened at the desk.",
        "If the supervisor keeps me, when does pay start, and who hands me the roster?",
        f"Pay is LKR {s['salary']} a month by payroll, in week {s['week']} after you sign. The supervisor writes the roster that morning.",
        f"Thank you. I will wear the {s['colour']} shirt, walk from {s['stop']}, and meet {s['hr']} on {s['day']} at {s['time']}.",
    ]


def legit_si(s: dict) -> list[str]:
    return [
        f"Hello {s['name']}, mama {s['hr']} {s['company']} eken, {s['city']} branch eken. Oya yawapu {s['role']} application eka mage desk eke. Mula dawasa set karanna call kale.",
        f"Hello {s['hr']}. Last week apply kale. {s['role']} post eka mata thama ona. Koheda enne kiyanna, monawa geniyanna kiyanna.",
        f"{s['day']} {s['time']} ta enna. {s['stop']} eken podi walk ekak. Reception eke {s['hr']} illanna. {s['colour']} shirt ekak andanna.",
        "Mama enna puluwan. Shirt ekata, file ekata, nathnam eka dawasa kalin seat ekakata salli gewanna ona da?",
        f"Naha. {s['company']} fee ekak, deposit ekak, nathnam kit charge ekak ganne ne. Shirt eka oya ge. File eka desk eke open karanawa.",
        "Supervisor mama keep karoth pay eka kawadada patan ganne? Roster eka kawuda dennewa?",
        f"Pay eka LKR {s['salary']} monthly, payroll eken, contract eka sign unata passe week {s['week']} eke. Eka dawasa ma supervisor roster eka liyanawa.",
        f"Thanks. {s['colour']} shirt eka andala, {s['stop']} eken awilla, {s['day']} {s['time']} ta {s['hr']} hamu wenna.",
    ]


def scam_ask_en(s: dict, pretext: str) -> str:
    fee, day, time, code = s["fee"], s["day"], s["time"], s["code"]
    asks = {
        "courier": f"The appointment letter goes by courier. Transfer LKR {fee} as the courier bond before {time} on {day}, and put {code} on the receipt, or the letter stays at the office.",
        "seat": f"The training room has one seat left. Reserve it with a seat fee of LKR {fee} before {time} on {day}. Quote {code}. Without that transfer the seat goes to the next name.",
        "biometric": f"Clock-in needs a staff biometric card. The card charge is LKR {fee}. Pay it before {time} on {day} with reference {code}, or the gate will not open for you.",
        "kit": f"The night shift needs our safety kit. Buy it for LKR {fee} from the branch store before {time} on {day}. The receipt must show {code}, or you cannot start the shift.",
        "referral": f"Your referral bonus sits in a team wallet. Load LKR {fee} into that wallet before {time} on {day} and mark it {code}. Until the load arrives the bonus does not move.",
    }
    return asks[pretext]


def scam_ask_si(s: dict, pretext: str) -> str:
    fee, day, time, code = s["fee"], s["day"], s["time"], s["code"]
    asks = {
        "courier": f"Appointment letter eka courier eken yanna one. LKR {fee} courier bond ekak {day} {time} ta kalin transfer karanna. Receipt eke {code} danna. Nathi nam letter eka office eke inna.",
        "seat": f"Training room eke seat ekak witharai thiyenne. LKR {fee} seat fee ekak {day} {time} ta kalin gewanna. {code} kiyanna. Transfer eka nathi nam seat eka ilaga nama ekata yanawa.",
        "biometric": f"Clock-in ekata staff biometric card ekak one. Card charge eka LKR {fee}. {day} {time} ta kalin reference {code} ekak danna. Nathi nam gate eka oyata open wenne ne.",
        "kit": f"Night shift ekata ape safety kit eka one. Branch store eken LKR {fee} ta {day} {time} ta kalin ganna. Receipt eke {code} pennanna. Nathi nam shift eka patan ganna ba.",
        "referral": f"Referral bonus eka team wallet ekakata inna. LKR {fee} eka wallet ekata {day} {time} ta kalin load karanna, {code} kiyala mark karanna. Load eka enakan bonus eka yanne ne.",
    }
    return asks[pretext]


def scam_en(s: dict, pretext: str) -> list[str]:
    return [
        f"Hello {s['name']}, {s['hr']} from {s['company']} in {s['city']}. Your {s['role']} application is here. I am calling about the next step.",
        f"Hello {s['hr']}. I applied last week and I still want the {s['role']} post. Please tell me what the next step is.",
        f"The next step is on {s['day']} at {s['time']}. Keep reference {s['code']} with you and stay near {s['stop']} so you can answer.",
        "I can do that. Is there any payment I must send before that step?",
        scam_ask_en(s, pretext),
        "Can the company take that from the first month pay instead of a transfer today?",
        f"No. LKR {s['fee']} has to arrive first, and the receipt has to show {s['code']}. Then the LKR {s['salary']} monthly pay can be discussed.",
        f"I need to think before I send LKR {s['fee']}. I will decide before {s['time']} on {s['day']}.",
    ]


def scam_si(s: dict, pretext: str) -> list[str]:
    return [
        f"Hello {s['name']}, mama {s['hr']} {s['company']} eken, {s['city']} branch eken. Oya yawapu {s['role']} application eka mage desk eke. Next step eka kiyanna call kale.",
        f"Hello {s['hr']}. Last week apply kale. {s['role']} post eka mata thama ona. Next step eka monawada kiyanna.",
        f"Next step eka {s['day']} {s['time']} ta. Reference {s['code']} eka lagin thiyanna. {s['stop']} eke langa inna, call ekakata answer karanna.",
        "Mama eka karanna puluwan. Eka step eka kalin monava hari payment ekak ewanna ona da?",
        scam_ask_si(s, pretext),
        "Company eka eka first month pay eken ganna puluwan da? Ada transfer ekak ewanna ona da?",
        f"Naha. LKR {s['fee']} kalin enna one, receipt eke {s['code']} pennanna one. Eka unama LKR {s['salary']} monthly pay eka gana katha karanna puluwan.",
        f"LKR {s['fee']} ewanna kalin mata hithanna one. {s['day']} {s['time']} ta kalin decide karannan.",
    ]


def build(i: int, label: int) -> dict:
    s = slot(i)
    lang = "en" if i < 20 else "singlish"
    pretext = PRETEXTS[i % len(PRETEXTS)]
    if label == 0 and lang == "en":
        lines, category = legit_en(s), "policy-legit-onboarding"
    elif label == 0:
        lines, category = legit_si(s), "policy-legit-onboarding"
    elif lang == "en":
        lines, category = scam_en(s, pretext), f"policy-shifted-{pretext}"
    else:
        lines, category = scam_si(s, pretext), f"policy-shifted-{pretext}"
    messages = [
        {"sender": "Recruiter" if n % 2 == 0 else "Candidate", "text": text}
        for n, text in enumerate(lines)
    ]
    return {
        "id": f"policy-{'legit' if label == 0 else 'shifted'}-{i}",
        "label": label,
        "category": category,
        "lang": lang,
        "source": "policy-confirm-frozen-three-signal",
        "messages": messages,
    }


def _span(rows: list[dict]) -> tuple[int, int, int]:
    counts = sorted(len(to_model_text(r["messages"]).split()) for r in rows)
    return counts[0], counts[len(counts) // 2], counts[-1]


def main() -> None:
    legit = [build(i, 0) for i in range(40)]
    shifted = [build(i, 1) for i in range(40)]
    legit_span, shifted_span = _span(legit), _span(shifted)
    print("spans", {"legit": legit_span, "shifted": shifted_span})
    if abs(legit_span[1] - shifted_span[1]) >= 15:
        raise SystemExit(f"medians differ by 15 or more: {legit_span} vs {shifted_span}")
    for name, span in (("legit", legit_span), ("shifted", shifted_span)):
        if span[0] < 140 or span[2] > 185:
            raise SystemExit(f"{name} words outside 140-185: {span}")
    OUT.mkdir(parents=True, exist_ok=True)
    write_jsonl(OUT / "policy_legit.jsonl", legit)
    write_jsonl(OUT / "policy_shifted.jsonl", shifted)
    REPORT.mkdir(parents=True, exist_ok=True)
    scenario = {
        "chosen_before_scoring": True,
        "scored": False,
        "drift_policy": "three-signal-alert-v1",
        "thresholds_changed": False,
        "development_evidence_not_rescored": [
            "data/confirm/legit.jsonl",
            "data/confirm/shifted.jsonl",
            "data/confirm/matched_legit.jsonl",
            "data/confirm/matched_shifted.jsonl",
        ],
        "shape": {
            "n": 40,
            "messages": 8,
            "english": 20,
            "singlish": 20,
            "word_band": [140, 185],
        },
        "legit_scenario": (
            "Branch onboarding. Bus stop, shirt colour, reception name, and payroll week. "
            "No fee. Harmless format change from an interview-slot chat."
        ),
        "shifted_scenario": (
            "Same application frame, then a payment the matched development pair did not use: "
            "courier bond, training-seat fee, biometric card, night-shift kit, or referral-wallet load."
        ),
        "hypothesis_before_scoring": (
            "The legitimate batch is ordinary hiring with a clear no-fee line, so it is not expected "
            "to trip the confidence, unfamiliar-rate, or uncertain-rate cuts. Mean unfamiliarity may "
            "still be advisory. The shifted batch uses new payment demands. Whether those demands "
            "cross the frozen cuts is what the one score measures. The chats will not be edited after that score."
        ),
        "word_span": {"legit": list(legit_span), "shifted": list(shifted_span)},
    }
    (REPORT / "policy_scenarios.json").write_text(json.dumps(scenario, indent=2), encoding="utf-8")
    print(json.dumps(scenario["word_span"]))


if __name__ == "__main__":
    main()
