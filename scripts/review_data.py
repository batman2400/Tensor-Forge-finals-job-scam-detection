"""Read-only review scan for generated recruitment chats.

Looks for broken rows, possible wrong labels, unrealistic chats, and personal
data: real phone numbers, NIC numbers, bank details, real organisations, and
links that are not on a reserved example domain.

Safe to run while a file is still being appended. It does not edit the data,
freeze splits, or score a model.

    uv run python scripts/review_data.py
    uv run python scripts/review_data.py data/raw/train_scam.jsonl
    uv run python scripts/review_data.py --strict
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield import config  # noqa: E402

# Local mobiles are 10 digits: 07X XXX XXXX. X marks the generator's placeholder.
PHONE_RE = re.compile(
    r"(?<!\d)(?:(?:\+94|0094)[\s\-.]?|0)7[0-9Xx](?:[\s\-.]?[0-9Xx]){7}(?!\d)",
    re.IGNORECASE,
)
LANDLINE_RE = re.compile(
    r"(?<!\d)\+94[\s\-.]?(?!7)\d(?:[\s\-.]?\d){8}(?!\d)"
    r"|(?<!\d)0(?!7)\d[\s\-]\d{3}[\s\-]\d{4}(?!\d)"
)
OLD_NIC_RE = re.compile(r"(?<!\d)\d{9}[VvXx]\b")
NEW_NIC_RE = re.compile(r"(?<!\d)(?:19|20)\d{10}(?!\d)")
ACCOUNT_RE = re.compile(
    r"\b(?:account|a/c|acct|acc(?:ount)?\.?)\b(?:\s*(?:no\.?|number|#))?\D{0,40}(\d(?:[\d\s\-]){6,}\d)",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", re.IGNORECASE)

# Amounts appear as "Rs. 5,000" and as "5,000 LKR".
_AMOUNT = r"(?:(?:rs\.?|lkr|rupees?)\s?[\d,]+|[\d,]+\s*(?:rs\.?|lkr|rupees?))"
PAY_ASK_RE = re.compile(
    rf"\b(?:registration|joining|processing|training|activation|security|onboarding|visa|unlock|withdrawal|insurance|guarantee|clearance)\s+(?:fee|charge|deposit)\b"
    rf"|\b(?:top[\s\-]?up|deposit|transfer|remit)\b.{{0,60}}{_AMOUNT}"
    rf"|{_AMOUNT}.{{0,60}}\b(?:deposit|top[\s\-]?up|fee|charge|bond|transfer|remit)\b"
    rf"|\b(?:fee|charge|deposit|bond|remit)\b.{{0,60}}{_AMOUNT}"
    rf"|\brefundable\b.{{0,40}}\b(?:fee|deposit|charge)\b"
    rf"|\b(?:gewanna|deposit karanna|transfer karanna|top[\s\-]?up karanna|salli danna|place karanna)\b"
    rf"|\byou (?:have to|need to|must|should) (?:pay|deposit|transfer|send|remit|top[\s\-]?up)\b"
    rf"|\b(?:pre-?fund|prepaid|pre-?pay(?:ment)?|paying|recharge)\b.{{0,60}}{_AMOUNT}"
    rf"|{_AMOUNT}.{{0,40}}\b(?:pre-?pay(?:ment)?|recharge|danna ona)\b"
    rf"|\b(?:voucher|activation tax|tax of|costs?|cost is|kit|starter pack fee)\b.{{0,50}}{_AMOUNT}"
    rf"|\b(?:transfer|deposit|pay|remit|send)\b.{{0,40}}\b(?:our|the merchant|merchant account|escrow)\b",
    re.IGNORECASE | re.DOTALL,
)
DENIAL_RE = re.compile(
    r"\b(?:no|not|never|don't|do not|won't|will not|without)\b.{0,60}\b(?:pay|fee|deposit|charge|payment|top[\s\-]?up)\b"
    r"|\b(?:free of charge|no payment|no fee|no deposit|company-paid)\b",
    re.IGNORECASE | re.DOTALL,
)
SHIFTED_PRETEXT_RE = re.compile(
    r"\bvip\b.{0,40}\b(?:level|upgrade)\b"
    r"|\btax clearance\b"
    r"|\bgovernment levy\b"
    r"|\busdt\b"
    r"|\bcrypto wallet\b"
    r"|\baccount (?:is |was )?frozen\b"
    r"|\bunlock fee\b"
    r"|\bpayout insurance\b"
    r"|\bguarantee deposit\b"
    r"|\blucky order\b"
    r"|\bcombo (?:task|order)\b",
    re.IGNORECASE | re.DOTALL,
)
SINGLISH_RE = re.compile(
    r"\b(?:machan|oyata|karanna|salli|aniwa|ehenam|puluwan|thiyanawa|thiyenawa|kohomada|"
    r"wistara|aiyo|malli|nangi|aiya|godak|hodai|gewanna|wenawa|karala|ekak|neda|ethakota|menna)\b",
    re.IGNORECASE,
)
REAL_ORG_RES = [
    (re.compile(p, re.IGNORECASE), name, severity)
    for p, name, severity in [
        (r"\bbank of ceylon\b", "Bank of Ceylon", "error"),
        (r"\bpeople'?s bank\b", "People's Bank", "error"),
        (r"\bhatton national bank\b|\bhnb\b", "Hatton National Bank", "error"),
        (r"\bsampath bank\b", "Sampath Bank", "error"),
        (r"\bnational savings bank\b|\bnsb\b", "National Savings Bank", "error"),
        (r"\bseylan bank\b", "Seylan Bank", "error"),
        (r"\bnations trust\b", "Nations Trust Bank", "error"),
        (r"\bdfcc\b", "DFCC", "error"),
        (r"\bpan asia bank\b", "Pan Asia Bank", "error"),
        (r"\bhsbc\b", "HSBC", "error"),
        (r"\bstandard chartered\b", "Standard Chartered", "error"),
        (r"\bcentral bank of sri lanka\b|\bcbsl\b", "Central Bank of Sri Lanka", "error"),
        (r"\bsri lanka bureau of foreign employment\b|\bslbfe\b", "SLBFE", "error"),
        (r"\bdepartment of immigration\b", "Department of Immigration", "error"),
        (r"\bforeign ministry\b|\bministry of foreign\b", "Foreign Ministry", "error"),
        (r"\bsrilankan airlines\b", "SriLankan Airlines", "error"),
    ]
]

ALLOWED_SENDERS = {"Recruiter", "Candidate"}
MIN_MESSAGES = 6
MAX_MESSAGES = 14


def _finding(severity: str, kind: str, code: str, detail: str, line: int | None = None, match: str | None = None) -> dict:
    item = {"severity": severity, "kind": kind, "code": code, "detail": detail}
    if line is not None:
        item["line"] = line
    if match:
        item["match"] = " ".join(match.split())[:160]
    return item


def _host(url: str) -> str:
    body = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    body = body.split("/")[0].split("?")[0].split("#")[0]
    if "@" in body:
        body = body.rsplit("@", 1)[-1]
    return body.lower().strip(".").split(":")[0]


def _allowed_host(host: str) -> bool:
    if host == "example" or host.endswith(".example"):
        return True
    return host in {"example.com", "example.org", "example.net"} or host.endswith(
        (".example.com", ".example.org", ".example.net")
    )


def _digit_count(text: str) -> int:
    return sum(ch.isdigit() for ch in text)


def payment_requests(messages: list) -> list[str]:
    """Recruiter turns that ask the candidate to pay. Denials are ignored."""
    hits = []
    for message in messages:
        if not isinstance(message, dict) or message.get("sender") != "Recruiter":
            continue
        text = str(message.get("text") or "")
        for match in PAY_ASK_RE.finditer(text):
            window = text[max(0, match.start() - 80): match.end() + 20]
            if DENIAL_RE.search(window):
                continue
            hits.append(match.group(0))
    return hits


def personal_data_findings(text: str, line: int) -> list[dict]:
    found = []
    for match in PHONE_RE.finditer(text):
        token = match.group(0)
        if re.search(r"[Xx]", token):
            continue
        found.append(_finding("error", "pii", "real_phone", "Phone number is all digits, not the 07X-XXX-XXXX placeholder.", line, token))
    for match in LANDLINE_RE.finditer(text):
        found.append(_finding("error", "pii", "real_phone", "Phone number is not the 07X-XXX-XXXX placeholder.", line, match.group(0)))
    for match in OLD_NIC_RE.finditer(text):
        found.append(_finding("error", "pii", "nic", "Old-format NIC number (9 digits plus V or X).", line, match.group(0)))
    for match in NEW_NIC_RE.finditer(text):
        found.append(_finding("error", "pii", "nic", "12-digit number in the new NIC shape (year plus 10 digits).", line, match.group(0)))
    for match in ACCOUNT_RE.finditer(text):
        number = match.group(1)
        if _digit_count(number) >= 8:
            found.append(_finding("error", "pii", "bank_account", "Account wording followed by a long digit string.", line, match.group(0)))
    for match in EMAIL_RE.finditer(text):
        host = match.group(0).split("@", 1)[1].lower()
        if not _allowed_host(host):
            found.append(_finding("error", "pii", "email", "Email is not on a reserved example domain.", line, match.group(0)))
    for match in URL_RE.finditer(text):
        host = _host(match.group(0))
        if host and not _allowed_host(host):
            found.append(_finding("error", "pii", "off_example_link", "Link is not on a reserved .example domain.", line, match.group(0)))
    for pattern, name, severity in REAL_ORG_RES:
        hit = pattern.search(text)
        if hit:
            found.append(_finding(severity, "pii", "real_organisation", f"Names a real organisation ({name}).", line, hit.group(0)))
    return found


def _expected_from_name(path: Path) -> tuple[str | None, int | None]:
    stem = path.stem
    split = next((name for name in ("train", "test", "shifted") if stem.startswith(name + "_")), None)
    label = 1 if stem.endswith("_scam") else 0 if stem.endswith("_legit") else None
    return split, label


def _chat_text(messages: list) -> str:
    parts = []
    for message in messages:
        if isinstance(message, dict):
            parts.append(str(message.get("text") or ""))
    return "\n".join(parts)


def review_row(row: dict, line: int, expected_split: str | None, expected_label: int | None) -> list[dict]:
    found = []
    label = row.get("label")
    if label not in (0, 1):
        found.append(_finding("error", "schema", "bad_label", "label must be 0 or 1.", line, str(label)))
    elif expected_label is not None and label != expected_label:
        found.append(_finding(
            "error", "label", "label_file_mismatch",
            f"label is {label} in a file that should contain label {expected_label}.", line,
        ))

    split = row.get("split")
    if expected_split and split and split != expected_split:
        found.append(_finding("error", "schema", "split_mismatch", f"row split is {split}, file is {expected_split}.", line))
    split = split or expected_split

    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) < 2:
        found.append(_finding("error", "realism", "too_few_messages", "Need at least two messages.", line))
        messages = messages if isinstance(messages, list) else []
    elif not MIN_MESSAGES <= len(messages) <= MAX_MESSAGES:
        found.append(_finding(
            "warning", "realism", "message_count",
            f"{len(messages)} messages; the generator prompt asks for {MIN_MESSAGES} to {MAX_MESSAGES}.", line,
        ))

    senders = set()
    for message in messages:
        if not isinstance(message, dict):
            found.append(_finding("error", "realism", "bad_message", "A message is not an object.", line))
            continue
        sender = message.get("sender")
        text = str(message.get("text") or "").strip()
        senders.add(sender)
        if sender not in ALLOWED_SENDERS:
            found.append(_finding("error", "realism", "bad_sender", f"Sender must be Recruiter or Candidate, got {sender!r}.", line))
        if not text:
            found.append(_finding("error", "realism", "empty_text", "Empty message text.", line, str(sender)))
    if len(messages) >= 2 and senders and senders <= ALLOWED_SENDERS and len(senders) < 2:
        found.append(_finding("warning", "realism", "one_speaker", "Every message is from the same speaker.", line))

    lang = row.get("lang")
    if lang not in ("en", "singlish"):
        found.append(_finding("warning", "realism", "bad_lang", "lang should be en or singlish.", line, str(lang)))
    if not str(row.get("category") or "").strip():
        found.append(_finding("warning", "schema", "missing_category", "category is empty.", line))

    text = _chat_text(messages)
    if lang == "singlish" and len(SINGLISH_RE.findall(text)) < 2:
        found.append(_finding("warning", "realism", "unrealistic_singlish", "Marked singlish, with fewer than two Singlish markers.", line))

    found.extend(personal_data_findings(text, line))

    asks = payment_requests(messages)
    if label == 0 and asks:
        found.append(_finding("warning", "label", "legit_asks_for_money", "Labelled legitimate, but a recruiter turn asks for money.", line, asks[0]))
    if label == 1 and not asks:
        found.append(_finding("warning", "label", "scam_without_payment", "Labelled scam, but no recruiter payment request was found.", line))

    category = str(row.get("category") or "")
    if label == 0 and re.search(r"\bscam\b", category, re.IGNORECASE):
        found.append(_finding("warning", "label", "category_conflict", "Legitimate label with a scam category name.", line, category))
    if label == 1 and re.search(r"\blegit", category, re.IGNORECASE):
        found.append(_finding("warning", "label", "category_conflict", "Scam label with a legit category name.", line, category))

    if split in ("train", "test") and label == 1 and SHIFTED_PRETEXT_RE.search(text):
        hit = SHIFTED_PRETEXT_RE.search(text)
        found.append(_finding(
            "warning", "leak", "shifted_pretext",
            "Train/test scam uses a pretext reserved for the shifted set. This is a review flag, not a split decision.",
            line, hit.group(0) if hit else None,
        ))
    if split == "shifted" and label == 1 and not SHIFTED_PRETEXT_RE.search(text):
        found.append(_finding(
            "warning", "leak", "shifted_missing_pretext",
            "Shifted scam does not use a shifted pretext (VIP, tax clearance, USDT, freeze, insurance, combo/lucky order).",
            line,
        ))
    return found


def _normal_key(row: dict) -> str:
    messages = row.get("messages") if isinstance(row.get("messages"), list) else []
    text = re.sub(r"\W+", " ", _chat_text(messages).lower()).strip()
    return hashlib.sha1(text.encode()).hexdigest()


def review_file(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    expected_split, expected_label = _expected_from_name(path)
    findings = []
    rows = 0
    seen: dict[str, int] = {}
    last_index = len(lines) - 1
    for index, line in enumerate(lines):
        if not line.strip():
            continue
        line_no = index + 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            partial = index == last_index and not raw.endswith("\n")
            findings.append(_finding(
                "warning" if partial else "error",
                "schema",
                "trailing_partial" if partial else "bad_json",
                "Last line is still being written." if partial else "Line is not valid JSON.",
                line_no,
            ))
            continue
        if not isinstance(row, dict):
            findings.append(_finding("error", "schema", "bad_json", "Line is not a JSON object.", line_no))
            continue
        rows += 1
        key = _normal_key(row)
        if key in seen:
            findings.append(_finding("warning", "realism", "duplicate", f"Same chat text as line {seen[key]}.", line_no))
        else:
            seen[key] = line_no
        findings.extend(review_row(row, line_no, expected_split, expected_label))
    errors = sum(item["severity"] == "error" for item in findings)
    warnings = sum(item["severity"] == "warning" for item in findings)
    return {
        "path": str(path),
        "rows": rows,
        "errors": errors,
        "warnings": warnings,
        "findings": findings,
    }


def default_paths(argv: list[str]) -> list[Path]:
    if argv:
        return [Path(item) for item in argv]
    return sorted(config.RAW_DIR.glob("*.jsonl"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan generated chats for labels, realism, and personal data.")
    parser.add_argument("paths", nargs="*", help="JSONL files. Default: data/raw/*.jsonl")
    parser.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well as errors.")
    parser.add_argument("--report", default=str(config.REPORT_DIR / "data_review.json"))
    parser.add_argument("--no-report", action="store_true")
    args = parser.parse_args(argv)

    paths = default_paths(args.paths)
    if not paths:
        print("No JSONL files to scan. data/raw is empty.")
        return 0

    reports = []
    for path in paths:
        if not path.exists():
            print(f"{path}: not found")
            reports.append({"path": str(path), "rows": 0, "errors": 1, "warnings": 0,
                            "findings": [_finding("error", "schema", "missing_file", "File not found.")]})
            continue
        report = review_file(path)
        reports.append(report)
        print(f"{path.name}: rows={report['rows']} errors={report['errors']} warnings={report['warnings']}")
        shown = 0
        for item in report["findings"]:
            if shown >= 40:
                print(f"  ... {len(report['findings']) - shown} more")
                break
            where = f"L{item['line']} " if item.get("line") else ""
            match = f" [{item['match']}]" if item.get("match") else ""
            print(f"  {where}{item['severity']} {item['kind']} {item['code']}: {item['detail']}{match}")
            shown += 1

    errors = sum(item["errors"] for item in reports)
    warnings = sum(item["warnings"] for item in reports)
    if not args.no_report:
        out = Path(args.report)
        out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "note": "Read-only review scan of files on disk. Not an evaluation and not a frozen split.",
            "scanned_at": datetime.now().isoformat(timespec="seconds"),
            "errors": errors,
            "warnings": warnings,
            "files": reports,
        }
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"wrote {out}")
    print(f"total errors={errors} warnings={warnings}")
    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
