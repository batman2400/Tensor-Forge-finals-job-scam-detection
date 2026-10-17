"""Move a classifier score when the wording and the request disagree.

Word weights treat fee, deposit, task, and rs as scam evidence even inside a
refusal, and they treat interview and branch as legitimate even beside a
payment instruction. This step changes a score only for those cases. Phrase
indicators still do not set the label.
"""
import re

_ABBREV = re.compile(r"\b(rs|mr|mrs|dr|lkr)\.", re.IGNORECASE)

# A speaker refusing to charge, or telling the reader not to pay.
# "I don't think I can pay" and "cannot dispatch without upfront settlement" are not refusals.
_DENIAL = re.compile(
    r"\b(?:do not|don't|dont|does not|did not|will not|won't|wont|never)\b.{0,40}"
    r"\b(?:charge|ask for|ask you|take a deposit)\b"
    r"|\b(?:do not|don't|dont|never)\s+(?:pay|deposit|send money|buy)\b"
    r"|\bno\s+(?:a\s+|any\s+)?(?:registration\s+fee|joining\s+fee|training\s+fee|"
    r"fee|deposit|upfront\s+payment|starter\s+kit)\b"
    r"|\bnot\s+have\b.{0,35}\b(?:fee|deposit)\b"
    r"|\bnever\s+(?:ask|charge|take)\b"
    r"|\bnever\s+take\s+a\s+deposit\b",
    re.IGNORECASE,
)

_PUSHBACK = re.compile(
    r"\b(?:i thought|i don't think|i dont think|why do i|can't you|can you deduct)\b",
    re.IGNORECASE,
)

# "If you do not pay, the balance expires" is pressure to pay, not a refusal.
_THREAT = re.compile(
    r"\bif you (?:do not|don't|dont)\b.{0,50}\b(?:pay|deposit|transfer|send|top)\b",
    re.IGNORECASE,
)

_REPORT = re.compile(
    r"\b(?:i blocked|asked me|they asked|told me|someone promised|someone asked|"
    r"i did not pay|did not pay|i didn't pay)\b"
    r"|\b(?:is that normal|is a deposit|is this (?:a )?scam|or a scam)\b"
    r"|\bif anyone asks\b|\bnot from us\b",
    re.IGNORECASE,
)

# The company paying the worker, or the worker naming a wage. Not a demand.
_PAYROLL = re.compile(
    r"\b(?:stipend|salary|wage|payroll|pay rate|daily pay|per hour|per shift|allowance|"
    r"you (?:can |will )?earn|paid (?:monthly|weekly|after)|earn after)\b"
    r"|\bto your account\b|\boyaage account\b|\baccount ekata\b"
    r"|\bafter (?:a |the )?customer signs\b",
    re.IGNORECASE,
)

_AMOUNT = r"(?:\d[\d,]{2,}|\b(?:rs\.?|lkr)\s*\d[\d,]*)"
_FEE_NAME = r"(?:activation|registration|joining|clearance|setup|enrollment|enrolment|kit|tax)"

# The reader is told to hand money over. Sending a CV or a bank form does not match.
_HANDOVER = re.compile(
    rf"\b(?:send|transfer)\s+{_AMOUNT}\b"
    rf"|\b(?:send|transfer)\b.{{0,40}}{_AMOUNT}.{{0,40}}\b(?:account|seat|place|hold|confirm|fee|unfreeze)\b"
    rf"|\bpay\b(?:\s+\w+){{0,4}}\s+(?:fee|deposit)\b"
    rf"|\b{_FEE_NAME}\s+fee\b.{{0,40}}{_AMOUNT}"
    rf"|{_AMOUNT}.{{0,40}}\b{_FEE_NAME}\s+fee\b"
    rf"|\b(?:top[\s-]?up|re-?charge)\b.{{0,40}}{_AMOUNT}"
    rf"|{_AMOUNT}.{{0,30}}\b(?:top[\s-]?up|re-?charge)\b"
    rf"|\b(?:buy|purchase)\b.{{0,40}}\b(?:starter kit|starter pack)\b"
    rf"|\bcost is\b.{{0,24}}{_AMOUNT}"
    rf"|\b(?:you must|you need to)\b.{{0,35}}\b(?:pay|deposit|top[\s-]?up|buy)\b"
    rf"|\b(?:frozen|unfreeze)\b.{{0,40}}\b(?:pay|transfer|fee|{_AMOUNT})\b",
    re.IGNORECASE,
)

# A refusal and a real payment instruction can share one sentence:
# "we never charge a fee, but you must transfer Rs 8000".
_CONTRAST = re.compile(r"\b(?:but|however|although|yet)\b", re.IGNORECASE)
_AFFIRMATIVE = re.compile(
    r"\b(?:must|have to|need to|required to)\b.{0,80}\b(?:pay|transfer|deposit|prepay|remit|buy)\b"
    r"|\b(?:transfer|send|deposit|prepay|remit)\b.{0,24}\d",
    re.IGNORECASE,
)

# A lesson about how criminals talk, not an instruction to the reader.
_LESSON = re.compile(
    r"\b(?:workshop|seminar|class|lesson)\b.{0,80}\b(?:explains?|teaches|shows|describes)\b"
    r"|\b(?:explains?|teaches|describes)\b.{0,40}\b(?:why|how)\b.{0,50}\b(?:criminals|scammers|fraudsters)\b"
    r"|\b(?:criminals|scammers|fraudsters)\s+say\b",
    re.IGNORECASE,
)

# Pay the employer is describing. "To your account" alone is not enough:
# that phrase is also how a demand names the destination.
_WAGE = re.compile(
    r"\b(?:stipend|salary|wage|payroll|pay rate|daily pay|per hour|per shift|allowance|"
    r"you (?:can |will )?earn|paid (?:monthly|weekly|after)|earn after)\b",
    re.IGNORECASE,
)

# Tokens the saved model uses as scam evidence. A greeting with none of these
# is not yet the scam, even when the score has already crossed 0.5.
# A later demand, not strong enough on its own to raise the score, but enough
# to stop a bait line such as "no upfront payment" from clearing a real ask.
_DEMAND_HINT = re.compile(
    r"\b(?:must|have to|need to|required to)\b.{0,80}\b(?:pay|transfer|deposit|prepay|remit|buy)\b"
    r"|\b(?:security (?:guarantee|deposit|fee|allocation)|activation tax|kit fee|"
    r"government levy|prepay|prepaid|refundable security)\b"
    r"|\b(?:transfer|deposit|prepay|remit)\b.{0,24}\d"
    r"|\d[\d,]{2,}.{0,24}\b(?:levy|guarantee|prepay)\b"
    r"|\bfee\s+of\s+\d"
    r"|\b(?:registration|verification|activation)\b.{0,50}\bfee\b",
    re.IGNORECASE,
)

_TOPIC = re.compile(
    r"\b(?:fees?|deposits?|tasks?|rs|lkr|usdt|merchant|salli|gewanna|"
    r"top[\s-]?ups?|recharge|registration|frozen|freeze|unfreeze|insurance|"
    r"withdraw(?:al)?|commission|kit)\b",
    re.IGNORECASE,
)

# A score at or above this is a scam signal, and outside the uncertain band.
_ASK_FLOOR = 0.72
# A refusal, question, or report of a scam stays under the uncertain band.
_DENIAL_CAP = 0.32
# A greeting with no scam wording stays legitimate, but still uncertain.
_GREETING_CAP = 0.42


def sentences(text: str) -> list[str]:
    """Split on newlines and sentence ends, keeping abbreviations such as Rs."""
    protected = _ABBREV.sub(lambda m: m.group(0).replace(".", "\0"), text)
    parts = re.split(r"[\n]+|(?<=[.!?])\s+", protected)
    return [part.replace("\0", ".").strip() for part in parts if part.strip()]


def _is_abbrev_dot(text: str, index: int) -> bool:
    return text[index:index + 1] == "." and bool(_ABBREV.search(text[max(0, index - 4):index + 1]))


def _sentence_at(text: str, pos: int) -> str:
    left = 0
    for index, mark in enumerate(text[:pos]):
        if mark == "\n":
            left = index + 1
        elif mark in ".!?" and not _is_abbrev_dot(text, index):
            left = index + 1
    right = len(text)
    for index in range(pos, len(text)):
        mark = text[index]
        if mark == "\n" or (mark in ".!?" and not _is_abbrev_dot(text, index)):
            right = index + 1
            break
    return text[left:right]


def sentence_is_wage(text: str, pos: int) -> bool:
    """True when this sentence is the employer describing pay, not asking for it."""
    return bool(_PAYROLL.search(_sentence_at(text, pos)))


def sentence_is_inert(text: str, pos: int) -> bool:
    """True when the phrase at pos is a refusal, a question, a warning, a report, or a wage."""
    sentence = _sentence_at(text, pos)
    if _credential_request_sentence(sentence) or _demand_clause(sentence):
        return False
    if _CREDENTIAL_REFUSAL.search(sentence):
        return True
    if _is_denial(sentence) or _is_report(sentence) or _is_lesson(sentence) or _wage_only(sentence):
        return True
    return "?" in sentence and not _candidate_pays(sentence)


def _is_denial(sentence: str) -> bool:
    if _PUSHBACK.search(sentence) or _THREAT.search(sentence):
        return False
    return bool(_DENIAL.search(sentence))


# "They asked me to tell you to pay" directs the reader. "Someone asked me to deposit"
# is the speaker describing a past request, and that one stays a report.
_READER_PAY = re.compile(
    r"\b(?:tell|asking|ask)\s+you\s+to\b.{0,60}\b(?:pay|transfer|send|deposit|top[\s-]?up|buy)\b"
    r"|\byou\b.{0,12}\b(?:must|have to|need to)\b.{0,40}\b(?:pay|transfer|send|deposit|top[\s-]?up|buy)\b",
    re.IGNORECASE,
)

_CREDENTIAL_ASK = re.compile(
    r"\b(?:give|send|share|provide|enter|tell)\b.{0,40}"
    r"\b(?:me\s+)?(?:your\s+)?(?:banking\s+password|bank\s+password|password|passcode|"
    r"one[- ]time code|otp|pin)\b"
    r"|\bwhat(?:'s| is) your\b.{0,20}\b(?:password|otp|one[- ]time code|pin)\b"
    r"|\b(?:password|otp|pin)\s+eka\b.{0,30}\b(?:ewanna|danna|yawanna)\b"
    r"|\b(?:ewanna|danna|yawanna)\b.{0,30}\b(?:password|otp|pin)\s+eka\b",
    re.IGNORECASE,
)

_CREDENTIAL_REFUSAL = re.compile(
    r"\b(?:do not|don't|dont|never|must not)\b.{0,50}\b(?:share|give|send|tell|enter|provide)\b"
    r"|\b(?:password|otp|pin)\b.{0,40}\b(?:epa|share karanna epa)\b"
    r"|\b(?:epa|naha)\b.{0,30}\b(?:password|otp|pin)\b",
    re.IGNORECASE,
)


def _directs_reader_to_pay(sentence: str) -> bool:
    """A line that tells the reader to pay. A refusal that mentions paying does not count."""
    if _is_denial(sentence):
        return False
    return bool(_READER_PAY.search(sentence))


def _credential_request_sentence(sentence: str) -> bool:
    """An explicit ask for a password, PIN, or one-time code. Advice not to share one is not a request."""
    if _is_lesson(sentence) or _CREDENTIAL_REFUSAL.search(sentence):
        return False
    if "?" in sentence and re.search(r"\b(?:is it|is this|should i|is that)\b", sentence, re.IGNORECASE):
        return False
    return bool(_CREDENTIAL_ASK.search(sentence))


def explicit_credential_request(text: str) -> bool:
    """True when any sentence asks the reader for a password, PIN, or one-time code."""
    return any(_credential_request_sentence(part) for part in sentences(text))


def _is_report(sentence: str) -> bool:
    if _directs_reader_to_pay(sentence):
        return False
    return bool(_REPORT.search(sentence))


def _is_lesson(sentence: str) -> bool:
    return bool(_LESSON.search(sentence))


def _span_demands(span: str) -> bool:
    if _is_denial(span) or _is_report(span) or _is_lesson(span):
        return False
    if _candidate_pays(span) or _THREAT.search(span):
        return True
    return bool(_AFFIRMATIVE.search(span))


def _demand_clause(sentence: str) -> bool:
    """True when a refusal or a lesson also has a separate clause that demands payment."""
    if not (_is_denial(sentence) or _is_lesson(sentence)):
        return False
    spans = [span.strip() for span in _CONTRAST.split(sentence) if span.strip()]
    if len(spans) < 2:
        return False
    return any(_span_demands(span) for span in spans)


def _wage_only(sentence: str) -> bool:
    """True when this sentence names a wage and does not tell the reader to pay."""
    if not _WAGE.search(sentence):
        return False
    return not _candidate_pays(sentence) and not _demand_clause(sentence)


def _has_other_demand(parts: list[str]) -> bool:
    """True when some sentence still tells the reader to pay, outside a refusal."""
    for part in parts:
        if _demand_clause(part):
            return True
        if _credential_request_sentence(part) or _directs_reader_to_pay(part):
            return True
        if _is_denial(part) or _is_report(part) or _is_lesson(part) or _wage_only(part):
            continue
        if _candidate_pays(part) or _THREAT.search(part) or _DEMAND_HINT.search(part):
            return True
    return False


def _candidate_pays(sentence: str) -> bool:
    if _is_denial(sentence) or _is_report(sentence) or _is_lesson(sentence):
        return False
    # A question about a fee is not an instruction to pay it.
    if "?" in sentence and not re.search(rf"\b(?:send|transfer|pay)\s+{_AMOUNT}", sentence, re.IGNORECASE):
        return False
    if not _HANDOVER.search(sentence):
        return False
    if _PAYROLL.search(sentence) and not re.search(
        r"\b(?:to confirm|place is held|so your place|unfreeze|top[\s-]?up|starter kit|fee)\b",
        sentence,
        re.IGNORECASE,
    ):
        return False
    return True


def adjust_score(text: str, score: float) -> float:
    """Return the score the verdict should use.

    A direct request that the reader pay is at least ``_ASK_FLOOR``. A refusal
    that also demands payment, in another clause of the same sentence, is a
    request. A chat whose fee and deposit words are only a refusal, a question,
    a lesson about a scam, or a wage is at most ``_DENIAL_CAP``. A passage with
    no scam wording at all, scored over the line by the greeting, is capped
    just under the line.
    """
    score = float(score)
    parts = sentences(text)
    if any(_candidate_pays(part) or _demand_clause(part) for part in parts):
        return max(score, _ASK_FLOOR)
    if any(_is_denial(part) or _is_report(part) or _is_lesson(part) for part in parts) and not _has_other_demand(parts):
        return min(score, _DENIAL_CAP)
    # A wage line caps the chat only when no other sentence still talks about a fee,
    # a deposit, or a task. A salary mention next to a payment ask stays a scam.
    wage_chat = any(_wage_only(part) for part in parts) and all(
        _wage_only(part) or not _TOPIC.search(part) for part in parts
    )
    if wage_chat and not _has_other_demand(parts):
        return min(score, _DENIAL_CAP)
    # A password or one-time-code request has none of the fee words, so the greeting
    # cap would hide it. Leave the classifier score as it is. Review routing is separate.
    if score >= 0.5 and not _TOPIC.search(text) and not explicit_credential_request(text):
        return min(score, _GREETING_CAP)
    return score
