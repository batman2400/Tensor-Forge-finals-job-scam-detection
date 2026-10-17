"""Parse pasted chat conversations into messages."""
import re

# WhatsApp-style prefixes: "[17/10/26, 9:00 AM] " or "17/10/2026, 09:00 - "
TIMESTAMP_RE = re.compile(
    r"^\s*\[?\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4},?\s+\d{1,2}:\d{2}(?::\d{2})?\s?(?:[APap][Mm])?\]?\s*-?\s*"
)
SPEAKER_RE = re.compile(r"^([^:\n]{1,30}):\s+(.+)$")


def parse_conversation(text: str) -> list[dict]:
    """Split pasted text into [{"sender", "text"}]. Lines without a speaker continue the previous message."""
    messages: list[dict] = []
    for raw in text.splitlines():
        line = TIMESTAMP_RE.sub("", raw).strip()
        if not line:
            continue
        match = SPEAKER_RE.match(line)
        if match:
            messages.append({"sender": match.group(1).strip(), "text": match.group(2).strip()})
        elif messages:
            messages[-1]["text"] += " " + line
        else:
            messages.append({"sender": "unknown", "text": line})
    return messages


def to_model_text(messages: list[dict]) -> str:
    # Sender names are dropped so the model cannot learn from labels like "Recruiter".
    return "\n".join(m["text"] for m in messages)


def to_display_text(messages: list[dict]) -> str:
    return "\n".join(f"{m['sender']}: {m['text']}" for m in messages)
