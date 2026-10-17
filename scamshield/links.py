"""Structural URL risk checks. Owned by: Sithum. See PLAN.md section 4 for milestones.

Risk aggregation (agreed after review): no flags = low, which is not "safe".
A strong flag (IP_HOST, CLAIMED_COMPANY_MISMATCH, LOOKALIKE, APK_DOWNLOAD) = high.
Any number of weak flags stays medium. Two weak flags must not be reported as high.

Contract (do not change without telling the team):

    check_urls(text: str, claimed_company: str | None = None) -> list[dict]

Each dict:
    {
        "url":   str,                      # URL as found in the text
        "host":  str,                      # lower-cased hostname ("" if unparsable)
        "risk":  "low" | "medium" | "high",
        "flags": [{"code": str, "reason": str}],
    }

URLs are inspected as text only: no network calls, redirects, or reputation lookups.
A link with no flags is "low" risk, which is NOT the same as "safe".

TODO (Sithum), in order:
  - AT_SYMBOL, SHORTENER, CHAT_REDIRECT (t.me / wa.me), APK_DOWNLOAD
  - LOOKALIKE, BRAND_IN_SUBDOMAIN (CLAIMED_COMPANY_MISMATCH is already wired; keep the risk rule above)
  - FREE_HOSTING_FORM, PUNYCODE, MANY_SUBDOMAINS
  - tests in tests/test_links.py
"""
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

STRONG_FLAGS = {"IP_HOST", "CLAIMED_COMPANY_MISMATCH", "LOOKALIKE", "APK_DOWNLOAD"}
_OFFICIAL: dict[str, str] | None = None

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+/[^\s<>\"')\]]*", re.IGNORECASE)

def extract_urls(text: str) -> list[str]:
    return [u.rstrip(".,;:!?") for u in URL_RE.findall(text)]


def _host(url: str) -> str:
    parsed = urlparse(url if "://" in url else "http://" + url)
    return (parsed.hostname or "").lower()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def official_domains() -> dict[str, str]:
    global _OFFICIAL
    if _OFFICIAL is None:
        path = Path(__file__).resolve().parent.parent / "data" / "official_domains.json"
        _OFFICIAL = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    return _OFFICIAL


def _on_official_domain(host: str, official: str) -> bool:
    official = official.lower().strip(".")
    return host == official or host.endswith("." + official)


def _risk(flags: list[dict]) -> str:
    if not flags:
        return "low"
    if any(f["code"] in STRONG_FLAGS for f in flags):
        return "high"
    return "medium"


def check_urls(text: str, claimed_company: str | None = None) -> list[dict]:
    domains = official_domains()
    official = None
    if claimed_company:
        official = next((domains[k] for k in domains if k.lower() == claimed_company.lower()), None)
    results = []
    for url in extract_urls(text):
        host = _host(url)
        flags = []
        if _is_ip(host):
            flags.append({"code": "IP_HOST", "reason": "Hostname is a raw IP address"})
        if official and host and not _on_official_domain(host, official):
            flags.append({
                "code": "CLAIMED_COMPANY_MISMATCH",
                "reason": f"Chat names {claimed_company}, whose demo domain is {official}; this host is {host}",
            })
        results.append({"url": url, "host": host, "risk": _risk(flags), "flags": flags})
    return results
