"""Rule-based URL checker for ScamShield LK (text only, no network).

Public contract (do not change)::

    check_urls(text: str, claimed_company: str | None = None) -> list[dict]
    # [{"url": str, "host": str, "risk": "low"|"medium"|"high",
    #   "flags": [{"code": str, "reason": str}]}]

IMPORTANT: risk "low" means *no warning sign was found by these rules*.
It does NOT mean the link is safe. The checker never opens, resolves or
downloads anything; it only looks at the text of the link.

Extraction
----------
* ``http://`` / ``https://`` URLs (any host),
* ``www.``-prefixed hosts,
* bare domains (optionally with port and ``/path``, ``?query``, ``#frag``)
  whose last label is in ``KNOWN_TLDS`` (e.g. ``abc-jobs.example/apply``),
* bare IPv4 addresses only when followed by a port or a path.

Surrounding punctuation ``( ) [ ] < > " ' , . ; : ! ?`` is stripped (a
closing ``)`` is kept when it balances an ``(`` inside the URL). E-mail
addresses (``hr@abc.example``), version numbers (``1.2.3``), ``e.g.`` and
sentence fragments such as ``end.Next`` are not URLs. ``http://`` with no
valid host is ignored.

Results are in first-appearance order and de-duplicated on a normalised
key (scheme ignored; userinfo, host and port lowercased; trailing
punctuation removed; a bare ``/`` path dropped). ``url`` keeps the text as
written; ``host`` is lowercased with userinfo, port, IPv6 brackets and a
trailing dot removed, and is what every check compares.

Flags (stable order = order of checks below)
--------------------------------------------
* ``IP_HOST``: host is an IPv4 or IPv6 address.
* ``AT_SYMBOL``: ``@`` in the authority part (``http://brand.example@other.example/``).
* ``SHORTENER``: host is a known link shortener (``SHORTENER_DOMAINS``).
* ``CHAT_REDIRECT``: link opens a Telegram/WhatsApp chat (``CHAT_DOMAINS``).
* ``APK_DOWNLOAD``: path ends with ``.apk`` or path/query mentions an
  ``.apk`` file (case-insensitive; fragment ignored).

All domain lists match the exact host or a genuine subdomain on a label
boundary (``host == d or host.endswith("." + d)``), so ``notbit.ly`` does
not match ``bit.ly``.

Risk rule
---------
Count distinct flag codes (each check emits at most one flag):
0 -> "low", 1 -> "medium", 2+ -> "high". ``IP_HOST`` or
``CLAIMED_COMPANY_MISMATCH`` alone already gives "high".
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

__all__ = ["check_urls"]

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

KNOWN_TLDS = frozenset(
    """
    example com lk net org xyz top info me ly gl io co app biz online site
    shop club live vip work jobs careers in uk us au sg my ai dev link click
    tk ml ga cf gq ru cn edu gov store tech pro cc id at gd gy page today
    world website space fun icu buzz cyou sbs
    """.split()
)

# Minimal list of two-label public suffixes so that the "registrable" part
# of abc.com.lk is abc.com.lk (label "abc"), not com.lk.
MULTI_PART_SUFFIXES = frozenset(
    """
    co.uk org.uk ac.uk gov.uk com.lk org.lk edu.lk gov.lk net.lk ac.lk
    sch.lk com.au net.au org.au co.in co.nz com.sg com.my co.jp
    """.split()
)

SHORTENER_DOMAINS = (
    "bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "is.gd", "ow.ly",
    "rb.gy", "shorturl.at", "tiny.cc", "buff.ly", "rebrand.ly", "s.id",
)

CHAT_DOMAINS = (
    "t.me", "telegram.me", "telegram.dog", "wa.me", "chat.whatsapp.com",
    "api.whatsapp.com", "whatsapp.com",
)

_APK_RE = re.compile(r"\.apk(?![a-z0-9])", re.IGNORECASE)

_STRIP_TRAILING = set("()[]<>\"',.;:!?")

_URL_RE = re.compile(
    r"""
    (?P<scheme>(?<![\w.+-])https?://[^\s<>"'`]*)
    |
    (?P<bare>(?<![\w@.\-/:%+])
        (?:[^\W_][\w-]*\.)+[^\W_][\w-]*      # dotted host
        (?::\d{1,5})?                         # optional port
        (?:[/?\#][^\s<>"'`]*)?                # optional path/query/fragment
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

_LABEL_RE = re.compile(r"^[^\W_](?:[\w-]*[^\W_])?$|^[^\W_]$")


# --------------------------------------------------------------------------
# Extraction helpers
# --------------------------------------------------------------------------

def _strip_trailing(candidate: str) -> str:
    while candidate and candidate[-1] in _STRIP_TRAILING:
        if candidate[-1] == ")" and candidate.count("(") >= candidate.count(")"):
            break
        candidate = candidate[:-1]
    return candidate


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _valid_hostname(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    return all(_LABEL_RE.match(label) for label in host.split("."))


def _parse(display: str, has_scheme: bool) -> dict | None:
    """Split a candidate into parts; return None if it is not a usable URL."""
    try:
        parts = urlsplit(display if has_scheme else "http://" + display)
    except ValueError:
        return None
    netloc = parts.netloc
    userinfo, at, hostport = netloc.rpartition("@")
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            return None
        host, port = hostport[1:end], hostport[end + 1:].lstrip(":")
    else:
        host, sep, port = hostport.rpartition(":")
        if not sep or not port.isdigit():
            host, port = hostport, ""
    host = host.lower().rstrip(".")
    if not host:
        return None
    if not (_is_ip(host) or _valid_hostname(host)):
        return None
    return {
        "scheme": parts.scheme.lower() if has_scheme else "",
        "netloc": netloc,
        "has_at": bool(at),
        "userinfo": userinfo.lower(),
        "host": host,
        "port": port,
        "path": parts.path,
        "query": parts.query,
        "fragment": parts.fragment,
    }


def _accept_bare(parsed: dict, display: str) -> bool:
    host = parsed["host"]
    if _is_ip(host):
        # Bare dotted numbers are usually versions; require a port or path.
        return bool(parsed["port"] or parsed["path"] or parsed["query"])
    if "." not in host:
        return False
    tld = host.rsplit(".", 1)[1]
    if tld in KNOWN_TLDS:
        return True
    return display.lower().startswith("www.") and tld.isalpha() and len(tld) >= 2


def _extract(text: str) -> list[tuple[str, dict]]:
    found: list[tuple[str, dict]] = []
    seen: set[tuple] = set()
    for match in _URL_RE.finditer(text):
        has_scheme = match.group("scheme") is not None
        display = _strip_trailing(match.group(0))
        if not display:
            continue
        parsed = _parse(display, has_scheme)
        if parsed is None:
            continue
        if not has_scheme and not _accept_bare(parsed, display):
            continue
        path = parsed["path"] if parsed["path"] != "/" else ""
        key = (parsed["userinfo"], parsed["host"], parsed["port"], path,
               parsed["query"], parsed["fragment"])
        if key in seen:
            continue
        seen.add(key)
        found.append((display, parsed))
    return found


# --------------------------------------------------------------------------
# Checks (each returns a reason string or None). Order here = flag order.
# --------------------------------------------------------------------------

def _check_ip_host(p: dict, ctx: dict) -> str | None:
    if _is_ip(p["host"]):
        return ("The link points to a raw IP address instead of a named "
                "website; legitimate employers normally use a domain name.")
    return None


def _check_at_symbol(p: dict, ctx: dict) -> str | None:
    if p["has_at"]:
        return ("The link contains '@' before the host, so everything before "
                "'@' is treated as a user name, not the website; the real destination "
                f"is '{p['host']}'. This trick can make a link look like another site.")
    return None


def _on_domain(host: str, domain: str) -> bool:
    """True if host is ``domain`` or a genuine subdomain of it."""
    return host == domain or host.endswith("." + domain)


def _match_any(host: str, domains) -> str | None:
    for d in domains:
        if _on_domain(host, d):
            return d
    return None


def _check_shortener(p: dict, ctx: dict) -> str | None:
    d = _match_any(p["host"], SHORTENER_DOMAINS)
    if d:
        return (f"Shortened link ({d}): the real destination is hidden until "
                "it is opened.")
    return None


def _check_chat_redirect(p: dict, ctx: dict) -> str | None:
    d = _match_any(p["host"], CHAT_DOMAINS)
    if d:
        app = "Telegram" if "telegram" in d or d == "t.me" else "WhatsApp"
        return (f"The link opens a {app} chat or group ({d}); moving a job "
                "conversation to a private chat app is a common pattern in "
                "task-job scams.")
    return None


def _check_apk_download(p: dict, ctx: dict) -> str | None:
    if _APK_RE.search(p["path"]) or _APK_RE.search(p["query"]):
        return ("The link appears to download an Android app file (.apk) "
                "from outside an app store; such files can install unwanted "
                "software.")
    return None


# --- end of checks ---

_CHECKS = (
    ("IP_HOST", _check_ip_host),
    ("AT_SYMBOL", _check_at_symbol),
    ("SHORTENER", _check_shortener),
    ("CHAT_REDIRECT", _check_chat_redirect),
    ("APK_DOWNLOAD", _check_apk_download),
)


def _risk(codes: list[str]) -> str:
    if "IP_HOST" in codes or "CLAIMED_COMPANY_MISMATCH" in codes:
        return "high"
    distinct = len(set(codes))
    if distinct == 0:
        return "low"
    return "medium" if distinct == 1 else "high"


def _context(claimed_company: str | None) -> dict:
    return {"claimed_company": claimed_company if isinstance(claimed_company, str) else None}


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------

def check_urls(text: str, claimed_company: str | None = None) -> list[dict]:
    """Extract links from ``text`` and attach rule-based warning flags.

    Returns a JSON-serialisable list in first-appearance order. "low" risk
    means no warning was found, not that the link is safe.
    """
    if not isinstance(text, str) or not text:
        return []
    ctx = _context(claimed_company)
    results: list[dict] = []
    for display, parsed in _extract(text):
        flags = []
        for code, check in _CHECKS:
            reason = check(parsed, ctx)
            if reason:
                flags.append({"code": code, "reason": reason})
        results.append({
            "url": display,
            "host": parsed["host"],
            "risk": _risk([f["code"] for f in flags]),
            "flags": flags,
        })
    return results
