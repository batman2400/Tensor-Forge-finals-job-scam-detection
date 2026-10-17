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
valid host is ignored. Explicit URLs glued together with ``,`` or ``;``
(``https://a.example,https://b.example``) are split into separate
links; if a candidate is invalid, any later ``http(s)://`` inside it is
still examined. Commas and semicolons inside a path or query are kept, and
``?next=https://...`` stays part of its link.

Results are in first-appearance order and de-duplicated on a normalised
key (scheme ignored; userinfo, host and port lowercased; trailing
punctuation removed; a bare ``/`` path dropped). ``url`` keeps the text as
written; ``host`` is lowercased with userinfo, port, IPv6 brackets and a
trailing dot removed, and is what every check compares.

Host parsing follows browser (WHATWG) rules for http/https, implemented
locally without any lookup:

* A backslash acts like ``/``: the authority (``userinfo@host:port``) ends
  at the first ``/``, ``\\``, ``?`` or ``#``, and backslashes in the path
  become ``/``. So ``https://evil.example\\@abcholdings.example/login``
  goes to ``evil.example`` (the ``@`` is in the path, no ``AT_SYMBOL``).
* Numeric IPv4 hosts in ``http(s)://`` links are decoded like a browser
  and shown as dotted quads: ``2130706433``, ``0x7f000001``, ``0177.0.0.1``
  and ``127.1`` all become ``127.0.0.1``. Each of 1-4 parts may be decimal,
  ``0x`` hex or leading-zero octal; out-of-range values are rejected (the
  link is dropped), never wrapped. A host whose last label is numeric but
  is not a valid address is rejected. Bare links (no scheme) only accept
  conventional dotted-quad IPv4 such as ``198.51.100.7/login``.
* Percent-encoded hosts are decoded exactly once, strictly (valid ``%XX``
  escapes and UTF-8 only), before validation: ``https://%65vil.example``
  is ``evil.example`` and ``http://%31%32%37.0.0.1`` is ``127.0.0.1``. A
  malformed escape, invalid UTF-8, or a decoded character that is not
  allowed in a host (``@ / : % ? #`` ...) drops the link. Decoded non-ASCII
  characters still trigger ``PUNYCODE``. Path and query are decoded
  separately (see ``APK_DOWNLOAD``).

Flags (stable order = order of checks below)
--------------------------------------------
* ``IP_HOST``: host is an IPv4 or IPv6 address.
* ``AT_SYMBOL``: ``@`` in the authority part (``http://brand.example@other.example/``).
* ``SHORTENER``: host is a known link shortener (``SHORTENER_DOMAINS``).
* ``CHAT_REDIRECT``: link opens a Telegram/WhatsApp chat (``CHAT_DOMAINS``).
* ``APK_DOWNLOAD``: path ends with ``.apk`` or path/query mentions an
  ``.apk`` file (case-insensitive; fragment ignored).
* ``CLAIMED_COMPANY_MISMATCH``: ``claimed_company`` maps (case-insensitive,
  whitespace-normalised name) to an official domain and the host is neither
  that domain nor a genuine subdomain. Skipped if the company is unknown or
  the mapping is unavailable.
* ``LOOKALIKE``: the host's registrable label (the label just before the
  public suffix, e.g. ``abcho1dings`` in ``abcho1dings.example``;
  ``abc.com.lk`` -> ``abc`` via ``MULTI_PART_SUFFIXES``) is within
  Levenshtein distance 1..2 of an official domain's label, and the host is
  not that official domain or its subdomain. Only that label is compared,
  so sharing the ``.example`` suffix never matches on its own. Labels
  shorter than ``LOOKALIKE_MIN_LEN`` (5) are ignored.
* ``BRAND_IN_SUBDOMAIN``: a brand token (official label, e.g.
  ``abcholdings``, or the company name squashed to lowercase alphanumerics,
  e.g. ``lankatalentpartners``; tokens < 5 chars ignored) appears
  (a) inside a subdomain label (``abcholdings.careers-portal.example``),
  (b) as a hyphen-separated token of a different registrable label
  (``abcholdings-careers.example``), or (c) as the whole registrable label
  under a different suffix (``abcholdings.com.lk``), while the host is not
  that company's official domain/subdomain. LOOKALIKE and
  BRAND_IN_SUBDOMAIN are independent: both fire if both conditions hold.
* ``FREE_HOSTING_FORM``: host is a free site builder / form service
  (``FREE_HOSTING_DOMAINS``; ``docs.google.com`` only when the path starts
  with ``/forms``).
* ``PUNYCODE``: any host label starts with ``xn--`` or the host contains
  non-ASCII characters (the reason shows the ``xn--`` form when the IDNA
  codec can encode it).
* ``MANY_SUBDOMAINS``: the host has ``MANY_SUBDOMAINS_MIN_LABELS`` (5) or
  more labels in total, e.g. ``a.b.c.d.example``.

The three company checks need ``data/official_domains.json`` (loaded lazily
from ``OFFICIAL_DOMAINS_PATH`` relative to this file, cached; see
``official_domains_available()``). If it is missing or invalid, they are
skipped silently: no flag is raised and nothing is reported as verified.

All domain lists match the exact host or a genuine subdomain on a label
boundary (``host == d or host.endswith("." + d)``), so ``notbit.ly`` does
not match ``bit.ly``.

Risk rule
---------
Count distinct flag codes (each check emits at most one flag):
0 -> "low", 1 -> "medium", 2+ -> "high". ``IP_HOST`` or
``CLAIMED_COMPANY_MISMATCH`` alone already gives "high".

Limitations
-----------
* Text rules only: no WHOIS/domain age, no reputation lists, no redirect
  following, so a brand-new or compromised site may score "low".
* The public-suffix handling is a small built-in list, not the full PSL.
* Bare domains need a TLD from ``KNOWN_TLDS`` (or a ``www.`` prefix).
* Brand detection inside a registrable label only matches whole hyphen
  tokens (``notabcholdings.example`` is caught only by
  ``CLAIMED_COMPANY_MISMATCH`` when a company is claimed).
"""

from __future__ import annotations

import functools
import ipaddress
import json
import re
from urllib.parse import unquote_to_bytes
from pathlib import Path

__all__ = ["check_urls", "official_domains_available", "OFFICIAL_DOMAINS_PATH",
           "FLAG_CODES"]

#: Company -> official domain mapping. Missing/invalid file => company checks
#: (CLAIMED_COMPANY_MISMATCH, LOOKALIKE, BRAND_IN_SUBDOMAIN) are skipped.
OFFICIAL_DOMAINS_PATH = Path(__file__).resolve().parent.parent / "data" / "official_domains.json"

LOOKALIKE_MIN_LEN = 5
LOOKALIKE_MAX_DISTANCE = 2
BRAND_MIN_LEN = 5
MANY_SUBDOMAINS_MIN_LABELS = 5

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

FREE_HOSTING_DOMAINS = (
    "wixsite.com", "blogspot.com", "sites.google.com", "forms.gle",
    "weebly.com", "netlify.app", "github.io", "000webhostapp.com",
    "forms.office.com", "typeform.com", "jotform.com",
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


_IPV4_PART_HEX = re.compile(r"0[xX][0-9a-fA-F]*")
_IPV4_PART_OCT = re.compile(r"0[0-7]+")
_IPV4_PART_DEC = re.compile(r"[0-9]+")
_DOTTED_QUAD = re.compile(r"(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}")


_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_FORBIDDEN_HOST_CHARS = frozenset("\x00\t\n\r #%/:<>?@[\\]^|")


def _ends_in_number(host: str) -> bool:
    last = host.rsplit(".", 1)[-1]
    return bool(_IPV4_PART_DEC.fullmatch(last) or _IPV4_PART_HEX.fullmatch(last))


def _parse_ipv4(host: str) -> str | None:
    """WHATWG IPv4 parser: 1-4 parts, each decimal, 0x-hex or 0-octal.

    All parts but the last must be <= 255; the last fills the remaining
    bytes (< 256 ** (5 - parts)). Out-of-range values return None (the URL
    is rejected), never wrapped. No resolver is involved.
    """
    parts = host.split(".")
    if len(parts) > 4:
        return None
    nums = []
    for part in parts:
        if _IPV4_PART_HEX.fullmatch(part):
            nums.append(int(part[2:] or "0", 16))
        elif len(part) > 1 and part.startswith("0"):
            if not _IPV4_PART_OCT.fullmatch(part):
                return None
            nums.append(int(part, 8))
        elif _IPV4_PART_DEC.fullmatch(part):
            nums.append(int(part))
        else:
            return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1] + sum(n << (8 * (3 - i)) for i, n in enumerate(nums[:-1]))
    return str(ipaddress.IPv4Address(value))


def _normalize_host(raw: str, bracketed: bool, strict_ipv4: bool) -> str | None:
    """Return the canonical destination host, or None if it is invalid."""
    if bracketed:
        try:
            return str(ipaddress.IPv6Address(raw)) if "%" not in raw else None
        except ValueError:
            return None
    if "%" in raw:
        # Decode exactly once, strictly: every % must start a valid %XX
        # escape and the bytes must be valid UTF-8. The decoded host is then
        # validated like any other, so an encoded '@', '/', ':', '%', ...
        # cannot change the authority structure (it makes the host invalid).
        if _BAD_PERCENT_RE.search(raw):
            return None
        try:
            raw = unquote_to_bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            return None
        if any(ch in _FORBIDDEN_HOST_CHARS for ch in raw):
            return None
    host = raw.lower().rstrip(".")
    if not host:
        return None
    if _ends_in_number(host):
        if strict_ipv4:
            # Bare text (no scheme): only conventional dotted quads, so that
            # section numbers like 1.2/3 are not read as addresses.
            return host if _DOTTED_QUAD.fullmatch(host) and _is_ip(host) else None
        return _parse_ipv4(host)
    return host if _valid_hostname(host) else None


_SCHEME_PREFIX_RE = re.compile(r"(https?):", re.IGNORECASE)
_AUTHORITY_END_RE = re.compile(r"[/\\?#]")


def _split_url(url: str) -> tuple[str, str, str, str, str] | None:
    """Browser-style split of an http(s) URL: (scheme, authority, path, query, fragment).

    Like the WHATWG URL parser for "special" schemes, a backslash counts as
    a path separator: the authority ends at the first ``/``, ``\\``, ``?``
    or ``#``, and backslashes in the *path* become ``/``. Query and fragment
    are left untouched.
    """
    m = _SCHEME_PREFIX_RE.match(url)
    if not m:
        return None
    scheme = m.group(1).lower()
    rest = url[m.end():].lstrip("/\\")
    end = _AUTHORITY_END_RE.search(rest)
    authority, tail = (rest[:end.start()], rest[end.start():]) if end else (rest, "")
    tail, _, fragment = tail.partition("#")
    path, _, query = tail.partition("?")
    return scheme, authority, path.replace("\\", "/"), query, fragment


def _parse(display: str, has_scheme: bool) -> dict | None:
    """Split a candidate into parts; return None if it is not a usable URL."""
    split = _split_url(display if has_scheme else "http://" + display)
    if split is None:
        return None
    scheme, authority, path, query, fragment = split
    userinfo, at, hostport = authority.rpartition("@")
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            return None
        host, port = hostport[1:end], hostport[end + 1:]
        if port and not (port.startswith(":") and port[1:].isdigit()):
            return None
        port = port[1:]
    else:
        host, sep, port = hostport.rpartition(":")
        if not sep or not (port.isdigit() or port == ""):
            host, port = hostport, ""
    host = _normalize_host(host, bracketed=hostport.startswith("["),
                           strict_ipv4=not has_scheme)
    if host is None:
        return None
    return {
        "scheme": scheme if has_scheme else "",
        "netloc": authority,
        "has_at": bool(at),
        "userinfo": userinfo.lower(),
        "host": host,
        "port": port,
        "path": path,
        "query": query,
        "fragment": fragment,
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


# A new explicit URL starts right after one of these separators even when
# there is no space ("a.example,https://b.example"). "=" is deliberately not
# a separator, so "?next=https://portal.example" stays one link.
_SCHEME_SPLIT_RE = re.compile(r"(?<=[,;])https?://", re.IGNORECASE)
_SCHEME_ANYWHERE_RE = re.compile(r"https?://", re.IGNORECASE)


def _scheme_candidates(chunk: str):
    """Yield (display, parsed) for one scheme-regex match.

    The match is split before every ``,https://`` and ``;https://``. If a piece is still not a valid URL, the search resumes at
    the next ``http(s)://`` inside it, so a rejected candidate never hides a
    later explicit URL.
    """
    starts = [0] + [m.start() for m in _SCHEME_SPLIT_RE.finditer(chunk)]
    for a, b in zip(starts, starts[1:] + [len(chunk)]):
        piece = chunk[a:b]
        while piece:
            display = _strip_trailing(piece)
            parsed = _parse(display, True) if display else None
            if parsed is not None:
                yield display, parsed
                break
            nxt = _SCHEME_ANYWHERE_RE.search(piece, 1)
            piece = piece[nxt.start():] if nxt else ""


def _bare_candidates(chunk: str):
    display = _strip_trailing(chunk)
    parsed = _parse(display, False) if display else None
    if parsed is not None and _accept_bare(parsed, display):
        yield display, parsed


def _extract(text: str) -> list[tuple[str, dict]]:
    found: list[tuple[str, dict]] = []
    seen: set[tuple] = set()
    for match in _URL_RE.finditer(text):
        if match.group("scheme") is not None:
            candidates = _scheme_candidates(match.group(0))
        else:
            candidates = _bare_candidates(match.group(0))
        for display, parsed in candidates:
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


def _norm_company(name: str) -> str:
    return " ".join(name.split()).casefold()


def _squash(name: str) -> str:
    return "".join(ch for ch in name.casefold() if ch.isalnum())


@functools.lru_cache(maxsize=1)
def _official_domains() -> tuple:
    """Return ((normalised_name, squashed_name, domain), ...) or () on error."""
    try:
        with open(OFFICIAL_DOMAINS_PATH, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return ()
    if not isinstance(raw, dict):
        return ()
    out = []
    for name, domain in raw.items():
        if not (isinstance(name, str) and isinstance(domain, str)):
            continue
        domain = domain.strip().lower().rstrip(".")
        if name.strip() and _valid_hostname(domain) and "." in domain:
            out.append((_norm_company(name), _squash(name), domain))
    return tuple(sorted(out, key=lambda t: (t[2], t[0])))


def official_domains_available() -> bool:
    """True if the official-domain mapping loaded with at least one entry."""
    return bool(_official_domains())


def _split_registrable(host: str) -> tuple[list[str], str, str]:
    """Return (subdomain_labels, registrable_label, suffix)."""
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        n = 2
    else:
        n = 1
    if len(labels) <= n:
        return [], labels[0], ".".join(labels[1:])
    return labels[:-(n + 1)], labels[-(n + 1)], ".".join(labels[-n:])


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _check_claimed_company(p: dict, ctx: dict) -> str | None:
    claimed = ctx.get("claimed_company")
    if not claimed or not claimed.strip():
        return None
    wanted = _norm_company(claimed)
    for name, _sq, domain in _official_domains():
        if name == wanted:
            if _on_domain(p["host"], domain):
                return None
            return (f"The chat claims to be from '{' '.join(claimed.split())}', whose "
                    f"official domain is {domain}, but this link goes to "
                    f"{p['host']}, which is a different domain.")
    return None


def _check_lookalike(p: dict, ctx: dict) -> str | None:
    if _is_ip(p["host"]):
        return None
    _sub, label, _suffix = _split_registrable(p["host"])
    if len(label) < LOOKALIKE_MIN_LEN:
        return None
    hits = []
    for _name, _sq, domain in _official_domains():
        if _on_domain(p["host"], domain):
            continue
        official_label = _split_registrable(domain)[1]
        if len(official_label) < LOOKALIKE_MIN_LEN:
            continue
        dist = _levenshtein(label, official_label)
        if 1 <= dist <= LOOKALIKE_MAX_DISTANCE:
            hits.append(domain)
    if hits:
        return (f"The name '{label}' differs by only one or two characters "
                f"from the official domain {', '.join(hits)}; look-alike "
                "names are often used to imitate a known company.")
    return None


def _check_brand_in_subdomain(p: dict, ctx: dict) -> str | None:
    host = p["host"]
    if _is_ip(host):
        return None
    sub, label, _suffix = _split_registrable(host)
    sub_squashed = [_squash(s) for s in sub]
    label_tokens = label.split("-")
    hits = []
    for _name, squashed, domain in _official_domains():
        if _on_domain(host, domain):
            continue
        tokens = {t for t in (_split_registrable(domain)[1], squashed)
                  if len(t) >= BRAND_MIN_LEN}
        for tok in sorted(tokens):
            if any(tok in s for s in sub_squashed) or tok in label_tokens:
                hits.append(domain)
                break
    if hits:
        return (f"The link uses a company name belonging to {', '.join(hits)} "
                f"inside a different website ({host}); the real owner of a "
                "link is the part just before the domain ending, not the "
                "words in front of it.")
    return None


def _check_free_hosting(p: dict, ctx: dict) -> str | None:
    host = p["host"]
    d = _match_any(host, FREE_HOSTING_DOMAINS)
    if d is None and _on_domain(host, "docs.google.com") and \
            p["path"].lower().startswith("/forms"):
        d = "docs.google.com/forms"
    if d:
        return (f"The link is on a free website or form service ({d}); "
                "anyone can create these pages, and established employers "
                "usually collect applications on their own domain.")
    return None


def _check_punycode(p: dict, ctx: dict) -> str | None:
    host = p["host"]
    labels = host.split(".")
    if any(label.startswith("xn--") for label in labels):
        return ("The website name uses an encoded international form "
                f"('{host}'), which can display as letters that look like "
                "a different, familiar name.")
    if not host.isascii():
        try:
            encoded = host.encode("idna").decode("ascii")
            shown = f" (encoded: {encoded})"
        except (UnicodeError, ValueError):
            shown = " (could not be converted to its encoded form)"
        return ("The website name contains non-English characters"
                f"{shown}; some of these look identical to normal letters "
                "and can imitate a familiar name.")
    return None


def _check_many_subdomains(p: dict, ctx: dict) -> str | None:
    host = p["host"]
    if _is_ip(host):
        return None
    n = len(host.split("."))
    if n >= MANY_SUBDOMAINS_MIN_LABELS:
        return (f"The website name has {n} parts separated by dots "
                f"(threshold {MANY_SUBDOMAINS_MIN_LABELS}); long chains of "
                "subdomains can hide the real domain at the end.")
    return None


# --- end of checks ---

_CHECKS = (
    ("IP_HOST", _check_ip_host),
    ("AT_SYMBOL", _check_at_symbol),
    ("SHORTENER", _check_shortener),
    ("CHAT_REDIRECT", _check_chat_redirect),
    ("APK_DOWNLOAD", _check_apk_download),
    ("CLAIMED_COMPANY_MISMATCH", _check_claimed_company),
    ("LOOKALIKE", _check_lookalike),
    ("BRAND_IN_SUBDOMAIN", _check_brand_in_subdomain),
    ("FREE_HOSTING_FORM", _check_free_hosting),
    ("PUNYCODE", _check_punycode),
    ("MANY_SUBDOMAINS", _check_many_subdomains),
)

#: Flag codes in the fixed order they appear in results.
FLAG_CODES = tuple(code for code, _ in _CHECKS)


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
