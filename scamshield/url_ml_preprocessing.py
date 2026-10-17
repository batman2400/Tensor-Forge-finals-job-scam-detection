"""Deterministic URL preprocessing for the optional URL ML model.

Stdlib only (no scikit-learn needed), no network, no file writes. The same
functions are used when building the training data (scripts/prepare_url_data.py)
and at inference time (scamshield/url_ml.py), so the model always sees text
produced by one versioned policy.

Policy (version ``PREPROCESSING_VERSION``):

* The URL is interpreted by the reviewed public rules API ``check_urls`` (no
  private helpers). The input must be exactly one supported http(s) link; a bare
  ``host/path`` link is parsed as ``http://`` + text. Anything else is
  ``not_evaluated``.
* Model text = lower-case scheme + ``://`` + canonical ASCII/xn-- ``host`` from
  ``check_urls`` + optional ``:port`` + the remainder of the link after the
  authority (path/query/fragment, case and encoding preserved, not decoded),
  truncated to ``MAX_MODEL_TEXT_CHARS``.
* Privacy filter (applied identically to training rows and inference inputs):
  links with userinfo (``@`` in the authority), an e-mail address anywhere, or a
  token-like query parameter name are excluded (``not_evaluated``); the rules
  layer still reports AT_SYMBOL etc. for them.
* Reserved / demo domains (``.example``, ``.test``, ``.invalid``,
  ``.localhost``, ``.local`` and ``example.com/net/org``) are ``not_evaluated``.
* Grouping key for splits = registrable domain using the small built-in
  ``MULTI_PART_SUFFIXES`` list below (offline approximation of the Public
  Suffix List, documented limitation); IP hosts group by the IP itself.
"""
from __future__ import annotations

import re

from scamshield.links import check_urls

PREPROCESSING_VERSION = "urlml-pre-1"
RULES_BASELINE_COMMIT = "f9c7961c442326ef475cbfd56f920bb71d1b9367"
MAX_MODEL_TEXT_CHARS = 2048
MAX_INPUT_CHARS = 8192

# UCI PhiUSIIL label: 1 = legitimate, 0 = phishing. Internal: 1 = phishing.
UCI_TO_INTERNAL = {1: 0, 0: 1}
INTERNAL_CLASS_NAMES = {0: "legitimate", 1: "phishing"}
PHISHING_CLASS = 1

RESERVED_TLDS = frozenset({"example", "test", "invalid", "localhost", "local"})
RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})

TOKEN_PARAM_NAMES = frozenset("""
token access_token id_token refresh_token auth auth_token authorization
session sessionid session_id sid jsessionid phpsessid password passwd pwd pass
secret client_secret apikey api_key key otp code signature sig
""".split())

MULTI_PART_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk
com.lk org.lk edu.lk gov.lk net.lk ac.lk sch.lk
com.au net.au org.au edu.au gov.au co.nz org.nz net.nz
co.in net.in org.in firm.in gen.in ind.in ac.in gov.in
com.sg com.my co.jp ne.jp or.jp ac.jp co.kr or.kr com.cn net.cn org.cn
com.hk com.tw com.br net.br org.br com.ar com.mx com.co com.pe com.ve
co.za org.za com.tr com.pk com.ng com.eg com.sa com.ua com.vn com.ph
co.id or.id ac.id co.th ac.th co.il com.pl com.ru
""".split())

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_EMAIL_ENC_RE = re.compile(r"[A-Za-z0-9._+-]+%40[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", re.IGNORECASE)
_SCHEME_RE = re.compile(r"^(https?)://", re.IGNORECASE)
_AUTH_END_RE = re.compile(r"[/\\?#]")
_IPV4_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){3}$")


def _query_param_names(rest: str) -> list[str]:
    q = rest.split("#", 1)[0]
    if "?" not in q:
        return []
    names = []
    for part in q.split("?", 1)[1].split("&"):
        name = part.split("=", 1)[0].strip().lower()
        if name:
            names.append(name)
    return names


def is_reserved_host(host: str) -> bool:
    host = host.rstrip(".").lower()
    labels = host.split(".")
    if labels[-1] in RESERVED_TLDS:
        return True
    return any(host == d or host.endswith("." + d) for d in RESERVED_DOMAINS)


def registrable_domain(host: str) -> str:
    """Offline approximation of the registrable domain (grouping key)."""
    host = host.rstrip(".").lower()
    if host.startswith("[") or _IPV4_RE.match(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _result(status, url, text=None, host=None, group=None, reason=""):
    return {"status": status, "text": text, "host": host, "group": group, "reason": reason}


def prepare_url(url) -> dict:
    """Return {"status": "ok"|"not_evaluated", "text", "host", "group", "reason"}.

    Never raises for any input value.
    """
    try:
        return _prepare(url)
    except Exception as exc:  # parser edge cases must not abort a batch
        return _result("not_evaluated", url, reason=f"preprocessing error ({type(exc).__name__})")


def _prepare(url) -> dict:
    if not isinstance(url, str):
        return _result("not_evaluated", url, reason="input is not a string")
    raw = url.strip()
    if not raw:
        return _result("not_evaluated", url, reason="empty input")
    if len(raw) > MAX_INPUT_CHARS:
        return _result("not_evaluated", url, reason="input too long")
    if any(ch.isspace() for ch in raw):
        return _result("not_evaluated", url, reason="input is not a single link")
    m = _SCHEME_RE.match(raw)
    if m:
        scheme, body = m.group(1).lower(), raw[m.end():]
        parse_text = raw
    elif "://" in raw:
        return _result("not_evaluated", url, reason="unsupported scheme")
    else:
        scheme, body = "http", raw
        parse_text = "http://" + raw
    end = _AUTH_END_RE.search(body)
    authority = body[:end.start()] if end else body
    rest = body[end.start():] if end else ""
    if "@" in authority:
        return _result("not_evaluated", url, reason="link contains login details before '@' (privacy policy)")
    if _EMAIL_RE.search(raw) or _EMAIL_ENC_RE.search(raw):
        return _result("not_evaluated", url, reason="link contains an e-mail address (privacy policy)")
    if any(n in TOKEN_PARAM_NAMES for n in _query_param_names(rest)):
        return _result("not_evaluated", url, reason="link contains a token-like query parameter (privacy policy)")
    found = check_urls(parse_text)
    if len(found) != 1:
        return _result("not_evaluated", url, reason="not exactly one supported link")
    host = found[0]["host"]
    if not host:
        return _result("not_evaluated", url, reason="no host")
    if is_reserved_host(host):
        return _result("not_evaluated", url, host=host, reason="reserved demo domain (not evaluated)")
    port = ""
    if not authority.startswith("[") and ":" in authority:
        p = authority.rsplit(":", 1)[1]
        if p.isdigit():
            port = ":" + str(int(p))
    text = f"{scheme}://{host}{port}{rest}"[:MAX_MODEL_TEXT_CHARS]
    return _result("ok", url, text=text, host=host, group=registrable_domain(host))
