"""Tests for scamshield.links (all URLs are synthetic; nothing is opened).

Runs with ``python -m pytest tests/test_links.py`` from any directory.
"""

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scamshield import links  # noqa: E402
from scamshield.links import check_urls  # noqa: E402


def codes(result):
    return [f["code"] for f in result["flags"]]


def one(text, claimed=None):
    res = check_urls(text, claimed)
    assert len(res) == 1, res
    return res[0]


# ---------------------------------------------------------------- schema ----

def test_empty_text_returns_empty_list():
    assert check_urls("") == []


def test_text_without_urls():
    assert check_urls("Hi, are you free for an interview on Monday at 10?") == []


def test_schema_and_types():
    res = check_urls("See https://abc-jobs.example/apply now")
    assert res == [{"url": "https://abc-jobs.example/apply",
                    "host": "abc-jobs.example", "risk": "low", "flags": []}]


def test_output_is_json_serialisable_and_deterministic():
    text = ("http://198.51.100.7/pay and http://abcholdings.example@evil.example/x "
            "and abc-jobs.example/apply")
    first = check_urls(text, "ABC Holdings")
    assert json.loads(json.dumps(first)) == first
    assert check_urls(text, "ABC Holdings") == first
    for r in first:
        assert set(r) == {"url", "host", "risk", "flags"}
        assert r["risk"] in {"low", "medium", "high"}
        for f in r["flags"]:
            assert set(f) == {"code", "reason"} and f["reason"]


# ------------------------------------------------------------ extraction ----

def test_extracts_scheme_www_and_bare_forms_in_order():
    text = ("1) https://portal.example/a 2) www.jobs-lk.example "
            "3) abc-jobs.example/apply 4) careers.example")
    assert [r["url"] for r in check_urls(text)] == [
        "https://portal.example/a", "www.jobs-lk.example",
        "abc-jobs.example/apply", "careers.example"]


def test_surrounding_punctuation_is_stripped():
    text = ('Links: (https://abc-jobs.example/apply), [www.portal.example]; '
            '<http://jobs.example/x>! "careers.example/form?id=3"? \'site.example\'.')
    assert [r["url"] for r in check_urls(text)] == [
        "https://abc-jobs.example/apply", "www.portal.example",
        "http://jobs.example/x", "careers.example/form?id=3", "site.example"]


def test_balanced_parenthesis_in_path_is_kept():
    assert one("see http://wiki.example/page_(info) now")["url"] == \
        "http://wiki.example/page_(info)"


def test_duplicates_are_removed_case_and_punctuation_insensitive():
    text = ("Go to https://ABC-Jobs.Example/apply. Again: https://abc-jobs.example/apply! "
            "and abc-jobs.example/apply, then other.example")
    res = check_urls(text)
    assert [r["url"] for r in res] == ["https://ABC-Jobs.Example/apply", "other.example"]


def test_host_is_normalised():
    r = one("Login at HTTP://User@WWW.Portal.EXAMPLE.:8443/Path")
    assert r["host"] == "www.portal.example"
    assert r["url"] == "HTTP://User@WWW.Portal.EXAMPLE.:8443/Path"


def test_malformed_candidates_are_ignored():
    text = ("Write to hr@abc.example, e.g. tomorrow. Use v1.2.3 or 1.2.3.4 "
            "it ended.Next time try http:// or https://. i.e. no link; file.txt "
            "costs Rs.500.")
    assert check_urls(text) == []


def test_multiple_links_mixed_case():
    res = check_urls("A: HTTPS://One.Example B: two.EXAMPLE/x C: http://Three.example")
    assert [r["host"] for r in res] == ["one.example", "two.example", "three.example"]


def test_non_string_input_is_tolerated():
    assert check_urls(None) == []  # type: ignore[arg-type]


# ----------------------------------------------------- IP_HOST / AT_SYMBOL ----

@pytest.mark.parametrize("text,host", [
    ("http://198.51.100.7/pay", "198.51.100.7"),
    ("https://[2001:db8::1]:8080/x", "2001:db8::1"),
    ("send to 203.0.113.9/login now", "203.0.113.9"),
])
def test_ip_host_is_high(text, host):
    r = one(text)
    assert r["host"] == host
    assert "IP_HOST" in codes(r)
    assert r["risk"] == "high"


def test_at_symbol_userinfo_trick():
    r = one("Verify: http://abcholdings.example@evil.example/login")
    assert r["host"] == "evil.example"
    assert codes(r) == ["AT_SYMBOL"]
    assert r["risk"] == "medium"


def test_at_symbol_in_path_is_not_flagged():
    r = one("http://portal.example/profile/@sithum")
    assert "AT_SYMBOL" not in codes(r)


def test_ip_and_at_symbol_combined_order():
    r = one("http://login.example@198.51.100.7/")
    assert codes(r) == ["IP_HOST", "AT_SYMBOL"]
    assert r["risk"] == "high"


# ---------------------------------------------------------------- safety ----

def test_works_from_another_cwd():
    code = ("import sys, json; sys.path.insert(0, %r); "
            "from scamshield.links import check_urls; "
            "print(json.dumps(check_urls('http://198.51.100.7/x')))" % str(REPO_ROOT))
    out = subprocess.run([sys.executable, "-c", code], cwd="/tmp",
                         capture_output=True, text=True, timeout=60, check=True)
    assert json.loads(out.stdout)[0]["risk"] == "high"


def test_no_network_used(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    res = check_urls("http://abcholdings.example@evil.example/ and https://portal.example",
                     "ABC Holdings")
    assert len(res) == 2
