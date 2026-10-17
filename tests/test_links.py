"""Tests for scamshield.links (all URLs are synthetic; nothing is opened).

Runs with ``python -m pytest tests/test_links.py`` from any directory.
"""

import contextlib
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

def test_works_from_another_cwd(tmp_path):
    code = ("import sys, json; sys.path.insert(0, %r); "
            "from scamshield.links import check_urls; "
            "print(json.dumps(check_urls('http://198.51.100.7/x')))" % str(REPO_ROOT))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path),
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


# ------------------------------------- SHORTENER / CHAT_REDIRECT / APK ----

@pytest.mark.parametrize("url", ["https://bit.ly/3xYzAbc", "tinyurl.com/abc123",
                                 "https://cutt.ly/jobLK", "t.co/abc", "rb.gy/x1",
                                 "https://shorturl.at/abc", "http://go.rebrand.ly/x"])
def test_shortener(url):
    r = one(f"Click {url} today")
    assert codes(r) == ["SHORTENER"]
    assert r["risk"] == "medium"


def test_shortener_requires_domain_boundary():
    r = one("https://notbit.ly/abc and nothing else")
    assert "SHORTENER" not in codes(r)
    r = one("https://bit.ly.evil.example/abc")
    assert "SHORTENER" not in codes(r)


@pytest.mark.parametrize("url", ["https://t.me/joinchat/AbCdEf", "wa.me/94770000000",
                                 "https://chat.whatsapp.com/InviteCode123",
                                 "https://api.whatsapp.com/send?phone=94770000000",
                                 "telegram.me/hr_desk"])
def test_chat_redirect(url):
    r = one(f"Join {url} for tasks")
    assert codes(r) == ["CHAT_REDIRECT"]


def test_chat_redirect_boundary():
    r = one("https://chat.whatsapp.com.evil.example/x")
    assert "CHAT_REDIRECT" not in codes(r)
    r = one("https://beat.me.example/x")
    assert "CHAT_REDIRECT" not in codes(r)


@pytest.mark.parametrize("url", ["https://files.example/TaskApp.APK",
                                 "https://files.example/get?file=earn.apk",
                                 "files.example/dl/app.apk?v=2#top"])
def test_apk_download(url):
    assert "APK_DOWNLOAD" in codes(one(url))


def test_apk_only_in_fragment_or_word_is_ignored():
    assert codes(one("https://files.example/apkinfo#x.apk")) == []


def test_two_flags_give_high_risk():
    r = one("Download https://bit.ly/earn.apk")
    assert codes(r) == ["SHORTENER", "APK_DOWNLOAD"]
    assert r["risk"] == "high"


# ------------------------------------------------ company-based checks ----

@pytest.fixture
def mapping_path(monkeypatch):
    """Point the module at another mapping file; restore cache afterwards."""
    def use(path):
        monkeypatch.setattr(links, "OFFICIAL_DOMAINS_PATH", Path(path))
        links._official_domains.cache_clear()
    yield use
    monkeypatch.undo()
    links._official_domains.cache_clear()


def test_mapping_file_is_fictional_example_domains():
    data = json.loads((REPO_ROOT / "data" / "official_domains.json").read_text())
    assert data and all(d.endswith(".example") for d in data.values())
    assert links.official_domains_available()


@pytest.mark.parametrize("url", ["https://abcholdings.example/careers",
                                 "https://careers.abcholdings.example/apply",
                                 "WWW.ABCHOLDINGS.EXAMPLE"])
def test_official_domain_and_genuine_subdomain_are_not_flagged(url):
    r = one(url, "  abc   HOLDINGS ")
    assert codes(r) == [] and r["risk"] == "low"


def test_claimed_company_mismatch_is_high():
    r = one("Pay the fee at https://abc-careers-pay.example/fee", "ABC Holdings")
    assert codes(r)[0] == "CLAIMED_COMPANY_MISMATCH"
    assert r["risk"] == "high"
    assert "abcholdings.example" in r["flags"][0]["reason"]


@pytest.mark.parametrize("url", ["https://abcholdings.example.evil.example/login",
                                 "https://notabcholdings.example/login",
                                 "https://abcholdingsexample.example/"])
def test_deceptive_boundaries_are_not_official(url):
    r = one(url, "ABC Holdings")
    assert "CLAIMED_COMPANY_MISMATCH" in codes(r)


def test_brand_in_subdomain_of_other_domain():
    r = one("https://abcholdings.example.evil.example/login")
    assert "BRAND_IN_SUBDOMAIN" in codes(r)
    r = one("https://abcholdings.careers-portal.example/")
    assert codes(r) == ["BRAND_IN_SUBDOMAIN"]


def test_brand_as_hyphen_token_and_squashed_name():
    assert codes(one("https://abcholdings-careers.example/")) == ["BRAND_IN_SUBDOMAIN"]
    assert "BRAND_IN_SUBDOMAIN" in codes(one("lankatalentpartners.jobs-desk.example/x"))
    assert "BRAND_IN_SUBDOMAIN" in codes(one("https://abcholdings.com.lk/"))


def test_brand_substring_in_registrable_label_is_not_brand_flag():
    # Documented limitation: only hyphen tokens / whole label are checked.
    assert "BRAND_IN_SUBDOMAIN" not in codes(one("https://notabcholdings.example/"))


@pytest.mark.parametrize("url,label", [("https://abcho1dings.example/apply", "abcho1dings"),
                                       ("https://kandytec.example/", "kandytec"),
                                       ("https://serendib-logistics.example/", "serendib-logistics"),
                                       ("https://lankatalent.com.lk/", None)])
def test_lookalike(url, label):
    r = one(url)
    if label is None:  # same label, different suffix: brand flag, distance 0
        assert "LOOKALIKE" not in codes(r) and "BRAND_IN_SUBDOMAIN" in codes(r)
    else:
        assert "LOOKALIKE" in codes(r)
        assert label in r["flags"][codes(r).index("LOOKALIKE")]["reason"]


def test_lookalike_ignores_suffix_only_and_short_labels():
    assert codes(one("https://random.example/")) == []
    assert codes(one("https://abcd.example/")) == []
    assert codes(one("https://zzzzzzzzzz.example/")) == []


def test_lookalike_plus_mismatch_order():
    r = one("Login https://abcho1dings.example/login", "ABC Holdings")
    assert codes(r) == ["CLAIMED_COMPANY_MISMATCH", "LOOKALIKE"]
    assert r["risk"] == "high"


def test_unknown_claimed_company_is_skipped():
    r = one("https://jobs-portal.example/apply", "Unknown Fictional Ltd")
    assert codes(r) == []


def test_levenshtein_implementation():
    assert links._levenshtein("abcholdings", "abcho1dings") == 1
    assert links._levenshtein("kitten", "sitting") == 3
    assert links._levenshtein("", "abc") == 3


def test_missing_mapping_skips_company_checks(mapping_path, tmp_path):
    mapping_path(tmp_path / "does_not_exist.json")
    assert not links.official_domains_available()
    r = one("https://abcho1dings.example.evil.example/x", "ABC Holdings")
    assert codes(r) == []
    assert r["risk"] == "low"


@pytest.mark.parametrize("content", ["{not json", "[1, 2, 3]", '{"ABC Holdings": 5}'])
def test_invalid_mapping_skips_company_checks(mapping_path, tmp_path, content):
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    mapping_path(bad)
    r = one("https://abcholdings-careers.example/", "ABC Holdings")
    assert codes(r) == []
    # non-company checks still work
    assert codes(one("https://bit.ly/x", "ABC Holdings")) == ["SHORTENER"]


def test_mapping_loaded_relative_to_module_from_other_cwd(tmp_path):
    code = ("import sys, json; sys.path.insert(0, %r); "
            "from scamshield.links import check_urls; "
            "print(json.dumps(check_urls('https://abc-pay.example/x', 'ABC Holdings')))"
            % str(REPO_ROOT))
    out = subprocess.run([sys.executable, "-c", code], cwd=str(tmp_path),
                         capture_output=True, text=True, timeout=60, check=True)
    res = json.loads(out.stdout)
    assert res[0]["flags"][0]["code"] == "CLAIMED_COMPANY_MISMATCH"


# ------------------------------ FREE_HOSTING_FORM / PUNYCODE / MANY_SUB ----

@pytest.mark.parametrize("url", ["https://abcjobs.wixsite.com/apply",
                                 "https://lk-jobs.blogspot.com/",
                                 "https://sites.google.com/view/jobs-lk",
                                 "https://forms.gle/AbC123",
                                 "https://docs.google.com/forms/d/e/xyz/viewform",
                                 "https://jobsdesk.netlify.app/",
                                 "https://hiring.github.io/",
                                 "https://form.jotform.com/123"])
def test_free_hosting_form(url):
    assert "FREE_HOSTING_FORM" in codes(one(url))


def test_google_docs_non_form_and_boundary_not_flagged():
    assert "FREE_HOSTING_FORM" not in codes(one("https://docs.google.com/document/d/x"))
    assert "FREE_HOSTING_FORM" not in codes(one("https://fakewixsite.com/x"))


def test_brand_on_free_hosting_gives_two_flags():
    r = one("https://abcholdings.github.io/careers")
    assert codes(r) == ["BRAND_IN_SUBDOMAIN", "FREE_HOSTING_FORM"]
    assert r["risk"] == "high"


def test_punycode_xn_label():
    r = one("https://xn--abchldings-abc.example/login")
    assert "PUNYCODE" in codes(r)


def test_non_ascii_host_is_punycode_and_lookalike():
    r = one("Visit https://\u0430bcholdings.example/login today")  # Cyrillic a
    assert r["host"] == "\u0430bcholdings.example"
    assert codes(r) == ["LOOKALIKE", "PUNYCODE"]
    assert "xn--" in r["flags"][1]["reason"]


def test_many_subdomains_threshold():
    assert "MANY_SUBDOMAINS" in codes(one("https://a.b.c.d.example/"))
    assert "MANY_SUBDOMAINS" not in codes(one("https://a.b.c.example/"))


def test_flag_order_is_fixed():
    r = one("http://abcholdings.login.verify.secure.portal.example@198.51.100.7/app.apk")
    assert codes(r) == ["IP_HOST", "AT_SYMBOL", "APK_DOWNLOAD"]
    r = one("https://abcholdings.secure.login.verify.abcho1dings.example/x", "ABC Holdings")
    assert codes(r) == ["CLAIMED_COMPANY_MISMATCH", "LOOKALIKE",
                        "BRAND_IN_SUBDOMAIN", "MANY_SUBDOMAINS"]
    order = list(links.FLAG_CODES)
    assert order == ["IP_HOST", "AT_SYMBOL", "SHORTENER", "CHAT_REDIRECT",
                     "APK_DOWNLOAD", "CLAIMED_COMPANY_MISMATCH", "LOOKALIKE",
                     "BRAND_IN_SUBDOMAIN", "FREE_HOSTING_FORM", "PUNYCODE",
                     "MANY_SUBDOMAINS"]


def test_all_risk_levels_in_one_message():
    text = ("Interview details: https://careers.abcholdings.example/slot . "
            "Chat: https://t.me/abc_hr_desk . Pay: http://198.51.100.7/fee")
    assert [r["risk"] for r in check_urls(text, "ABC Holdings")] == ["low", "high", "high"]
    assert [r["risk"] for r in check_urls(text)] == ["low", "medium", "high"]


def test_module_docstring_documents_every_flag():
    doc = links.__doc__
    assert "not" in doc and "safe" in doc
    for code in links.FLAG_CODES:
        assert code in doc


# ------------------------------------------- review regressions (fixes) ----

def test_backslash_ends_authority_real_host_is_before_it():
    r = one(r"https://evil.example\@abcholdings.example/login", "ABC Holdings")
    assert r["url"] == r"https://evil.example\@abcholdings.example/login"
    assert r["host"] == "evil.example"
    assert "CLAIMED_COMPANY_MISMATCH" in codes(r)
    assert "AT_SYMBOL" not in codes(r)
    assert r["risk"] == "high"
    assert all("'abcholdings.example' " not in f["reason"] for f in r["flags"])


def test_backslash_at_in_path_of_official_domain():
    r = one(r"https://abcholdings.example\@evil.example/login", "ABC Holdings")
    assert r["host"] == "abcholdings.example"
    assert "CLAIMED_COMPANY_MISMATCH" not in codes(r)
    assert "AT_SYMBOL" not in codes(r)


def test_plain_userinfo_trick_still_flagged():
    r = one("https://abcholdings.example@evil.example/login", "ABC Holdings")
    assert r["host"] == "evil.example"
    assert codes(r)[:2] == ["AT_SYMBOL", "CLAIMED_COMPANY_MISMATCH"]
    assert "'evil.example'" in r["flags"][0]["reason"]


def test_backslash_in_query_is_not_rewritten():
    r = one(r"https://portal.example/a\b?x=c\d#e\f")
    assert r["host"] == "portal.example"
    p = links._parse(r["url"], True)
    assert (p["path"], p["query"], p["fragment"]) == ("/a/b", r"x=c\d", r"e\f")


@pytest.mark.parametrize("url", ["http://2130706433/pay", "http://0x7f000001/pay",
                                 "http://0177.0.0.1/pay", "http://127.1/pay",
                                 "http://0x7F.0.0.0x1/pay", "http://127.0.0.1./pay"])
def test_numeric_ipv4_forms_are_canonicalised(url):
    r = one(url)
    assert r["url"] == url
    assert r["host"] == "127.0.0.1"
    assert "IP_HOST" in codes(r)
    assert r["risk"] == "high"


@pytest.mark.parametrize("url", ["http://4294967296/pay", "http://256.0.0.1/pay",
                                 "http://1.2.3.4.5/pay", "http://0x100000000/pay",
                                 "http://1.2.65536/pay", "http://08.0.0.1/pay",
                                 "http://abc.0x1/pay", "http://jobs.example.99/pay",
                                 "http://1..2/pay"])
def test_out_of_range_numeric_hosts_rejected_not_wrapped(url):
    assert check_urls(url) == []


def test_numeric_edges_and_company_names_unchanged():
    assert one("http://4294967295/x")["host"] == "255.255.255.255"
    assert one("http://1.16777215/x")["host"] == "1.255.255.255"
    r = one("https://abc123.example/x")
    assert r["host"] == "abc123.example" and codes(r) == []
    assert one("https://0xdeadbeef.example/x")["host"] == "0xdeadbeef.example"
    assert one("https://[2001:DB8::1]/x")["host"] == "2001:db8::1"


def test_bare_text_only_accepts_dotted_quads():
    assert check_urls("See section 1.2/3 and 127.1/x and v1.2.3") == []
    assert one("open 198.51.100.7/login")["host"] == "198.51.100.7"


def test_percent_encoded_host_is_decoded_for_checks():
    r = one("https://%65vil.example/login", "ABC Holdings")
    assert r["url"] == "https://%65vil.example/login"
    assert r["host"] == "evil.example"
    assert "CLAIMED_COMPANY_MISMATCH" in codes(r)
    assert r["risk"] == "high"


def test_percent_encoded_official_host_is_not_a_mismatch():
    r = one("https://%61%62%63holdings.EXAMPLE/careers", "ABC Holdings")
    assert r["host"] == "abcholdings.example"
    assert codes(r) == [] and r["risk"] == "low"
    r = one("https://careers.abcholding%73.example/", "ABC Holdings")
    assert r["host"] == "careers.abcholdings.example" and codes(r) == []


def test_percent_encoded_ip_host_gets_ip_flag():
    r = one("http://%31%32%37.0.0.1/pay")
    assert r["host"] == "127.0.0.1"
    assert "IP_HOST" in codes(r) and r["risk"] == "high"
    assert one("http://%32%31%33%30%37%30%36%34%33%33/x")["host"] == "127.0.0.1"


@pytest.mark.parametrize("url", ["https://%zzabcholdings.example/", "https://abcholdings%2.example/",
                                 "https://abcholdings%.example/", "https://%ff%fe.example/",
                                 "https://evil.example%40abcholdings.example/",
                                 "https://evil.example%2fabcholdings.example/",
                                 "https://abcholdings.example%3a80/",
                                 "https://%2561bcholdings.example/"])
def test_malformed_or_structure_changing_encodings_are_dropped(url):
    res = check_urls(url, "ABC Holdings")
    assert res == []  # never reported, so never "verified" as the company


def test_percent_encoded_unicode_host_still_punycode():
    r = one("https://%D0%B0bcholdings.example/login")  # Cyrillic a
    assert r["host"] == "\u0430bcholdings.example"
    assert codes(r) == ["LOOKALIKE", "PUNYCODE"]


@pytest.mark.parametrize("sep", [",", ";", ", ", ";\n"])
def test_punctuation_separated_urls_are_both_found(sep):
    res = check_urls(f"https://abcholdings.example{sep}https://198.51.100.7/pay")
    assert [r["url"] for r in res] == ["https://abcholdings.example",
                                       "https://198.51.100.7/pay"]
    assert res[0]["host"] == "abcholdings.example" and res[0]["risk"] == "low"
    assert res[1]["host"] == "198.51.100.7"
    assert "IP_HOST" in codes(res[1]) and res[1]["risk"] == "high"


def test_rejected_candidate_does_not_swallow_next_url():
    res = check_urls("http://bad_host!/x?u=https://198.51.100.7/pay")
    assert [r["host"] for r in res] == ["198.51.100.7"]
    res = check_urls("http://,https://bit.ly/x")
    assert [r["host"] for r in res] == ["bit.ly"]


def test_commas_semicolons_and_nested_url_in_query_are_kept():
    text = ("Go https://portal.example/a,b;c?x=1,2;y=3&next=https://other.example/z "
            "and (https://wiki.example/page_(info)), done.")
    assert [r["url"] for r in check_urls(text)] == [
        "https://portal.example/a,b;c?x=1,2;y=3&next=https://other.example/z",
        "https://wiki.example/page_(info)"]


@pytest.mark.parametrize("url", ["https://downloads.example/task%2Eapk",
                                 "https://downloads.example/get?file=task%2Eapk",
                                 "https://downloads.example/task%2eapk",
                                 "https://downloads.example/task.%61pk",
                                 "https://downloads.example/task%2E%41%50%4B",
                                 "https://downloads.example/get?f=task.%61%70%6b&v=2",
                                 "https://downloads.example/task.apk"])
def test_encoded_apk_filenames_are_flagged(url):
    r = one(url)
    assert codes(r) == ["APK_DOWNLOAD"]
    assert r["risk"] == "medium"


@pytest.mark.parametrize("url", ["https://downloads.example/page#task%2Eapk",
                                 "https://downloads.example/apkpure-guide",
                                 "https://downloads.example/task%2Eapkg",
                                 "https://downloads.example/task%252Eapk"])
def test_apk_fragment_word_and_double_encoding_not_flagged(url):
    assert codes(one(url)) == []


# ----------------------------------------- CHAT_REDIRECT path patterns ----

@pytest.mark.parametrize("url,kind", [
    ("https://wa.me/94770000000", "private WhatsApp chat"),
    ("https://wa.me/94770000000?text=Hi", "private WhatsApp chat"),
    ("https://wa.me/message/ABCDEFG1234", "private WhatsApp chat"),
    ("https://wa.me/qr/ABCDEFG1234", "private WhatsApp chat"),
    ("https://api.whatsapp.com/send?phone=94770000000&text=hi", "private WhatsApp chat"),
    ("https://web.whatsapp.com/send?phone=+94770000000", "private WhatsApp chat"),
    ("https://chat.whatsapp.com/AbCdEf123456", "join a private WhatsApp group"),
    ("https://chat.whatsapp.com/invite/AbCdEf123456", "join a private WhatsApp group"),
    ("https://www.whatsapp.com/channel/0029VaAbCdEf", "WhatsApp channel"),
    ("https://t.me/+AbCdEfGhIjK", "join a private Telegram group"),
    ("https://t.me/joinchat/AbCdEfGhIjK", "join a private Telegram group"),
    ("https://t.me/addlist/AbCdEf", "join a private Telegram group"),
    ("https://t.me/+94770000000", "private Telegram chat"),
    ("https://t.me/contact/AbCdEf123", "private Telegram chat"),
    ("https://t.me/hr_desk_lk", "Telegram account, group, channel or bot"),
    ("https://telegram.me/hr_desk_lk/42", "Telegram account, group, channel or bot"),
    ("https://telegram.dog/hr_desk_lk", "Telegram account, group, channel or bot"),
    ("https://hrdesklk.t.me/", "Telegram account, group, channel or bot"),
    ("https://t.me/s/lk_task_jobs", "Telegram account, group, channel or bot"),
])
def test_chat_redirect_patterns_and_wording(url, kind):
    r = one(url)
    assert codes(r) == ["CHAT_REDIRECT"]
    assert kind in r["flags"][0]["reason"]


@pytest.mark.parametrize("url", [
    "https://www.whatsapp.com/legal/privacy-policy", "https://whatsapp.com/download",
    "https://faq.whatsapp.com/5913398998672934", "https://www.whatsapp.com/",
    "https://wa.me/?text=Hello", "https://wa.me/", "https://api.whatsapp.com/send?text=hi",
    "https://chat.whatsapp.com/", "https://t.me/", "https://t.me/addstickers/CatPack",
    "https://t.me/share/url?url=https://portal.example", "https://t.me/proxy?server=x",
    "https://t.me/setlanguage/si", "https://t.me/abc", "https://www.t.me/",
    "https://blog.whatsapp.com/news", "https://business.whatsapp.com/products",
    "https://addstickers.t.me/", "https://wa.me.evil.example/94770000000",
    "https://t.me.evil.example/+AbCdEf", "https://notwa.me/94770000000",
])
def test_chat_service_information_pages_not_flagged(url):
    assert "CHAT_REDIRECT" not in codes(one(url))


# --------------------------------------------- proportionate wording ----

ALL_FLAG_SAMPLES = [
    ("http://198.51.100.7/x", None), ("http://a.example@b.example/", None),
    ("https://bit.ly/x", None), ("https://wa.me/94770000000", None),
    ("https://f.example/a.apk", None), ("https://abc-pay.example/", "ABC Holdings"),
    ("https://abcho1dings.example/", None), ("https://abcholdings.careers-portal.example/", None),
    ("https://forms.gle/x", None), ("https://xn--abchldings-abc.example/", None),
    ("https://\u0430bcholdings.example/", None), ("https://a.b.c.d.example/", None),
]


def test_reasons_never_claim_fraud_and_cover_every_flag():
    seen = set()
    for url, company in ALL_FLAG_SAMPLES:
        for f in one(url, company)["flags"]:
            seen.add(f["code"])
            low = f["reason"].lower()
            for banned in ("is a scam", "is fraud", "fraudulent", "is fake.", "definitely",
                           "proves"):
                assert banned not in low, (f["code"], f["reason"])
    assert seen == set(links.FLAG_CODES)


@pytest.mark.parametrize("url,word", [
    ("https://forms.gle/x", "genuine employers use these too"),
    ("https://xn--abchldings-abc.example/", "normal for non-english names"),
    ("https://\u0430bcholdings.example/", "normal for some local-language sites"),
    ("https://abcho1dings.example/", "can be a coincidence"),
    ("https://a.b.c.d.example/", "large legitimate sites also use"),
    ("https://bit.ly/x", "common in ordinary messages"),
])
def test_structural_flags_mention_legitimate_use(url, word):
    assert any(word in f["reason"].lower() for f in one(url)["flags"])


def test_mismatch_reason_is_a_comparison_not_an_accusation():
    reason = one("https://jobs-platform.example/abc", "ABC Holdings")["flags"][0]["reason"]
    assert "configured official domain is abcholdings.example" in reason
    assert "destination is the website jobs-platform.example" in reason
    assert "outside recruiting platforms or forms" in reason
    assert "does not prove" in reason
    ip_reason = one("http://198.51.100.7/x", "ABC Holdings")["flags"][1]["reason"]
    assert "the IP address 198.51.100.7" in ip_reason


def test_brand_and_many_subdomains_name_the_real_owner():
    r = one("https://abcholdings.careers-portal.example/")
    assert "'careers-portal.example'" in r["flags"][0]["reason"]
    assert "'abcholdings' (abcholdings.example)" in r["flags"][0]["reason"]
    r = one("https://a.b.c.d.example/")
    assert "'d.example'" in r["flags"][0]["reason"]


# ======================================================================
# Frozen synthetic evaluation set (Step 4). Expectations were reviewed by
# hand and describe the IDEAL output for each case. Cases marked
# known_gap=True are honest misses of the current rules: they stay in the
# set (xfail strict) and are counted in the evaluation report.
# Risk is not stored: it is derived from the expected flags with the team
# rule. This is a small hand-built set, NOT a measure of real-world
# scam-detection accuracy. Run the report with:
#     python tests/test_links.py --eval
# ======================================================================

IP, AT, SH, CH, APK = "IP_HOST", "AT_SYMBOL", "SHORTENER", "CHAT_REDIRECT", "APK_DOWNLOAD"
MIS, LOOK, BRAND = "CLAIMED_COMPANY_MISMATCH", "LOOKALIKE", "BRAND_IN_SUBDOMAIN"
FREE, PUNY, MANY = "FREE_HOSTING_FORM", "PUNYCODE", "MANY_SUBDOMAINS"
ABC = "ABC Holdings"

# (id, group, text, claimed_company, mapping, [(url, host, [flags])], why, known_gap)
EVAL_CASES = [
    # --- A: ordinary recruiting links / official domains -------------------
    ("A1", "official", "Interview link: https://careers.abcholdings.example/interview?id=7", ABC, None,
     [("https://careers.abcholdings.example/interview?id=7", "careers.abcholdings.example", [])],
     "genuine subdomain of the mapped official domain", False),
    ("A2", "official", "Apply at https://kandytech.example/careers/se-intern.", "Kandy Tech Solutions", None,
     [("https://kandytech.example/careers/se-intern", "kandytech.example", [])],
     "exact official domain; trailing full stop is not part of the URL", False),
    ("A3", "official", "Jobs: www.lankatalent.example/jobs", "lanka  talent PARTNERS", None,
     [("www.lankatalent.example/jobs", "www.lankatalent.example", [])],
     "www subdomain of official domain; company name case/space-insensitive", False),
    ("A4", "official", "See https://jobs.example/listing/42 for details", None, None,
     [("https://jobs.example/listing/42", "jobs.example", [])],
     "ordinary link without any indicator", False),
    ("A5", "official", "Our site is https://ABCHoldings.Example/ (official)", ABC, None,
     [("https://ABCHoldings.Example/", "abcholdings.example", [])],
     "mixed-case official host is normalised before comparison", False),
    # --- B: hosted forms, chat links, service information pages ----------
    ("B1", "forms-chat", "Fill https://forms.gle/AbCdEf123 to apply", None, None,
     [("https://forms.gle/AbCdEf123", "forms.gle", [FREE])],
     "hosted form: structural indicator even if the employer is genuine", False),
    ("B2", "forms-chat", "Form: https://docs.google.com/forms/d/e/1FAIpQ/viewform", None, None,
     [("https://docs.google.com/forms/d/e/1FAIpQ/viewform", "docs.google.com", [FREE])],
     "docs.google.com counts only under /forms", False),
    ("B3", "forms-chat", "Doc: https://docs.google.com/document/d/abc/edit", None, None,
     [("https://docs.google.com/document/d/abc/edit", "docs.google.com", [])],
     "ordinary document page is not a form", False),
    ("B4", "forms-chat", "Message HR on https://wa.me/94770000000", None, None,
     [("https://wa.me/94770000000", "wa.me", [CH])], "WhatsApp click-to-chat contact link", False),
    ("B5", "forms-chat", "Join https://chat.whatsapp.com/AbCdEf123456 now", None, None,
     [("https://chat.whatsapp.com/AbCdEf123456", "chat.whatsapp.com", [CH])], "WhatsApp group invite", False),
    ("B6", "forms-chat", "Telegram: https://t.me/+AbCdEfGhIjK", None, None,
     [("https://t.me/+AbCdEfGhIjK", "t.me", [CH])], "Telegram private invite", False),
    ("B7", "forms-chat", "Privacy: https://www.whatsapp.com/legal/privacy-policy", None, None,
     [("https://www.whatsapp.com/legal/privacy-policy", "www.whatsapp.com", [])],
     "service legal page does not open a chat", False),
    ("B8", "forms-chat", "Stickers https://t.me/addstickers/CatPack", None, None,
     [("https://t.me/addstickers/CatPack", "t.me", [])], "Telegram sticker link is not a chat", False),
    ("B9", "forms-chat", "Form https://forms.gle/AbCdEf123", "Ceylon Digital Careers", None,
     [("https://forms.gle/AbCdEf123", "forms.gle", [MIS, FREE])],
     "mapped company using a hosted form: mismatch by policy (no allowlist)", False),
    ("B10", "forms-chat", "https://ceylondigital.wixsite.com/careers", "Ceylon Digital Careers", None,
     [("https://ceylondigital.wixsite.com/careers", "ceylondigital.wixsite.com", [MIS, BRAND, FREE])],
     "brand on a free site builder", False),
    # --- C: brand names under other domains / near misses ----------------
    ("C1", "brand", "https://abcholdings.careers-portal.example/apply", None, None,
     [("https://abcholdings.careers-portal.example/apply", "abcholdings.careers-portal.example", [BRAND])],
     "brand as subdomain of unrelated domain", False),
    ("C2", "brand", "Register: https://abcholdings-careers.example/", ABC, None,
     [("https://abcholdings-careers.example/", "abcholdings-careers.example", [MIS, BRAND])],
     "brand as hyphen token", False),
    ("C3", "brand", "Login https://abcho1dings.example/login", None, None,
     [("https://abcho1dings.example/login", "abcho1dings.example", [LOOK])], "one-character look-alike", False),
    ("C4", "brand", "https://kandytec.example/jobs", "Kandy Tech Solutions", None,
     [("https://kandytec.example/jobs", "kandytec.example", [MIS, LOOK])], "look-alike plus claimed company", False),
    ("C5", "brand", "https://abcholdings.example.verify-login.example/", None, None,
     [("https://abcholdings.example.verify-login.example/", "abcholdings.example.verify-login.example", [BRAND])],
     "official domain used as a prefix of another domain", False),
    ("C6", "brand", "https://notabcholdings.example/", ABC, None,
     [("https://notabcholdings.example/", "notabcholdings.example", [MIS, BRAND])],
     "brand glued inside another label: mismatch fires, brand rule only matches hyphen tokens", True),
    ("C7", "brand", "https://abc-holdings-careers.example/", None, None,
     [("https://abc-holdings-careers.example/", "abc-holdings-careers.example", [BRAND])],
     "brand split by hyphens is not recognised", True),
    ("C8", "brand", "https://serendiblogistics.com.lk/", None, None,
     [("https://serendiblogistics.com.lk/", "serendiblogistics.com.lk", [BRAND])],
     "same brand label under a different suffix", False),
    ("C9", "brand", "lankatalentpartners.jobs-desk.example/x", None, None,
     [("lankatalentpartners.jobs-desk.example/x", "lankatalentpartners.jobs-desk.example", [BRAND])],
     "squashed company name in subdomain (bare link)", False),
    ("C10", "brand", "https://random-careers.example/", None, None,
     [("https://random-careers.example/", "random-careers.example", [])], "no false look-alike", False),
    # --- D: IP destinations ---------------------------------------------
    ("D1", "ip", "http://198.51.100.7/pay", None, None,
     [("http://198.51.100.7/pay", "198.51.100.7", [IP])], "dotted IPv4", False),
    ("D2", "ip", "http://2130706433/pay", None, None,
     [("http://2130706433/pay", "127.0.0.1", [IP])], "decimal integer IPv4", False),
    ("D3", "ip", "http://0x7f000001/pay", None, None,
     [("http://0x7f000001/pay", "127.0.0.1", [IP])], "hex IPv4", False),
    ("D4", "ip", "http://%31%32%37.0.0.1/x", None, None,
     [("http://%31%32%37.0.0.1/x", "127.0.0.1", [IP])], "percent-encoded IPv4", False),
    ("D5", "ip", "https://[2001:db8::1]/x", None, None,
     [("https://[2001:db8::1]/x", "2001:db8::1", [IP])], "bracketed IPv6", False),
    ("D6", "ip", "http://4294967296/pay", None, None, [], "out-of-range number is not a host", False),
    ("D7", "ip", "Version 1.2.3.4 released", None, None, [], "bare dotted number without path is a version", False),
    # --- E: encoding, unicode, authority ambiguity -----------------------
    ("E1", "encoded", "https://%65vil.example/login", ABC, None,
     [("https://%65vil.example/login", "evil.example", [MIS])], "encoded host decoded once", False),
    ("E2", "encoded", "https://%61bcholdings.example/", ABC, None,
     [("https://%61bcholdings.example/", "abcholdings.example", [])], "encoded official host", False),
    ("E3", "encoded", "https://downloads.example/task%2Eapk", None, None,
     [("https://downloads.example/task%2Eapk", "downloads.example", [APK])], "encoded dot in apk name", False),
    ("E4", "encoded", "https://downloads.example/get?file=task.%61pk", None, None,
     [("https://downloads.example/get?file=task.%61pk", "downloads.example", [APK])], "encoded letter in query", False),
    ("E5", "encoded", "https://downloads.example/page#task.apk", None, None,
     [("https://downloads.example/page#task.apk", "downloads.example", [])], "fragment is not downloaded", False),
    ("E6", "encoded", "https://xn--abchldings-abc.example/", None, None,
     [("https://xn--abchldings-abc.example/", "xn--abchldings-abc.example", [PUNY])], "punycode label", False),
    ("E7", "encoded", "https://\u0430bcholdings.example/", None, None,
     [("https://\u0430bcholdings.example/", "\u0430bcholdings.example", [LOOK, PUNY])],
     "Cyrillic letter imitating the brand", False),
    ("E8", "encoded", r"https://evil.example\@abcholdings.example/login", ABC, None,
     [(r"https://evil.example\@abcholdings.example/login", "evil.example", [MIS])],
     "backslash ends the authority", False),
    ("E9", "encoded", "https://abcholdings.example@evil.example/login", ABC, None,
     [("https://abcholdings.example@evil.example/login", "evil.example", [AT, MIS])], "userinfo trick", False),
    ("E10", "encoded", "http://login.example@198.51.100.7/", None, None,
     [("http://login.example@198.51.100.7/", "198.51.100.7", [IP, AT])], "userinfo + IP", False),
    ("E11", "encoded", "https://a.b.c.d.example/", None, None,
     [("https://a.b.c.d.example/", "a.b.c.d.example", [MANY])], "five labels", False),
    ("E12", "encoded", "https://downloads.example/task%252Eapk", None, None,
     [("https://downloads.example/task%252Eapk", "downloads.example", [])],
     "double encoding names a file 'task%2Eapk', not an .apk", False),
    # --- F: several links, punctuation, duplicates, malformed -------------
    ("F1", "text", "First https://bit.ly/3xYz then https://t.me/joinchat/AbCdEf and http://198.51.100.7/fee",
     None, None,
     [("https://bit.ly/3xYz", "bit.ly", [SH]), ("https://t.me/joinchat/AbCdEf", "t.me", [CH]),
      ("http://198.51.100.7/fee", "198.51.100.7", [IP])], "three links in order", False),
    ("F2", "text", "https://abcholdings.example,https://198.51.100.7/pay", None, None,
     [("https://abcholdings.example", "abcholdings.example", []), ("https://198.51.100.7/pay", "198.51.100.7", [IP])],
     "comma-glued links", False),
    ("F3", "text", "(see https://wiki.example/page_(info)), ok", None, None,
     [("https://wiki.example/page_(info)", "wiki.example", [])], "balanced parenthesis kept", False),
    ("F4", "text", "Go https://ABC-Jobs.Example/apply. Again https://abc-jobs.example/apply!", None, None,
     [("https://ABC-Jobs.Example/apply", "abc-jobs.example", [])], "duplicate removed", False),
    ("F5", "text", "Contact hr@abcholdings.example e.g. tomorrow; v1.2.3; end.Next; http://", None, None, [],
     "email, abbreviation, version, sentence fragment and empty scheme are not links", False),
    ("F6", "text", "Apply at abc-jobs.example/apply, or www.jobs-lk.example.", None, None,
     [("abc-jobs.example/apply", "abc-jobs.example", []), ("www.jobs-lk.example", "www.jobs-lk.example", [])],
     "bare and www links", False),
    ("F7", "text", "https://portal.example/a,b?x=1;y=2&next=https://other.example/z", None, None,
     [("https://portal.example/a,b?x=1;y=2&next=https://other.example/z", "portal.example", [])],
     "punctuation and nested URL inside one link", False),
    ("F8", "text", "Links: https://good.example|https://198.51.100.7/pay", None, None,
     [("https://good.example", "good.example", []), ("https://198.51.100.7/pay", "198.51.100.7", [IP])],
     "pipe-glued links: only the second is recovered", True),
    ("F9", "text", "Apply on careers.abcholdings.lk/apply", None, None,
     [("careers.abcholdings.lk/apply", "careers.abcholdings.lk", [BRAND])], "brand under another TLD", False),
    ("F10", "text", "", None, None, [], "empty text", False),
    ("F11", "text", "Pay here: bit.ly/3xYzAbc.", None, None,
     [("bit.ly/3xYzAbc", "bit.ly", [SH])], "bare shortener with trailing full stop", False),
    # --- G: unknown company / mapping unavailable -------------------------
    ("G1", "mapping", "https://jobs-portal.example/apply", "Unknown Fictional Ltd", None,
     [("https://jobs-portal.example/apply", "jobs-portal.example", [])], "unknown company is skipped", False),
    ("G2", "mapping", "https://abcho1dings.example/x", ABC, "missing",
     [("https://abcho1dings.example/x", "abcho1dings.example", [])], "missing mapping: company checks skipped", False),
    ("G3", "mapping", "https://abcholdings-careers.example/", ABC, "invalid",
     [("https://abcholdings-careers.example/", "abcholdings-careers.example", [])], "invalid mapping", False),
    ("G4", "mapping", "https://bit.ly/x", ABC, "missing",
     [("https://bit.ly/x", "bit.ly", [SH])], "other checks still run without mapping", False),
    ("G5", "mapping", "https://abcholdings.example/careers", "  abc   HOLDINGS ", None,
     [("https://abcholdings.example/careers", "abcholdings.example", [])], "whitespace/case in company name", False),
]


def _derived_risk(flags):
    if IP in flags or MIS in flags:
        return "high"
    return {0: "low", 1: "medium"}.get(len(set(flags)), "high")


@contextlib.contextmanager
def _mapping_mode(mode):
    if mode is None:
        yield
        return
    old = links.OFFICIAL_DOMAINS_PATH
    links.OFFICIAL_DOMAINS_PATH = (REPO_ROOT / "data" / "__missing_mapping__.json"
                                   if mode == "missing" else Path(__file__).resolve())
    links._official_domains.cache_clear()
    try:
        yield
    finally:
        links.OFFICIAL_DOMAINS_PATH = old
        links._official_domains.cache_clear()


def _run_case(case):
    _id, _g, text, company, mapping, _exp, _why, _gap = case
    with _mapping_mode(mapping):
        return check_urls(text, company)


@pytest.mark.parametrize("case", [
    pytest.param(c, id=c[0], marks=[pytest.mark.xfail(strict=True, reason="known gap: " + c[6])]
                 if c[7] else []) for c in EVAL_CASES])
def test_eval_case(case):
    expected = [{"url": u, "host": h, "risk": _derived_risk(f), "flags": f} for u, h, f in case[5]]
    actual = [{"url": r["url"], "host": r["host"], "risk": r["risk"], "flags": codes(r)}
              for r in _run_case(case)]
    assert actual == expected, case[6]


def evaluate(cases=EVAL_CASES):
    """Compute the evaluation report (extraction, hosts, flags, contract)."""
    ext = {"expected": 0, "found": 0, "missed": 0, "spurious": 0}
    hosts = {"compared": 0, "correct": 0}
    per_flag = {c: {"tp": 0, "fp": 0, "fn": 0} for c in links.FLAG_CODES}
    risk = {"compared": 0, "correct": 0}
    exact, wrong = 0, []
    contract = {"json_roundtrip": True, "deterministic": True, "schema": True,
                "flag_order": True, "no_duplicates": True}
    order = {c: i for i, c in enumerate(links.FLAG_CODES)}
    for case in cases:
        res = _run_case(case)
        res2 = _run_case(case)
        contract["deterministic"] &= res == res2
        contract["json_roundtrip"] &= json.loads(json.dumps(res)) == res
        for r in res:
            contract["schema"] &= (set(r) == {"url", "host", "risk", "flags"}
                                   and r["risk"] in ("low", "medium", "high")
                                   and all(set(f) == {"code", "reason"} for f in r["flags"]))
            idx = [order[c] for c in codes(r)]
            contract["flag_order"] &= idx == sorted(set(idx))
        contract["no_duplicates"] &= len({r["url"].lower() for r in res}) == len(res)
        exp = {u: (h, f) for u, h, f in case[5]}
        act = {r["url"]: r for r in res}
        ext["expected"] += len(exp)
        ext["found"] += len(exp.keys() & act.keys())
        ext["missed"] += len(exp.keys() - act.keys())
        ext["spurious"] += len(act.keys() - exp.keys())
        for u, (h, f) in exp.items():
            got = set(codes(act[u])) if u in act else set()
            if u in act:
                hosts["compared"] += 1
                hosts["correct"] += act[u]["host"] == h
                risk["compared"] += 1
                risk["correct"] += act[u]["risk"] == _derived_risk(f)
            for c in links.FLAG_CODES:
                per_flag[c]["tp"] += c in f and c in got
                per_flag[c]["fn"] += c in f and c not in got
                per_flag[c]["fp"] += c not in f and c in got
        for u in act.keys() - exp.keys():
            for c in codes(act[u]):
                per_flag[c]["fp"] += 1
        ok = [(r["url"], r["host"], codes(r)) for r in res] == [(u, h, f) for u, h, f in case[5]]
        exact += ok
        if not ok:
            wrong.append(case[0])
    errors = 0
    for bad in (None, 123, b"http://x.example", "\x00" * 10, "http://" * 500, "(" * 1000 + "a.example"):
        try:
            check_urls(bad)  # type: ignore[arg-type]
        except Exception:  # noqa: BLE001
            errors += 1
    contract["no_exceptions_on_odd_input"] = errors == 0
    for c, v in per_flag.items():
        v["precision"] = round(v["tp"] / (v["tp"] + v["fp"]), 3) if v["tp"] + v["fp"] else None
        v["recall"] = round(v["tp"] / (v["tp"] + v["fn"]), 3) if v["tp"] + v["fn"] else None
    return {"cases": len(cases), "exact_correct": exact, "incorrect_cases": wrong,
            "known_gaps": [c[0] for c in cases if c[7]], "extraction": ext, "hosts": hosts,
            "risk": risk, "per_flag": per_flag, "contract": contract}


def test_eval_report_is_consistent():
    rep = evaluate()
    print(json.dumps(rep, indent=1))
    assert 40 <= rep["cases"] <= 60
    assert sorted(rep["incorrect_cases"]) == sorted(rep["known_gaps"])
    assert all(rep["contract"].values()), rep["contract"]


if __name__ == "__main__" and "--eval" in sys.argv:
    print(json.dumps(evaluate(), indent=1))


# ------------------------------------ mapping availability (Step 5) ----

def test_availability_helper_tracks_load_state_and_recovery(mapping_path, tmp_path):
    good = tmp_path / "good.json"
    good.write_text('{"ABC Holdings": "abcholdings.example"}')
    mapping_path(tmp_path / "missing.json")
    assert links.official_domains_available() is False
    # cached failure: creating the file is not seen until reload
    (tmp_path / "missing.json").write_text(good.read_text())
    assert links.official_domains_available() is False
    assert links.reload_official_domains() is True
    assert "CLAIMED_COMPANY_MISMATCH" in codes(one("https://x.example/", "ABC Holdings"))


def test_availability_helper_with_partially_and_fully_invalid_entries(mapping_path, tmp_path):
    part = tmp_path / "part.json"
    part.write_text('{"ABC Holdings": "abcholdings.example", "Bad": 5, "": "x.example", "N": "no dots"}')
    mapping_path(part)
    assert links.official_domains_available() is True
    assert links._official_domains() == (("abc holdings", "abcholdings", "abcholdings.example"),)
    bad = tmp_path / "bad.json"
    bad.write_text('{"Bad": 5, "Also bad": ["x.example"]}')
    mapping_path(bad)
    assert links.official_domains_available() is False


def test_edited_mapping_needs_reload(mapping_path, tmp_path):
    f = tmp_path / "m.json"
    f.write_text('{"ABC Holdings": "abcholdings.example"}')
    mapping_path(f)
    assert codes(one("https://new-abc.example/", "ABC Holdings")) == ["CLAIMED_COMPANY_MISMATCH"]
    f.write_text('{"ABC Holdings": "new-abc.example"}')
    assert codes(one("https://new-abc.example/", "ABC Holdings")) == ["CLAIMED_COMPANY_MISMATCH"]
    links.reload_official_domains()
    assert codes(one("https://new-abc.example/", "ABC Holdings")) == []


def test_output_shape_identical_when_mapping_unavailable(mapping_path, tmp_path):
    text = "https://abcholdings-careers.example/ and https://bit.ly/x"
    with_map = check_urls(text, "ABC Holdings")
    mapping_path(tmp_path / "none.json")
    without = check_urls(text, "ABC Holdings")
    assert [set(r) for r in with_map] == [set(r) for r in without]
    assert [r["url"] for r in with_map] == [r["url"] for r in without]
    assert codes(without[0]) == [] and codes(with_map[0]) != []


# ------------------------------------------- Step 6 optimisation checks ----

def test_bounded_levenshtein_matches_full_computation():
    import random
    rng = random.Random(7)
    for _ in range(3000):
        a = "".join(rng.choice("abch1o-") for _ in range(rng.randint(0, 12)))
        b = "".join(rng.choice("abch1o-") for _ in range(rng.randint(0, 12)))
        full = links._levenshtein(a, b)
        assert links._levenshtein(a, b, 2) == (full if full <= 2 else 3)


def test_precomputed_index_follows_mapping_reload(mapping_path, tmp_path):
    f = tmp_path / "m.json"
    f.write_text('{"Galle Fort Careers": "gallefort.example"}')
    mapping_path(f)
    assert "LOOKALIKE" in codes(one("https://ga1lefort.example/"))
    assert "BRAND_IN_SUBDOMAIN" in codes(one("https://gallefortcareers.jobs.example/"))
    assert "LOOKALIKE" not in codes(one("https://abcho1dings.example/"))
    links.reload_official_domains()
    f.write_text('{"ABC Holdings": "abcholdings.example"}')
    links.reload_official_domains()
    assert "LOOKALIKE" in codes(one("https://abcho1dings.example/"))
    assert "LOOKALIKE" not in codes(one("https://ga1lefort.example/"))


# ------------------------------------------ demo cases (Step 7, synthetic) ----

DEMO_CASES = [
    ("DEMO-1 official subdomain",
     "Hi Nimal, your ABC Holdings interview is confirmed: "
     "https://careers.abcholdings.example/interview?slot=0930", ABC,
     "careers.abcholdings.example", []),
    ("DEMO-2 brand under another domain",
     "ABC Holdings HR: finish registration at "
     "https://abcholdings.careers-portal.example/register to unlock paid tasks", ABC,
     "abcholdings.careers-portal.example", [MIS, BRAND]),
    ("DEMO-3 disguised destination",
     "Withdraw your earnings now: http://abcholdings.example@0xC6336407/payout", ABC,
     "198.51.100.7", [IP, AT, MIS]),
]


@pytest.mark.parametrize("name,text,company,host,flags", DEMO_CASES, ids=[d[0] for d in DEMO_CASES])
def test_demo_cases(name, text, company, host, flags):
    r = one(text, company)
    assert r["host"] == host and codes(r) == flags
    assert r["risk"] == _derived_risk(flags)


# ------------------------------- round 3: bounded numeric IPv4 (Fix 1) ----

@pytest.mark.parametrize("host", [
    "1" * 5000, "0x" + "f" * 5000, "0" + "7" * 5000, "9" * 11, "0x1" + "0" * 8,
    "0" + "4" * 12, "4294967296", "0x100000000", "040000000000", "1." + "1" * 5000,
    "1.2.3." + "9" * 400, "0x" + "1" * 9 + ".0.0.1",
])
def test_oversized_numeric_hosts_rejected_without_error(host):
    assert check_urls(f"http://{host}/pay") == []


def test_reviewer_reproducer_and_following_link_still_found():
    assert check_urls("http://" + "1" * 5000 + "/pay") == []
    res = check_urls("http://" + "1" * 5000 + "/pay and then https://abc-jobs.example/apply "
                     "and http://198.51.100.7/x", ABC)
    assert [r["host"] for r in res] == ["abc-jobs.example", "198.51.100.7"]
    assert codes(res[1])[0] == "IP_HOST"


@pytest.mark.parametrize("host,canon", [
    ("4294967295", "255.255.255.255"), ("0xffffffff", "255.255.255.255"),
    ("037777777777", "255.255.255.255"), ("0" * 300 + "17700000001", "127.0.0.1"),
    ("0x" + "0" * 300 + "7f000001", "127.0.0.1"), ("0" * 50 + "2130706433", "17.99.141.27"),
    ("0" * 50 + "77777777777", None),
    ("000127.0.0.1", "87.0.0.1"), ("127.0.0.1", "127.0.0.1"), ("127.1", "127.0.0.1"),
])
def test_numeric_boundaries_and_leading_zeros(host, canon):
    res = check_urls(f"http://{host}/x")
    if canon is None:  # octal value above 32 bits: rejected, not wrapped
        assert res == []
    else:
        assert res[0]["host"] == canon and "IP_HOST" in codes(res[0])
