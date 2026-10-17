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
