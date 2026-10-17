"""Compatibility of scamshield.links with origin/main's callers.

origin/main's scamshield/service.py::infer_claimed_company does
``from .links import official_domains`` and iterates
``sorted(official_domains(), key=len, reverse=True)`` matching names
case-insensitively in the chat. These tests pin that contract without
importing the conversation model. Synthetic .example domains only.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scamshield import links  # noqa: E402
from scamshield.links import check_urls, official_domains  # noqa: E402


def infer_claimed_company(text):
    """Verbatim copy of the lookup in origin/main scamshield/service.py (84f59f9)."""
    try:
        from scamshield.links import official_domains
    except Exception:
        return None
    lowered = text.lower()
    for name in sorted(official_domains(), key=len, reverse=True):
        if name.lower() in lowered:
            return name
    return None


@pytest.fixture
def mapping(monkeypatch, tmp_path):
    def use(data):
        p = tmp_path / "official_domains.json"
        p.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        monkeypatch.setattr(links, "OFFICIAL_DOMAINS_PATH", p)
        links.reload_official_domains()
        return p
    yield use
    monkeypatch.undo()
    links.reload_official_domains()


def test_official_domains_importable_and_exported():
    assert "official_domains" in links.__all__
    assert callable(official_domains)


def test_shipped_mapping_shape_matches_file():
    raw = json.loads((REPO_ROOT / "data" / "official_domains.json").read_text(encoding="utf-8"))
    got = official_domains()
    assert isinstance(got, dict) and got
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in got.items())
    assert got == {k: v.lower() for k, v in raw.items()}
    assert got["ABC Holdings"] == "abcholdings.example"


def test_returns_copy():
    a = official_domains()
    a["Injected"] = "evil.example"
    a.pop("ABC Holdings", None)
    assert "Injected" not in official_domains()
    assert "ABC Holdings" in official_domains()


def test_infer_claimed_company_pattern_works():
    assert infer_claimed_company("Hi, this is HR from abc holdings, apply today") == "ABC Holdings"
    assert infer_claimed_company("Welcome to Kandy Tech Solutions") == "Kandy Tech Solutions"
    assert infer_claimed_company("no company here") is None


def test_infer_prefers_longest_name(mapping):
    mapping({"Kandy Tech": "kandytech.example", "Kandy Tech Solutions": "kts.example"})
    assert infer_claimed_company("from Kandy Tech Solutions HR") == "Kandy Tech Solutions"


def test_names_as_written_and_canonical_domains(mapping):
    mapping({"  Serendib  Logistics ": "Serendib.EXAMPLE.", "Bad": 3, "": "x.example",
             "Ünicode Co": "bücher.example"})
    got = official_domains()
    assert got == {"  Serendib  Logistics ": "serendib.example",
                   "Ünicode Co": "xn--bcher-kva.example"}
    # check_urls still matches the normalised name form
    res = check_urls("https://serendib-pay.example/x", "serendib logistics")
    assert any(f["code"] == "CLAIMED_COMPANY_MISMATCH" for f in res[0]["flags"])


@pytest.mark.parametrize("data", ["{not json", "[1, 2]", "{}"])
def test_bad_or_empty_mapping_gives_empty_dict(mapping, data):
    mapping(data)
    assert official_domains() == {}
    assert not links.official_domains_available()
    assert infer_claimed_company("ABC Holdings") is None


def test_missing_file_and_reload(mapping, monkeypatch, tmp_path):
    monkeypatch.setattr(links, "OFFICIAL_DOMAINS_PATH", tmp_path / "missing.json")
    links.reload_official_domains()
    assert official_domains() == {}
    p = mapping({"Lanka Talent Partners": "lankatalent.example"})
    assert official_domains() == {"Lanka Talent Partners": "lankatalent.example"}
    p.write_text(json.dumps({"Other Co": "other.example"}), encoding="utf-8")
    assert "Lanka Talent Partners" in official_domains()  # cached until reload
    links.reload_official_domains()
    assert official_domains() == {"Other Co": "other.example"}


def test_check_urls_contract_unchanged():
    assert links.FLAG_CODES == (
        "IP_HOST", "AT_SYMBOL", "SHORTENER", "CHAT_REDIRECT", "APK_DOWNLOAD",
        "CLAIMED_COMPANY_MISMATCH", "LOOKALIKE", "BRAND_IN_SUBDOMAIN",
        "FREE_HOSTING_FORM", "PUNYCODE", "MANY_SUBDOMAINS")
    r = check_urls("see http://198.51.100.7/x", None)[0]
    assert set(r) == {"url", "host", "risk", "flags"} and r["risk"] == "high"


def test_subprocess_import_from_other_cwd(tmp_path):
    code = ("import sys; sys.path.insert(0, %r)\n"
            "from scamshield.links import official_domains\n"
            "print(sorted(official_domains())[0])" % str(REPO_ROOT))
    p = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, capture_output=True,
                       text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "ABC Holdings"
