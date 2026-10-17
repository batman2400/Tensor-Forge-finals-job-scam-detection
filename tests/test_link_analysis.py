"""Adapter tests. The disabled-path tests need no scikit-learn or artifact."""
import builtins
import copy
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scamshield import link_analysis  # noqa: E402
from scamshield.link_analysis import analyze_links  # noqa: E402
from scamshield.links import check_urls  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
TEXT = "Apply at https://abc-holdings-careers.xyz/apply or https://abcholdings.example/jobs"


def test_disabled_returns_rules_unchanged_and_empty_ml():
    out = analyze_links(TEXT, "ABC Holdings")
    assert out == {"links": check_urls(TEXT, "ABC Holdings"), "url_ml": []}


def test_disabled_does_not_import_ml(monkeypatch):
    sys.modules.pop("scamshield.url_ml", None)
    real = builtins.__import__

    def guard(name, *a, **k):
        if name.startswith(("sklearn", "joblib", "scamshield.url_ml")) and name != "scamshield.url_ml_preprocessing":
            raise AssertionError(f"imported {name} while disabled")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", guard)
    assert analyze_links(TEXT)["url_ml"] == []


def test_no_links_gives_two_empty_lists():
    assert analyze_links("no links here", enable_url_ml=True) == {"links": [], "url_ml": []}
    assert analyze_links("", enable_url_ml=True) == {"links": [], "url_ml": []}
    assert analyze_links(None) == {"links": [], "url_ml": []}


def test_check_urls_called_once(monkeypatch):
    calls = []
    real = link_analysis.check_urls

    def spy(*a, **k):
        calls.append(a)
        return real(*a, **k)

    monkeypatch.setattr(link_analysis, "check_urls", spy)
    analyze_links(TEXT, enable_url_ml=True, model_dir=REPO / "nonexistent_model_dir")
    assert len(calls) == 1


def test_enabled_missing_model_keeps_rules_and_marks_unavailable(tmp_path):
    expected = check_urls(TEXT, "ABC Holdings")
    out = analyze_links(TEXT, "ABC Holdings", enable_url_ml=True, model_dir=tmp_path)
    assert out["links"] == expected
    assert [m["url"] for m in out["url_ml"]] == [r["url"] for r in expected]
    st = [m["status"] for m in out["url_ml"]]
    assert st == ["unavailable", "not_evaluated"]  # .example is reserved
    assert all(m["phishing_score"] is None for m in out["url_ml"])
    assert [m["host"] for m in out["url_ml"]] == [r["host"] for r in expected]


def test_enabled_predict_crash_is_unavailable(monkeypatch, tmp_path):
    import scamshield.url_ml as um
    monkeypatch.setattr(um, "predict_urls", lambda *a, **k: 1 / 0)
    before = check_urls(TEXT)
    out = analyze_links(TEXT, enable_url_ml=True, model_dir=tmp_path)
    assert out["links"] == before
    assert [m["status"] for m in out["url_ml"]] == ["unavailable"] * 2
    assert all(m["phishing_score"] is None for m in out["url_ml"])


def test_rule_dicts_not_mutated(monkeypatch, tmp_path):
    out = analyze_links(TEXT, enable_url_ml=True, model_dir=tmp_path)
    snapshot = copy.deepcopy(out["links"])
    assert out["links"] == snapshot == check_urls(TEXT)
    assert all("phishing_score" not in r for r in out["links"])


def test_disabled_works_without_sklearn_in_subprocess(tmp_path):
    code = (
        "import sys; sys.modules['sklearn'] = None; sys.modules['joblib'] = None\n"
        "from scamshield.link_analysis import analyze_links\n"
        "r = analyze_links('see https://abc-holdings-careers.xyz/apply')\n"
        "assert r['url_ml'] == [] and len(r['links']) == 1\n"
        "r = analyze_links('see https://abc-holdings-careers.xyz/apply', enable_url_ml=True)\n"
        "assert r['url_ml'][0]['status'] == 'unavailable', r\n"
        "print('ok')\n"
    )
    env = {"PYTHONPATH": str(REPO), "SCAMSHIELD_URL_ML_DIR": str(tmp_path), "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, "-c", code], cwd=tmp_path, env=env,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "ok"


def test_enabled_corrupt_artifact_keeps_rules(tmp_path):
    (tmp_path / "url_model.joblib").write_bytes(b"not a model")
    (tmp_path / "url_model_meta.json").write_text("{broken", encoding="utf-8")
    from scamshield import url_ml
    url_ml._CACHE.clear()
    out = analyze_links(TEXT, enable_url_ml=True, model_dir=tmp_path)
    assert out["links"] == check_urls(TEXT)
    assert [m["status"] for m in out["url_ml"]] == ["unavailable", "not_evaluated"]
    assert all(m["phishing_score"] is None for m in out["url_ml"])


def test_multiple_links_one_to_one_in_order(tmp_path):
    text = ("1) https://abc-holdings-careers.xyz/apply 2) http://198.51.100.7/pay "
            "3) https://abcholdings.example/jobs 4) https://bit.ly/abc123 "
            "5) https://abc-holdings-careers.xyz/apply")
    rules = check_urls(text, "ABC Holdings")
    out = analyze_links(text, "ABC Holdings", enable_url_ml=True, model_dir=tmp_path)
    assert out["links"] == rules
    assert len(out["url_ml"]) == len(rules) >= 4
    assert [m["url"] for m in out["url_ml"]] == [r["url"] for r in rules]
    assert [m["host"] for m in out["url_ml"]] == [r["host"] for r in rules]
    assert all(m["status"] in ("unavailable", "not_evaluated") for m in out["url_ml"])
