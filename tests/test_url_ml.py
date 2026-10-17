"""URL ML tests. Run without the dataset (tiny synthetic fixtures). Tests that
need scikit-learn skip cleanly when it is not installed. Synthetic hosts are
made-up names that are never contacted (no network)."""
import json
import math
import socket
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scamshield import url_ml  # noqa: E402
from scamshield.url_ml_preprocessing import (  # noqa: E402
    PREPROCESSING_VERSION, UCI_TO_INTERNAL, prepare_url, registrable_domain,
)

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import prepare_url_data as prep_script  # noqa: E402


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    url_ml._CACHE.clear()
    yield
    url_ml._CACHE.clear()


# ---------------- stdlib-only tests ----------------

def test_uci_label_mapping():
    assert UCI_TO_INTERNAL == {1: 0, 0: 1}
    assert prep_script.map_label("1") == 0 and prep_script.map_label("0") == 1
    assert prep_script.map_label(" 0 ") == 1
    for bad in ("", "2", "x", None, "1.5"):
        assert prep_script.map_label(bad) is None


def test_preprocessing_deterministic_and_canonical():
    a = prepare_url("https://WWW.Shop-Alpha.com:443/Path?q=1")
    b = prepare_url("https://WWW.Shop-Alpha.com:443/Path?q=1")
    assert a == b and a["status"] == "ok"
    assert a["text"] == "shop-alpha.com:443"  # host-only policy, no scheme/www/path
    assert a["group"] == "shop-alpha.com"
    assert prepare_url("shop-alpha.com/x")["text"] == "shop-alpha.com"
    assert prepare_url("http://www.shop-alpha.com/")["text"] == "shop-alpha.com"
    assert prepare_url("https://www.com/")["text"] == "www.com"
    assert prepare_url("https://jobs.shop-alpha.com/")["text"] == "jobs.shop-alpha.com"
    assert prepare_url("https://shop-alpha.com/a")["text"] == prepare_url("https://SHOP-alpha.com/b?c=1")["text"]
    assert prepare_url("https://exämple.de/p")["host"] == "xn--exmple-cua.de"


@pytest.mark.parametrize("u,reason", [
    ("https://abcholdings.example/jobs", "reserved"),
    ("https://x.test/", "reserved"),
    ("https://www.example.com/", "reserved"),
    ("https://user:pw@shop-alpha.com/", "login"),
    ("https://shop-alpha.com/?mail=a@b.com", "e-mail"),
    ("https://shop-alpha.com/?token=abc", "token"),
    ("ftp://shop-alpha.com/", "scheme"),
    ("", "empty"),
    (None, "string"),
    (12345, "string"),
    ("two https://a-site.com https://b-site.com", "single"),
    ("https://" + "9" * 400 + ".1.1.1/", ""),
    ("https://shop-alpha.com:99999/", ""),
    ("https://" + "a" * 9000 + ".com/", "too long"),
])
def test_not_evaluated_cases_never_raise(u, reason):
    r = prepare_url(u)
    assert r["status"] == "not_evaluated" and r["text"] is None
    assert reason in r["reason"]


def test_registrable_domain_groups():
    assert registrable_domain("a.b.shop.co.uk") == "shop.co.uk"
    assert registrable_domain("login.shop.com") == "shop.com"
    assert registrable_domain("10.0.0.1") == "10.0.0.1"


def test_missing_model_is_unavailable_never_zero(tmp_path):
    out = url_ml.predict_urls(["https://shop-alpha.com/", "https://abc.example/"], model_dir=tmp_path)
    assert [r["status"] for r in out] == ["unavailable", "not_evaluated"]
    assert all(r["phishing_score"] is None and r["above_threshold"] is None for r in out)


def test_empty_and_bad_batches(tmp_path):
    assert url_ml.predict_urls([], model_dir=tmp_path) == []
    assert url_ml.predict_urls(None, model_dir=tmp_path) == []


def test_corrupt_metadata_unavailable(tmp_path):
    (tmp_path / url_ml.META_FILE).write_text("{not json")
    (tmp_path / url_ml.MODEL_FILE).write_bytes(b"garbage")
    r = url_ml.predict_urls(["https://shop-alpha.com/"], model_dir=tmp_path)[0]
    assert r["status"] == "unavailable" and "metadata" in r["reason"]


def test_split_groups_disjoint_and_dedup():
    rows = []
    for i in range(60):
        rows.append({"url": f"https://site{i}.com/p{i}", "label": i % 2})
    rows.append({"url": "https://site1.com/p1", "label": 1})        # dup, same label
    rows.append({"url": "https://SITE2.com/p2", "label": 1})        # canonical dup, contradictory
    prepared, stats = prep_script.audit_and_prepare(rows)
    assert stats["duplicates_dropped"] >= 1
    assert stats["contradictory_texts"] == 1
    assert stats["contradictory_rows_quarantined"] == 2
    texts = [r["text"] for r in prepared]
    assert len(texts) == len(set(texts))
    parts = prep_script.split_groups(prepared, seed=7, val_frac=0.15, test_frac=0.15)
    groups = {k: {r["group"] for r in v} for k, v in parts.items()}
    assert not (groups["train"] & groups["val"]) and not (groups["train"] & groups["test"])
    assert not (groups["val"] & groups["test"])
    assert sum(len(v) for v in parts.values()) == len(prepared)
    assert parts == prep_script.split_groups(prepared, seed=7, val_frac=0.15, test_frac=0.15)


def test_class_aware_sampling_keeps_proportions():
    rows = [{"text": f"t{i}", "group": f"g{i % 50}", "label": 1 if i < 430 else 0} for i in range(1000)]
    s = prep_script.sample_rows(rows, 200, seed=3)
    assert len(s) == 200
    pos = sum(r["label"] for r in s)
    assert 80 <= pos <= 92  # ~43%


# ---------------- scikit-learn tests ----------------

PHISH = ["http://secure-login-verify{i}.xyz/account/update?id={i}",
         "http://paypa1-confirm{i}.top/signin/verify",
         "http://{i}-bank-alert.click/login.php"]
LEGIT = ["https://www.shop{i}.com/products/item-{i}",
         "https://news{i}.org/articles/{i}/story",
         "https://blog{i}.net/posts/hello-world"]


def _fixture_rows(n=40):
    X, y = [], []
    for i in range(n):
        for t in PHISH:
            X.append(prepare_url(t.format(i=i))["text"]); y.append(1)
        for t in LEGIT:
            X.append(prepare_url(t.format(i=i))["text"]); y.append(0)
    return X, y


@pytest.fixture
def trained(tmp_path):
    pytest.importorskip("sklearn")
    pytest.importorskip("joblib")
    X, y = _fixture_rows()
    model = url_ml.build_pipeline(max_features=2 ** 12, min_df=1)
    model.fit(X, y)
    meta = url_ml.save_artifact(model, {"model_version": "test-1", "threshold": 0.5}, tmp_path)
    return tmp_path, model, meta, X


def test_probability_column_via_classes():
    assert url_ml.phishing_column([0, 1]) == 1
    assert url_ml.phishing_column([1, 0]) == 0
    with pytest.raises(url_ml.ModelUnavailable):
        url_ml.phishing_column([0, 2])


def test_scored_results_finite_ordered(trained):
    d, model, meta, X = trained
    urls = ["http://secure-login-verify99.xyz/account/update?id=99", "https://abc.example/x",
            "https://www.shop99.com/products/item-99", None, "https://user:pw@x-site.com/"]
    out = url_ml.predict_urls(urls, model_dir=d)
    assert [r["url"] for r in out] == urls
    assert [r["status"] for r in out] == ["scored", "not_evaluated", "scored", "not_evaluated", "not_evaluated"]
    s = [r["phishing_score"] for r in out if r["status"] == "scored"]
    assert all(isinstance(v, float) and math.isfinite(v) and 0 <= v <= 1 for v in s)
    assert s[0] > 0.5 > s[1]
    assert out[0]["above_threshold"] is True and out[0]["model_version"] == "test-1"
    assert out[2]["above_threshold"] is False


def test_export_load_equivalence(trained):
    d, model, meta, X = trained
    loaded = url_ml.load_model(d)
    col = list(model.classes_).index(1)
    a = model.predict_proba(X)[:, col]
    b = loaded["model"].predict_proba(X)[:, loaded["col"]]
    assert max(abs(x - y) for x, y in zip(a, b)) < 1e-9


def test_load_is_reused(trained, monkeypatch):
    d, *_ = trained
    first = url_ml.load_model(d)
    import joblib
    monkeypatch.setattr(joblib, "load", lambda *a, **k: 1 / 0)
    assert url_ml.load_model(d) is first
    url_ml.predict_urls(["https://www.shop1.com/"], model_dir=d)


@pytest.mark.parametrize("field,value", [
    ("preprocessing_version", "other"), ("schema_version", 99),
    ("class_mapping", {"legitimate": 1, "phishing": 0}), ("threshold", 3),
    ("model_sha256", "0" * 64),
])
def test_incompatible_metadata_unavailable(trained, field, value):
    d, *_ = trained
    p = d / url_ml.META_FILE
    meta = json.loads(p.read_text())
    meta[field] = value
    p.write_text(json.dumps(meta))
    r = url_ml.predict_urls(["https://www.shop1.com/"], model_dir=d)[0]
    assert r["status"] == "unavailable" and r["phishing_score"] is None


def test_sklearn_version_mismatch_unavailable(trained):
    d, *_ = trained
    p = d / url_ml.META_FILE
    meta = json.loads(p.read_text())
    meta["dependencies"]["scikit-learn"] = "0.1.0"
    p.write_text(json.dumps(meta))
    assert url_ml.predict_urls(["https://www.shop1.com/"], model_dir=d)[0]["status"] == "unavailable"


def test_corrupt_model_file_unavailable(trained):
    d, *_ = trained
    (d / url_ml.MODEL_FILE).write_bytes(b"not a model")
    meta = json.loads((d / url_ml.META_FILE).read_text())
    meta["model_sha256"] = url_ml._sha256(d / url_ml.MODEL_FILE)
    (d / url_ml.META_FILE).write_text(json.dumps(meta))
    r = url_ml.predict_urls(["https://www.shop1.com/"], model_dir=d)[0]
    assert r["status"] == "unavailable" and "unreadable" in r["reason"]


def test_scoring_failure_is_unavailable(trained, monkeypatch):
    d, *_ = trained
    b = url_ml.load_model(d)
    monkeypatch.setattr(b["model"], "predict_proba", lambda X: 1 / 0)
    out = url_ml.predict_urls(["https://www.shop1.com/", "https://abc.example/"], model_dir=d)
    assert [r["status"] for r in out] == ["unavailable", "not_evaluated"]
    assert all(r["phishing_score"] is None for r in out)


def test_metadata_records_versions(trained):
    _, _, meta, _ = trained
    assert meta["preprocessing_version"] == PREPROCESSING_VERSION
    assert meta["class_mapping"] == {"legitimate": 0, "phishing": 1}
    assert set(meta["dependencies"]) >= {"scikit-learn", "numpy", "scipy", "joblib"}


def test_adapter_end_to_end(trained):
    from scamshield.link_analysis import analyze_links
    from scamshield.links import check_urls
    d, *_ = trained
    text = "Apply http://secure-login-verify5.xyz/account/update?id=5 or https://abcholdings.example/jobs"
    out = analyze_links(text, "ABC Holdings", enable_url_ml=True, model_dir=d)
    assert out["links"] == check_urls(text, "ABC Holdings")
    assert [m["status"] for m in out["url_ml"]] == ["scored", "not_evaluated"]
