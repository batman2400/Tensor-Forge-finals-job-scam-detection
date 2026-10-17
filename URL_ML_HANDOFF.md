# URL ML + links workflow: handoff for the main developer

Branch `url-ml`. Reviewed against `origin/main` at `84f59f9` (fetched 2026-10-17 ~12:42 Asia/Colombo). All line numbers below were read from that commit. Re-check them if `main` has moved.

## 1. Branch and reviewed base

- **Branch:** `url-ml`. Code and tests are final at `8eca595`; the commit that adds this file revision is the branch HEAD (see `git log origin/url-ml -1`).
- **History:**
  - `url-ml` was branched from `links` at `f9c7961`. It does **not** contain any `main` commits after `2b914af`.
  - The merge base with `origin/main` is `2b914af`.
  - `main`'s `563ab75`, `e8ae0ca` and `84f59f9` are not in `url-ml`. `84f59f9` ("Add the full link checker with the agreed risk rule") holds `main`'s own copy of `links.py`: `f9c7961` plus `official_domains()` plus a changed risk rule.
- **`url-ml` commits on top of `f9c7961`:**

| Commit | Content |
|---|---|
| `3426dd0` | Preprocessing, inference module, `analyze_links` adapter, data-prep script, tests |
| `56f5087` | Training script |
| `238c2da` | First handoff |
| `004633d` | Preprocessing `urlml-pre-2` (host only) + tests |
| `4c67300` | `official_domains()` compatibility fix + `tests/test_links_compat.py` |
| `8eca595` | Test hardening (import check, adapter corrupt-artifact/multi-link tests) |

- **Trial merge** (done locally in a throwaway worktree, branch `trial-merge-urlml`; **not pushed**): `git merge --no-ff --no-commit url-ml` on top of `origin/main` 84f59f9. **It is not a clean merge.** There are 3 add/add conflicts, because both sides added these files independently after `2b914af`:
  1. `data/official_domains.json`: `main` adds three companies (`Lakview Solutions`, `Bright Path Careers`, `Ceyfin`). **Resolve: take main's version** (`git checkout --ours data/official_domains.json` while on main).
  2. `scamshield/links.py`: the only real differences are main's agreed risk rule (`STRONG_FLAGS`, `_risk` accepting flag dicts, risk docstring) and url-ml's extra `"official_domains"` in `__all__`. The `official_domains()` code is byte-identical on both sides. **Resolve: take main's version** (`git checkout --ours scamshield/links.py`). Optionally add `"official_domains"` to `__all__` by hand; no test needs it.
  3. `tests/test_links.py`: main's version tests main's risk rule. **Resolve: take main's version** (`git checkout --ours tests/test_links.py`).

  All other url-ml files are new and merge without conflict: `scamshield/url_ml.py`, `scamshield/url_ml_preprocessing.py`, `scamshield/link_analysis.py`, `scripts/prepare_url_data.py`, `scripts/train_url_model.py`, `tests/test_url_ml.py`, `tests/test_link_analysis.py`, `tests/test_links_compat.py`, `requirements-url-ml.txt` and this file.
- **Merged tree after the 3 resolutions:**
  - Environment: `uv sync --frozen` from main's `uv.lock`, Python 3.12.15 (scikit-learn 1.9.1, numpy 2.5.4, scipy 1.18.1, joblib 1.6.0), plus `pytest`, which main's lock does not include.
  - `python -m pytest -q -p no:cacheprovider tests`, run from the repo root and from `/tmp`: **386 passed, 3 xfailed** both times.
  - `origin/main` alone in the same environment: **328 passed, 3 xfailed**.
  - On the merged tree I also checked:
    - The real `service.infer_claimed_company("HR from ABC Holdings here")` returns `"ABC Holdings"`, and `"Ceyfin team"` returns `"Ceyfin"`.
    - FastAPI `TestClient` `POST /links` returned 200 with the unchanged list shape, even though no conversation model was present.
    - `analyze_links(..., enable_url_ml=True)` gave `unavailable` with no artifact, and `scored` with `SCAMSHIELD_URL_ML_DIR` pointing at the delivered artifact.

## 2. What is complete in the links branch

| File | What it provides |
|---|---|
| `scamshield/links.py` | Rules checker (`check_urls`, unchanged contract) + `official_domains()` (section 3) |
| `scamshield/link_analysis.py` | `analyze_links(text, claimed_company=None, *, enable_url_ml=False, model_dir=None) -> dict` |
| `scamshield/url_ml.py` | `predict_urls(urls, *, model_dir=None)`, `load_model`, `reload_model`, `model_available`, `default_model_dir`; training helpers `build_pipeline`, `save_artifact` |
| `scamshield/url_ml_preprocessing.py` | Stdlib-only preprocessing `urlml-pre-2`, privacy/reserved-domain filter, UCI label mapping |
| `scripts/prepare_url_data.py`, `scripts/train_url_model.py` | Rebuild data splits and model (data lives outside git) |
| `tests/test_url_ml.py`, `tests/test_link_analysis.py`, `tests/test_links_compat.py` | 58 tests using synthetic data, no network, no dataset |
| `requirements-url-ml.txt` | scikit-learn==1.9.1, numpy==2.5.4, scipy==1.18.1, joblib==1.6.0, threadpoolctl==3.7.0 |

**`analyze_links` behaviour** (each point is covered by tests in `tests/test_link_analysis.py`):
- Calls `check_urls(text, claimed_company)` **once** and returns that list unchanged as `"links"`.
- `"url_ml"` is `[]` when disabled (the default). In that case it does not import scikit-learn, joblib or `scamshield.url_ml`, and needs no artifact (tested in a subprocess with sklearn blocked).
- No links gives `{"links": [], "url_ml": []}`.
- When enabled, `"url_ml"` has exactly one entry per link, in the same order, carrying the same `url` and canonical `host`. This holds for multiple links (the rules de-duplicate repeated URLs first).
- A missing, corrupt or incompatible artifact gives per-URL `unavailable` with `phishing_score: null`; the rule results are unchanged.
- If `predict_urls` itself raises, every entry becomes `unavailable` and the rules are kept.
- It never changes rule risk, flags, conversation verdict, review routing, drift or training. There is no score fusion.

Example (`enable_url_ml=True`, shipped artifact):
```json
{"links": [
   {"url": "https://abc-pay.example/x", "host": "abc-pay.example", "risk": "high", "flags": [{"code": "CLAIMED_COMPANY_MISMATCH", "reason": "..."}]},
   {"url": "http://secure-login-verify.top", "host": "secure-login-verify.top", "risk": "low", "flags": []}],
 "url_ml": [
   {"url": "https://abc-pay.example/x", "host": "abc-pay.example", "status": "not_evaluated", "phishing_score": null, "above_threshold": null, "model_version": "urlml-lr-char35-168566-202610171216", "reason": "reserved demo domain (not evaluated)"},
   {"url": "http://secure-login-verify.top", "host": "secure-login-verify.top", "status": "scored", "phishing_score": 0.999749, "above_threshold": true, "model_version": "urlml-lr-char35-168566-202610171216", "reason": "URL text resembles phishing URLs in the training data"}]}
```
(The exact `risk` value depends on which `links.py` risk rule is in the tree; see section 1.)

**Status values:**
- `scored`: score in [0,1]. `above_threshold` uses the validation-chosen threshold 0.626499.
- `unavailable`: no artifact, corrupt or mismatched metadata, checksum mismatch, scikit-learn major.minor ≠ 1.9, or a scoring error.
- `not_evaluated`: one of the following.
  - Reserved demo domains (`.example`, `.test`, `.invalid`, `.localhost`, `.local`, `example.com/net/org`); this covers **all of the team's demo links**.
  - Login details before `@`, an e-mail address, or token-like query parameters.
  - Non-http(s) input, empty input or a non-string, invalid ports or hosts, or more than 1,000 URLs per batch.

**Tests on `url-ml` at `8eca595`** (`python -m pytest -q -p no:cacheprovider tests`, from the repo root and from `/tmp`, same counts both times):

| Environment | Result |
|---|---|
| Python 3.13.5 with `requirements-url-ml.txt` | 370 passed, 3 xfailed |
| Python 3.12.15 with the same pins | 370 passed, 3 xfailed |
| Python 3.13.5 without scikit-learn | 357 passed, 13 skipped (the sklearn-only tests), 3 xfailed |

- `tests/test_links.py tests/test_links_compat.py`: 324 passed, 3 xfailed.
- `tests/test_url_ml.py tests/test_link_analysis.py`: 46 passed.

**Model:** char TF-IDF (3-5) followed by logistic regression, using the host name only (scheme, `www.` and path are dropped because of a PhiUSIIL artefact). It was trained on 168,566 domain-grouped UCI PhiUSIIL rows (CC BY 4.0, zip sha256 `0a639fd0…c9a59a`). Results on the untouched test set (27,479 rows) at threshold 0.6265, which was chosen on validation as the lowest threshold with precision ≥ 0.95:

| Precision | Recall | F1 | False-positive rate | PR-AUC |
|---|---|---|---|---|
| 0.961 (6,769/7,042) | 0.479 (6,769/14,140) | 0.639 | 0.0205 (273/13,339) | 0.911 |

**Limitations:**
- It is a weak hint. Legitimate hosts with subdomains or unusual TLDs can score high (e.g. careers or form-hosting subdomains).
- Phishing that sits in the path of a trusted site is not visible to the model.
- The data is general phishing, not Sri Lankan job scams.
- Domain grouping uses a small built-in suffix list.

## 3. Compatibility fix: `official_domains()`

- **The problem:** `main`'s `scamshield/service.py` (`infer_claimed_company`, lines 12-22) runs `from .links import official_domains` inside `try/except Exception: return None`, then `for name in sorted(official_domains(), key=len, reverse=True): if name.lower() in lowered: return name`. `url-ml`'s `links.py` (from `f9c7961`) had no `official_domains`, so after a merge that kept url-ml's module, company inference would have silently returned `None`, disabling the company-mismatch input.
- **The fix** (`4c67300`): `url-ml`'s `links.py` now has main's exact `official_domains()` implementation (the same code as in `84f59f9`).
  - It returns a **new `dict[str, str]`** each call: company name exactly as written in `data/official_domains.json` → canonical lower-case ASCII/xn-- domain.
  - Invalid entries (non-string, empty name, invalid domain) are skipped.
  - A missing, invalid or non-object file gives `{}`.
  - The result uses the same `lru_cache` as `check_urls`. `reload_official_domains()` refreshes it, and `official_domains_available()` is unchanged.
  - `check_urls` output fields, flag order and url-ml's risk rule are unchanged.
- **Evidence** (`tests/test_links_compat.py`, 12 tests):
  - The function imports by name.
  - Its output equals the shipped file (names → lower-case domains).
  - It returns a copy.
  - A verbatim copy of main's `infer_claimed_company` loop finds "ABC Holdings" and "Kandy Tech Solutions", prefers the longest name, and returns `None` for bad, empty or missing files.
  - Names keep their as-written form, and Unicode domains become xn--.
  - Reload picks up file changes.
  - The `check_urls` contract is pinned.
  - A subprocess import from another directory works.
  - On the merged tree, the **real** `service.infer_claimed_company` was exercised (section 1).
- **Other callers checked on `main`:**
  - `scamshield/service.py`: `official_domains`, `check_urls`.
  - `scamshield/api.py`: reaches links only through `service.safe_check_urls` / `infer_claimed_company`.
  - `tests/test_guards.py`: `from scamshield.links import _risk, check_urls`. It expects main's risk rule: `_risk` accepts flag dicts, and SHORTENER + CHAT_REDIRECT gives `"medium"`.
  - `tests/test_links.py` (main's version).
  - `ui/app.py` uses only the API response.

  `test_guards.py` passes only with main's `links.py`. That is why section 1 says to take main's `links.py` in the merge.

## 4. Exact teammate edits after merge (owned by the main developer, not done on this branch)

**`scamshield/config.py`.** Insert after line 34 (`ENABLE_LINK_CHECK = ...`):
```python
ENABLE_URL_ML = os.getenv("ENABLE_URL_ML", "false").lower() == "true"
URL_ML_DIR = Path(os.getenv("URL_ML_DIR", ARTIFACT_DIR / "url_ml"))
```
- `ENABLE_URL_ML` is independent of `ENABLE_LINK_CHECK`. `ARTIFACT_DIR` is defined at line 12.
- Without `model_dir`, `url_ml` falls back to env `SCAMSHIELD_URL_ML_DIR`, then to `<repo>/artifacts/url_ml`. Passing `config.URL_ML_DIR` explicitly is preferred.

**`scamshield/service.py`.** No change is needed for compatibility. Leave `infer_claimed_company` (12-22), `safe_check_urls` (25-35) and `Analyzer.analyze` (verdict, `risky_links` at line 66, review, drift, `result["links"]` at line 103) as they are. Wire `url_ml` into `/analyze` only if the team explicitly wants it; the links page does not need it.

**`scamshield/api.py`.**
- Keep `POST /links` (lines 59-65) unchanged.
- Add an import, `from .link_analysis import analyze_links`, next to line 9.
- Add after line 65:
```python
@app.post("/links/analyze")
def links_analyze(req: AnalyzeRequest):
    if not config.ENABLE_LINK_CHECK:
        raise HTTPException(503, "Link checker disabled")
    company = req.claimed_company or infer_claimed_company(req.text)
    result = analyze_links(req.text, company, enable_url_ml=config.ENABLE_URL_ML,
                           model_dir=config.URL_ML_DIR)
    return {"claimed_company": company, "url_ml_enabled": config.ENABLE_URL_ML, **result}
```
- **Response:** `{"claimed_company": str|null, "url_ml_enabled": bool, "links": [rule records], "url_ml": [...]}`.
  - With ML disabled, `url_ml` is `[]`.
  - With ML enabled and no or bad artifact, every entry is `status: "unavailable"` with HTTP 200, and the rules are still returned.
  - Do **not** call `_require_model()`: the endpoint works without the conversation model (verified for `POST /links` on the merged tree).
- **Optional:** add `"url_ml_available": url_ml.model_available(config.URL_ML_DIR) if config.ENABLE_URL_ML else False` to `/health` (lines 41-44).

**`ui/app.py`.**
- Line 57 creates `st.tabs(["Check chat", "Monitoring", "Review queue"])`. Add a fourth tab, `"Check links"` (e.g. `tab_check, tab_links, tab_monitor, tab_review = st.tabs([...])`).
- In it: a text area, an optional company text input, and a button calling `api("POST", "/links/analyze", json={"text": text, "claimed_company": company or None})`.
- For each index `i`, show `links[i]` (url, risk, flag codes and reasons) next to `url_ml[i]`:
  - `scored`: show the score, and "resembles phishing URLs" vs "does not resemble (not a safety verdict)".
  - `not_evaluated`: show the reason.
  - `unavailable`: show "URL model unavailable".
  - If `url_ml_enabled` is false, show "URL model off".
- Keep the existing per-link block at lines 102-106 unchanged.

**`.env.example`.** Add `ENABLE_URL_ML=false` and `URL_ML_DIR=` (empty means `artifacts/url_ml`) after `ENABLE_LINK_CHECK=true`.

**`pyproject.toml` / `uv.lock`.** These already contain `scikit-learn>=1.5`, `numpy>=2.0`, `scipy>=1.14` and `joblib>=1.4`. The lock resolves to scikit-learn 1.9.1, numpy 2.5.4, scipy 1.18.1 and joblib 1.6.0 on Python 3.12, which match the artifact. Recommended: tighten to `scikit-learn>=1.9,<1.10` (the artifact check requires major.minor 1.9), then `uv lock`. `requirements-url-ml.txt` is only for the standalone URL-ML environment.

**`Dockerfile` / `docker-compose.yml`.**
- `.dockerignore` excludes `artifacts`, and the image build writes the conversation model into `/app/artifacts` (`RUN python scripts/train.py --kind tfidf`). So **do not mount over `/app/artifacts`**.
- Mount the URL artifact read-only elsewhere. In the `api` service add:
  - `volumes: ["./url_ml_artifact:/app/url_ml_model:ro"]`
  - environment `ENABLE_URL_ML: "true"` and `URL_ML_DIR: /app/url_ml_model`
- The `ui` service needs no artifact.

## 5. Artifact delivery (not in Git)

- **Files:**

| File | SHA-256 |
|---|---|
| `url_model.joblib` (4,265,807 bytes) | `829e0e8d11fa486081faf49883d344668b41ead02d3e18af09d2e1ec8b0f9dc2` |
| `url_model_meta.json` | `11b25317225d428bc53e638aa0565a238954e21efdab1a389bc34d441115c642` |
| `eval_report.json` (informational) | `11119438c8bf02981581d0fbfe92e1d8e800951caf272d004054908ae536e516` |

- **Model version:** `urlml-lr-char35-168566-202610171216`, preprocessing `urlml-pre-2`, rules commit `f9c7961`.
- **Source on the build box:** `/workspace/url_ml_delivery/urlml-lr-char35-168566-202610171216/`. Pilot alternatives are in `/workspace/url_ml_delivery/urlml-lr-char35-5000-202610171216/` and `...-20000-.../`.
- **Expected directory:** `config.URL_ML_DIR` (default `artifacts/url_ml/`) or the Docker mount `/app/url_ml_model/`. Both files must be in the same directory.
- **Transfer:** copy both files and verify with `sha256sum url_model.joblib url_model_meta.json` against the table above.
  - The loader also checks the model hash recorded in the metadata, plus the preprocessing version, class mapping and scikit-learn 1.9.x. A mismatch gives `unavailable`, not a crash.
- **Not deployable** until it is placed and verified in the app's configured directory.
- **Never** load joblib files supplied by users or from untrusted locations (pickle can execute code). Only the configured directory is read.

## 6. Integration sequence and checks

1. Merge `url-ml` into `main` locally. Resolve the 3 conflicts by taking main's `data/official_domains.json`, `scamshield/links.py` and `tests/test_links.py` (section 1).
2. `uv sync --frozen` (optionally tighten scikit-learn first, then `uv lock`). Install `pytest`.
3. Run `python -m pytest -q tests`. Expected on 84f59f9 + url-ml: 386 passed, 3 xfailed. This must include `tests/test_guards.py`, `tests/test_links.py`, `tests/test_links_compat.py`, `tests/test_link_analysis.py` and `tests/test_url_ml.py`.
4. Make the section 4 edits to `config.py`, `api.py`, `ui/app.py`, `.env.example` and Docker.
5. Place the artifact in `URL_ML_DIR` and check `sha256sum`.
6. Start the API with `ENABLE_URL_ML=false` and **no conversation model**. Then check:
   - `POST /links` returns the same list shape as before.
   - `POST /links/analyze` returns `url_ml: []`.
7. Restart with `ENABLE_URL_ML=true`. `POST /links/analyze` with one `.example` link and one non-reserved synthetic host should give `not_evaluated` and `scored`.
8. Point `URL_ML_DIR` at an empty directory. Every `url_ml` entry should be `unavailable` (HTTP 200), with rules intact.
9. Check the `/analyze` response is unchanged (no `url_ml` unless the team chose to add it).
10. In the UI, open the "Check links" tab and check it shows rules + model per URL for the off, scored, not-evaluated and unavailable states. The "Check chat" tab should be unchanged.

## 7. Ownership boundary

- **Done on `url-ml`:**
  - All files listed in section 2.
  - The `official_domains()` compatibility function and its tests.
  - Trained and verified artifacts on the build box.
  - The local trial-merge check. It was **not** pushed, and nothing was merged into `main`.
- **Owned by the main developer, not done:**
  - Resolving the merge conflicts.
  - All edits in section 4: `config.py`, `api.py`, `ui/app.py`, `.env.example`, `pyproject.toml`/`uv.lock`, Docker files.
  - Placing the artifact.
  - The section 6 verification on the integrated app.

  This document is implementation guidance; it does not claim any of those changes have been made.
