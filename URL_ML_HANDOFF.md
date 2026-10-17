# URL ML model: handoff (branch `url-ml`)

**Status:** optional and **observation only**. It sits next to the rule-based link checker (`scamshield/links.py`, rules commit `f9c7961`). It never changes rule risk, flags, the chat-model verdict or review routing, and there is **no score fusion**. "Not phishing-like" does **not** mean safe.

## What it is
- **Model:** a scikit-learn `Pipeline`, char `TfidfVectorizer(analyzer="char", ngram_range=(3,5), lowercase=False, min_df=2, sublinear_tf=True, max_features=2**18, dtype=float32)` followed by `LogisticRegression(liblinear)`. The vectorizer and classifier are saved together in one joblib file. The matrices stay sparse.
- **Input text** (preprocessing `urlml-pre-2`, see `scamshield/url_ml_preprocessing.py`): the canonical ASCII/xn-- **host** from the public `check_urls` API, with leading `www.` removed, plus `:port`. Scheme, `www.` and path/query/fragment are **deliberately dropped**. In PhiUSIIL every legitimate URL is `https://www.<domain>` with no path, and 100% of the 107,948 legitimate training rows have that shape. A first pilot that used the full URL scored 0.99+ on every metric only by learning "http / no www / has a path => phishing". It flagged ordinary links such as a careers page, so that version was discarded.
- **Probability column:** chosen via `classes_.index(1)` and never by position. Internal labels are 1 = phishing and 0 = legitimate; UCI labels are inverted (1 = legitimate), and the conversion is tested.

## Files
| File | Purpose |
|---|---|
| `scamshield/url_ml_preprocessing.py` | Stdlib-only, deterministic preprocessing; privacy/reserved-domain filter; offline grouping key; label mapping |
| `scamshield/url_ml.py` | `predict_urls(urls, *, model_dir=None)`, `load_model`, `reload_model`, `model_available`, plus training helpers `build_pipeline` and `save_artifact` |
| `scamshield/link_analysis.py` | `analyze_links(text, claimed_company=None, *, enable_url_ml=False, model_dir=None) -> {"links": [...], "url_ml": [...]}` |
| `scripts/prepare_url_data.py` | CSV → audited, domain-grouped `train/val/test.jsonl` + `manifest.json` (outside git) |
| `scripts/train_url_model.py` | Picks C and threshold on validation, scores test once, writes artifact + `eval_report.json` |
| `tests/test_url_ml.py`, `tests/test_link_analysis.py` | 44 tests using synthetic fixtures only (no dataset, no network) |
| `requirements-url-ml.txt` | Pinned scikit-learn 1.9.1, numpy 2.5.4, scipy 1.18.1, joblib 1.6.0, threadpoolctl 3.7.0 |

## Result contract
`analyze_links` calls `check_urls` **once** and returns its list unchanged under `"links"`. That is the full, cumulative rules payload. `"url_ml"` is a separate list with one entry per link, in the same order:
```json
{"url": "...", "host": "<canonical host from check_urls>", "status": "scored|unavailable|not_evaluated",
 "phishing_score": 0.0-1.0 or null, "above_threshold": true|false|null,
 "model_version": "..." or null, "reason": "plain-English"}
```
- **Disabled (default):** `url_ml == []`. No sklearn import and no artifact needed (tested in a subprocess with sklearn blocked).
- **No links:** both lists are empty.
- **`unavailable`:** the model or its metadata is missing or corrupt, there is a checksum, schema, preprocessing, class-mapping or scikit-learn major.minor mismatch, or `predict_proba` raised. Score is `null`. The rule results are still returned.
- **`not_evaluated`:** reserved demo domains (`.example`, `.test`, `.invalid`, `.localhost`, `.local`, `example.com/net/org`), plus privacy-filtered links (userinfo `@`, an e-mail address, or token-like query parameters such as `token`, `session`, `sid`, `password`, `key`, `code`, `sig`). Also non-strings, empty input, non-http(s), more than one link, parser rejects (e.g. port > 65535, overlong numeric host) and anything past 1,000 URLs per batch. None of these abort the batch.
- A score of 0 or a "safe" verdict is never invented.

## Integration into the app (origin/main `84f59f9`, inspected)
- `scamshield/config.py`: has `ENABLE_LINK_CHECK = os.getenv("ENABLE_LINK_CHECK", "true")...`. **Add** `ENABLE_URL_ML = os.getenv("ENABLE_URL_ML", "false").lower() == "true"`. Default off, and independent of `ENABLE_LINK_CHECK`. Optionally add `URL_ML_DIR`, mapped to env `SCAMSHIELD_URL_ML_DIR`, which `url_ml.default_model_dir()` already reads.
- `scamshield/service.py`: `safe_check_urls()` and `Analyzer.analyze()` build `result["links"]`. Keep `"links"` exactly as is. When `ENABLE_URL_ML` is on, add `result["url_ml"] = predict_urls([l["url"] for l in links])`, or switch to `analyze_links(text, company, enable_url_ml=config.ENABLE_URL_ML)`. Leave `risky_links`, `label` and `review_reason` untouched (no fusion).
- `scamshield/api.py`: `POST /links` returns the `safe_check_urls` list. Changing it to an object would break clients, so either keep it and add a new `POST /links/ml`, or add `url_ml` only to `/analyze`. Optionally report `url_ml_available` from `url_ml.model_available()` in `GET /health`.
- `ui/app.py` (around line 102): renders `result["links"]`. Add a separate small "URL model (experimental)" line per link that shows the score only when `status == "scored"`, and otherwise the reason.
- **Pending verification:** origin/main's `scamshield/links.py` is an older/different version than `f9c7961` (50+/12- lines), and `service.py` imports `official_domains` from it, which `f9c7961` does not export. Reconcile before merging `url-ml`. `pyproject.toml` on main already depends on scikit-learn/numpy/scipy/joblib, and `uv.lock` pins scikit-learn 1.9.1 (it matches the artifact), numpy 2.4.6/2.5.4 and scipy 1.17.1/1.18.1. Main uses Python 3.12; tests and artifact loading were also run on Python 3.12.15.
- Load once: `load_model` caches per directory (failures too). Call `reload_model()` after replacing the artifact. Only load artifacts from the configured trusted directory, **never a user-supplied file** (joblib/pickle can run code).

## Data (UCI PhiUSIIL, id 967, CC BY 4.0)
- **Source:** `https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip`, retrieved 2026-10-17 12:08:51 Asia/Colombo, zip SHA-256 `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a`. Stored in `/workspace/url_ml_data/` and not committed.
- **Columns:** only `URL` and `label` are used.
- **Raw rows:** 235,795 (100,945 phishing / 134,850 legitimate). No missing URLs or invalid labels.
- **Exclusions:** 1,300 contain an e-mail address, 430 have a token-like parameter, 10 have userinfo. 15,957 duplicates of the host-level model text were dropped (first occurrence kept). 57 texts (155 rows) had contradictory labels and were quarantined. **Kept: 218,041.**
- **Splits:** domain-grouped by `sha256(seed, registrable domain)`, seed 20261017, 80/10/10. Groups are disjoint across partitions (tested).
  - **train:** 168,566 rows (60,661 phishing), 137,066 domains
  - **val:** 21,996 rows (8,447 phishing), 17,236 domains
  - **test:** 27,479 rows (14,140 phishing), 17,026 domains
- **Sampling:** training subsets use class-aware, domain-diverse deterministic sampling (5k → 1,799 phishing, 36% = train-partition proportion after dedup).

## Results (test partition, scored once per model; C and threshold chosen on validation)
- **Threshold objective:** the lowest validation threshold reaching **precision ≥ 0.95**, which maximises recall at that precision.
- **Model choice:** C is chosen from {1, 4, 16} by validation PR-AUC. The shipped default is the model with the best validation PR-AUC.

| Train rows | C | Threshold | Val PR-AUC | Test precision | Test recall | Test F1 | Test FPR | Test PR-AUC | Test ROC-AUC |
|---|---|---|---|---|---|---|---|---|---|
| 5,000 (pilot) | 16 | 0.7748 | 0.809 | 0.970 (6,841/7,050) | 0.484 (6,841/14,140) | 0.646 | 0.0157 (209/13,339) | 0.920 | 0.905 |
| 20,000 | 4 | 0.7010 | 0.859 | 0.958 (5,774/6,029) | 0.408 (5,774/14,140) | 0.573 | 0.0191 (255/13,339) | 0.905 | 0.897 |
| **168,566 (all train; shipped default)** | 4 | **0.6265** | **0.896** | 0.961 (6,769/7,042) | 0.479 (6,769/14,140) | 0.639 | 0.0205 (273/13,339) | 0.911 | 0.901 |

Validation improves clearly with more data (PR-AUC 0.81 → 0.86 → 0.90), but the untouched test set shows no gain. The test partition has a different class mix (51% phishing vs 38% on validation), and the model ceiling is set mostly by the host-only input.

Other precision targets for the shipped model, shown for information only (the threshold was still picked on validation):

| Precision target | Threshold | Test precision | Test recall | Test FPR |
|---|---|---|---|---|
| 0.90 | 0.4735 | 0.924 | 0.606 | 0.053 |
| 0.99 | 0.8698 | 0.988 | 0.212 | 0.0027 |

Disclosure: one discarded run (the full-URL pilot) and a 0.99-target run of the 5k host-only model were also scored on test before this final 0.95 objective was fixed.

**Timings and size (box, Python 3.13.5)**

| Train rows | Fit (chosen C) | Grid of 3 | Peak RSS (ru_maxrss) | Model file | Load | `predict_urls` end-to-end | Raw `predict_proba` |
|---|---|---|---|---|---|---|---|
| 5k | 0.22 s | 1.7 s | 285 MB | 360 KB | 0.08 s | 0.076 ms/URL | 0.016 ms/URL |
| 20k | 0.79 s | 3.5 s | 338 MB | 1.07 MB | 0.21 s | 0.083 ms/URL | 0.020 ms/URL |
| full | 8.3 s | 28.3 s | 701 MB | 4.27 MB (262,144 features) | 0.89 s | 0.097 ms/URL | 0.027 ms/URL |

- Peak RSS covers data load + training + evaluation.
- End-to-end `predict_urls` is measured on 1,000 URLs and includes preprocessing.
- `/usr/bin/time` is not installed on the box.

**Coverage:** of the 1,000-URL latency sample, 1,000 were scored. In training data, 1,740 of 235,795 rows (0.74%) would be `not_evaluated` by the privacy filter.

## Artifacts (not in git)
- **Default load path:** `artifacts/url_ml/` in the repo (gitignored) = full model `urlml-lr-char35-168566-202610171216`, sha256 `829e0e8d…9dc2`.
- **Stable delivery copies** (model + metadata + eval report each):
  - `/workspace/url_ml_delivery/urlml-lr-char35-168566-202610171216/` (default)
  - `/workspace/url_ml_delivery/urlml-lr-char35-20000-202610171216/`
  - `/workspace/url_ml_delivery/urlml-lr-char35-5000-202610171216/` (pilot)
- **Metadata** records the model version, preprocessing version, rules commit `f9c7961`, class mapping, dependency versions, dataset checksum/licence/retrieval time, threshold + objective, and the eval summary. It is validated before scoring.
- **Rebuild:** `python scripts/prepare_url_data.py --source-sha256 <sha> --retrieved-at <iso>`, then `python scripts/train_url_model.py --train-rows 1000000` (or `5000`).

## Tests
- **Commands:** `python -m pytest tests` from the repo root, and `python -m pytest /path/to/repo/tests` from another directory.
- **With requirements-url-ml installed:** 356 passed, 3 xfailed (Python 3.13.5 and 3.12.15).
- **Without scikit-learn:** 343 passed, 13 skipped, 3 xfailed. The adapter-disabled tests pass with no sklearn.
- **Rules suite alone:** still 312 passed, 3 xfailed.

## Limitations
1. **Dataset artefact:** PhiUSIIL legitimate URLs are all `https://www.<domain>` homepages. Even host-only, the model learns "has subdomains / unusual TLD ⇒ phishing-like". Legitimate hosted job pages (e.g. `jobs.<ats>.co`, `forms.gle`, `sites.google.com`) can score high. Treat the score as a weak, experimental hint, never as a verdict.
2. **No path information:** host-only means that phishing hosted on a reputable platform's paths is invisible to the model (the rules cover APK, free-hosting forms, chat redirects).
3. **Grouping key:** uses a small built-in multi-part suffix list, not the full Public Suffix List, so some groups may be too coarse or too fine.
4. **Not Sri-Lanka specific:** the data is general phishing from around 2023, not job-scam links. Recall at the chosen threshold is only about 48%.
5. **Not evaluated:** Reserved demo domains (`.example`) are not evaluated, so the team's demo links get no ML score by design.
6. **Pinned runtime:** the artifact needs scikit-learn 1.9.x (a major.minor check). Other versions return `unavailable`.
