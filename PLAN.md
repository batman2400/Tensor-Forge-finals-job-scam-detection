# ScamShield LK: Team Plan (TensorForge 2.0 Final)

Repo: https://github.com/batman2400/Tensor-Forge-finals-job-scam-detection
Build window: 8:00 to 2:00. Judges review the **last commit before 2:00**.

## Problem statement (submitted)

> An ML service that warns Sri Lankan job seekers when a recruitment chat turns into a task-job scam, monitors shifting scam tactics, and routes uncertain cases to human review.

**Who we protect:** university students, school leavers and job seekers who get "part-time online job" offers on WhatsApp, Telegram and social media.

---

## 1. Features

### Must-have (judged directly)
| # | Feature | What the user / judge sees |
|---|---|---|
| 1 | Conversation check | Paste a chat and get **Scam / Legit** plus a confidence score |
| 2 | Risk timeline | Score after every message: offer, then tasks, then deposit, then pay-to-withdraw (risk climbs) |
| 3 | Why it's flagged | Highlighted warning phrases (fees, top-ups, pay to withdraw, Telegram, VIP levels, crypto) |
| 4 | Prediction log | Every prediction stored (SQLite) with score, confidence, unfamiliarity |
| 5 | Drift monitor | Rolling-window signals: confidence falling, unfamiliar inputs rising, uncertain predictions rising, alert banner |
| 6 | Review queue | Uncertain / unfamiliar cases go to a human, who labels them Scam / Legit |
| 7 | Retrain trigger | Retrain with reviewed labels and show shifted-set accuracy **before and after** |

### Optional (Sithum, hidden if not ready by 12:00)
| 8 | Link checker | Each URL gets a risk level and reasons ("company name in an unrelated domain", "shortened link", ...) |

### Stretch (only if everything above works by 11:30)
- Safe fallback mode: during a drift alert, lean toward warning and send more cases to review
- README table comparing TF-IDF baseline vs embedding model
- Sithum's optional URL ML model (see section 4)

**Not doing today:** Sinhala/Tamil script, opening URLs, domain-age/WHOIS, reputation APIs, browser extension, WhatsApp bot.

---

## 2. Architecture

```
            ┌──────────────── Streamlit UI (port 8501) ────────────────┐
            │ Check chat │ Monitoring │ Replay batch │ Review queue    │
            └──────────────────────────┬───────────────────────────────┘
                                       │ HTTP
            ┌──────────────────────────▼───────────────────────────────┐
            │                FastAPI service (port 8000)               │
            │  /analyze  /replay  /monitoring  /review  /retrain       │
            │                                                          │
            │  parse chat → classifier (score + novelty)               │
            │            → indicators (explanations only)              │
            │            → links.check_urls  [optional, try/except]    │
            │            → log to SQLite → drift check → route review  │
            └──────────────────────────────────────────────────────────┘
   scripts/: generate_data.py → prepare_data.py → train.py (evaluate) ; retrain via /retrain
   docker-compose: api + ui, model trained at image build
```

**Model:** multilingual sentence embeddings (`paraphrase-multilingual-MiniLM-L12-v2`) + logistic regression. Baseline: word+char TF-IDF + logistic regression.
**Unfamiliarity:** 1 minus cosine similarity to the nearest training example; above the 95th percentile of validation counts as "unfamiliar".
**Drift alert:** over the last 40 predictions, compared with validation reference stats:
- mean confidence drops by more than 0.10, or
- unfamiliar rate rises by more than 20 points, or
- uncertain rate (score 0.35 to 0.65) rises by more than 15 points.

**Response:** alert banner, uncertain/unfamiliar cases sent to review, human labels, `/retrain`, new model (previous one kept as `model_prev.joblib`).

---

## 3. Data plan

Schema (one JSON per line):
```json
{"id": "...", "label": 1, "category": "task_wallet_topup", "lang": "en|singlish",
 "source": "gemini-2.5-flash:prompt-v1", "messages": [{"sender": "Recruiter", "text": "..."},
                                                      {"sender": "Candidate", "text": "..."}]}
```

| Split | Size target | How | Used for |
|---|---|---|---|
| train | ~300 scam + ~300 legit | Gemini, prompt set A, + hand-written seed | training |
| test | ~80 + ~80 | Gemini, **separate runs, reworded prompts**, near-duplicates of train removed | held-out results in README |
| shifted | ~100 + ~100 | New scam pretexts + more Singlish (legit Singlish too) | half = replay stream (drift demo + review), half = held-out shifted eval |

**Scam categories (train/test):** registration/training fee, task-wallet top-up (rate products, hotels, like videos), "merchant/combo" prepaid tasks, data-entry security deposit, overseas job visa processing fee, pay-to-withdraw earnings.
**Shifted scam pretexts (never in train):** VIP level upgrade, "tax clearance" to withdraw, USDT/crypto wallet activation, account freeze unlock fee, "insurance" for payout, plus heavy Singlish wording.
**Legit (all splits, include hard negatives):** interview scheduling, internship offers, salary/bank details *for payroll after hiring*, freelance gigs paid after delivery, background checks, HR asking for CV/certificates, legit Singlish recruiter chats.

**Safety rules (Rule 2 and Rule 5):** fictional names and companies only, no real phone numbers (`07X-XXX-XXXX`), no real NIC or bank numbers, links only on `.example` domains, no real banks or agencies as targets, never send or post the data. Each source is listed in the README.

---

## 4. Work split

### Main dev: model, service, monitoring, UI, data generation, integration
1. 8:55: push scaffold to repo, first commit, submit problem statement
2. 9:00: test Gemini key with 1 batch; start `generate_data.py` running in background
3. 9:15 to 10:00: train on seed data, API `/analyze` working, logging on, **commit**
4. 10:00 to 10:45: Streamlit UI (check chat + timeline), **commit**
5. 10:45 to 11:30: real data, `prepare_data.py`, train both models, evaluation numbers, **commit**
6. 11:30 to 12:15: replay shifted stream, drift alert fires, review queue, retrain before/after, **commit**
7. 12:15 to 12:45: wire Sithum's link module behind `ENABLE_LINK_CHECK` (try/except, UI hides section if off)
8. 12:45 to 1:15: Dockerfile + compose, test clean start from README commands, **commit**

### Sithum: link checker (independent, optional)
**Files you own (touch nothing else to avoid merge conflicts):**
`scamshield/links.py`, `tests/test_links.py`, `data/official_domains.json`
Work on branch `links`; open a PR / tell main dev when each milestone passes tests.

**Contract (do not change):**
```python
def check_urls(text: str, claimed_company: str | None = None) -> list[dict]:
    # [{"url": str, "host": str, "risk": "low"|"medium"|"high",
    #   "flags": [{"code": str, "reason": str}]}]
```
Rules: text only, no network calls. No flags gives "low" risk, which is **not** "safe". Standard library only, if possible.

**Milestones (in order; each one is usable on its own):**
| By | Flags |
|---|---|
| 9:45 | URL extraction (http, https, www., bare domain/path); `IP_HOST`; `AT_SYMBOL` (user@host trick) |
| 10:30 | `SHORTENER` (bit.ly, tinyurl, cutt.ly, …); `CHAT_REDIRECT` (t.me, wa.me, chat.whatsapp); `APK_DOWNLOAD` |
| 11:15 | `CLAIMED_COMPANY_MISMATCH` (chat claims company X, link isn't X's official domain); `LOOKALIKE` (edit distance ≤ 2 to an official domain); `BRAND_IN_SUBDOMAIN` (`abc.careers-portal.example`) |
| 11:45 | `FREE_HOSTING_FORM` (wixsite, blogspot, sites.google, forms.gle, docs.google.com/forms); `PUNYCODE` (xn--); `MANY_SUBDOMAINS` |
| 12:00 | **Cut-off.** ≥ 15 tests passing with synthetic `.example` URLs; one-paragraph README section listing every flag |
| Stretch | Char n-gram URL classifier on a public phishing-URL dataset (check licence, report its accuracy separately) |

Risk rule (keep simple and documented): 0 flags = low, 1 flag = medium, 2+ flags or `IP_HOST` / `CLAIMED_COMPANY_MISMATCH` = high.
`data/official_domains.json`: fictional demo companies only, e.g. `{"ABC Holdings": "abcholdings.example"}`.

### Presenter: demo content, label review, impact, deck, README text
1. 8:55 to 9:30: write **2 demo chats** (clearly labelled synthetic):
   - `legit_recruitment.txt`: normal interview / internship chat
   - `task_scam.txt`: offer, tasks, promised earnings, deposit request, pay to withdraw (with one `.example` link)
2. 9:30 to 10:00: write 20 hand-made examples (10 scam, 10 legit, incl. Singlish) for `data/seed/seed.jsonl`
3. 10:30 to 11:00: **spot-check 40 generated conversations**: wrong labels, real names/numbers, unrealistic Singlish
4. 9:00 to 12:00 in parallel: impact research. Sri Lankan figures (CBSL "Be Scam Proof" June 2026, university/job-seeker numbers, police/CERT scam reports) with sources
5. 11:00 to 12:30: `IMPACT.md` (≤ 1 page): who, how many, harm prevented, pilot path (university career centres, CERT|CC awareness, WhatsApp tipline)
6. 12:00 to 1:15: pitch deck PDF (structure below); fill README sections: problem/users, data sources, AI tools used
7. 1:15 to 1:30: record backup demo video

---

## 5. Timeline and checkpoints

| Time | Checkpoint (all three check in) |
|---|---|
| 8:55 | Problem statement submitted, repo has first commit, everyone knows their files |
| 10:00 | **Checkpoint 1:** API returns a verdict for a pasted chat (seed model). Gemini data flowing. Sithum milestone 1. |
| 11:30 | **Checkpoint 2:** UI working end-to-end on real data, test-set numbers known. Sithum milestone 3. |
| 12:15 | **Checkpoint 3:** drift alert fires on shifted replay, review + retrain works. Decide: link checker in or out. |
| 1:15 | **Feature freeze.** Docker clean start tested. README, impact, deck done. |
| 1:15 to 1:45 | Rehearse 8-min pitch twice, record backup video |
| 1:50 | **Final commit + submit** (repo link, README, impact, deck PDF) |

Commit at least every 30 min with clear messages (judges read history). No API keys in the repo; use `.env` (gitignored) + `.env.example`.

---

## 6. Live demo script (2 to 3 min)

1. Paste `legit_recruitment.txt`: **Legit**, low risk, no warnings.
2. Reveal `task_scam.txt` message by message; the timeline climbs as the deposit and pay-to-withdraw messages appear; highlighted indicators; (if ready) the link shows `CLAIMED_COMPANY_MISMATCH`.
3. Monitoring tab: replay the **test** batch, healthy (no alert).
4. Replay the **shifted** batch (new pretexts + Singlish): confidence drops, unfamiliar rises, **DRIFT ALERT**, cases fill the review queue.
5. Label some cases, then **Retrain**: shifted held-out accuracy before and after.

## 7. Pitch deck (8 min)
1. Problem (1 min): task-job scams in Sri Lanka, who loses money, CBSL campaign
2. Solution (1 min): what it does, who uses it
3. Live demo (2 to 3 min): section 6
4. How it's built (1 to 2 min): architecture, data and safety rules, test results, monitoring and drift response
5. Impact and next steps (1 min): reach, harm prevented, pilot path

**Viva prep:** everyone must explain the data generation, the model and unfamiliarity score, the drift thresholds, and the retrain flow. 10-minute walkthrough at 1:15.

---

## 8. Risks and fallbacks
| Risk | Fallback |
|---|---|
| Gemini refuses scam text or rate-limits | Reword prompt as "training data for a fraud-detection classifier"; else template generator with slot-filling (main dev, 20 min) |
| Embedding model slow / download fails | Ship TF-IDF model (`MODEL_KIND=tfidf`), already supported |
| Test accuracy suspiciously ~100% | Report honestly, explain synthetic-data limitation, show the shifted-set drop as the real story |
| Drift alert doesn't fire on shifted set | Make the shift stronger (more Singlish, newer pretexts); lower `DRIFT_WINDOW` |
| Link checker not ready by 12:00 | `ENABLE_LINK_CHECK=false`, mention as roadmap item |
| Docker build fails at the end | Documented `uv`/`pip` run commands in README (also accepted) |
| Internet outage | Backup hotspot; embedding model pre-downloaded in Docker image; TF-IDF fallback works offline |
