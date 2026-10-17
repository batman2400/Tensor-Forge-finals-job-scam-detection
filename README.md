# ScamShield LK

**Task-job scam detection for Sri Lankan recruitment chats, built to support a career adviser.**

A student receives a "part-time online job" offer on WhatsApp or Telegram. A career adviser pastes the chat into ScamShield. The service returns a wording score, highlights the phrases behind it, shows how the score moved message by message, and routes uncertain, unfamiliar, or risky-link chats to a person.

ScamShield does not message anyone, open links, or move money. The adviser makes the decision. The score is a draft.

> **"No strong scam signal" is a wording assessment, not a statement that the recruiter is genuine.**

---

## Contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [API](#api)
- [Data](#data)
- [Results](#results)
- [Monitoring and drift](#monitoring-and-drift)
- [Configuration](#configuration)
- [Project layout](#project-layout)
- [Testing](#testing)
- [Limitations](#limitations)
- [AI tools used](#ai-tools-used)
- [Further reading](#further-reading)

---

## Why this exists

Task-job scams follow a pattern. They open with a friendly part-time offer and move to small paid tasks. A dashboard then shows growing earnings, and finally the victim is asked for a fee. The fee can be a registration charge, a task-wallet top-up, a "merchant" deposit, or a payment before withdrawal. Sri Lanka CERT and the CID have described fake job offers and work-from-home schemes spread over chat apps. Students and school leavers are an obvious target. See [IMPACT.md](IMPACT.md) for the figures and sources.

ScamShield helps an adviser answer three questions in front of the student:

1. **Does this chat carry a scam signal, and which phrases support it?**
2. **When did the signal appear?** The timeline is the model's score after each message. It is not a scripted climb.
3. **Are new chats behaving unlike the ones the model was trained on?** If so, raise a drift alert and send uncertain cases to a person.

## Features

- **Chat analysis.** A verdict, a score, and the phrases that support it. English and Singlish are both covered.
- **Per-message timeline.** The score after each message, so the adviser can see where the signal appeared.
- **Link checker.** Text-only checks with no network calls. It flags lookalike domains, IP hosts, APK downloads, and links that don't match a company named in the chat.
- **Review queue.** Uncertain, unfamiliar, credential-request, and high-risk-link chats are queued for a person to label.
- **Drift monitoring.** A rolling window of the last 40 predictions is compared with a validation reference.
- **Optional retraining.** Reviewed examples can be folded back into the model. The previous model is kept as a backup.

## Quick start

You need Python 3.11 or newer and [uv](https://docs.astral.sh/uv/). Docker is optional.

### Option A: run locally

From this directory:

```powershell
uv sync
copy .env.example .env
```

The defaults in `.env` work as they are. A Gemini API key is only needed if you want to regenerate the synthetic data. `.env` is git-ignored.

The frozen data in `data/processed/` is committed. Train the default model, then start the API and the UI in two terminals:

```powershell
uv run python scripts/train.py --kind tfidf
```

```powershell
uv run uvicorn scamshield.api:app --host 127.0.0.1 --port 8000
```

```powershell
uv run streamlit run ui/app.py
```

- UI: <http://127.0.0.1:8501>
- API health check: <http://127.0.0.1:8000/health>

The API returns `503` from `/analyze` until a model has been trained.

### Option B: Docker

```powershell
docker compose up --build
```

The image trains the TF-IDF model from `data/processed` while it builds. It reads no Gemini key and doesn't install the embedding model. The UI container calls the API at `http://api:8000`.

- UI: <http://127.0.0.1:8501>
- API health check: <http://127.0.0.1:8000/health>

Stop with `docker compose down`.

### Optional: embedding model

The default model is TF-IDF and downloads nothing. To try the multilingual embedding model:

```powershell
uv sync --group embed
uv run python scripts/train.py --kind embed
```

Then set `MODEL_KIND=embed` in `.env`. It scored worse than TF-IDF in the comparison below, so TF-IDF is the one deployed.

### Try the demo chats

Two synthetic chats are in `data/demo/`. Paste `legit_recruitment.txt` first, then `task_scam.txt`. The scam chat links to a "Bright Path" site that is not on `brightpath.example`, so the link checker should flag `CLAIMED_COMPANY_MISMATCH`.

## How it works

```
Streamlit UI (8501)
  Check chat | Monitoring | Review queue
        │ HTTP
FastAPI (8000)
  /analyze  /links  /replay  /monitoring  /review  /retrain
        │
  parse chat ─► classifier (score + unfamiliarity)
            ─► context rules (refusals, questions, reports, "send money")
            ─► phrase indicators (explanation only)
            ─► link checker (optional)
            ─► SQLite log ─► drift check ─► review queue
```

**Classifier.** Word and character TF-IDF with logistic regression (default). The alternative is `paraphrase-multilingual-MiniLM-L12-v2` embeddings with logistic regression (`MODEL_KIND=embed`). The scam line is 0.50.

**Context rules.** A short check adjusts the classifier score for cases it handles badly. A refusal, a question, or a report of a scam is moved down. An instruction to send money without the usual fee words is lifted to 0.72. A greeting with none of those cues stays under the line. Phrase hits inside a refusal are not shown.

**Phrase indicators.** These explain a verdict. They never decide it.

**Unfamiliarity.** One minus the cosine similarity to the nearest training example. The deployed model fits on 80% of train. The other 20% is used only to set the unfamiliarity cut (95th percentile) and the drift reference.

**Credential requests.** A request for a password, PIN, or one-time code is queued with the reason `credential-request`. It does not change the classifier score. "Do not share an OTP" is not a credential request.

**Link checker.** Text only, controlled by `ENABLE_LINK_CHECK`. No flags means risk `low`, which is not "safe".

| Strength | Flags | Effect |
|---|---|---|
| Strong | `IP_HOST`, `CLAIMED_COMPANY_MISMATCH`, `LOOKALIKE`, `APK_DOWNLOAD` | One flag alone makes the risk `high` |
| Weak | `AT_SYMBOL`, `SHORTENER`, `CHAT_REDIRECT`, `BRAND_IN_SUBDOMAIN`, `FREE_HOSTING_FORM`, `PUNYCODE`, `MANY_SUBDOMAINS` | Any number stays `medium` |

A company counts as claimed when the chat names one listed in `data/official_domains.json` and the host isn't that company's domain or a subdomain of it. See `scamshield/links.py`.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Model loaded, model version, fit version, drift policy |
| `POST` | `/analyze` | Score a chat. Body: `text`, optional `claimed_company`, `expected_domain` |
| `POST` | `/links` | Run the link checker alone |
| `POST` | `/replay` | Push a stored set (`test`, `shifted`, `drift`) through the live pipeline |
| `GET` | `/monitoring` | Current drift status |
| `GET` | `/predictions` | Recent logged predictions |
| `GET` | `/review` | The review queue |
| `POST` | `/review/{id}` | Label a queued chat (`label` 0 or 1) |
| `POST` | `/retrain` | Retrain with reviewed examples. Keeps the old model as `artifacts/model_prev.joblib` |
| `POST` | `/admin/reset-logs` | Clear the prediction log |

Example:

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze `
  -ContentType "application/json" `
  -Body '{"text": "Recruiter: Pay Rs 5000 to unlock your earnings."}'
```

FastAPI also serves interactive docs at <http://127.0.0.1:8000/docs>.

## Data

Every chat is **synthetic**. None come from real victims, and none are sent to a phone, an email address, or a public channel.

| Source | What it is |
|---|---|
| `data/raw/*.jsonl` | Gemini-generated conversations. Train and test use different prompt wording. The shifted set uses new scam pretexts and more Singlish. |
| `data/seed/seed.jsonl` | 12 hand-written chats, folded into train. |
| `data/seed/reviewed_tactics.jsonl` | Reviewed examples added to the model fit only. |
| `data/demo/` | Two labelled demo chats and a drift sample for the UI. |
| `data/official_domains.json` | Fictional companies on `.example` domains, used by the link checker. |
| `data/confirm/` | Evaluation batches written before they were scored. |

One JSON object per line:

```json
{"label": 1, "category": "task_wallet_topup", "lang": "en",
 "source": "gemini-3.8-flash:prompt-v1-train", "split": "train",
 "messages": [{"sender": "Recruiter", "text": "..."}, {"sender": "Candidate", "text": "..."}]}
```

`label` 1 is a scam and 0 is a legitimate recruitment chat. The legitimate set includes hard cases such as salary figures and a bank account requested only after hiring.

| Split | Size | Role |
|---|---|---|
| Train | 682 (387 scam, 295 legit) | Fit the model |
| Test | 154 (76 scam, 78 legit) | Held-out results from a separate generation run |
| Shifted eval | 98 (48 scam, 50 legit) | New pretexts and more Singlish |
| Shifted stream | 97 (52 scam, 45 legit) | Replay stream for monitoring |

**Safety rules** for generation and for the review scan:

- Fictional people and companies. No real bank or agency appears as the recruiter.
- Phone numbers only as `07X-XXX-XXXX`. No NIC numbers and no real account numbers.
- Links only on the reserved `.example` domain, or `example.com`, `example.org`, and `example.net`.

`scripts/review_data.py` enforces these rules. It exits 1 on a real phone number, NIC number, bank account, named real organisation, off-example link, or broken row. Its last run found 0 errors and 127 warnings (possible wrong labels, unrealistic chats, and shifted pretexts that also appear in train or test). The warnings need a person to read them.

### Regenerating the data (optional)

This needs `GEMINI_API_KEY` in `.env`. Generate one file at a time, then freeze the splits only once the raw files are finished:

```powershell
uv run python scripts/generate_data.py --split train   --label 1 --n 300
uv run python scripts/generate_data.py --split train   --label 0 --n 300
uv run python scripts/generate_data.py --split test    --label 1 --n 80
uv run python scripts/generate_data.py --split test    --label 0 --n 80
uv run python scripts/generate_data.py --split shifted --label 1 --n 100
uv run python scripts/generate_data.py --split shifted --label 0 --n 100
uv run python scripts/review_data.py
uv run python scripts/prepare_data.py
```

Don't run `prepare_data.py` on a file that is still growing.

## Results

Deployed pipeline: `tfidf-20261017T080050+pipeline-20261017T080050`. The scam threshold is 0.50 and was not lowered to improve any number below.

*Raw* is the classifier probability. *Final* is that probability after the context rules.

### New wording (the realistic test)

| Set | Role | Raw correct | Final correct | False positives | Sent to review | Silent scam misses |
|---|---|---|---|---|---|---|
| New tactics | Development, already inspected | 30 of 40 | 40 of 40 | 0 | 20 of 40 | 0 |
| Onboarding (all legitimate) | Development, already inspected | 40 of 40 | 40 of 40 | 0 | 40 of 40 | 0 |
| Fresh scenarios | Scored once, never trained on | 14 of 16 | 16 of 16 | 0 | 7 of 16 | 0 |

- On the new-tactic batch, ten English scams scored 0.47 to 0.50 raw and are lifted to 0.72 by the payment rule. Those ten are not queued.
- On the fresh set, an equipment bond (raw 0.446) and a joining clinic fee (raw 0.460) are lifted by the rules. Both are unfamiliar, so both still reach review.
- A correct label on onboarding chats does not save the adviser work. All 40 legitimate chats still go to review, because they are unlike the training chats.

### Original frozen splits

| Set | n | Precision (scam) | Recall (scam) | False positives | Review rate |
|---|---|---|---|---|---|
| Held-out test | 154 | 1.000 | 1.000 | 0 | 7 of 154 (4.5%) |
| Shifted eval | 98 | 1.000 | 1.000 | 0 | 10 of 98 (10.2%) |

Review rate is the share of the set with an uncertain score (0.35 to 0.65) or unfamiliarity above the validation cut.

> **Read the perfect scores carefully.** The train and test chats are synthetic and share a lot of fee and task wording. Some train and test scams already use a pretext that is also in the shifted set (VIP, tax clearance, combo or lucky order). The original shifted eval is therefore not a fully unseen-pretext test. The new-tactic batch above, where the raw classifier gets 30 of 40, is the better measure on different wording.

### Model comparison (earlier run, original splits only)

| Model | Test precision | Test recall | Test false positives | Shifted precision | Shifted recall |
|---|---|---|---|---|---|
| TF-IDF + logistic regression (deployed) | 1.000 | 1.000 | 0 | 1.000 | 1.000 |
| Multilingual embeddings + logistic regression | 0.962 | 0.987 | 3 | 0.941 | 1.000 |

To reproduce the comparison, install the embedding extra and run `uv run python scripts/train.py --kind tfidf --compare`. The saved file stays TF-IDF.

Raw numbers are in `reports/metrics.json` (frozen splits) and `reports/layer_comparison.json` (raw vs final).

## Monitoring and drift

Every `/analyze` and replay call is logged to SQLite (`logs/predictions.db`): score, chosen-side score `max(score, 1 − score)`, unfamiliarity, and whether the row went to review. Chat text is stored only for rows that enter the queue.

Drift uses the last 40 predictions from the current pipeline version, compared with that version's validation reference. It needs at least 15 predictions. Policy `three-signal-alert-v1` is frozen:

| Signal | Condition | Effect |
|---|---|---|
| Confidence drop | Mean chosen-side score falls by more than 0.10 | **Drift alert** |
| Unfamiliar rate | Rises by more than 20 points | **Drift alert** |
| Uncertain rate | Score between 0.35 and 0.65 rises by more than 15 points | **Drift alert** |
| Mean unfamiliarity | Above a stored one-sided Student-t prediction limit | **Advisory only**, with no alert and no review |

While an alert is active, chats scoring at or above `DRIFT_FALLBACK_THRESHOLD` (0.20) also go to review. An uncertain score, an unfamiliar chat, or a high-risk link queues that chat on its own at any time.

**Replay controls** in the Monitoring tab:

- **Replay shifted set** is the job-chat control. Its rows can be queued and reviewed.
- **Replay test set** is logged but never queued, and it can never be labelled into a retrain.
- **Replay unfamiliar writing** sends out-of-domain text, including biology writing. It shows that unfamiliar text can move the window. It is not evidence that the service detects evolving job scams.

**What the drift checks showed.** The rules behave as written. Each of the three signals can raise an alert on its own, and the advisory alone does not. But on a matched pair of fresh batches, both ordinary onboarding chats and new-tactic chats raised the alert. The alert is therefore an *input-change* warning. It also fires on ordinary hiring chats that differ from the training set. The cuts were not moved after seeing this. Details are in `reports/confirm_drift_policy.json`, `reports/confirm_drift_matched.json`, and `reports/verify_drift_policy.json`.

**Retraining.** `POST /retrain` is optional. It adds reviewed examples to the fit and keeps the previous model as `artifacts/model_prev.joblib`. It has not been run on the finished data, and no retrain improvement has been measured.

## Configuration

Set these in `.env`. Every value except the keys has a default in `scamshield/config.py`.

| Variable | Default | Meaning |
|---|---|---|
| `GEMINI_API_KEY` (and `_2` to `_9`) | empty | Only for data generation |
| `GEMINI_MODEL` | `gemini-3.8-flash` | Model used by `generate_data.py` |
| `MODEL_KIND` | `tfidf` | `tfidf` or `embed` |
| `ENABLE_LINK_CHECK` | `true` | Turn the link checker on or off |
| `SCAM_THRESHOLD` | `0.50` | Scam line |
| `UNCERTAIN_LOW` / `UNCERTAIN_HIGH` | `0.35` / `0.65` | Uncertain band |
| `DRIFT_WINDOW` | `40` | Predictions in the drift window |
| `DRIFT_MIN_SAMPLES` | `15` | Minimum predictions before drift is assessed |
| `CONFIDENCE_DROP_ALERT` | `0.10` | Alert on confidence drop |
| `UNFAMILIAR_RISE_ALERT` | `0.20` | Alert on unfamiliar-rate rise |
| `UNCERTAIN_RISE_ALERT` | `0.15` | Alert on uncertain-rate rise |
| `DRIFT_FALLBACK_THRESHOLD` | `0.20` | Review floor while an alert is active |
| `API_URL` | `http://localhost:8000` | Where the UI finds the API |

The drift cuts and policy are frozen. Don't retune them after looking at a later batch.

## Project layout

```
scamshield/
├── scamshield/      Core package: api, model, training, service, context rules,
│                    indicators, links, monitoring, config
├── ui/              Streamlit app and styles
├── scripts/         Train, generate and prepare data, review data, drift checks
├── tests/           Unit tests
├── data/
│   ├── raw/         Generated chats, one file per split and label
│   ├── processed/   Frozen train, test, shifted, and shifted-stream splits
│   ├── seed/        Hand-written and reviewed examples
│   ├── confirm/     Evaluation batches written before scoring
│   └── demo/        Chats for the UI demo
├── reports/         Metrics and drift-check results (JSON)
├── artifacts/       Trained model (git-ignored)
├── logs/            Prediction log database (git-ignored)
├── Dockerfile
└── docker-compose.yml
```

## Testing

```powershell
uv run python -m unittest discover -s tests
uv run python scripts/review_data.py
```

`review_data.py` is read-only. Run it again whenever a raw data file changes.

## Limitations

- **Synthetic data.** The model has never seen a real victim's chat. Real scam wording may differ.
- **Perfect original scores don't transfer.** Use the new-tactic and fresh-scenario results as the guide to behaviour on unfamiliar wording.
- **A human stays in the loop on purpose.** The raw classifier misses 10 of 40 new-tactic chats, and legitimate onboarding chats are all queued as unfamiliar.
- **The drift alert is noisy on ordinary hiring chats** that differ from the training set. Treat it as a prompt to look, not proof of a new scam.
- **Not a verification service.** A low score never means the job is real. The tool doesn't contact recruiters, open links, or stop payments.
- **Unproven impact.** There is no pilot data yet, so deposits prevented is unmeasured. The proposed first pilot is one university career centre with a person reading the queue.

## AI tools used

- **Gemini** (`GEMINI_MODEL`) writes the synthetic chats through `scripts/generate_data.py`.
- **Cursor's coding assistant** helped write the service, the review scan, and the docs. The team is responsible for explaining the data, the model, the unfamiliarity score, and the drift rules.

## Further reading

- [IMPACT.md](IMPACT.md): the problem in Sri Lanka, sources, and the pilot path
- [PITCH.md](PITCH.md): the eight-minute talk track and demo script
- [PLAN.md](PLAN.md): the build plan
