# ScamShield LK

An ML service that warns Sri Lankan job seekers when a recruitment chat turns into a task-job scam, monitors shifting scam tactics, and routes uncertain cases to human review.

**Who it is for:** university students, school leavers, and other job seekers who receive "part-time online job" offers on WhatsApp, Telegram, and social media. A career adviser can paste the chat. The service does not message anyone, open links, or send money.

The score on a single chat is not a measured accuracy. Held-out numbers are in the tables below. They come from the frozen splits, not from a raw file.

## Start here

From this directory (`scamshield/`):

```powershell
uv sync
copy .env.example .env
```

Put `GEMINI_API_KEY` in `.env` only if you are generating data. The key stays out of the repo. `.env.example` lists the names and nothing else.

`MODEL_KIND=tfidf` is the default and does not download an embedding model. For the multilingual embedding model:

```powershell
uv sync --group embed
```

Then set `MODEL_KIND=embed` in `.env`. If that download fails, leave `MODEL_KIND=tfidf`.

Train a model before the API will analyse a chat. Do this only after the raw files are finished and `scripts/prepare_data.py` has been run. A partial `data/raw` file is not a split.

```powershell
uv run python scripts/prepare_data.py
uv run python scripts/train.py --kind tfidf
```

Two processes:

```powershell
uv run uvicorn scamshield.api:app --host 127.0.0.1 --port 8000
uv run streamlit run ui/app.py
```

Open the Streamlit URL it prints (port 8501). Health check: `http://127.0.0.1:8000/health`.

`uv.lock` pins the dependency set that `uv sync` installs. These `uv` commands are the start path when Docker is not running.

Container start, from this same directory. The image trains the TF-IDF model from `data/processed` while it builds. It does not read a Gemini key and it does not install the embedding model.

```powershell
docker compose up --build
```

Open `http://127.0.0.1:8501`. Health check: `http://127.0.0.1:8000/health`. The UI container calls the API at `http://api:8000`. Stop with `docker compose down`.

Checks that do not need a finished dataset:

```powershell
uv run python -m unittest discover -s tests
uv run python scripts/review_data.py
```

`review_data.py` is read-only. Run it again whenever a file in `data/raw/` finishes. It exits 1 if it finds a real phone number, NIC number, bank account, named real organisation, off-example link, or a broken row. Warnings, which do not fail the run, cover a possible wrong label, an unrealistic chat, and a shifted pretext that showed up in train or test. A trailing half-written line is reported as still in progress.

## Problem

Task-job scams start as a friendly part-time offer, move through small paid tasks, show earnings on a dashboard, and then ask for a fee: registration, a task-wallet top-up, a "merchant" deposit, or a payment before withdrawal. Sri Lanka CERT and the CID have described fake job offers and work-from-home schemes on WhatsApp, Telegram, and other chat apps. See [IMPACT.md](IMPACT.md).

The product answers three questions a career adviser can check in front of a student:

1. Does this chat carry a scam signal, and which phrases support that?
2. Did the signal appear only after the fee, or was it there earlier? The timeline is the model's score after each message. It is not a scripted climb.
3. Are new chats behaving unlike the ones the model was trained on? If so, raise a drift alert and send uncertain cases to a person.

A "no strong scam signal" result is not a statement that the recruiter is genuine.

## Data

Every chat is synthetic, written during this build, and stays in the repo only as training and test material. Nothing here is sent to a phone, an email address, or a public channel.

| Source | What it is | Licence / method |
|---|---|---|
| `data/raw/*.jsonl` | Gemini conversations. Train and test use different prompt wording. The shifted file uses new scam pretexts and more Singlish. | Generated for this project. Not a public dataset. Model name is in each row's `source` field (`GEMINI_MODEL` in `.env`, default `gemini-3.8-flash`). |
| `data/seed/seed.jsonl` | Hand-written chats, if present. Folded into train by `prepare_data.py`. | Written by the team. |
| `data/demo/*.txt` | Two labelled synthetic demos for the UI. | Written by the team. |
| `data/official_domains.json` | Fictional companies and `.example` domains for the link checker. | Written by the team. |

Schema, one JSON object per line:

```json
{"label": 1, "category": "task_wallet_topup", "lang": "en",
 "source": "gemini-3.8-flash:prompt-v1-train", "split": "train",
 "messages": [{"sender": "Recruiter", "text": "..."}, {"sender": "Candidate", "text": "..."}]}
```

`label` 1 is a scam chat. `label` 0 is a legitimate recruitment chat, including hard cases such as salary figures and a bank account requested only after hiring.

| Split | Frozen size | Role |
|---|---|---|
| train | 682 (387 scam, 295 legit) | Fit the model. Includes the 12 hand-written seed chats. |
| test | 154 (76 scam, 78 legit) | Held-out results. Separate generation run. No near-duplicate of train was removed at similarity 0.9. |
| shifted | 195 before the cut (100 scam, 95 legit) | New pretexts that are not in the train prompt, plus more Singlish, including legitimate Singlish chats. Eval half: 98 (48 scam, 50 legit). Replay stream: 97 (52 scam, 45 legit). No stream row was a near-duplicate of the eval half. |

Safety rules used in generation and in the review scan:

- Fictional people and companies. No real banks or agencies as the recruiter.
- Phone numbers only as `07X-XXX-XXXX`. No NIC numbers and no real account numbers.
- Links only on the reserved `.example` domain (or `example.com` / `example.org` / `example.net`).

After the review scan, 29 chats that named a real bank or agency were removed: Sampath Bank, Hatton National Bank, Bank of Ceylon, the Foreign Ministry, and the Sri Lanka Bureau of Foreign Employment. Two of those chats named two organisations, which is why the scan reported 31 errors. Payroll chats stay. In each of them the company is paying the candidate, or the recruiter says there is no fee.

Generation commands, one file at a time:

```powershell
uv run python scripts/generate_data.py --split train   --label 1 --n 300
uv run python scripts/generate_data.py --split train   --label 0 --n 300
uv run python scripts/generate_data.py --split test    --label 1 --n 80
uv run python scripts/generate_data.py --split test    --label 0 --n 80
uv run python scripts/generate_data.py --split shifted --label 1 --n 100
uv run python scripts/generate_data.py --split shifted --label 0 --n 100
```

`prepare_data.py` is what freezes the splits. Do not run it on a file that is still growing. It has been run on the finished raw files. The frozen files are `data/processed/train.jsonl`, `test.jsonl`, `shifted.jsonl`, and `shifted_stream.jsonl`.

## Architecture

```
Streamlit UI (port 8501)
  Check chat | Monitoring | Review queue
            | HTTP
FastAPI (port 8000)
  /analyze  /replay  /monitoring  /review  /retrain
  parse chat -> classifier (score + unfamiliarity)
             -> phrase indicators (explanation only)
             -> links.check_urls (optional)
             -> SQLite log -> drift check -> review queue
```

The verdict comes from the classifier. Phrase lists and the link checker explain a chat. They do not decide the label.

**Model.** Default: word and character TF-IDF plus logistic regression. Optional: `paraphrase-multilingual-MiniLM-L12-v2` embeddings plus logistic regression (`MODEL_KIND=embed`).

**Unfamiliarity.** One minus the cosine similarity to the nearest training example. The deployed model is fit on 80% of train. The other 20% is used only to set the unfamiliarity cut (95th percentile on that slice) and the drift reference. Reviewed extras can be added to the fit later. They are not added to that 20%.

**Link checker.** Text only, no network calls. `ENABLE_LINK_CHECK=false` turns it off. A missing or crashing checker is skipped. No flags means risk `low`, which is not "safe". A strong flag is `high` on its own: `IP_HOST`, `CLAIMED_COMPANY_MISMATCH` (the chat names a company in `official_domains.json` and the host is not that company's domain or a subdomain of it), `LOOKALIKE`, and `APK_DOWNLOAD`. Any number of weak flags stays `medium`: `AT_SYMBOL`, `SHORTENER`, `CHAT_REDIRECT`, `BRAND_IN_SUBDOMAIN`, `FREE_HOSTING_FORM`, `PUNYCODE`, and `MANY_SUBDOMAINS`. See `scamshield/links.py`.

## Evaluation

Filled from the frozen splits. The first table is the saved model, word and character TF-IDF plus logistic regression (`artifacts/model.joblib`, version `tfidf-20261017T054258`). `reports/metrics.json` is that run, including the embedding comparison. Quote the tables, which match that file.

| Set | n | Precision (scam) | Recall (scam) | False positives | Review rate |
|---|---|---|---|---|---|
| Held-out test | 154 | 1.000 | 1.000 | 0 | 7 of 154 (4.5%) |
| Shifted eval | 98 | 1.000 | 1.000 | 0 | 10 of 98 (10.2%) |

False positives means legitimate chats scored as a scam signal. Review rate is the share of that frozen set with an uncertain score (0.35 to 0.65) or an unfamiliarity above the cut from the validation slice. A chat can be both, so the rate is not the sum of the two. Drift fallback is not included: it only adds chats while a drift alert is already on. The test replay is still not queued. This column is the share that meets the standing review rule.

| Model | Test precision | Test recall | Test false positives | Shifted precision | Shifted recall |
|---|---|---|---|---|---|
| TF-IDF + logistic regression | 1.000 | 1.000 | 0 | 1.000 | 1.000 |
| Multilingual embeddings + logistic regression | 0.962 | 0.987 | 3 | 0.941 | 1.000 |

The embedding model also has 3 false positives on the shifted eval (47 of 50 legitimate chats scored as legitimate). Its scam recall there is 1.000 (48 of 48).

TF-IDF is correct on every held-out chat, including the shifted eval half. That is a property of this synthetic set, which reuses a lot of the same fee and task wording. It is not evidence that a real WhatsApp chat would be scored this cleanly. The embedding model is where the misses are. Some train and test scams already use a pretext reserved for the shifted set (VIP, tax clearance, combo or lucky order). Those chats were left in, so the shifted eval is not a fully unseen-pretext test.

On the TF-IDF model, unfamiliar chats are 3.2% of the test set and 8.2% of the shifted eval. Labels can be right while the chat is still unlike the training slice.

Reproduce the comparison with the embed extra installed. The saved file stays TF-IDF:

```powershell
uv sync --group embed
uv run python scripts/train.py --kind tfidf --compare
```

Thresholds in `scamshield/config.py` stayed at the defaults (`SCAM_THRESHOLD` 0.50, uncertain band 0.35–0.65, drift window 40). They were not tuned on a development batch, and they were not moved after these shifted numbers.

## Monitoring and drift response

Every `/analyze` and replay is logged in SQLite (`logs/predictions.db`): score, chosen-side score `max(score, 1 − score)`, unfamiliarity, and whether the row was sent to review. Chat text is stored only for rows that enter the queue.

Drift uses the last 40 predictions from the current model version only, compared with that model's validation reference:

- mean chosen-side score drops by more than 0.10, or
- unfamiliar rate rises by more than 20 points, or
- uncertain rate (score between 0.35 and 0.65) rises by more than 15 points.

The window needs at least 15 predictions. The UI then shows an alert banner.

Response today: the banner, and uncertain or unfamiliar live chats and shifted-stream replays go to the review queue. While a drift alert is active, chats at or above `DRIFT_FALLBACK_THRESHOLD` (0.20) also go to review.

The shifted-stream button was replayed on `tfidf-20261017T054258` after the log was cleared. It sends 80 of the 97 stream chats. The last 40 did not raise a drift alert: mean chosen-side score 0.86 against a reference of 0.86, unfamiliar rate 2% against 5%, and uncertain rate 0% against 3%. Six of those 80 chats went to the review queue (five unfamiliar, one uncertain). Scoring the remaining 17 the same way still did not raise an alert. The thresholds were not changed after this replay.

The test replay is a monitoring control. Those rows are logged and are not queued, and they cannot be labelled into a later retrain. Retrain (`POST /retrain`) is optional. It keeps the previous file as `artifacts/model_prev.joblib`. It has not been run on the finished data.

## AI tools

- **Gemini** (`GEMINI_MODEL`, default `gemini-3.8-flash`) writes the synthetic chats via `scripts/generate_data.py`. The API key is local.
- **Cursor's coding assistant** was used while writing the service, the review scan, and these docs. The team still has to be able to explain the data, the model, the unfamiliarity score, and the drift rules.

## Pitch and impact

- Impact, one page: [IMPACT.md](IMPACT.md)
- Talk track, with the same result lines: [PITCH.md](PITCH.md)
- Build plan: [PLAN.md](PLAN.md)
