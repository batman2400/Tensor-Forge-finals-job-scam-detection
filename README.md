# ScamShield LK

An adviser-support prototype. A career adviser pastes a recruitment chat a student has already received. The service proposes a wording score, shows the phrases behind it, and sends uncertain, unfamiliar, and high-risk-link chats to a person. It does not message anyone, open links, or send money.

**Who it is for:** university students, school leavers, and other job seekers who receive "part-time online job" offers on WhatsApp, Telegram, and social media. The person using the screen is the adviser, not the student alone.

The deployed pipeline is `tfidf-20261017T080050+pipeline-20261017T080050`. The classification line is still 0.50. Read the raw classifier and the final verdict separately. On the inspected new-tactic batch the raw classifier is **30 of 40** and the final verdict is **40 of 40**, with 0 false positives. Ten of those final hits are English chats the payment rule lifts to 0.72; those ten are not queued. A one-time fresh set, not used for training, is raw **14 of 16** and final **16 of 16**, with 0 false positives and 7 of 16 sent to review. The original held-out test is still **154 of 154** and the original shifted eval is **98 of 98**. A "no strong scam signal" line is a wording assessment, not a statement that the recruiter is genuine.

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

The verdict comes from the classifier. A short check then moves the score when the chat is a refusal, a question, or a report of a scam, or when it tells the reader to send money without the usual fee words. A greeting with none of those words stays under the line. Phrase lists and the link checker explain a chat. They do not decide the label. Phrase hits inside a refusal are not shown.

**Model.** Default: word and character TF-IDF plus logistic regression. Optional: `paraphrase-multilingual-MiniLM-L12-v2` embeddings plus logistic regression (`MODEL_KIND=embed`).

**Unfamiliarity.** One minus the cosine similarity to the nearest training example. The deployed model is fit on 80% of train. The other 20% is used only to set the unfamiliarity cut (95th percentile on that slice) and the drift reference. Reviewed extras can be added to the fit later. They are not added to that 20%.

**Link checker.** Text only, no network calls. `ENABLE_LINK_CHECK=false` turns it off. A missing or crashing checker is skipped. No flags means risk `low`, which is not "safe". A strong flag is `high` on its own: `IP_HOST`, `CLAIMED_COMPANY_MISMATCH` (the chat names a company in `official_domains.json` and the host is not that company's domain or a subdomain of it), `LOOKALIKE`, and `APK_DOWNLOAD`. Any number of weak flags stays `medium`: `AT_SYMBOL`, `SHORTENER`, `CHAT_REDIRECT`, `BRAND_IN_SUBDOMAIN`, `FREE_HOSTING_FORM`, `PUNYCODE`, and `MANY_SUBDOMAINS`. See `scamshield/links.py`.

## Evaluation

Quote the layer table first, then the frozen-split tables. The saved model is word and character TF-IDF plus logistic regression (`artifacts/model.joblib`, fit `tfidf-20261017T080050`, pipeline `tfidf-20261017T080050+pipeline-20261017T080050`). The threshold was not lowered. `reports/layer_comparison.json` is this run. `reports/metrics.json` is the frozen-split run. The embedding block in that file is the earlier comparison and was not retrained.

Reviewed examples in `data/seed/reviewed_tactics.jsonl` were added only to the fit. The 40 new-tactic chats and the 40 onboarding chats stayed development data. `data/confirm/fresh_scenarios.jsonl` was written before this score and was not used to train or to move a threshold.

| Set | Role | Raw correct | Final correct | False positives | Sent to review | Silent scam misses |
|---|---|---|---|---|---|---|
| New tactics (`policy_shifted.jsonl`) | development, already inspected | 30 of 40 | 40 of 40 | 0 | 20 of 40 | 0 |
| Onboarding (`policy_legit.jsonl`) | development, already inspected | 40 of 40 | 40 of 40 | 0 | 40 of 40 | 0 |
| Fresh scenarios (`fresh_scenarios.jsonl`) | scored once | 14 of 16 | 16 of 16 | 0 | 7 of 16 | 0 |

Raw is the classifier probability. Final is that probability after the context rules. On the tactic batch the ten chats the rule changes are English, with raw scores from 0.472 to 0.498 lifted to 0.72, and none of those ten is queued. The Singlish half of that batch is inside the 30 raw hits. On the fresh set the two rule changes are an equipment bond (raw 0.446) and a joining clinic fee (raw 0.460). Both are unfamiliar, so both still reach review. The onboarding batch is all legitimate and all 40 still go to review, so a correct label there does not by itself save the adviser work.

An explicit password, PIN, or one-time-code request is the review reason `credential-request`. It does not change the classifier score. "Give me your banking password and the one-time code" scores 0.648 before and after the rules, and the queue reason is `uncertain,credential-request`. "They asked me to tell you to pay Rs 10000 to unlock your earnings" stays at its classifier score of 0.692, which is over the line. "Do not share an OTP" is not a credential request.

The tables below are the original frozen splits. They are real, and they are a different test from the fresh tactics.

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

TF-IDF is correct on every chat in the original held-out test and the original shifted eval. Those chats reuse a lot of the same fee and task wording. The fresh tactic batch is the measurement on different wording, and that is 21 of 40. Some train and test scams already use a pretext reserved for the shifted set (VIP, tax clearance, combo or lucky order), so the original shifted eval is not a fully unseen-pretext test. The embedding comparison is a second model on the original splits only. It is not deployed.

On the TF-IDF model, unfamiliar chats are 3.2% of the test set and 8.2% of the shifted eval. Labels can be right while the chat is still unlike the training slice.

Reproduce the comparison with the embed extra installed. The saved file stays TF-IDF:

```powershell
uv sync --group embed
uv run python scripts/train.py --kind tfidf --compare
```

Thresholds in `scamshield/config.py` stayed at the defaults (`SCAM_THRESHOLD` 0.50, uncertain band 0.35–0.65, drift window 40, confidence drop 0.10, unfamiliar-rate rise 0.20, uncertain-rate rise 0.15). They were not moved after the shifted numbers. Mean unfamiliarity was added after the shifted stream was inspected, so that stream is development data. The number stored as `novelty_mean_alert` is a one-sided Student-t prediction limit for the mean of a future 40-chat window: validation mean plus `t_{n-1, 0.99} * sd * sqrt(1/40 + 1/n)`. It is not a confidence interval for the validation mean, and the 0.01 tail probability is only the nominal rate under an i.i.d. normal model. It is not a measured false-alarm rate.

## Monitoring and drift response

Every `/analyze` and replay is logged in SQLite (`logs/predictions.db`): score, chosen-side score `max(score, 1 − score)`, unfamiliarity, and whether the row was sent to review. Chat text is stored only for rows that enter the queue.

Drift uses the last 40 predictions from the current pipeline version only, compared with that version's validation reference. Policy `three-signal-alert-v1` is frozen:

- **Drift alert:** mean chosen-side score drops by more than 0.10, or unfamiliar rate rises by more than 20 points, or uncertain rate (score between 0.35 and 0.65) rises by more than 15 points.
- **Advisory:** mean unfamiliarity rises above the window prediction limit stored on the model (`novelty_mean_alert`). The screen says “Input patterns differ from the reference—monitor closely.” That note does not raise the drift alert and does not send a chat to review by itself.
- **Individual review:** an uncertain score, an unfamiliar chat, or a high-risk link still queues that chat on its own.

The window needs at least 15 predictions.

The fitted classifier is `tfidf-20261017T080050`. The scoring rules and this policy are pipeline `tfidf-20261017T080050+pipeline-20261017T080050`. Rows logged under the previous pipeline stay in `logs/predictions.db` and are left out of the new window. The working log was not rewritten for this fit.

Response today: the alert banner, and uncertain or unfamiliar live chats and shifted-stream replays go to the review queue. While a drift alert is active, chats at or above `DRIFT_FALLBACK_THRESHOLD` (0.20) also go to review. The advisory does not do that.

The shifted stream is development data for the choice of mean unfamiliarity. On that stream the old normal approximation (limit 0.736) was crossed by 0.738. That gap is too small to treat as confirmation. The frozen Student-t limit, computed from the 137 validation scores only, is 0.739.

A first pair of short repetitive chats (`data/confirm/legit.jsonl` and `shifted.jsonl`) both crossed the limit. That pair is not the length of the training chats, so it mixes format with tactic. The limit was not moved.

A second pair keeps the limit frozen and matches the training shape: 40 chats each, 8 messages each, 20 English and 20 Singlish, median length 163 words for the legitimate control and 168 for the shifted tactics (training medians are 143 and 148). They were scored once into temporary databases. The working log was not used.

| Batch | Mean unfamiliarity | Unfamiliar rate | Chosen-side score | Alert |
|---|---|---|---|---|
| Matched legitimate control | 0.775 | 25% | 0.79 | yes, mean unfamiliarity only |
| Matched shifted tactics | 0.821 | 90% | 0.58 | yes, all four signals |

Both sit above 0.739. The shifted batch is farther out, and its confidence drop and uncertain rate would alert even without the mean-unfamiliarity rule. The matched legitimate control would not. Mean unfamiliarity alone still flags that control. That pair is development evidence for moving mean unfamiliarity to an advisory. The cuts were not moved. Details are in `reports/confirm_drift_matched.json`.

The revised policy was then frozen as `three-signal-alert-v1` and scored once on a new pair written before that score (`reports/policy_scenarios.json`). Same shape: 40 chats, 8 messages, 20 English and 20 Singlish. Word spans were 154–176 for onboarding chats and 158–168 for the new tactics (courier bond, training-seat fee, biometric card, night-shift kit, referral-wallet load). The working log was not used. The limit stayed 0.739.

| Batch | Mean unfamiliarity | Unfamiliar rate | Uncertain rate | Chosen-side score | Drift alert | Advisory |
|---|---|---|---|---|---|---|
| Onboarding control | 0.836 | 100% | 50% | 0.67 | yes, all three signals | yes |
| New tactics | 0.829 | 100% | 50% | 0.64 | yes, all three signals | yes |

The pre-written hope was that ordinary onboarding would stay quiet on the three signals. It did not. Both batches alert, and the onboarding chats are slightly more unfamiliar than the new tactics. On that earlier pipeline, accuracy on the onboarding batch was 1.0 and accuracy on the new tactics was 0.525. The chats were not edited after that score. Details are in `reports/confirm_drift_policy.json`. The later fit, above, is a different pipeline. It does not move these cuts.

A later API check on this same frozen policy (`reports/verify_drift_policy.json`) shows the rules do what they say: mean unfamiliarity alone stays an advisory, each of the three original signals can raise the alert by itself, and uncertain, unfamiliar, and high-risk-link chats still reach review during an advisory. That check does not show the alert can stay quiet on ordinary chats of this shape. Both the onboarding batch and the tactic batch still raise it. These results do not justify moving the cuts.

The Monitoring button **Replay unfamiliar writing** posts the `drift` sample. That sample is out-of-domain text, including biology writing, and it is not a set of job scams. A drift alert from that button shows that unfamiliar writing can trip the window. It is not evidence that the service detects evolving recruitment scams. The shifted-set replay is the job-chat control. The test replay stays out of review and out of retraining.

`scripts/review_data.py` last reported 0 errors and 127 warnings on the raw files. The warnings are possible wrong labels, unrealistic chats, and shifted pretexts that also appear in train or test. They still need a person to read them. The scan does not clear those rows.

The test replay is a monitoring control. Those rows are logged and are not queued, and they cannot be labelled into a later retrain. Retrain (`POST /retrain`) is optional. It keeps the previous file as `artifacts/model_prev.joblib`. It has not been run on the finished data.

## AI tools

- **Gemini** (`GEMINI_MODEL`, default `gemini-3.8-flash`) writes the synthetic chats via `scripts/generate_data.py`. The API key is local.
- **Cursor's coding assistant** was used while writing the service, the review scan, and these docs. The team still has to be able to explain the data, the model, the unfamiliarity score, and the drift rules.

## Pitch and impact

- Impact, one page: [IMPACT.md](IMPACT.md)
- Talk track, with the same result lines: [PITCH.md](PITCH.md)
- Build plan: [PLAN.md](PLAN.md)
