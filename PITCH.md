# Pitch outline (8 minutes)

This is the talk track, not the PDF. The README result tables are filled from the frozen splits. Read those numbers. Do not read counts from a raw file.

Speaker order can change. Everyone should be able to answer a question on the data rules, the model, the unfamiliarity score, and why a test replay cannot be labelled into training.

## 1. Problem — 1 minute

Task-job scams in Sri Lanka start as a part-time chat offer. The student does a few likes or ratings, sees a balance, and is then told to pay a fee to continue or to withdraw.

Who loses the money: students and school leavers. The Ministry of Higher Education reports 143,203 Z-score undergraduates in the state system, inside a wider state higher-education enrolment of about 444,057, and a 2023 A/L cycle where 173,444 students were eligible for university and about 43,204 places were expected. Many of those students are on Mahapola or a bursary (92,550 received that support in 2024).

CERT's complaint figures, as reported by the Daily Mirror on 28 June 2025: 7,210 online-scam complaints in 2024, about 1,440 of them financial fraud, including job-offer fraud. The Central Bank opened Be Scam Proof month on 2 June 2026 and named students among the people the campaign has to reach. One CBSL teaching example of this exact scam is a Rs. 150,000 deposit for a job that then disappears.

Point at the chat, not at a national loss total we do not have.

## 2. Solution — 1 minute

ScamShield LK is for a career adviser sitting with a student who already received the chat.

They paste it. The service returns **Scam signal detected** or **No strong scam signal detected**, a score, the phrases that support the warning, and a score after every message. If the chat is uncertain or unlike the training chats, it goes to a person. If a batch of new chats drifts, the screen shows an alert.

"No strong scam signal" does not mean the recruiter is genuine. We do not message the recruiter, open the link, or move money.

## 3. Live demo — 2 to 3 minutes

Use the two files in `data/demo/`. Both are synthetic.

1. Paste `legit_recruitment.txt`. Read the verdict the screen actually shows. If it says no strong scam signal, add that this is not a verification.
2. Reveal `task_scam.txt` one message at a time, or paste the whole chat and walk the timeline. Say whether the score rose when the deposit and the pay-to-withdraw lines appeared. Do not promise that it will. Mention the highlighted phrases. If the link checker is on, the Bright Path link should show `CLAIMED_COMPANY_MISMATCH` because it is not on `brightpath.example`.
3. Monitoring tab: replay the **test** batch. Say that this replay is a control. It is logged and it is not sent to review, so it cannot be used to retrain.
4. Replay the **shifted** stream (new pretexts and more Singlish, including legitimate Singlish chats). Say what the banner actually does: whether chosen-side score fell, unfamiliar rate rose, or an alert fired. Uncertain shifted rows may sit in the review queue. Label one only if we are showing the stretch retrain. Otherwise stop at the queue.

If the shifted replay does not fire an alert, say so. The thresholds stay as frozen. We do not lower the window on stage.

## 4. How it is built — 1 to 2 minutes

- Chats are synthetic, from Gemini, plus a few we wrote. Train and test were separate generation runs. The shifted set uses pretexts that were not in the train prompt. Phone numbers are placeholders, links are `.example`, and there are no real NIC or account numbers. `scripts/review_data.py` is the check for labels and personal data.
- The verdict is a classifier: TF-IDF plus logistic regression, with an optional multilingual embedding model. Phrase lists only explain the verdict.
- Unfamiliarity is the distance from the nearest training example. It is set on a 20% slice of train that the deployed model never fits.
- Drift compares the last 40 predictions from this model version with that slice: chosen-side score down more than 0.10, unfamiliar rate up more than 20 points, or uncertain rate up more than 15 points. The response is the banner and the review queue. Test replays are excluded from retraining.

Results, read only from the README tables. These lines match that TF-IDF run:

- Held-out test: precision 1.000, recall 1.000, false positives 0, review rate 7 of 154 (4.5%), n 154
- Shifted eval: precision 1.000, recall 1.000, false positives 0, review rate 10 of 98 (10.2%), n 98
- TF-IDF vs embeddings: TF-IDF is 1.000 precision and 1.000 recall on both sets, with 0 false positives. Embeddings are test precision 0.962, test recall 0.987, 3 test false positives; shifted precision 0.941, shifted recall 1.000, and 3 shifted false positives.

If someone asks why the TF-IDF score is perfect, say the chats are synthetic and share the same fee and task wording. Do not invent a shifted-set drop for TF-IDF. The misses are on the embedding model. Some train and test scams already use a shifted pretext, so this is not a clean unseen-pretext test. Do not describe a retrain improvement we did not measure.

## 5. Impact and next step — 1 minute

A first pilot is one university career centre: staff paste chats students bring to the desk. We would count chats checked, cases where the student had been asked to pay, and deposits the student then did not send. We do not have those counts today.

We are not claiming the 143,203 undergraduates as users. The first reach is whoever already walks into that one office. A contact line with CERT or a career-guidance unit can come later. It is not built, and we will not post these chats or send them to real numbers.

The Central Bank, CERT, and university career centres already talk to this audience. That is the adoption path. No partner agreement exists today.

## Do not say

- A precision, recall, false-positive, or review-rate number, until the README table has one.
- That the timeline always climbs, that drift always fires, or that retraining improved the shifted score.
- That "no strong scam signal" means the job is real.
- A figure that is not in the README table. `reports/metrics.json` is this frozen-split run, and the tables are copied from it.
- That we prevent a rupee total for the country.
