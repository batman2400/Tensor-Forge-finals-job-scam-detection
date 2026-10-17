# Pitch outline (8 minutes)

This is the talk track, not the PDF. The README result tables are filled from the frozen splits. Read those numbers. Do not read counts from a raw file.

Speaker order can change. Everyone should be able to answer a question on the data rules, the model, the unfamiliarity score, and why a test replay cannot be labelled into training.

## 1. Problem — 1 minute

Task-job scams in Sri Lanka start as a part-time chat offer. The student does a few likes or ratings, sees a balance, and is then told to pay a fee to continue or to withdraw.

Who loses the money: students and school leavers. The Ministry of Higher Education reports 143,203 Z-score undergraduates in the state system, inside a wider state higher-education enrolment of about 444,057, and a 2023 A/L cycle where 173,444 students were eligible for university and about 43,204 places were expected. Many of those students are on Mahapola or a bursary (92,550 received that support in 2024).

CERT's complaint figures, as reported by the Daily Mirror on 28 June 2025: 7,210 online-scam complaints in 2024, about 1,440 of them financial fraud, including job-offer fraud. The Central Bank opened Be Scam Proof month on 2 June 2026 and named students among the people the campaign has to reach. One CBSL teaching example of this exact scam is a Rs. 150,000 deposit for a job that then disappears.

Point at the chat, not at a national loss total we do not have.

## 2. Solution — 1 minute

ScamShield LK is an adviser-support prototype. A career adviser sits with a student who already received the chat.

They paste it. The service returns **Scam signal detected** or **No strong scam signal detected**, a score, the phrases that support the warning, and a score after every message. If the chat is uncertain or unlike the training chats, it goes to a person. If a batch of new chats drifts, the screen shows an alert. The person at the desk is the decision. The score is a draft.

Say the limitation in this minute, before the demo. On the inspected new-tactic batch the raw classifier is right on **30 of 40**. The final verdict is **40 of 40** because the payment rule lifts ten English chats, and those ten are not queued. The one-time fresh set is raw **14 of 16** and final **16 of 16**, with 7 of 16 sent to review. The original test sets are still 154 of 154 and 98 of 98. The line is still 0.50.

"No strong scam signal" does not mean the recruiter is genuine. We do not message the recruiter, open the link, or move money.

## 3. Live demo — 2 to 3 minutes

Use the two files in `data/demo/`. Both are synthetic.

1. Paste `legit_recruitment.txt`. Read the verdict the screen actually shows. If it says no strong scam signal, add that this is not a verification.
2. Reveal `task_scam.txt` one message at a time, or paste the whole chat and walk the timeline. Say whether the score rose when the deposit and the pay-to-withdraw lines appeared. Do not promise that it will. Mention the highlighted phrases. If the link checker is on, the Bright Path link should show `CLAIMED_COMPANY_MISMATCH` because it is not on `brightpath.example`.
3. Monitoring tab: replay the **test** batch. Say that this replay is a control. It is logged and it is not sent to review, so it cannot be used to retrain.
4. Leave **Replay unfamiliar writing** unpressed in the demo. That button sends out-of-domain text, including biology writing. An alert from it shows that text unlike the training chats can move the window. It is not a demonstration of evolving job scams. If a judge asks, say that in one sentence.
5. Mean unfamiliarity is an advisory. The alert is only a confidence drop over 0.10, an unfamiliar-rate rise over 20 points, or an uncertain-rate rise over 15 points. The advisory line is “Input patterns differ from the reference—monitor closely,” and it does not send chats to review by itself. Say that those rules were checked on the API and behaved that way. Then say the limitation: a fresh onboarding batch and a fresh new-tactic batch both raised the alert (chosen-side scores 0.67 and 0.64, unfamiliar rate 100% on both). The alert is an input-change warning, including on ordinary hiring chats. The policy is frozen. These results do not justify moving the cuts. Older log rows stay stored and are not part of pipeline `tfidf-20261017T080050+pipeline-20261017T080050`.

## 4. How it is built — 1 to 2 minutes

- Chats are synthetic, from Gemini, plus a few we wrote. Train and test were separate generation runs. The shifted set uses pretexts that were not in the train prompt. Phone numbers are placeholders, links are `.example`, and there are no real NIC or account numbers. `scripts/review_data.py` is the check for labels and personal data.
- The verdict is a classifier: TF-IDF plus logistic regression, with an optional multilingual embedding model. Phrase lists only explain the verdict.
- Unfamiliarity is the distance from the nearest training example. It is set on a 20% slice of train that the deployed model never fits.
- Drift compares the last 40 predictions from the current pipeline version with the validation slice. The alert is a chosen-side score down more than 0.10, an unfamiliar rate up more than 20 points, or an uncertain rate up more than 15 points. Mean unfamiliarity above the stored limit is only an advisory. An uncertain chat, an unfamiliar chat, or a high-risk link still goes to review on its own. The fitted classifier and the pipeline version are different ids. Test replays are excluded from retraining.

Results, in this order. Pipeline `tfidf-20261017T080050+pipeline-20261017T080050`. The line is still 0.50.

- New-tactic development batch: raw 30 of 40, final 40 of 40, 0 false positives, 20 of 40 reviewed. Ten English chats are lifted by the payment rule and are not queued.
- Onboarding development batch: raw and final 40 of 40, and all 40 still go to review.
- Fresh scenarios, scored once: raw 14 of 16, final 16 of 16, 0 false positives, 7 of 16 reviewed, 0 silent misses.
- Held-out test: 154 of 154, precision 1.000, recall 1.000, false positives 0, review rate 7 of 154 (4.5%).
- Original shifted eval: 98 of 98, precision 1.000, recall 1.000, false positives 0, review rate 10 of 98 (10.2%).
- If asked about the two old misses: a banking password and one-time code now scores 0.648 and is queued as `uncertain,credential-request`. The score was not forced. “They asked me to tell you to pay Rs 10000” stays at 0.692. “Do not share an OTP” is not a credential request.
- Embeddings, only if asked: the earlier run, not this fit. Test precision 0.962, test recall 0.987, 3 test false positives; shifted precision 0.941, shifted recall 1.000, 3 shifted false positives. That model is not deployed.

If someone asks why the original TF-IDF score is perfect, say those chats are synthetic and share the same fee and task wording. Then give the 21 of 40. Some train and test scams already use a shifted pretext, so the original shifted eval is not a clean unseen-pretext test. Do not describe a retrain improvement we did not measure. Retraining was checked in memory and the deployed file was left in place.

## 5. Impact and next step — 1 minute

A first pilot is one university career centre, with a person reading the queue: staff paste chats students bring to the desk. The raw 30 of 40, and the onboarding batch that still queues all 40 chats, are why that person stays in the loop. We would count chats checked, cases where the student had been asked to pay, and deposits the student then did not send. We do not have those counts today. The raw-file scan has 0 errors and 127 warnings, and those warnings still need a person.

We are not claiming the 143,203 undergraduates as users. The first reach is whoever already walks into that one office. A contact line with CERT or a career-guidance unit can come later. It is not built, and we will not post these chats or send them to real numbers.

The Central Bank, CERT, and university career centres already talk to this audience. That is the adoption path. No partner agreement exists today.

## Do not say

- A precision, recall, false-positive, or review-rate number, until the README table has one.
- That the timeline always climbs, that drift always fires, or that retraining improved the shifted score.
- That "no strong scam signal" means the job is real.
- That 154 of 154, 98 of 98, or a final 40 of 40 is the raw accuracy on new wording. The raw line on the inspected tactic batch is 30 of 40. The one-time fresh line is raw 14 of 16.
- That **Replay unfamiliar writing** detects evolving job scams. That sample is out-of-domain text.
- A figure that is not in the README. `reports/metrics.json` is the frozen-split run. `reports/confirm_drift_policy.json` is the 21 of 40 run.
- That we prevent a rupee total for the country.
