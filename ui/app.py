"""ScamShield LK demo UI. Talks to the FastAPI service over HTTP.

Run the API first, then:
    uv run streamlit run ui/app.py
"""
import html
import sys
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scamshield import config  # noqa: E402
from scamshield.conversation import parse_conversation  # noqa: E402
from scamshield.links import UNVERIFIED_NOTICE  # noqa: E402

st.set_page_config(
    page_title="ScamShield LK",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

API = config.API_URL.rstrip("/")
STYLES = Path(__file__).with_name("styles.css").read_text(encoding="utf-8")


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def break_id(value) -> str:
    return esc(value).replace("+", "<wbr>+")


def show(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def api(method: str, path: str, **kwargs):
    try:
        resp = requests.request(method, f"{API}{path}", timeout=120, **kwargs)
    except requests.RequestException as e:
        st.error(
            f"API is not reachable at {API}. Start it with: "
            f"uv run uvicorn scamshield.api:app --port 8000\n\n{e}"
        )
        st.stop()
    if resp.status_code >= 400:
        detail = (
            resp.json().get("detail", resp.text)
            if resp.headers.get("content-type", "").startswith("application/json")
            else resp.text
        )
        st.error(f"{resp.status_code}: {detail}")
        return None
    return resp.json()


def tone_for(label: str, uncertain: bool) -> str:
    if uncertain:
        return "warn"
    return "danger" if label == "scam" else "ok"


def banner(kind: str, title: str, lines: list[str] | None = None) -> None:
    body = "".join(f'<div class="ss-banner-line">{esc(line)}</div>' for line in lines or [])
    css = {"warn": "ss-warn", "danger": "ss-danger-banner", "info": "ss-info", "ok": "ss-ok-banner"}[kind]
    show(f'<div class="ss-banner {css}"><strong>{esc(title)}</strong>{body}</div>')


def metric(label: str, value: str, note: str, ref: str = "") -> str:
    ref_html = f'<div class="ss-metric-ref">{esc(ref)}</div>' if ref else ""
    return (
        '<div class="ss-metric">'
        f'<div class="ss-metric-label">{esc(label)}</div>'
        f'<div class="ss-metric-value">{esc(value)}</div>'
        f'<div class="ss-metric-note">{esc(note)}</div>'
        f"{ref_html}</div>"
    )


def verdict_banner(result: dict) -> None:
    tone = tone_for(result["label"], result["uncertain"])
    verdict = result.get("verdict") or (
        "Scam signal detected" if result["label"] == "scam" else "No strong scam signal detected"
    )
    eyebrow = "Uncertain score" if result["uncertain"] else (
        "Scam signal" if result["label"] == "scam" else "No strong scam signal"
    )
    review = "Queued for a person" if result["routed_to_review"] else "Not queued"
    if result.get("review_reason"):
        review = f"{review} · {result['review_reason']}"
    width = max(0, min(100, round(float(result["score"]) * 100)))
    company = result.get("claimed_company")
    company_line = (
        f" Name read from the chat: {company}. It was not checked against a registry."
        if company else ""
    )
    show(
        f'<div class="ss-verdict ss-{tone}">'
        '<div class="ss-verdict-top"><div>'
        f'<div class="ss-kicker">{esc(eyebrow)}</div>'
        f'<div class="ss-verdict-title">{esc(verdict)}</div>'
        f'<div class="ss-pill">{esc(review)}</div>'
        "</div>"
        f'<div class="ss-score">{result["score"]:.0%}</div></div>'
        f'<div class="ss-track"><div class="ss-fill" style="width:{width}%"></div></div>'
        '<p class="ss-fine">Draft for the adviser. A score is not proof the job is real. '
        "This tool does not open links or message the recruiter."
        f"{esc(company_line)} Prediction {esc(result.get('prediction_id'))}.</p>"
        "</div>"
    )


def verdict_metrics(result: dict) -> None:
    show(
        '<div class="ss-metrics">'
        + metric("Scam score", f"{result['score']:.0%}", "Model score for this chat. Not a measured accuracy.")
        + metric(
            "Chosen-side score",
            f"{result['confidence']:.0%}",
            "Score on the side the model chose. Not the distance from 50/50.",
        )
        + metric(
            "Unfamiliarity",
            f"{result['novelty']:.0%}",
            "Distance from the nearest training chat. Not a measured accuracy.",
        )
        + metric(
            "Human review",
            "Yes" if result["routed_to_review"] else "No",
            result.get("review_reason") or "No review reason on this chat.",
        )
        + "</div>"
    )


def chip(text: str, kind: str = "") -> str:
    css = f"ss-chip ss-chip-{kind}" if kind else "ss-chip"
    return f'<span class="{css}">{esc(text)}</span>'


def risk_chip(risk: str) -> str:
    if risk == "high":
        return chip("High", "danger")
    if risk == "medium":
        return chip("Medium", "warn")
    return chip("Unverified")


def render_indicators(indicators: list[dict]) -> None:
    if not indicators:
        show('<div class="ss-panel"><div class="ss-panel-title">Why it was flagged</div><div class="ss-empty">No warning phrases in this chat.</div></div>')
        return
    rows = []
    for ind in indicators:
        rows.append(
            '<div class="ss-ind"><div>'
            f'<strong>{esc(ind["label"])}</strong>'
            f'<code>{esc(ind["match"])}</code></div>'
            f'{chip(ind["code"])}</div>'
        )
    show('<div class="ss-panel"><div class="ss-panel-title">Why it was flagged</div>' + "".join(rows) + "</div>")


def render_links(links: list[dict] | None) -> None:
    if links is None:
        return
    if not links:
        show(
            '<div class="ss-panel"><div class="ss-panel-title">Links</div>'
            '<div class="ss-empty">No links found in this chat. Website legitimacy has not been verified.</div></div>'
        )
        return
    rows = []
    for link in links:
        flags = link.get("flags") or []
        flag_html = "".join(chip(flag["code"]) for flag in flags) or chip("none")
        reasons = "".join(
            f'<div class="ss-link-reason">{esc(flag["reason"])}</div>'
            for flag in flags if flag.get("reason")
        )
        rows.append(
            '<div class="ss-linkcard">'
            f'<div class="ss-case-top"><div class="ss-link-host">{esc(link["host"])}</div>'
            f'{risk_chip(link["risk"])}</div>'
            f'<div class="ss-link-url">{esc(link["url"])}</div>'
            f'<div class="ss-chips">{flag_html}</div>{reasons}</div>'
        )
    notice = ""
    if all(link.get("risk") == "low" for link in links):
        notice = f'<div class="ss-empty">{esc(UNVERIFIED_NOTICE)}</div>'
    elif any(link.get("risk") != "high" for link in links):
        notice = '<div class="ss-empty">Website legitimacy has not been verified.</div>'
    show('<div class="ss-panel"><div class="ss-panel-title">Links</div>' + "".join(rows) + notice + "</div>")


def render_timeline(timeline: list[dict]) -> None:
    show('<div class="ss-section">Risk timeline</div>')
    show(
        '<p class="ss-note">Each point is the model score after that message. '
        "The dashed line is 0.50. A score on or above that line is a scam signal on the wording, "
        "not a measured accuracy.</p>"
    )
    frame = pd.DataFrame([
        {
            "step": str(i + 1),
            "sender": row["sender"],
            "score": row["cumulative_score"],
            "message": row["text"],
            "side": "At or above 0.50" if row["cumulative_score"] >= config.SCAM_THRESHOLD else "Below 0.50",
        }
        for i, row in enumerate(timeline)
    ])
    order = frame["step"].tolist()
    try:
        import altair as alt

        x = alt.X(
            "step:N",
            sort=order,
            title=None,
            axis=alt.Axis(grid=False, labelColor="#5e6a7a", domainColor="#d5dae1"),
        )
        y = alt.Y(
            "score:Q",
            title=None,
            scale=alt.Scale(domain=[0, 1]),
            axis=alt.Axis(
                format=".0%",
                labelColor="#5e6a7a",
                gridColor="#e4e7ec",
                domainColor="#d5dae1",
            ),
        )
        tooltips = [
            alt.Tooltip("step:N", title="Message"),
            alt.Tooltip("sender:N", title="Sender"),
            alt.Tooltip("score:Q", title="Score", format=".0%"),
            alt.Tooltip("message:N", title="Text"),
        ]
        base = alt.Chart(frame).encode(x=x, y=y, tooltip=tooltips)
        line = base.mark_line(color="#1f4e79", strokeWidth=2)
        points = base.mark_circle(size=70, stroke="#ffffff", strokeWidth=1).encode(
            color=alt.Color(
                "side:N",
                scale=alt.Scale(domain=["Below 0.50", "At or above 0.50"], range=["#1f4e79", "#b42318"]),
                legend=alt.Legend(title=None, orient="bottom", labelColor="#5e6a7a", labelFont="Source Sans"),
            )
        )
        rule = (
            alt.Chart(pd.DataFrame({"y": [config.SCAM_THRESHOLD]}))
            .mark_rule(strokeDash=[5, 4], color="#8a5a12", strokeWidth=1)
            .encode(y="y:Q")
        )
        chart = (
            alt.layer(line, rule, points)
            .properties(height=280)
            .configure(background="transparent")
            .configure_view(strokeWidth=0)
        )
        st.altair_chart(chart, use_container_width=True)
    except Exception:
        fallback = frame.rename(columns={"step": "message", "score": "scam score"})
        st.line_chart(fallback, x="message", y="scam score", height=260)

    steps = []
    for i, row in enumerate(timeline):
        tags = "".join(chip(ind["code"]) for ind in row["indicators"])
        above = row["cumulative_score"] >= config.SCAM_THRESHOLD
        hot = " ss-hot" if above else ""
        fill = "ss-fill ss-fill-hot" if above else "ss-fill"
        who = row["sender"].strip().lower()
        who_css = "ss-who-recruiter" if who == "recruiter" else "ss-who-candidate" if who == "candidate" else ""
        width = max(0, min(100, round(row["cumulative_score"] * 100)))
        steps.append(
            '<div class="ss-step">'
            f'<div class="ss-step-index">{i + 1:02d}</div>'
            '<div class="ss-step-body">'
            '<div class="ss-step-head">'
            f'<span class="ss-who {who_css}">{esc(row["sender"])}</span>'
            f'<span class="ss-step-score{hot}">{row["cumulative_score"]:.0%}</span>'
            "</div>"
            f'<p>{esc(row["text"])}</p>'
            f'<div class="ss-chips">{tags}</div>'
            f'<div class="ss-track ss-track-sm"><div class="{fill}" style="width:{width}%"></div></div>'
            "</div></div>"
        )
    show('<div class="ss-panel ss-steps">' + "".join(steps) + "</div>")


def render_result(result: dict) -> None:
    verdict_metrics(result)
    if result["routed_to_review"]:
        banner("warn", "Sent to human review", [result["review_reason"] or ""])
    if result.get("credential_request"):
        banner("warn", "Credential request", [
            "This chat asks for a password, PIN, or one-time code. "
            "The wording score was not changed. A person should check it.",
        ])
    high_links = [link for link in (result.get("links") or []) if link.get("risk") == "high"]
    if high_links:
        lines = ["A link in this chat needs a person to check it. The wording score is separate."]
        for link in high_links:
            lines.append(f"{link['url']} goes to {link['host']}.")
            for flag in link.get("flags") or []:
                if flag.get("reason"):
                    lines.append(flag["reason"])
        banner("warn", "Link needs a person", lines)
    if result.get("expected_domain"):
        banner("info", "Adviser-provided domain", [
            f"{result['expected_domain']}. {result.get('expected_domain_note') or ''}".strip(),
        ])
    if result["drift_active"]:
        banner("danger", "Drift alert is active", ["Uncertain cases are being routed to review."])
    for note in result.get("advisory") or []:
        banner("warn", "Monitor closely", [note])

    show('<div class="ss-section">Evidence</div>')
    left, right = st.columns(2, gap="medium")
    with left:
        render_indicators(result["indicators"])
    with right:
        if result.get("links") is None:
            show(
                '<div class="ss-panel"><div class="ss-panel-title">Links</div>'
                '<div class="ss-empty">Link checking is off for this service.</div></div>'
            )
        else:
            render_links(result.get("links"))

    timeline = result.get("timeline") or []
    if timeline:
        render_timeline(timeline)


def sidebar(health: dict) -> None:
    loaded = bool(health.get("model_loaded"))
    with st.sidebar:
        show(
            '<div class="ss-brand"><div class="ss-mark">S</div><div>'
            '<div class="ss-brand-name">ScamShield</div>'
            '<div class="ss-brand-sub">LK · Career desk</div></div></div>'
        )
        status = "ss-on" if loaded else "ss-off"
        label = "Model loaded" if loaded else "No model loaded"
        rows = [
            ("Pipeline", health.get("model_version") or "not loaded"),
        ]
        if health.get("fit_version"):
            rows.append(("Fitted classifier", health["fit_version"]))
        if health.get("drift_policy"):
            rows.append(("Drift policy", health["drift_policy"]))
        body = "".join(
            f'<div class="ss-side-row"><span>{esc(name)}</span><b>{break_id(value)}</b></div>'
            for name, value in rows
        )
        show(
            '<div class="ss-side-card">'
            f'<div class="ss-status {status}"><i></i>{label}</div>'
            f'<div style="height:10px"></div>{body}</div>'
        )
        if not loaded:
            st.caption("Train first: python scripts/train.py")
        st.caption(API)
        st.divider()
        st.caption("Clears the prediction log and the review queue.")
        if st.button("Reset prediction log", use_container_width=True):
            st.session_state["confirm_reset"] = True
        if st.session_state.get("confirm_reset"):
            if st.button("Confirm reset", type="primary", use_container_width=True):
                api("POST", "/admin/reset-logs")
                st.session_state["confirm_reset"] = False
                st.session_state.pop("result", None)
                st.session_state.pop("replay", None)
                st.rerun()


def check_tab() -> None:
    demos = {
        "Blank": "",
        "Legit recruitment": (config.DEMO_DIR / "legit_recruitment.txt").read_text(encoding="utf-8"),
        "Task-job scam": (config.DEMO_DIR / "task_scam.txt").read_text(encoding="utf-8"),
    }
    composer, result_col = st.columns([1.12, 0.88], gap="large")
    with composer:
        with st.container(border=True):
            choice = st.radio("Sample chat", list(demos), horizontal=True)
            text = st.text_area(
                "Paste a WhatsApp or Telegram chat",
                value=demos[choice],
                height=210,
                key=f"chat-{choice}",
                placeholder="Recruiter: ...\nCandidate: ...",
            )
            messages = parse_conversation(text) if text.strip() else []
            if text.strip():
                st.caption(f"{len(messages)} message{'s' if len(messages) != 1 else ''} ready.")
            expected_domain = st.text_input(
                "Expected employer domain (optional)",
                placeholder="lakview.example",
                help="A website you looked up yourself. Leave this blank unless you have that name from outside the chat. "
                     "Do not copy a link out of the chat and treat it as verified.",
            )
            st.caption(
                "Leave this blank unless you looked the name up outside the chat. "
                "Do not paste a link from the chat and treat it as verified."
            )
            analyze = st.button("Analyze chat", type="primary", disabled=not text.strip(), use_container_width=True)

    result = st.session_state.get("result")
    if result and (
        st.session_state.get("analyzed_text") != text
        or st.session_state.get("analyzed_domain") != expected_domain.strip()
    ):
        result = None

    if analyze:
        payload = {"text": text, "source": "ui"}
        if expected_domain.strip():
            payload["expected_domain"] = expected_domain.strip()
        with st.spinner("Reading the chat"):
            fresh = api("POST", "/analyze", json=payload)
        if fresh:
            st.session_state["result"] = fresh
            st.session_state["analyzed_text"] = text
            st.session_state["analyzed_domain"] = expected_domain.strip()
            result = fresh

    with result_col:
        if result:
            verdict_banner(result)
        else:
            show(
                '<div class="ss-guide ss-guide-stack">'
                '<article><div class="ss-num">1</div><strong>Paste the chat</strong>'
                '<p>Use a sample, or a WhatsApp or Telegram thread a student brought to the desk.</p></article>'
                '<article><div class="ss-num">2</div><strong>Read the draft</strong>'
                '<p>The screen returns a wording score, the phrases behind it, and a score after each message.</p></article>'
                '<article><div class="ss-num">3</div><strong>A person decides</strong>'
                '<p>Uncertain, unfamiliar, credential, and high-risk-link chats wait in the review queue.</p></article>'
                "</div>"
            )
    if result:
        render_result(result)


def monitoring_tab() -> None:
    show(
        '<p class="ss-note">The test replay is a monitoring control. Those rows are not queued for review '
        "and cannot be used for retraining. The shifted replay is still job chats. "
        "The unfamiliar-writing replay is not. One new chat cannot meet the 15-prediction minimum by itself. "
        "A chat can move a window that already has enough rows.</p>"
    )
    c1, c2, c3 = st.columns(3, gap="medium")
    with c1:
        with st.container(border=True):
            st.markdown("**Test set**")
            st.caption("Monitoring control. Logged, not queued, and kept out of retraining.")
            run_test = st.button("Replay test set", use_container_width=True)
    with c2:
        with st.container(border=True):
            st.markdown("**Shifted set**")
            st.caption("Still job chats. These rows can be queued for review.")
            run_shifted = st.button("Replay shifted set", use_container_width=True)
    with c3:
        with st.container(border=True):
            st.markdown("**Unfamiliar writing**")
            st.caption("Not job chats. Unlike text can move the window. This is not evolving scam wording.")
            run_drift = st.button("Replay unfamiliar writing", use_container_width=True)

    if run_test or run_shifted or run_drift:
        dataset = "test" if run_test else "shifted" if run_shifted else "drift"
        limit = 40 if dataset == "drift" else 80
        with st.spinner("Replaying chats through the live pipeline"):
            replay = api("POST", "/replay", json={"dataset": dataset, "limit": limit})
        if replay:
            st.session_state["replay"] = replay

    status = api("GET", "/monitoring")
    if status:
        if status.get("drift"):
            banner("danger", "Drift alert", status.get("alerts") or [])
        else:
            window = status["window_size"]
            noun = "prediction" if window == 1 else "predictions"
            banner(
                "ok",
                "No drift alert",
                [f"Window has {window} {noun} (needs {config.DRIFT_MIN_SAMPLES})."],
            )
        for note in status.get("advisory") or []:
            banner("warn", "Monitor closely", [note])
        if status.get("note"):
            show(f'<p class="ss-note">{esc(status["note"])}</p>')

        current = status.get("current") or {}
        ref = status.get("reference") or {}
        show(
            '<div class="ss-metrics">'
            + metric(
                "Mean chosen-side score",
                f"{current.get('mean_confidence', 0):.0%}",
                "Average of the score on the side the model chose. Not a measured accuracy.",
                f"Reference {ref.get('mean_confidence', 0):.0%}",
            )
            + metric(
                "Unfamiliar rate",
                f"{current.get('unfamiliar_rate', 0):.0%}",
                "Share of chats far from the training examples.",
                f"Reference {ref.get('unfamiliar_rate', 0):.0%}",
            )
            + metric(
                "Uncertain rate",
                f"{current.get('uncertain_rate', 0):.0%}",
                "Share of chats inside the uncertain band.",
                f"Reference {ref.get('uncertain_rate', 0):.0%}",
            )
            + metric(
                "Mean unfamiliarity",
                f"{current.get('mean_novelty', 0):.3f}",
                "Advisory only. Crossing the limit does not raise the drift alert.",
                f"Limit {ref.get('novelty_mean_alert', 0):.3f}",
            )
            + "</div>"
        )
        show(
            '<p class="ss-note">Mean unfamiliarity is the average distance from the nearest training chat. '
            "The limit is a prediction bound for a future 40-chat average under an i.i.d. normal model. "
            "It is not a measured false-alarm rate. Crossing it shows a monitor-closely note. "
            "It does not raise the drift alert and does not send a chat to review by itself.</p>"
        )

    replay = st.session_state.get("replay")
    if replay:
        show('<div class="ss-section">Last replay</div>')
        cards = [
            metric("Dataset", str(replay.get("dataset", "")), "Stored batch sent through the live pipeline."),
            metric("Chats", str(replay.get("n", 0)), "Rows from this run."),
            metric("Routed to review", str(replay.get("routed_to_review", 0)), "Queued only when the set allows it."),
            metric(
                "Eligible to retrain",
                "Yes" if replay.get("eligible_for_retrain") else "No",
                "Test and unfamiliar-writing replays stay out.",
            ),
        ]
        show('<div class="ss-metrics">' + "".join(cards) + "</div>")
        if "accuracy" in replay:
            st.caption(
                f"Share correct on this replay: {replay['accuracy']:.0%}. "
                "A held-out replay figure is not the result on new scam wording."
            )
        with st.expander("Replay payload"):
            st.json(replay)

    rows = api("GET", "/predictions?limit=50") or []
    show('<div class="ss-section">Prediction log</div>')
    if not rows:
        show('<div class="ss-empty-state"><div class="ss-kicker">Log</div><div class="ss-empty-title">No predictions yet</div><p>Analyze a chat, or replay a stored batch, and the window will fill in here.</p></div>')
        return
    frame = pd.DataFrame(rows)
    preferred = ["id", "ts", "source", "label", "score", "confidence", "novelty", "unfamiliar", "uncertain", "status"]
    ordered = [col for col in preferred if col in frame.columns] + [col for col in frame.columns if col not in preferred]
    frame = frame[ordered]
    for col in ("unfamiliar", "uncertain"):
        if col in frame.columns:
            frame[col] = frame[col].fillna(0).astype(bool)
    st.dataframe(
        frame,
        use_container_width=True,
        hide_index=True,
        column_config={
            "id": st.column_config.NumberColumn("ID", format="%d"),
            "ts": st.column_config.TextColumn("When"),
            "source": st.column_config.TextColumn("Source"),
            "label": st.column_config.TextColumn("Label"),
            "score": st.column_config.NumberColumn("Scam score", format="%.0%"),
            "confidence": st.column_config.NumberColumn("Chosen-side", format="%.0%"),
            "novelty": st.column_config.NumberColumn("Unfamiliarity", format="%.3f"),
            "unfamiliar": st.column_config.CheckboxColumn("Unfamiliar"),
            "uncertain": st.column_config.CheckboxColumn("Uncertain"),
            "status": st.column_config.TextColumn("Status"),
            "model_version": st.column_config.TextColumn("Pipeline"),
        },
    )


def review_tab() -> None:
    queue = api("GET", "/review") or []
    if not queue:
        show(
            '<div class="ss-empty-state"><div class="ss-kicker">Review queue</div>'
            '<div class="ss-empty-title">Nothing waiting</div>'
            "<p>Uncertain chats, unfamiliar chats, credential requests, and high-risk links land here. "
            "Test replays are excluded.</p></div>"
        )
    else:
        show(
            f'<div class="ss-section">{len(queue)} case{"s" if len(queue) != 1 else ""} waiting</div>'
        )
    for item in queue:
        signal = "Scam signal" if item["label"] == "scam" else "No strong scam signal"
        reasons = [part for part in (item.get("review_reason") or "").split(",") if part]
        chips = "".join(chip(part, "warn") for part in reasons)
        with st.container(border=True):
            show(
                '<div class="ss-case-top"><div>'
                f'<div class="ss-kicker">Case {esc(item["id"])}</div>'
                f'<div class="ss-case-title">{esc(signal)} · {item["score"]:.0%}</div>'
                f'<div class="ss-meta-line">Chosen-side {item["confidence"]:.0%} · '
                f'unfamiliarity {item["novelty"]:.0%} · {esc(item.get("source") or "")}</div>'
                "</div>"
                f'<div class="ss-chips">{chips}</div></div>'
                f'<pre class="ss-chat">{esc(item.get("text") or "")}</pre>'
            )
            b1, b2 = st.columns(2)
            if b1.button("Label scam", key=f"scam-{item['id']}", use_container_width=True):
                api("POST", f"/review/{item['id']}", json={"label": 1})
                st.rerun()
            if b2.button("Label: no scam signal", key=f"legit-{item['id']}", use_container_width=True):
                api("POST", f"/review/{item['id']}", json={"label": 0})
                st.rerun()

    show('<div class="ss-section">Stretch</div>')
    show(
        '<p class="ss-note">Do this only after detection, monitoring, and review are solid. '
        "Held-out test replays are excluded.</p>"
    )
    if st.button("Retrain on reviewed labels"):
        with st.spinner("Retraining on reviewed labels"):
            outcome = api("POST", "/retrain")
        if outcome:
            st.session_state["retrain"] = outcome
    if st.session_state.get("retrain"):
        outcome = st.session_state["retrain"]
        show(
            '<div class="ss-metrics">'
            + metric("Reviewed examples", str(outcome.get("reviewed_examples", 0)), "Human labels added for this run.")
            + "</div>"
        )
        with st.expander("Before and after"):
            st.json(outcome)


def main() -> None:
    show(f"<style>{STYLES}</style>")
    health = api("GET", "/health")
    if not health:
        st.stop()
    sidebar(health)
    show(
        '<div class="ss-top"><div class="ss-top-copy">'
        '<div class="ss-kicker">Adviser tool · Sri Lanka</div>'
        '<div class="ss-title">ScamShield LK</div>'
        "<p>Warns job seekers when a recruitment chat turns into a task-job scam.</p>"
        "</div>"
        '<div class="ss-top-note"><strong>The person decides.</strong>'
        "A clear score is not proof the recruiter is genuine.</div></div>"
    )
    tab_check, tab_monitor, tab_review = st.tabs(["Check chat", "Monitoring", "Review queue"])
    with tab_check:
        check_tab()
    with tab_monitor:
        monitoring_tab()
    with tab_review:
        review_tab()


main()
