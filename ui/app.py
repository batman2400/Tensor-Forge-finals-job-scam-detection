"""ScamShield LK demo UI. Talks to the FastAPI service over HTTP.

Run the API first, then:
    uv run streamlit run ui/app.py
"""
import sys
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scamshield import config  # noqa: E402

st.set_page_config(page_title="ScamShield LK", page_icon="🛡️", layout="wide")

API = config.API_URL.rstrip("/")


def api(method: str, path: str, **kwargs):
    try:
        resp = requests.request(method, f"{API}{path}", timeout=120, **kwargs)
    except requests.RequestException as e:
        st.error(f"API is not reachable at {API}. Start it with: uv run uvicorn scamshield.api:app --port 8000\n\n{e}")
        st.stop()
    if resp.status_code >= 400:
        detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
        st.error(f"{resp.status_code}: {detail}")
        return None
    return resp.json()


def verdict_color(label: str, uncertain: bool) -> str:
    if uncertain:
        return "#b45309"
    return "#b91c1c" if label == "scam" else "#15803d"


st.title("ScamShield LK")
st.caption("Warns Sri Lankan job seekers when a recruitment chat turns into a task-job scam.")

health = api("GET", "/health")
if not health:
    st.stop()

with st.sidebar:
    st.subheader("Service")
    st.write(f"Model: `{health.get('model_version') or 'not loaded'}`")
    st.write("Loaded" if health.get("model_loaded") else "No model — run `python scripts/train.py`")
    if st.button("Reset prediction log"):
        api("POST", "/admin/reset-logs")
        st.rerun()

tab_check, tab_monitor, tab_review = st.tabs(["Check chat", "Monitoring", "Review queue"])

with tab_check:
    demos = {
        "Blank": "",
        "Legit recruitment": (config.DEMO_DIR / "legit_recruitment.txt").read_text(encoding="utf-8"),
        "Task-job scam": (config.DEMO_DIR / "task_scam.txt").read_text(encoding="utf-8"),
    }
    choice = st.radio("Load a demo", list(demos), horizontal=True)
    text = st.text_area("Paste a WhatsApp or Telegram chat", value=demos[choice], height=280,
                        key=f"chat-{choice}", placeholder="Recruiter: ...\nCandidate: ...")
    if st.button("Analyze", type="primary", disabled=not text.strip()):
        result = api("POST", "/analyze", json={"text": text, "source": "ui"})
        if result:
            st.session_state["result"] = result
            st.session_state["analyzed_text"] = text

    result = st.session_state.get("result")
    if result and st.session_state.get("analyzed_text") != text:
        result = None
    if result:
        color = verdict_color(result["label"], result["uncertain"])
        verdict = result.get("verdict") or (
            "Scam signal detected" if result["label"] == "scam" else "No strong scam signal detected"
        )
        c1, c2, c3, c4 = st.columns(4)
        c1.markdown(f"### <span style='color:{color}'>{verdict}</span>", unsafe_allow_html=True)
        c2.metric("Scam score", f"{result['score']:.0%}", help="Model score for this chat. Not a measured accuracy.")
        c3.metric("Chosen-side score", f"{result['confidence']:.0%}",
                  help="max(scam score, 1 − scam score): the score on the side the model chose. "
                       "Not the distance from 50/50, and not a measured accuracy.")
        c4.metric("Unfamiliarity", f"{result['novelty']:.0%}",
                  help="Distance from the nearest training example. Not a measured accuracy.")
        if result["routed_to_review"]:
            st.warning(f"Sent to human review: {result['review_reason']}")
        if result["drift_active"]:
            st.error("Drift alert is active. Uncertain cases are being routed to review.")

        st.subheader("Why it was flagged")
        if result["indicators"]:
            for ind in result["indicators"]:
                st.markdown(f"- **{ind['label']}** — `{ind['match']}`")
        else:
            st.write("No warning phrases in this chat.")

        if result.get("links"):
            st.subheader("Links")
            for link in result["links"]:
                flags = ", ".join(f["code"] for f in link["flags"]) or "none"
                st.write(f"`{link['url']}` — {link['risk']} ({flags})")

        timeline = result.get("timeline") or []
        if timeline:
            st.subheader("Risk timeline")
            frame = pd.DataFrame({
                "message": [f"{i + 1}. {row['sender']}" for i, row in enumerate(timeline)],
                "scam score": [row["cumulative_score"] for row in timeline],
            })
            st.line_chart(frame, x="message", y="scam score")
            for row in timeline:
                tags = " ".join(f"`{i['code']}`" for i in row["indicators"])
                st.markdown(f"**{row['sender']}** ({row['cumulative_score']:.0%}) {tags}  \n{row['text']}")

with tab_monitor:
    st.caption("The test replay is a monitoring control. Those rows are not queued for review and cannot be used for retraining.")
    c1, c2 = st.columns(2)
    if c1.button("Replay test set (monitoring only)"):
        replay = api("POST", "/replay", json={"dataset": "test", "limit": 80})
        if replay:
            st.session_state["replay"] = replay
    if c2.button("Replay shifted set"):
        replay = api("POST", "/replay", json={"dataset": "shifted", "limit": 80})
        if replay:
            st.session_state["replay"] = replay

    # Fetched after replay so the banner matches the log from this run.
    status = api("GET", "/monitoring")
    if status:
        if status.get("drift"):
            st.error("DRIFT ALERT — " + "; ".join(status["alerts"]))
        else:
            st.success(f"No drift alert. Window has {status['window_size']} predictions "
                       f"(needs {config.DRIFT_MIN_SAMPLES}).")
        current = status.get("current") or {}
        ref = status.get("reference") or {}
        m1, m2, m3 = st.columns(3)
        m1.metric("Mean chosen-side score", f"{current.get('mean_confidence', 0):.0%}",
                  help="Average of max(scam score, 1 − scam score) in this window. "
                       "Not the distance from 50/50, and not a measured accuracy.",
                  delta=f"ref {ref.get('mean_confidence', 0):.0%}")
        m2.metric("Unfamiliar rate", f"{current.get('unfamiliar_rate', 0):.0%}",
                  delta=f"ref {ref.get('unfamiliar_rate', 0):.0%}")
        m3.metric("Uncertain rate", f"{current.get('uncertain_rate', 0):.0%}",
                  delta=f"ref {ref.get('uncertain_rate', 0):.0%}")

    if st.session_state.get("replay"):
        st.json(st.session_state["replay"])

    rows = api("GET", "/predictions?limit=50") or []
    if rows:
        st.subheader("Prediction log")
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No predictions logged yet.")

with tab_review:
    queue = api("GET", "/review") or []
    st.write(f"{len(queue)} case(s) waiting.")
    for item in queue:
        signal = "scam signal" if item["label"] == "scam" else "no strong scam signal"
        with st.expander(f"#{item['id']}  {signal}  score {item['score']:.0%}  ({item['review_reason']})"):
            st.text(item.get("text") or "")
            b1, b2 = st.columns(2)
            if b1.button("Label scam", key=f"scam-{item['id']}"):
                api("POST", f"/review/{item['id']}", json={"label": 1})
                st.rerun()
            if b2.button("Label: no scam signal", key=f"legit-{item['id']}"):
                api("POST", f"/review/{item['id']}", json={"label": 0})
                st.rerun()
    st.caption("Stretch. Do this only after detection, monitoring, and review are solid. Held-out test replays are excluded.")
    if st.button("Stretch: retrain on reviewed labels"):
        outcome = api("POST", "/retrain")
        if outcome:
            st.session_state["retrain"] = outcome
    if st.session_state.get("retrain"):
        st.subheader("Before and after")
        st.json(st.session_state["retrain"])
