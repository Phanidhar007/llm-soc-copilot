"""LLM-Powered SOC Copilot — local demo (AI Shield dark theme, Streamlit).

Run from the repo root:
    streamlit run demo/app.py

The demo reads the SQLite alert store produced by ``scripts/run_pipeline.py``
(results/soc_alerts.db), recomputes the headline metrics live, renders the
figures from results/figures/, and provides an interactive alert inspector with
human-in-the-loop Approve / Edit / Reject controls that write to the action log.

The AI Shield dark palette (#030303 bg, emerald #10b981 accent, Space Grotesk /
Plus Jakarta Sans, mono uppercase labels, stat cards) is applied via CSS
injection because Streamlit does not expose raw template control.
"""

from __future__ import annotations

import os
import sys
import html as _html

import pandas as pd
import streamlit as st

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

from soccopilot.alert_store import AlertStore  # noqa: E402
from soccopilot.human_loop import TIME_FACTOR, analyst_time  # noqa: E402
from soccopilot.knowledge import load_techniques, severity_name  # noqa: E402
from soccopilot.rag import TechniqueRetriever  # noqa: E402

DB_PATH = os.path.join(REPO_ROOT, "results", "soc_alerts.db")
FIG_DIR = os.path.join(REPO_ROOT, "results", "figures")

EMERALD = "#10b981"
AMBER = "#fbbf24"
RED = "#ef4444"
GREY = "#52525b"

CSS = """
<style>
:root {
  --bg:#030303; --card:rgba(9,9,11,.95); --border:#18181b; --border-strong:#27272a;
  --emerald:#10b981; --emerald-400:#34d399; --red:#ef4444; --red-400:#f87171;
  --amber:#fbbf24; --purple:#c084fc;
  --text:#ffffff; --text-2:#d4d4d8; --text-3:#a1a1aa; --text-4:#71717a;
  --font-heading:"Space Grotesk",sans-serif;
  --font-body:"Plus Jakarta Sans",sans-serif;
  --font-mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
}
html, body, [data-testid="stAppViewContainer"] { background: var(--bg); }
[data-testid="stAppViewContainer"] { color: var(--text); font-family: var(--font-body); }
[data-testid="stHeader"] { background: transparent; }
.block-container { padding-top: 1.2rem; }
h1,h2,h3,h4 { font-family: var(--font-heading); letter-spacing: -0.02em; }
.stApp a { color: var(--emerald-400); }
.grad-title {
  background: linear-gradient(135deg,#fff,#f4f4f5 50%,#a1a1aa);
  -webkit-background-clip:text; background-clip:text; color:transparent;
  font-family: var(--font-heading); font-weight:700; font-size:2.3rem; margin:0;
}
.grad-accent { background: linear-gradient(90deg,#34d399,#5eead4,#06b6d2);
  -webkit-background-clip:text; background-clip:text; color:transparent; }
.section-label { font-family: var(--font-mono); font-size:11px; color: var(--emerald);
  letter-spacing:.15em; text-transform:uppercase; margin-bottom:6px; display:block; }
.nav { display:flex; align-items:center; gap:12px; padding:.4rem 0 1.2rem;
  border-bottom:1px solid rgba(255,255,255,.05); margin-bottom:1.4rem; }
.brand { display:flex; align-items:center; gap:10px; font-family:var(--font-heading);
  font-weight:700; font-size:1.05rem; color:#fff; }
.dot { width:10px; height:10px; border-radius:50%; background: var(--emerald-400);
  box-shadow:0 0 10px var(--emerald-500); display:inline-block; }
.pill { display:inline-flex; align-items:center; gap:8px; padding:6px 14px; border-radius:9999px;
  background:rgba(24,24,27,.6); border:1px solid var(--border-strong); color:var(--text-3);
  font-family:var(--font-mono); font-size:12px; }
.card { border-radius:16px; border:1px solid var(--border); background:var(--card);
  padding:20px; margin-bottom:16px; box-shadow:0 20px 50px rgba(0,0,0,.85); }
.grid { display:grid; gap:14px; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); }
.stat-card { padding:18px; border-radius:16px; border:1px solid var(--border);
  background:var(--card); box-shadow:0 8px 30px rgba(0,0,0,.8); }
.stat-card .label { font-family:var(--font-mono); font-size:10px; color:var(--text-4);
  letter-spacing:.12em; text-transform:uppercase; margin-bottom:4px; }
.stat-card .value { font-family:var(--font-mono); font-size:22px; font-weight:800; color:#fff; }
.stat-card .sub { font-family:var(--font-mono); font-size:11px; color:var(--text-4); margin-top:4px; }
.badge { font-family:var(--font-mono); font-size:9px; font-weight:700; text-transform:uppercase;
  padding:3px 8px; border-radius:4px; letter-spacing:.08em; display:inline-block; }
.badge.green { background:rgba(16,185,129,.12); color:var(--emerald-400); }
.badge.red { background:rgba(239,68,68,.12); color:var(--red-400); }
.badge.amber { background:rgba(245,158,11,.12); color:var(--amber); }
.badge.purple { background:rgba(192,132,252,.12); color:var(--purple); }
.mono { font-family:var(--font-mono); }
.muted { color:var(--text-3); }
.hint { font-family:var(--font-mono); font-size:11px; color:var(--text-4);
  letter-spacing:.08em; text-transform:uppercase; }
pre { background:rgba(0,0,0,.5); border:1px solid var(--border); border-radius:12px;
  padding:14px; font-family:var(--font-mono); font-size:12px; color:var(--text-2); }
div[data-testid="stSelectbox"] label, div[data-testid="stTextArea"] label,
div[data-testid="stRadio"] label { font-family:var(--font-mono); font-size:10px;
  letter-spacing:.12em; text-transform:uppercase; color:var(--text-4); }
[data-testid="stWidgetLabel"] p { font-family:var(--font-mono); font-size:10px;
  letter-spacing:.12em; text-transform:uppercase; color:var(--text-4); }
[data-testid="stTabs"] button { font-family:var(--font-heading); }
.stDataFrame, [data-testid="stTable"] { background:var(--card); }
</style>
"""


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def esc(text) -> str:
    return _html.escape(str(text))


def stat_card(label, value, sub=""):
    return (
        f'<div class="stat-card"><div class="label">{esc(label)}</div>'
        f'<div class="value">{esc(value)}</div>'
        f'<div class="sub">{esc(sub)}</div></div>'
    )


def action_badge(action: str) -> str:
    cls = {"approved": "green", "edited": "amber", "rejected": "red"}.get(
        action, "purple")
    return f'<span class="badge {cls}">{esc(action)}</span>'


def load_store() -> AlertStore:
    return AlertStore(DB_PATH)


def compute_live_metrics(alerts: pd.DataFrame, actions: pd.DataFrame) -> dict:
    test = alerts[alerts["is_test"] == 1] if "is_test" in alerts.columns else alerts
    agree = (test["ai_label"].astype(str) == test["analyst_verdict"].astype(str))
    acc = float(agree.mean()) if len(test) else float("nan")
    acts = actions["action"].value_counts().to_dict()
    total = sum(acts.values())
    approve = acts.get("approved", 0) / total if total else 0.0
    bl = float(test["baseline_time"].mean()) if len(test) else 0.0
    as_ = float(test["assisted_time"].mean()) if len(test) else 0.0
    reduction = 1.0 - (as_ / bl) if bl else 0.0
    return {
        "triage_acc": acc,
        "approve_rate": approve,
        "baseline": bl,
        "assisted": as_,
        "reduction": reduction,
    }


def main() -> None:
    st.set_page_config(page_title="SOC Copilot", layout="wide",
                       page_icon="\U0001F50D")
    inject_css()

    if not os.path.exists(DB_PATH):
        st.markdown(
            '<div class="nav"><span class="dot"></span>'
            '<div class="brand">LLM-Powered SOC Copilot</div></div>',
            unsafe_allow_html=True)
        st.error("Alert store not found. Run the pipeline first:\n\n"
                 "    python scripts/run_pipeline.py")
        return

    store = load_store()
    alerts = store.get_alerts()
    actions = store.get_actions()
    metrics = compute_live_metrics(alerts, actions)
    techniques = load_techniques()
    retriever = TechniqueRetriever(techniques)
    by_id = {t.id: t for t in techniques}

    st.markdown(
        '<div class="nav"><span class="dot"></span>'
        '<div class="brand">LLM-Powered SOC Copilot</div>'
        '<span class="pill">LOCAL · OFFLINE RAG + FALLBACK LLM</span></div>',
        unsafe_allow_html=True)
    st.markdown(
        '<span class="section-label">ALERT INGESTION \u2192 RAG TRIAGE \u2192 HUMAN-IN-THE-LOOP</span>'
        '<h1 class="grad-title">Retrieval-augmented triage<br>'
        '<span class="grad-accent">for security operations</span></h1>',
        unsafe_allow_html=True)

    tab_overview, tab_inspect, tab_log = st.tabs(
        ["OVERVIEW", "ALERT INSPECTOR", "ACTION LOG"])

    with tab_overview:
        cols = st.columns(4)
        with cols[0]:
            st.markdown(stat_card("Triage accuracy",
                                  f"{metrics['triage_acc']:.1%}" if metrics['triage_acc'] == metrics['triage_acc'] else "n/a",
                                  "vs. analyst labels (test)"),
                        unsafe_allow_html=True)
        with cols[1]:
            st.markdown(stat_card("Approval rate",
                                  f"{metrics['approve_rate']:.1%}",
                                  "suggestions accepted"),
                        unsafe_allow_html=True)
        with cols[2]:
            st.markdown(stat_card("Response time",
                                  f"{metrics['baseline']:.1f}\u2192{metrics['assisted']:.1f} min",
                                  f"{metrics['reduction']:.1%} faster"),
                        unsafe_allow_html=True)
        with cols[3]:
            st.markdown(stat_card("Alerts in store", str(len(alerts)),
                                  "synthetic, seeded & reproducible"),
                        unsafe_allow_html=True)

        st.markdown("<div class='card'><h3>Measured metrics</h3>"
                    "<p class='muted'>Figures below are saved by the pipeline run "
                    "(results/figures/) \u2014 real numbers, computed locally.</p></div>",
                    unsafe_allow_html=True)
        figs = [f for f in ["triage_accuracy", "attack_mapping",
                            "response_time", "action_distribution"]
                if os.path.exists(os.path.join(FIG_DIR, f + ".png"))]
        if figs:
            c = st.columns(2)
            for i, f in enumerate(figs):
                with c[i % 2]:
                    st.image(os.path.join(FIG_DIR, f + ".png"),
                             caption=f.replace("_", " ").title(),
                             width="stretch")

    with tab_inspect:
        alert_ids = alerts["id"].tolist()
        chosen = st.selectbox("Select alert", alert_ids)
        a = alerts[alerts["id"] == chosen].iloc[0]
        tech = by_id.get(a["technique_ground_truth"])

        st.markdown(
            f'<div class="card">'
            f'<span class="hint">ALERT {esc(a["id"])} \u00b7 {esc(a["ts"])} '
            f'\u00b7 {esc(a["src_ip"])} \u2192 {esc(a["dst_ip"])}</span>'
            f'<h2>{esc(a["sig_id"])}</h2>'
            f'<div style="margin:6px 0">'
            f'<span class="badge purple">severity {esc(severity_name(a["severity"]))}</span> '
            f'<span class="badge purple">ground truth {esc(a["technique_ground_truth"])}</span> '
            f'{action_badge(a["action"]) if "action" in a.index and a["action"] else ""} '
            f'<span class="badge {"amber" if a["is_decoy"] else "green"}">'
            f'{"decoy / false positive" if a["is_decoy"] else "true detection"}</span>'
            f'</div><pre>{esc(a["raw_log"])}</pre></div>',
            unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            ai_label = a["ai_label"] if "ai_label" in a.index else "n/a"
            ai_tech = a["ai_technique"] if "ai_technique" in a.index else "n/a"
            ai_conf = a["ai_conf"] if "ai_conf" in a.index and a["ai_conf"] == a["ai_conf"] else 0.0
            st.markdown(
                f'<div class="card"><span class="section-label">AI TRIAGE</span>'
                f'<div style="margin:8px 0">'
                f'<span class="badge green">verdict {esc(ai_label)}</span> '
                f'<span class="badge purple">technique {esc(ai_tech)}</span> '
                f'<span class="badge purple">conf {float(ai_conf):.0%}</span></div>'
                f'<div class="muted">Recommended technique: '
                f'<span class="mono">{esc(a["ai_technique"])}</span> '
                f'{esc(by_id[a["ai_technique"]].name) if a["ai_technique"] in by_id else ""}</div>'
                f'</div>', unsafe_allow_html=True)

            # interactive human-in-the-loop controls
            st.markdown(
                '<span class="section-label">ANALYST DECISION (human-in-the-loop)</span>',
                unsafe_allow_html=True)
            choice = st.radio("Your verdict", ["approved", "edited", "rejected"],
                              horizontal=True, label_visibility="collapsed")
            edited_text = ""
            if choice == "edited":
                edited_text = st.text_area(
                    "Corrected summary",
                    value=(a["summary"] if "summary" in a.index else ""),
                    height=180)
            if st.button("Submit decision", type="primary"):
                base = float(a["baseline_time"])
                store.log_action(chosen, choice, analyst_time(choice, base),
                                 edited_text or None)
                st.success(f"Logged action '{choice}' for alert {chosen} "
                           f"({analyst_time(choice, base):.1f} min analyst time).")
                st.rerun()

        with c2:
            if "summary" in a.index and a["summary"]:
                st.markdown(
                    f'<div class="card"><span class="section-label">AI SUMMARY '
                    f'(RAG + fallback LLM)</span>'
                    f'<pre>{esc(a["summary"])}</pre></div>',
                    unsafe_allow_html=True)
                if a["severity_justification"]:
                    st.markdown(
                        f'<div class="card"><span class="section-label">SEVERITY '
                        f'JUSTIFICATION</span><p class="muted">'
                        f'{esc(a["severity_justification"])}</p></div>',
                        unsafe_allow_html=True)
                if a["recommended_steps"]:
                    st.markdown(
                        f'<div class="card"><span class="section-label">RECOMMENDED '
                        f'RESPONSE</span><pre>{esc(a["recommended_steps"])}</pre></div>',
                        unsafe_allow_html=True)

    with tab_log:
        if len(actions) == 0:
            st.info("No analyst actions logged yet.")
        else:
            right = alerts[["id", "sig_id", "severity", "technique_ground_truth",
                            "ai_label", "analyst_verdict", "baseline_time"]].rename(
                                columns={"id": "alert_id"})
            joined = actions.merge(right, on="alert_id", how="left")
            st.markdown(f'<div class="card"><span class="section-label">'
                        f'ANALYST ACTION LOG \u00b7 {len(joined)} entries</span></div>',
                        unsafe_allow_html=True)
            st.dataframe(joined, width="stretch", hide_index=True)

    st.markdown('<div class="footer" style="margin-top:2rem;padding-top:1rem;'
                'border-top:1px solid rgba(255,255,255,.05);color:var(--text-4);'
                'text-align:center;font-size:13px;font-family:var(--font-mono)">'
                'LLM-Powered SOC Copilot \u00b7 MITRE ATT&CK RAG \u00b7 local & offline</div>',
                unsafe_allow_html=True)


if __name__ == "__main__":
    main()
