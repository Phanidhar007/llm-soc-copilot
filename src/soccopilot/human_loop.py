"""Human-in-the-loop: analyst approve / edit / reject logging.

In production an analyst reviews the copilot's suggestion in a queue UI and the
decision is stored per alert. In this offline simulation the analyst decision is
derived deterministically from the AI output vs. the analyst's own verdict:

* AI label == analyst verdict  -> ``approved`` (copilot agreed).
* AI label != analyst verdict AND analyst says benign -> ``rejected``
  (copilot produced a false positive; suggestion discarded).
* AI label != analyst verdict AND analyst is not benign -> ``edited``
  (copilot misfired on severity/intent; analyst corrects the summary).

Response time reduction is measured from the same decisions: an approved
suggestion saves the most analyst time; edits save some; rejections save the
least because the analyst must redo the triage from scratch.
"""

from __future__ import annotations

from typing import Dict, Optional

from .alert_store import AlertStore

# fraction of baseline time the analyst spends when a copilot suggestion is
# approved / edited / rejected (simulated analyst workload model)
TIME_FACTOR = {"approved": 0.35, "edited": 0.60, "rejected": 0.85}


def simulate_action(ai_label: str, analyst_verdict: str) -> str:
    """Deterministic action from AI output vs. analyst verdict."""
    if ai_label == analyst_verdict:
        return "approved"
    if analyst_verdict == "benign":
        return "rejected"
    return "edited"


def edited_summary_for(alert, ai_result: Dict) -> str:
    """Produce a plausible corrected summary when the analyst edits the AI text."""
    analyst = alert["analyst_verdict"]
    tech = ai_result.get("ai_technique", "unknown")
    return (
        f"[analyst corrected] {alert['id']} reassessed by analyst as '{analyst}' "
        f"(AI suggested '{ai_result.get('ai_label')}'). Technique mapping {tech} "
        f"kept; severity wording and response priority adjusted after manual review."
    )


def analyst_time(action: str, baseline_min: float) -> float:
    """Simulated assisted time (minutes) given the analyst's action."""
    return round(float(baseline_min) * TIME_FACTOR[action], 2)


def run_human_loop(store: AlertStore, alert, ai_result: Dict) -> Dict:
    """Log one analyst decision and return the outcome record."""
    action = simulate_action(ai_result["ai_label"], alert["analyst_verdict"])
    summary = ai_result["summary"]
    edited = None
    if action == "edited":
        edited = edited_summary_for(alert, ai_result)
        summary = f"{summary}\n\n{edited}"
    elif action == "rejected":
        summary = "[analyst rejected] Copilot suggestion discarded; manual triage performed."

    assisted = analyst_time(action, float(alert["baseline_time"]))
    store.log_action(alert["id"], action, assisted, edited)

    return {
        "action": action,
        "assisted_time": assisted,
        "summary": summary,
    }
