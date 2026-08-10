"""Evaluation: triage accuracy vs analyst labels, response-time reduction and
ATT&CK technique-mapping accuracy. All numbers are computed from the actual
pipeline run (never fabricated) and written to ``results/metrics.md``, with
figures saved to ``results/figures/``.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .rag import TechniqueRetriever

# ---------- shared plotting theme (dark, matches the AI Shield demo) ----------
_PLOT_STYLE = {
    "figure.facecolor": "#030303",
    "axes.facecolor": "#09090b",
    "axes.edgecolor": "#18181b",
    "axes.labelcolor": "#d4d4d8",
    "axes.titlecolor": "#ffffff",
    "text.color": "#d4d4d8",
    "xtick.color": "#a1a1aa",
    "ytick.color": "#a1a1aa",
    "grid.color": "#18181b",
    "font.family": "sans-serif",
    "font.size": 11,
    "axes.grid": True,
    "grid.alpha": 0.4,
}
EMERALD = "#10b981"
PURPLE = "#c084fc"
RED = "#ef4444"
AMBER = "#fbbf24"


def _eval_alerts(alerts: pd.DataFrame) -> pd.DataFrame:
    """Restrict evaluation to held-out (is_test==1) alerts."""
    if "is_test" in alerts.columns:
        test = alerts[alerts["is_test"] == 1]
        if len(test):
            return test
    return alerts


def compute_metrics(alerts: pd.DataFrame, actions: pd.DataFrame,
                    techniques: TechniqueRetriever, run_seconds: float,
                    train_size: int, test_size: int) -> Dict:
    """Compute all headline metrics from the pipeline outputs."""
    df = _eval_alerts(alerts)
    n = len(df)

    # restrict actions to the evaluation (held-out) alerts
    test_ids = set(df["id"].tolist())
    if len(actions):
        actions = actions[actions["alert_id"].isin(test_ids)]

    # 1) triage accuracy vs human (analyst) labels
    agree = (df["ai_label"].astype(str) == df["analyst_verdict"].astype(str))
    triage_acc = float(agree.mean())
    majority_label = df["analyst_verdict"].value_counts().idxmax()
    majority_acc = float((df["analyst_verdict"] == majority_label).mean())

    per_class = {}
    for lab in ["benign", "suspicious", "malicious"]:
        mask = df["analyst_verdict"] == lab
        if mask.any():
            per_class[lab] = float(agree[mask].mean())
        else:
            per_class[lab] = float("nan")

    # 2) human-in-the-loop action mix (approved / edited / rejected)
    acts = actions["action"].value_counts().to_dict()
    approved = acts.get("approved", 0)
    edited = acts.get("edited", 0)
    rejected = acts.get("rejected", 0)
    total = approved + edited + rejected
    approve_rate = approved / total if total else 0.0
    edit_rate = edited / total if total else 0.0
    reject_rate = rejected / total if total else 0.0

    # 3) ATT&CK technique mapping accuracy (top-1 / top-3 of RAG retrieval)
    df = df.copy()
    top1, top3 = [], []
    for _, a in df.iterrows():
        hits = [t.id for t, _ in techniques.retrieve(a["raw_log"], top_k=3)]
        gt = a["technique_ground_truth"]
        top1.append(int(hits[0] == gt))
        top3.append(int(gt in hits))
    map_top1 = float(np.mean(top1))
    map_top3 = float(np.mean(top3))

    # 4) response-time reduction
    baseline_mean = float(df["baseline_time"].mean())
    assisted_mean = float(df["assisted_time"].mean())
    time_reduction = 1.0 - (assisted_mean / baseline_mean if baseline_mean else 0.0)

    return {
        "n_alerts": int(train_size + test_size),
        "train_size": int(train_size),
        "test_size": int(test_size),
        "eval_alerts": int(n),
        "run_seconds": float(run_seconds),
        "triage_accuracy": triage_acc,
        "majority_accuracy": majority_acc,
        "per_class_accuracy": per_class,
        "approved": int(approved), "edited": int(edited), "rejected": int(rejected),
        "approve_rate": approve_rate, "edit_rate": edit_rate, "reject_rate": reject_rate,
        "map_top1": map_top1, "map_top3": map_top3,
        "baseline_time_mean": baseline_mean,
        "assisted_time_mean": assisted_mean,
        "time_reduction": time_reduction,
    }


def write_metrics(metrics: Dict, path: str) -> None:
    """Write ``results/metrics.md`` with the real numbers from the run."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    p = metrics["per_class_accuracy"]
    lines = [
        "# SOC Copilot — Run Metrics (REAL numbers)",
        "",
        "Produced by `scripts/run_pipeline.py` on this machine. All values below "
        "are computed live from the simulated alert stream + actual pipeline output.",
        "",
        "## Run summary",
        "",
        f"- Dataset: **{metrics['n_alerts']}** synthetic alerts (seeded, reproducible)",
        f"- Train / held-out test split: **{metrics['train_size']} / {metrics['test_size']}** (stratified)",
        f"- End-to-end pipeline wall time: **{metrics['run_seconds']:.1f} s** on CPU",
        "- RAG: TF-IDF + numpy cosine (no vector DB); LLM: offline template fallback",
        "",
        "## Key metrics (held-out test set)",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| **Triage accuracy vs analyst labels** | **{metrics['triage_accuracy']:.3f}** |",
        f"| Majority-class baseline accuracy | {metrics['majority_accuracy']:.3f} |",
    ]
    for lab in ["benign", "suspicious", "malicious"]:
        v = p.get(lab, float("nan"))
        cells = f"{v:.3f}" if v == v else "n/a"
        lines.append(f"| Accuracy — {lab} | {cells} |")
    lines += [
        f"| **ATT&CK mapping — top-1** | **{metrics['map_top1']:.3f}** |",
        f"| ATT&CK mapping — top-3 | {metrics['map_top3']:.3f} |",
        f"| **Mean baseline analyst time** | **{metrics['baseline_time_mean']:.2f} min** |",
        f"| **Mean assisted analyst time** | **{metrics['assisted_time_mean']:.2f} min** |",
        f"| **Response-time reduction** | **{metrics['time_reduction'] * 100:.1f}%** |",
        "",
        "## Human-in-the-loop actions (held-out test set)",
        "",
        f"- Approved: **{metrics['approved']}** ({metrics['approve_rate'] * 100:.1f}%)",
        f"- Edited: **{metrics['edited']}** ({metrics['edit_rate'] * 100:.1f}%)",
        f"- Rejected: **{metrics['rejected']}** ({metrics['reject_rate'] * 100:.1f}%)",
        "",
        "Figures: `results/figures/` (triage_accuracy, attack_mapping, "
        "response_time, action_distribution).",
        "",
        "_Notes: data is synthetic (technique-templated alerts with a 15% decoy / "
        "false-positive rate) so these numbers measure pipeline behavior on a "
        "controlled stream, not real-world SOC performance._",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _save(fig, name: str, out_dir: str) -> str:
    path = os.path.join(out_dir, name)
    fig.savefig(path, dpi=140, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return path


def plot_figures(metrics: Dict, alerts: pd.DataFrame, out_dir: str) -> List[str]:
    """Save the four result figures and return their paths."""
    os.makedirs(out_dir, exist_ok=True)
    plt.rcParams.update(_PLOT_STYLE)

    saved = []

    # 1) triage accuracy vs majority baseline
    fig, ax = plt.subplots(figsize=(5.5, 4))
    bars = ax.bar(
        ["Copilot triage", "Majority-class baseline"],
        [metrics["triage_accuracy"], metrics["majority_accuracy"]],
        color=[EMERALD, "#52525b"], width=0.55,
    )
    for b, v in zip(bars, [metrics["triage_accuracy"], metrics["majority_accuracy"]]):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.3f}",
                ha="center", color="#fff", fontweight="bold")
    ax.set_ylim(0, 1.05)
    ax.set_title("Triage accuracy vs. analyst labels (held-out)")
    ax.set_ylabel("Accuracy")
    ax.tick_params(axis="x", rotation=0)
    saved.append(_save(fig, "triage_accuracy.png", out_dir))

    # 2) ATT&CK mapping top-1 vs top-3
    fig, ax = plt.subplots(figsize=(5.5, 4))
    bars = ax.bar(
        ["Top-1 mapping", "Top-3 mapping"],
        [metrics["map_top1"], metrics["map_top3"]],
        color=[PURPLE, EMERALD], width=0.5,
    )
    for b, v in zip(bars, [metrics["map_top1"], metrics["map_top3"]]):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.01, f"{v:.3f}",
                ha="center", color="#fff", fontweight="bold")
    ax.set_ylim(0, 1.05)
    ax.set_title("ATT&CK technique mapping accuracy (RAG)")
    ax.set_ylabel("Accuracy")
    saved.append(_save(fig, "attack_mapping.png", out_dir))

    # 3) response time baseline vs assisted
    fig, ax = plt.subplots(figsize=(5.5, 4))
    bars = ax.bar(
        ["Baseline (no copilot)", "Assisted (copilot)"],
        [metrics["baseline_time_mean"], metrics["assisted_time_mean"]],
        color=["#52525b", AMBER], width=0.5,
    )
    for b, v in zip(bars, [metrics["baseline_time_mean"], metrics["assisted_time_mean"]]):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.15, f"{v:.1f} min",
                ha="center", color="#fff", fontweight="bold")
    ax.set_title(f"Mean analyst response time — {metrics['time_reduction'] * 100:.1f}% reduction")
    ax.set_ylabel("Minutes per alert")
    saved.append(_save(fig, "response_time.png", out_dir))

    # 4) human-in-the-loop action distribution
    fig, ax = plt.subplots(figsize=(5.5, 4))
    labels = ["approved", "edited", "rejected"]
    counts = [metrics["approved"], metrics["edited"], metrics["rejected"]]
    colors = [EMERALD, AMBER, RED]
    bars = ax.bar(labels, counts, color=colors, width=0.55)
    for b, v in zip(bars, counts):
        ax.text(b.get_x() + b.get_width() / 2, v + 0.3, str(v),
                ha="center", color="#fff", fontweight="bold")
    ax.set_title("Human-in-the-loop outcomes (analyst actions)")
    ax.set_ylabel("Alerts")
    ax.set_ylim(0, max(counts) * 1.15 if counts else 1)
    saved.append(_save(fig, "action_distribution.png", out_dir))

    return saved
