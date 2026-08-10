"""End-to-end SOC Copilot pipeline.

1. Builds a SQLite alert store and synthesizes a seeded alert stream.
2. Fits the retrieval-augmented triage classifier on analyst-labeled alerts.
3. Runs RAG triage (technique retrieval + similar-past-alert retrieval +
   summary generation) on every alert and simulates the analyst
   approve / edit / reject decision (human-in-the-loop logging).
4. Computes REAL metrics (triage accuracy vs analyst labels, response-time
   reduction, ATT&CK mapping accuracy) on a held-out test split.
5. Writes ``results/metrics.md`` and saves figures to ``results/figures/``.

Usage:
    python scripts/run_pipeline.py [--alerts 300] [--seed 7]
        [--db results/soc_alerts.db] [--ollama] [--ollama-model llama3]
        [--openai]

Defaults run fully offline using the deterministic template fallback "LLM".
Pass ``--ollama`` (or ``--openai``) to try a live model; if it is unreachable
the pipeline silently falls back to the offline generator.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from soccopilot.alert_store import AlertStore, generate_alerts
from soccopilot.evaluate import compute_metrics, plot_figures, write_metrics
from soccopilot.human_loop import run_human_loop
from soccopilot.knowledge import load_techniques
from soccopilot.rag import LLMInterface, TechniqueRetriever
from soccopilot.triage import TriageEngine

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(REPO_ROOT, "results", "soc_alerts.db")
METRICS_PATH = os.path.join(REPO_ROOT, "results", "metrics.md")
FIG_DIR = os.path.join(REPO_ROOT, "results", "figures")


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LLM-Powered SOC Copilot pipeline")
    p.add_argument("--alerts", type=int, default=300, help="number of synthetic alerts")
    p.add_argument("--seed", type=int, default=7, help="RNG seed (reproducible)")
    p.add_argument("--db", default=DB_PATH, help="SQLite store path")
    p.add_argument("--ollama", action="store_true",
                   help="attempt to use a local Ollama model (falls back offline)")
    p.add_argument("--ollama-model", default="llama3")
    p.add_argument("--openai", action="store_true",
                   help="attempt to use the OpenAI API (needs OPENAI_API_KEY)")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    t0 = time.time()

    provider = None
    if args.ollama:
        provider = "ollama"
    elif args.openai:
        provider = "openai"

    print(f"[1/6] Generating {args.alerts} synthetic alerts (seed={args.seed}) ...")
    alerts = generate_alerts(n=args.alerts, seed=args.seed)

    print(f"[2/6] Building SQLite store at {args.db} ...")
    os.makedirs(os.path.dirname(args.db), exist_ok=True)
    store = AlertStore(args.db)
    store.reset()
    store.save_alerts(alerts)

    print("[3/6] Splitting train / held-out test (stratified) ...")
    train, test = train_test_split(
        alerts, test_size=0.30, random_state=args.seed, stratify=alerts["analyst_verdict"]
    )
    train = train.reset_index(drop=True)
    test = test.reset_index(drop=True)
    train_ids, test_ids = set(train["id"]), set(test["id"])

    print("[4/6] Fitting retrieval + triage model ...")
    techniques = load_techniques()
    tech_retriever = TechniqueRetriever(techniques)
    llm = LLMInterface(provider=provider, model=args.ollama_model)
    engine = TriageEngine(techniques, tech_retriever, llm)
    engine.set_past_alerts(train)   # "already triaged" context = the training set
    engine.fit(train)

    print(f"[5/6] Triaging {len(alerts)} alerts + human-in-the-loop logging "
          f"(provider={provider or 'offline fallback'}) ...")
    result_rows = []
    for _, alert in alerts.iterrows():
        ai = engine.triage_alert(alert)
        outcome = run_human_loop(store, alert, ai)

        row = alert.to_dict()
        row.update({
            "ai_label": ai["ai_label"],
            "ai_conf": ai["ai_conf"],
            "ai_technique": ai["ai_technique"],
            "ai_technique_conf": ai["ai_technique_conf"],
            "summary": ai["summary"],
            "severity_justification": ai["severity_justification"],
            "recommended_steps": ai["recommended_steps"],
            "action": outcome["action"],
            "assisted_time": outcome["assisted_time"],
            "is_test": int(alert["id"] in test_ids),
        })
        result_rows.append(row)

    store.save_alerts(pd.DataFrame(result_rows))
    final = store.get_alerts()
    actions = store.get_actions()
    store.close()

    elapsed = time.time() - t0
    print(f"[6/6] Computing metrics (elapsed {elapsed:.1f}s) ...")
    metrics = compute_metrics(
        final, actions, tech_retriever, elapsed, len(train), len(test)
    )
    write_metrics(metrics, METRICS_PATH)
    figures = plot_figures(metrics, final, FIG_DIR)

    print("\n================ RESULTS ================")
    print(f"Triage accuracy vs analyst labels : {metrics['triage_accuracy']:.3f}")
    print(f"Majority-class baseline accuracy  : {metrics['majority_accuracy']:.3f}")
    print(f"ATT&CK mapping top-1 / top-3      : {metrics['map_top1']:.3f} / {metrics['map_top3']:.3f}")
    print(f"Mean baseline vs assisted time    : {metrics['baseline_time_mean']:.2f} vs "
          f"{metrics['assisted_time_mean']:.2f} min ({metrics['time_reduction']*100:.1f}% faster)")
    print(f"Actions approved/edited/rejected  : {metrics['approved']} / {metrics['edited']} / {metrics['rejected']}")
    print(f"Metrics written to                : {METRICS_PATH}")
    for f in figures:
        print(f"Figure saved to                  : {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
