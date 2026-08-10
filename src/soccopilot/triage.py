"""Triage engine: retrieve context -> classify -> build a natural-language
triage package (summary + severity justification + recommended response).

Classification is a small sklearn pipeline trained on analyst-labeled alerts:
features are the TF-IDF of the raw log plus retrieval-aware numeric features
(top technique retrieval score and the technique's baseline severity). This
keeps the copilot literally retrieval-augmented: the RAG step runs first, and
its output is part of the classifier input.
"""

from __future__ import annotations

from typing import Dict, Optional, Sequence

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .knowledge import Technique, severity_name
from .rag import AlertRetriever, LLMInterface, TechniqueRetriever, fallback_summary

LABELS = ["benign", "suspicious", "malicious"]
LABEL_RANK = {k: i for i, k in enumerate(LABELS)}


def _numeric_features(alerts: pd.DataFrame, tech_index: Dict[str, Technique],
                      tech_retriever: TechniqueRetriever) -> pd.DataFrame:
    """Build the retrieval-aware numeric feature block for a batch of alerts.

    Columns: sev (alert severity), score (top-1 retrieval score),
    base_sev (top-1 technique baseline severity).
    """
    rows = []
    for _, a in alerts.iterrows():
        top1, score = tech_retriever.retrieve(a["raw_log"], top_k=1)[0]
        rows.append([float(a["severity"]), float(score), float(top1.base_severity)])
    return pd.DataFrame(rows, columns=["sev", "score", "base_sev"])


class TriageEngine:
    """Fits and applies the copilot triage classifier + summary generator."""

    def __init__(self, techniques: Sequence[Technique],
                 tech_retriever: TechniqueRetriever,
                 llm: Optional[LLMInterface] = None):
        self.techniques = list(techniques)
        self.tech_index = {t.id: t for t in self.techniques}
        self.tech_retriever = tech_retriever
        self.llm = llm or LLMInterface()
        self.alert_retriever: Optional[AlertRetriever] = None
        self.model: Optional[Pipeline] = None

    def set_past_alerts(self, past: pd.DataFrame) -> None:
        """Provide the store of already-triaged alerts for similarity retrieval."""
        self.alert_retriever = AlertRetriever(past)

    def fit(self, train: pd.DataFrame) -> "TriageEngine":
        """Train the triage classifier on analyst-labeled alerts."""
        X = pd.concat([
            pd.DataFrame({"log": train["raw_log"].tolist()}),
            _numeric_features(train, self.tech_index, self.tech_retriever),
        ], axis=1)
        y = train["analyst_verdict"].astype(str).tolist()
        self.model = Pipeline([
            ("feat", ColumnTransformer(
                transformers=[
                    ("tfidf", TfidfVectorizer(
                        lowercase=True, max_features=2000, sublinear_tf=True), "log"),
                    ("num", StandardScaler(),
                     ["sev", "score", "base_sev"]),
                ],
                sparse_threshold=1.0,
            )),
            ("clf", LogisticRegression(max_iter=2000, C=1.0)),
        ])
        self.model.fit(X, y)
        return self

    def predict_label(self, alert: pd.Series) -> "tuple[str, float]":
        """Return (predicted triage label, confidence) for one alert."""
        X = pd.concat([
            pd.DataFrame({"log": [alert["raw_log"]]}),
            _numeric_features(alert.to_frame().T, self.tech_index,
                              self.tech_retriever),
        ], axis=1)
        probs = self.model.predict_proba(X)[0]
        idx = int(np.argmax(probs))
        return self.model.classes_[idx], float(probs[idx])

    def triage_alert(self, alert: pd.Series) -> Dict:
        """End-to-end triage for one alert.

        Pipeline:
          1. retrieve top-2 techniques (RAG over ATT&CK),
          2. retrieve top-3 similar past alerts (RAG over the alert store),
          3. predict triage label (retrieval-augmented classifier),
          4. generate the natural-language triage package (LLM or fallback).
        """
        raw = alert["raw_log"]
        tech_hits = self.tech_retriever.retrieve(raw, top_k=2)
        top_tech, top_score = tech_hits[0]
        similar = (
            self.alert_retriever.retrieve(raw, top_k=3)
            if self.alert_retriever is not None else []
        )

        label, conf = self.predict_label(alert)

        context = {
            "raw_log": raw,
            "severity": int(alert["severity"]),
            "techniques": [
                {"id": t.id, "name": t.name, "description": t.description,
                 "score": s, "label": t.label, "base_severity": t.base_severity}
                for t, s in tech_hits
            ],
            "similar": similar,
        }

        # --- where the (optional) live LLM call happens ---
        if self.llm.available():
            summary = self.llm.generate(context)
        else:
            summary = fallback_summary(context)

        just = _extract_justification(summary)
        steps = _extract_steps(summary)

        return {
            "ai_technique": top_tech.id,
            "ai_technique_conf": float(top_score),
            "ai_label": label,
            "ai_conf": conf,
            "summary": summary,
            "severity_justification": just,
            "recommended_steps": " | ".join(steps),
            "similar": similar,
            "technique_hits": [t.id for t, _ in tech_hits],
        }


def _extract_justification(summary: str) -> str:
    """Pull the severity-justification line out of the generated summary."""
    for line in summary.splitlines():
        if "[severity justification]" in line:
            return line.replace("[severity justification]", "").strip()
    return summary.split("\n")[0][:200]


def _extract_steps(summary: str) -> list:
    steps = []
    for line in summary.splitlines():
        line = line.strip()
        if line.startswith("1.") or line.startswith("2.") or line.startswith("3."):
            steps.append(line)
    return steps or ["1. Escalate to analyst for manual review."]
