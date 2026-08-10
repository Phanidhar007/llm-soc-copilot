"""Retrieval-augmented generation (RAG) core.

Two retrieval indices, both implemented with TF-IDF + numpy cosine similarity
(no external vector DB required — ChromaDB / FAISS are optional extras):

1. ``TechniqueRetriever``  - searches the MITRE ATT&CK technique table.
2. ``AlertRetriever``      - searches previously-ingested (already triaged) alerts
                             for "similar past alerts" context.

``LLMInterface`` is the pluggable LLM front end:
* default ``provider=None``  -> deterministic template-based fallback generator
  (so the whole pipeline runs offline with zero extra installs);
* ``provider="ollama"``      -> calls a real local LLM (e.g. Llama/Mistral) via
  ``requests`` to ``http://localhost:11434/api/generate``;
* ``provider="openai"``      -> calls the OpenAI chat-completions API (paid, opt-in).

The method that makes the LLM call is ``LLMInterface.generate`` — read its
docstring: that is the exact slot where a production model would plug in.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize

from .knowledge import Technique, load_techniques, severity_name

OLLAMA_ENDPOINT = os.environ.get("OLLAMA_ENDPOINT", "http://localhost:11434")


class TechniqueRetriever:
    """TF-IDF + cosine retrieval over the ATT&CK technique corpus."""

    def __init__(self, techniques: Sequence[Technique], max_features: int = 3000):
        self.techniques = list(techniques)
        self.vectorizer = TfidfVectorizer(
            lowercase=True, max_features=max_features, sublinear_tf=True
        )
        docs = [t.corpus_doc for t in self.techniques]
        matrix = self.vectorizer.fit_transform(docs)
        # L2-normalized rows so the dot product below is true cosine similarity
        self._matrix_norm = normalize(csr_matrix(matrix), norm="l2", axis=1)

    def retrieve(self, query: str, top_k: int = 2) -> List[Tuple[Technique, float]]:
        """Return top-k techniques ranked by cosine similarity to ``query``."""
        q = self.vectorizer.transform([query])
        q = normalize(csr_matrix(q), norm="l2", axis=1)
        scores = np.asarray((self._matrix_norm @ q.T).todense()).flatten()
        order = np.argsort(scores)[::-1][:top_k]
        return [(self.techniques[i], float(scores[i])) for i in order]


class AlertRetriever:
    """TF-IDF + cosine retrieval over previously triaged alerts."""

    def __init__(self, past_logs: pd.DataFrame, max_features: int = 3000):
        self.logs = past_logs
        self.vectorizer = TfidfVectorizer(
            lowercase=True, max_features=max_features, sublinear_tf=True
        )
        matrix = self.vectorizer.fit_transform(past_logs["raw_log"].tolist())
        self._matrix_norm = normalize(csr_matrix(matrix), norm="l2", axis=1)

    def retrieve(self, query: str, top_k: int = 3) -> List[Dict]:
        """Return top-k similar past alerts (id, similarity, analyst verdict)."""
        q = self.vectorizer.transform([query])
        q = normalize(csr_matrix(q), norm="l2", axis=1)
        scores = np.asarray((self._matrix_norm @ q.T).todense()).flatten()
        order = np.argsort(scores)[::-1][:top_k]
        hits = []
        for i in order:
            hits.append({
                "id": self.logs.iloc[i]["id"],
                "similarity": float(scores[i]),
                "analyst_verdict": self.logs.iloc[i]["analyst_verdict"],
            })
        return hits


class LLMInterface:
    """Pluggable LLM front end with an offline fallback.

    ``provider`` config:
    * None           -> deterministic template generator (default, offline).
    * "ollama"       -> local model via requests to the Ollama HTTP API.
    * "openai"       -> OpenAI chat completions (needs OPENAI_API_KEY).

    The *real* LLM call happens in :meth:`generate`. To wire a different model
    (Claude, custom endpoint) implement ``generate`` accordingly — callers only
    rely on ``generate(context: dict) -> str``.
    """

    def __init__(self, provider: Optional[str] = None, model: str = "llama3",
                 api_key: Optional[str] = None, timeout: float = 10.0):
        self.provider = provider
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.timeout = timeout

    def available(self) -> bool:
        """Check whether the configured live LLM backend is reachable."""
        if self.provider == "ollama":
            try:
                import requests  # noqa: F401
                resp = requests.get(f"{OLLAMA_ENDPOINT}/api/tags", timeout=self.timeout)
                return resp.status_code == 200
            except Exception:
                return False
        if self.provider == "openai":
            return bool(self.api_key)
        return False

    # ------------------------------------------------------------------ #
    # THE LLM CALL SLOT
    # ------------------------------------------------------------------ #
    def generate(self, context: Dict) -> str:
        """Generate a free-form triage summary from retrieval ``context``.

        * fallback provider: returns a templated summary (offline, deterministic).
        * ollama provider:   builds a prompt from ``context`` and POSTs it to
                             ``{OLLAMA_ENDPOINT}/api/generate``. The live call is
                             the ``requests.post(...)`` line below.
        * openai provider:   POSTs ``context`` to the chat completions endpoint.

        Return value is always plain text that downstream code renders as the
        "AI summary" of the alert.
        """
        if self.provider == "ollama":
            live = self._generate_ollama(context)
            if live:
                return live
        elif self.provider == "openai":
            live = self._generate_openai(context)
            if live:
                return live
        return fallback_summary(context)

    def _generate_ollama(self, context: Dict) -> Optional[str]:
        """Call a local Ollama model. Returns None on any failure (falls back)."""
        try:
            import requests
            prompt = build_llm_prompt(context)
            payload = {"model": self.model, "prompt": prompt, "stream": False}
            resp = requests.post(
                f"{OLLAMA_ENDPOINT}/api/generate",
                json=payload,
                timeout=min(self.timeout * 6, 120),
            )
            resp.raise_for_status()
            return resp.json().get("response", "").strip() or None
        except Exception:
            return None

    def _generate_openai(self, context: Dict) -> Optional[str]:
        """Call the OpenAI chat completions API (paid, opt-in)."""
        try:
            import requests
            prompt = build_llm_prompt(context)
            resp = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system",
                         "content": "You are a SOC analyst copilot. Produce a concise, "
                                    "actionable triage summary with severity justification "
                                    "and recommended response steps."},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
                timeout=min(self.timeout * 6, 120),
            )
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"].strip()
        except Exception:
            return None


def build_llm_prompt(context: Dict) -> str:
    """Assemble the prompt fed to a live LLM from the retrieval context."""
    lines = [
        "ALERT RAW LOG:",
        context.get("raw_log", ""),
        "",
        "TOP MATCHED ATT&CK TECHNIQUES:",
    ]
    for t in context.get("techniques", []):
        lines.append(
            f"- {t['id']} {t['name']} (sim {t['score']:.3f}) :: {t['description']}"
        )
    lines += ["", "SIMILAR PAST ALERTS:"]
    for s in context.get("similar", []):
        lines.append(f"- {s['id']} sim={s['similarity']:.3f} verdict={s['analyst_verdict']}")
    lines += [
        "",
        "TASK: Write a 3-5 sentence triage summary, one severity-justification line, "
        "and 3 numbered recommended response steps.",
    ]
    return "\n".join(lines)


def fallback_summary(context: Dict) -> str:
    """Deterministic template-based summary generator (the offline 'LLM').

    This is the fallback that keeps the entire pipeline runnable with only the
    installed packages (no network, no model weights). It fills a structured
    template from the retrieval context: top technique + similarity, evidence
    fields, similar past alerts, and severity justification.
    """
    raw = context.get("raw_log", "")
    sev = context.get("severity", 1)
    techniques = context.get("techniques", [])
    similar = context.get("similar", [])

    if not techniques:
        return (
            f"[triage summary] No ATT&CK technique could be confidently matched for "
            f"'{raw[:80]}'. Severity kept at {severity_name(sev)} pending analyst review. "
            f"Recommended: escalate to analyst for manual correlation."
        )

    top = techniques[0]
    t_id = top["id"]
    t_name = top["name"]
    t_desc = top["description"]
    t_score = float(top["score"])
    t_base = int(top["base_severity"])
    t_label = top["label"]
    base_sev = severity_name(t_base)

    verdict = "malicious" if t_label == "malicious" else "suspicious"
    sev_just = (
        f"Alert severity '{severity_name(sev)}' against technique {t_id} {t_name} "
        f"(baseline '{base_sev}', adversarial intent '{t_label}') with retrieval "
        f"similarity {t_score:.3f}. "
    )
    if t_base >= 3:
        sev_just += "High-impact technique; treat as priority for containment."
    elif sev >= t_base:
        sev_just += "Alert severity matches or exceeds technique baseline."
    else:
        sev_just += "Alert severity is below technique baseline; verify with additional context."

    if similar:
        ref = similar[0]
        sim_note = (f"Most similar past alert {ref['id']} (sim {ref['similarity']:.3f}) "
                    f"was verdict '{ref['analyst_verdict']}'.")
    else:
        sim_note = "No closely similar past alerts in the store yet."

    steps = [f"1. Verify and isolate the host that reported '{raw[:60]}...'.",
             f"2. Apply response for {t_id} {t_name}: {_response_for(t_id)}",
             f"3. Log the decision in the human-in-the-loop store and, if confirmed, "
             f"update detection coverage for {t_id}."]

    return (
        f"[triage summary] Alert matched {t_id} {t_name} (sim {t_score:.3f}). "
        f"Evidence '{raw[:120]}...' is consistent with {verdict} activity. "
        f"{sim_note}\n"
        f"[severity justification] {sev_just}\n"
        f"[recommended response] " + " ".join(steps)
    )


def _response_for(technique_id: str) -> str:
    """Look up the recommended response text for a technique ID."""
    for t in load_techniques():
        if t.id == technique_id:
            return t.response
    return "contain the affected asset and escalate."
