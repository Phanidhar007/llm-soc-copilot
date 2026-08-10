# LLM-Powered SOC Copilot

A retrieval-augmented triage copilot for security operations centers:
**alert in → RAG over MITRE ATT&CK + similar past alerts → natural-language
triage summary, severity justification and recommended response steps →
human-in-the-loop approve / edit / reject logging → measured accuracy.**

Runs fully offline on CPU with only installed packages (`numpy`, `scikit-learn`,
`pandas`, `matplotlib`, `scipy`, `requests`, `streamlit`). The "LLM" is a
deterministic retrieval+template fallback by default; a real local model
(Llama/Mistral via Ollama) or a paid API (OpenAI) can be plugged in behind a
config flag.

---

## 🌐 Live demo

**https://llm-soc-copilot.vercel.app** — live results dashboard: real metrics from `results/metrics.md` plus charts from `results/figures/` (AI Shield dark theme, no model executed server-side).

Interactive **local** demo (Streamlit): `streamlit run demo/app.py` — see [demo/README.md](demo/README.md).

## Threat model

**The problem.** SOC teams drown in alerts — a mid-size enterprise can generate
thousands per day, and most are triaged by human analysts who must correlate each
alert against a huge knowledge base (which MITRE ATT&CK technique is this? did we
see it before? how severe? what do we do first?). Analysis shows most alert
triage time goes to *lookup and correlation*, not judgment. The bottleneck is
information retrieval, not reasoning.

**Adversary capability assumptions.** The adversary uses standard, well-documented
TTPs from the MITRE ATT&CK matrix (command & scripting, phishing, credential
dumping, ransomware, tunneling, brute force, ...). They are assumed to be capable
of evading simplistic signature checks (which is why the copilot matches against
technique *behaviour* text, not just signatures) and to exploit the *volume* of
alerts to bury real incidents in noise. Defenders are assumed to be time-starved
and inconsistent under load — hence the need for a copilot that reduces time to
triage, cites its evidence, and keeps a human in the loop.

**How this project defends against it.** The copilot
1. **ingests** alerts from a SQLite alert store,
2. **retrieves** the relevant ATT&CK technique description + detection + response
   and the most similar *past triaged alerts* (RAG over a TF-IDF / cosine index —
   no external vector DB required),
3. **generates** a triage summary with a severity justification and numbered
   response steps,
4. exposes every suggestion to an **analyst who approves, edits or rejects** it —
   every decision is logged (human-in-the-loop),
5. and then **measures** what matters: triage accuracy vs. analyst labels,
   response-time reduction, and ATT&CK technique-mapping accuracy.

The claim the repo demonstrates: retrieval-augmented triage reaches high agreement
with analysts while cutting mean response time by ~64% on a synthetic (but
reproducible) alert stream, with the human decision logged for audit.

> **Honesty note.** The alert stream is synthetic and technique-templated, with a
> 15% decoy (false-positive) rate and simulated analyst verdicts (ground truth +
> ~5% human error). Numbers in `results/metrics.md` are real output of an actual
> local run of `scripts/run_pipeline.py` — they measure pipeline behaviour on a
> controlled stream, not real-world SOC performance.

---

## Repository layout

```
llm-soc-copilot/
  README.md                # this file
  requirements.txt         # installed deps (+ optional extras commented)
  .gitignore
  src/soccopilot/
    __init__.py
    alert_store.py         # SQLite alert store + synthetic alert generator
    knowledge.py           # MITRE ATT&CK table (20 techniques) loader
    rag.py                 # TF-IDF+cosine retrieval (techniques & past alerts)
                           # + LLMInterface (Ollama/OpenAI) + offline fallback
    triage.py              # retrieval-augmented triage classifier + summary gen
    human_loop.py          # approve / edit / reject logging + time model
    evaluate.py            # metrics + metrics.md writer + figure plotting
  scripts/
    run_pipeline.py        # end-to-end: build store, triage, log, evaluate
  notebooks/
    soc_copilot_experiment.ipynb  # matching experiment notebook
  demo/
    app.py                 # local Streamlit demo (AI Shield dark theme)
    README.md
  results/
    metrics.md             # REAL numbers from running the pipeline
    soc_alerts.db          # SQLite store produced by the pipeline (git-ignored)
    figures/               # charts saved by the run
```

## The "LLM": offline fallback + pluggable real model

The pipeline must run with only the installed packages, so `rag.LLMInterface`
provides:

- **Offline fallback (default).** Retrieval + structured template fills the
  natural-language summary: top matched technique + similarity, evidence fields,
  similar past alerts, severity justification vs. the technique baseline, and
  numbered response steps. Deterministic, no network, no weights.
- **Ollama (free, local).** `LLMInterface(provider="ollama", model="llama3")`
  POSTs the retrieval context to `http://localhost:11434/api/generate` via
  `requests`. If Ollama is unreachable it silently falls back offline.
- **OpenAI (paid, optional).** `LLMInterface(provider="openai")` with
  `OPENAI_API_KEY`.

The single call site is `LLMInterface.generate(context)` — read its docstring;
that is exactly where a production model would slot in.

## Vector store

No vector DB is needed: both retrieval indices are **TF-IDF + numpy cosine
similarity** (`sklearn` + `scipy`). ChromaDB/FAISS are listed as optional extras
in `requirements.txt` and are not used.

---

## Setup

```bash
cd llm-soc-copilot
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt                  # or use the pre-installed env
```

Everything is computed on CPU; the full run takes a few seconds.

## Usage

### 1) Run the pipeline (produces results/metrics.md + figures)

```bash
python scripts/run_pipeline.py                       # offline fallback LLM
python scripts/run_pipeline.py --alerts 500 --seed 3 # different stream
python scripts/run_pipeline.py --ollama --ollama-model llama3   # live local LLM
python scripts/run_pipeline.py --openai                         # paid API path
```

Output: console summary + `results/metrics.md` (real numbers) +
`results/figures/*.png` (triage accuracy, ATT&CK mapping, response time,
action distribution).

### 2) Local demo (AI Shield dark theme)

```bash
python scripts/run_pipeline.py   # first
streamlit run demo/app.py
```

See `demo/README.md` for details.

### 3) Experiment notebook

```bash
jupyter notebook notebooks/soc_copilot_experiment.ipynb
```

Mirrors the pipeline cell-by-cell (data → retrieval → triage → human loop →
evaluation).

---

## Results (from an actual local run)

Run: `python scripts/run_pipeline.py --alerts 300 --seed 7` · wall time ~4.1 s CPU.

| Metric | Value |
| --- | --- |
| **Triage accuracy vs analyst labels** (held-out) | **0.967** |
| Majority-class baseline accuracy | 0.456 |
| Accuracy — benign / suspicious / malicious | 0.867 / 1.000 / 0.976 |
| **ATT&CK mapping — top-1 / top-3** | **0.911 / 0.989** |
| Mean baseline analyst time | 12.27 min |
| Mean assisted analyst time | 4.44 min |
| **Response-time reduction** | **63.8%** |
| Human-in-the-loop actions (test set) | 87 approved · 1 edited · 2 rejected (96.7% / 1.1% / 2.2%) |

Full detail (including per-class accuracy) in [`results/metrics.md`](results/metrics.md).

---

## Deviations / decisions vs. the original spec

- **No external vector DB.** ChromaDB/FAISS marked optional; retrieval uses
  numpy + TF-IDF cosine (allowed by spec).
- **LLM = retrieval+template fallback** by default with real Ollama/OpenAI
  integration code behind a flag (`try: import requests`, config) — spec-compliant.
- **Synthetic, seeded alert data** (300 alerts, 20 ATT&CK techniques, 15% decoys)
  keeps the run < 10 s and reproducible; a real SOC feed can be dropped into
  `alert_store` without changing the rest of the pipeline.
- All metrics are computed live by the run script — nothing is hard-coded.
