# SOC Copilot — Run Metrics (REAL numbers)

Produced by `scripts/run_pipeline.py` on this machine. All values below are computed live from the simulated alert stream + actual pipeline output.

## Run summary

- Dataset: **300** synthetic alerts (seeded, reproducible)
- Train / held-out test split: **210 / 90** (stratified)
- End-to-end pipeline wall time: **3.2 s** on CPU
- RAG: TF-IDF + numpy cosine (no vector DB); LLM: offline template fallback

## Key metrics (held-out test set)

| Metric | Value |
| --- | --- |
| **Triage accuracy vs analyst labels** | **0.967** |
| Majority-class baseline accuracy | 0.456 |
| Accuracy — benign | 0.867 |
| Accuracy — suspicious | 1.000 |
| Accuracy — malicious | 0.976 |
| **ATT&CK mapping — top-1** | **0.911** |
| ATT&CK mapping — top-3 | 0.989 |
| **Mean baseline analyst time** | **12.27 min** |
| **Mean assisted analyst time** | **4.44 min** |
| **Response-time reduction** | **63.8%** |

## Human-in-the-loop actions (held-out test set)

- Approved: **87** (96.7%)
- Edited: **1** (1.1%)
- Rejected: **2** (2.2%)

Figures: `results/figures/` (triage_accuracy, attack_mapping, response_time, action_distribution).

_Notes: data is synthetic (technique-templated alerts with a 15% decoy / false-positive rate) so these numbers measure pipeline behavior on a controlled stream, not real-world SOC performance._
