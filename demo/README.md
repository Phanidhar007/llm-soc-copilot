# SOC Copilot Demo

A **live results dashboard** is deployed at https://llm-soc-copilot.vercel.app (real metrics + figures, AI Shield theme). This Streamlit app is the full local version — interactive UI in the **AI Shield dark theme** (#030303 background, emerald
`#10b981` accent, Space Grotesk / Plus Jakarta Sans, mono uppercase labels,
stat cards, badges, SVG-style figures) that reads the local SQLite alert store + figures produced by the pipeline.

## Run it

From the repo root:

```bash
python scripts/run_pipeline.py          # first: build the store + metrics
streamlit run demo/app.py
```

Then open the URL Streamlit prints (default http://localhost:8501).

## What it shows

- **Overview tab** — headline stat cards (triage accuracy vs. analyst labels,
  approval rate, response-time reduction) computed live from the SQLite store,
  plus the four figures saved by the pipeline run.
- **Alert Inspector tab** — pick any alert to see the full evidence `raw_log`,
  the **AI summary** (retrieval-augmented: matched ATT&CK technique + similar
  past alerts), severity justification, recommended response steps, and the
  analyst action badge. Interactive **Approve / Edit / Reject** buttons write
  to the human-in-the-loop action log (choose "edited" to correct the summary
  text before submitting).
- **Action log tab** — every analyst decision (approve / edit / reject) with
  timestamps and simulated analyst time, joined to the alert evidence.

## Styling

The AI Shield palette is injected via CSS in `app.py` (`CSS` constant) because
Streamlit does not expose raw template control. Fonts are loaded from Google
Fonts; if offline, the app falls back to system sans/mono fonts — the palette
and layout are unchanged.


## 🌐 Live demo

https://llm-soc-copilot.vercel.app — real metrics + figures dashboard (AI Shield theme).
