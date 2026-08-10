"""LLM-Powered SOC Copilot.

A retrieval-augmented triage assistant for security operations centers:
ingest alerts -> retrieve MITRE ATT&CK context + similar past alerts (RAG) ->
generate a natural-language triage summary, severity justification and
recommended response steps -> human-in-the-loop approve / edit / reject logging.

The project runs fully offline with a deterministic retrieval + template
fallback "LLM". A real LLM (Ollama / OpenAI / Claude) can be plugged in through
``soccopilot.rag.LLMInterface`` behind a config flag; the code marks exactly
where the LLM call would slot in.

Compute budget: everything here is small (synthetic data, TF-IDF, sklearn);
the end-to-end pipeline finishes in well under 2-3 minutes on CPU.
"""

__version__ = "0.1.0"
