"""janus-v1 suite: parity reproduction of the Janus 72-cell matrix .

Powered by :mod:`eval.harness` (clean-room Janus-Harness reimplementation).
Configuration via env vars (see :mod:`eval.harness.llm`):

  - ``CUSTOS_EVAL_AGENT_MODEL`` / ``CUSTOS_EVAL_JUDGE_MODEL``
    Default to local Ollama (``ollama/llama3.1:8b``); set to a hosted
    LiteLLM model id (e.g. ``openai/gpt-4o-mini``) for cloud runs.
"""

from __future__ import annotations

from custos.eval.suites.janus_v1.suite import JanusV1Suite

__all__ = ["JanusV1Suite"]
