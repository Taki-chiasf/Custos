# Custos eval harness

CI suite for agent permission behavior .  deliverable.

## Surface

```
custos eval --suite janus-v1 --smoke --dry-run       # plan + manifest; no LLM (default)
custos eval --suite janus-v1 --smoke --execute      # 3-cell live smoke (per-PR tier)
custos eval --suite janus-v1 --execute              # full 1440-cell matrix (release-gated)
custos eval --suite janus-v1 --execute \
  --baseline Janus/metrics/submission_metrics.csv   # add the ±5% parity gate
custos eval --suite adversarial                     # 5-cell keyless regression suite (M8)
custos eval --suite adversarial --smoke             # 3-cell prompt-injection + confused-deputy smoke
custos audit replay audit.jsonl --policy new.yaml   # policy what-if analysis
```

## Suites

- `janus-v1` — clean-room re-implementation of the Janus-Harness evaluation
  framework, reproducing the published 72-cell × 5-rep = 1440-row matrix
  . Default backend is **local Ollama** (no API spend, no key);
  set `CUSTOS_EVAL_AGENT_MODEL` / `CUSTOS_EVAL_JUDGE_MODEL` to any LiteLLM
  model id for hosted runs. Parity diff: `eval/parity/compare.py`.
- `adversarial` — Custos-authored regression suite exercising the production
  sync `Gateway` (deny-floor) against four attack categories (cf. arXiv:2606.28679): prompt injection, confused deputy, tool spoofing,
  delegation-depth abuse. Keyless + deterministic; M8 gate (zero false-allows).

## Layout

```
eval/
├── harness/             # janus-v1 parity stack (clean-room; Janus no-deny-floor)
│   ├── scenarios.py, metrics.py, tool_call_evaluator.py, synthetic_responder.py
│   ├── run_harness.py, cell_runner.py, llm.py (default -> ollama/llama3.1:8b)
│   ├── assistants/ (async A1-A6), policy/ (Janus semantics), tools.py, permission_manager.py
├── suites/
│   ├── janus_v1/  (suite.py + fixtures/ + PARITY_REPORT.md + DECISION_SEMANTICS.md)
│   └── adversarial/ (suite.py + scenarios.py)
├── reports/render.py    # stdlib HTML + JSON report writer
├── metrics.py           #  aggregates (precision/recall/false-allow/fatigue)
├── parity/compare.py    # ±5% parity gate (M7)
└── audit_replay.py      # custos audit replay
```

## Backend config

| Env var | Default | Notes |
|---|---|---|
| `CUSTOS_EVAL_AGENT_MODEL` | `ollama/llama3.1:8b` | Agent loop + default for LLM-backed assistants. Any LiteLLM model id works (`openai/gpt-4o-mini`, `anthropic/...`, `gemini/...`). |
| `CUSTOS_EVAL_JUDGE_MODEL` | = agent model | LLM used by goal/output criteria judges. |
| `CUSTOS_EVAL_MAX_FOLLOWUPS` | `5` | Per-goal follow-up turn cap in the Janus agent loop. |
| `CUSTOS_EVAL_OLLAMA_TIMEOUT` | `120` (seconds) | Per-request HTTP socket timeout for the native Ollama client. Raise for bigger local models. |
| `OPENAI_API_KEY` / `GEMINI_API_KEY` / `ANTHROPIC_API_KEY` | — | Required only for hosted models (the Ollama path needs none). |