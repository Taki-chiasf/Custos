# Eval harness

`custos eval` (+  hardening). Two suites ship in
the box: `janus-v1` (Janus paper parity) and `adversarial` (Custos-authored
attack cells).

## Install

```bash
pip install "custos[eval]"      # adds the Janus parity stack
# default backend is local Ollama (no API key, no cost)
```

## Run

```bash
custos eval --suite janus-v1 --smoke --dry-run        # plan + write manifest
custos eval --suite janus-v1 --smoke --execute        # 3 cells, local Ollama
custos eval --suite janus-v1 --execute --repetitions 1   # full 1440-cell matrix
custos eval --suite adversarial                        # 53 cells, keyless
```

Exit codes : 0 OK, 1 regression (parity or false-allow), 2 suite
not found / config error, 3 other.

## janus-v1

Reproduces the 3 scenarios x 4 subscenarios x 3 synthetic responders x 2
risk tolerances (72 cells x repetitions) from the Janus paper. Smoke = 3
cells; full = 1440 cells (deferred to  single overnight run per D18).
Parity checked at +/-5% on `desired_tool_calls` / `attack_tool_calls` via
`eval/parity/compare.py` against `--baseline <submission_metrics.csv>`.

Backend: local Ollama by default (`ollama/llama3.1:8b`); env
`CUSTOS_EVAL_AGENT_MODEL` / `CUSTOS_EVAL_JUDGE_MODEL` to override. No paid
API key is required (M3 cost note).

## adversarial

53 Custos-authored attack cells covering prompt injection, confused deputy,
tool spoofing, delegation-depth abuse, learned-policy poisoning (expansion: N=53 exceeds the N>=50 bar).

Key features:
- Positive-control cells with `expected = ALLOW` (catches over-deny
  regressions; verifies the floor height works both directions).
- LLM-injection cells driving a production `Gateway` with a
  `FunctionLLMClient` stub returning a "low-risk allow" from injected
  assistant reasoning — asserts sec 15 escalation holds (DENY regardless).
- A `tool_spoofing` allow-control proving the gateway evaluates on
  `invocation.tool` (not a lying descriptor label).

M8 returns "zero false-allows AND zero false-denies across the 53-cell
regression set".

## Reports + CI exit codes

Both suites emit `report.html` + `report.json` carrying the
`MetricReport` (precision/recall of denials vs ground-truth-risk, prompt
count per session, cognitive-load proxy, false-allow rate). HTML is
self-contained (no jinja, no JS — inline `<style>`, stdlib-only writer).

```bash
custos eval --suite adversarial --output-dir runs/eval
# -> runs/eval/adversarial/report.html + report.json
```

## Programmatic

```python
from custos.eval.suite import SuiteArgs, run_eval

rc = run_eval(SuiteArgs(suite="adversarial",
    policy="policy.yaml",
    smoke=False,
    execute=True,
    output_dir="runs/eval",))
sys.exit(rc)
```

## The eval packaging contract

The `custos eval` and `custos audit replay` entry points are importable
from a wheel install — the eval code lives under `src/custos/eval/` (not
the Python builtin-shadowing `eval/` legacy layout). `pip install
custos[eval]` is the user-facing gate.