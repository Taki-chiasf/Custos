# Assistants

The assistant catalog (A1–A11). Assistants implement the
`Assistant` (sync) or `AssistantAsync` (native-async) Protocol and are
registered with the gateway by name (named-assistant routing).

| ID | `name` | Behavior | `exfiltrates_args` | Decision |
|---|---|---|---|---|
| A1 | `auto-approve` | Unconditionally approves every denied call. Baseline. | False | `allow_once` |
| A2 | `user-confirmation` | Prompts the user for every denied call. Severity: max fatigue. | False | `allow_once` / `deny` |
| A3 | `constitution` | Compiles a plain-language constitution doc into JSON rules (LLM, cached by SHA-256). | True | `allow_once` / `deny` |
| A4 | `policy-suggestion` | Interactive policy co-pilot. LLM drafts a generalized ABAC rule; user accepts / revises / rejects. | True | `allow_and_persist` / `deny` |
| A5 | `risk-assessment` | Goal-aware LLM risk scoring (2 LLM calls). | True | `allow_once` / `prompt` / `deny` |
| A6 | `risk-assessment-autonomous` | Same as A5 but above-tolerance calls are denied silently. | True | `allow_once` / `deny` |
| A7 | `rule-policy` | Pure deterministic rules; no LLM. Fast path. | False | per-rule |
| A8 | `summarize-batch` | Batches calls in a window; one prompt with a count + summary. | False | `prompt` (batched) |
| A9 | `context-adaptive` | Chooses prompt granularity by task sensitivity. | True | `allow` / `prompt` |
| A10 | `learned-policy` | Learns from past user decisions to auto-resolve low-disagreement calls. Cold-starts to A7. | False | `allow_once` / `deny` |
| A11 | `delegation-aware` | Gradient by delegation depth; deeper -> stricter. | False | `allow` / `prompt` / `deny` |
| A12 | `ipi-defender` | Context inspector for selective IPI defence. Fast-path pattern matching + leave-one-out causal attribution + CoT masking. | configurable | SAFE / SUSPICIOUS / INJECTION |

A1–A6 reproduce the Janus reference assistants. A7–A11 are Custos extensions.
A12 is a context inspector — it operates on full agent context, not on
individual tool invocations. See [Context Inspectors](inspectors.md).

## Installing the LLM-backed ones

```bash
pip install "custos-middleware[llm]"            # adds LiteLLM; A3–A6 + A9 need it
# or use the local Ollama backend in the eval harness (no API key):
pip install "custos-middleware[eval]"
```

A7/A10/A11 are in-process and require no LLM. A1/A2 are pure Python.

## Wiring

```python
from custos import Gateway, Policy
from custos.assistants import (RulePolicy, RiskAssessment, RiskAssessmentAutonomous,
    DelegationAwareAssistant, LearnedPolicyAssistant,)
from custos.integrations.litellm_ import LiteLLMClient

gw = Gateway(policy=Policy.from_yaml("policy.yaml"),
    assistant=RiskAssessment(tolerance=0.35,
                             llm=LiteLLMClient(model="openai/gpt-4o-mini")),
    responder=CLIResponder,)
```

The `assist:<name>` policy action routes to a registered assistant by name.
A single configured `assistant=` is the default assistant (path); a
`RegisteredAssistantRegistry`  is available for multi-assistant
deployments so a single gateway can route distinct assistants per-tool,
per-goal, etc.

## Goal extraction (A5/A9)

`observe_user_message(msg)` is the host extension hook — same "host calls a
documented extension method" precedent as A10's `record_decision`. Call it
BEFORE the first tool call so goals are available for risk judging.

```python
assistant.observe_user_message("send the weekly team update email")
# ... later, an email.send decision call now carries goal context
```

## The floor / ceiling

An assistant can ONLY escalate strictness, never relax a policy `deny`. The
gateway never invokes the assistant on a policy `deny` short-circuit. An
assistant `allow` is untrusted at the boundary. See the
[threat model](THREAT_MODEL.md) row 1.

## `allow_and_persist` (H3 narrowness bullet 7)

A4 and A10 can return `allow_and_persist` to insert a new rule for fatigue.
The gateway's shared `_persist_assistant_rule_impl` rejects broad globs /
`any:true` / bare `allow` actions / `matches` regex operators; the persisted
rule MUST be structurally narrower than the rule it escalates from AND MUST
NOT intersect any later `deny*` rule's match-set. The adversarial sub-suite
(6 poisoning shapes) asserts this.