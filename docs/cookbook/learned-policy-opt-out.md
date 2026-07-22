# Recipe: learned-policy opt-out

The A10 `LearnedPolicyAssistant` learns per-user decisions to auto-resolve
low-disagreement future calls (cold-starts to A7 `RulePolicy`). For a
deployments that does NOT want any in-session learning — e.g. a
compliance-strict deployment where the policy is the sole source of truth —
opt A10 into **read-only mode**. This is the  A10-poisoning mitigation.

## What A10 is

A10 is `exfiltrates_args=False` (it consumes `SubjectContext` + observed
decisions, never LLM goals). It cold-starts to a composed `RulePolicy`
(A7 semantics), and with enough unanimous user observations for a
`(user, tool, _args_hash)` triple, auto-resolves to the learned decision.
Disagreement marks an entry non-confident -> falls back to A7 (no
fatigue-induced capricious auto-resolves).

## What the  A10-poisoning risk is

`record_decision(inv, decision)` is a host extension method (the same
"host calls a documented extension method" precedent as
`observe_user_message`). A malicious host (or a buggy integration) could
feed a broad `allow_and_persist` verdict to poison the per-user learned
overlay with a broad allow. **The floor at the gateway layer is untouched**:
the gateway's shared `_persist_assistant_rule_impl` (H3 narrowness) rejects
broad globs / `any:true` / `allow` actions / cross-shadowing of later denies
before they ever hit the policy. The adversarial sub-suite `tests/assistants`
asserts this:

- `test_gateway_rejects_broad_persisted_rule_from_learned_policy`: an A10
  emitting a poisoned `any:true` ALLOW_AND_PERSIST is accepted for the
  one-time call but NOT inserted into the policy — the next call re-runs the
  assistant, no broad allow survives.

## Opt-out: read-only mode

```python
from custos import Gateway, Policy
from custos.assistants import LearnedPolicyAssistant
from custos.audit import FileAuditSink
from custos.responders import CLIResponder

assistant = LearnedPolicyAssistant(read_only=True)
gw = Gateway(policy=Policy.from_yaml("policy.yaml"),
    assistant=assistant,
    responder=CLIResponder(timeout=30),
    audit_sink=FileAuditSink("audit.jsonl"),)
```

In read-only mode:
- A10 still cold-starts to A7 rules.
- No `record_decision` calls are stored; the in-process
  `LearnedPolicyStore` rejects writes (a `read_only=True` constructor flag).
- `allow_and_persist` from A10 is still subject to the gateway-layer H3
  narrowness assertion (read-only is a defense-in-depth layer; the gateway
  is the floor either way).

Read-only mode is the standing default recommendation for compliance-strict
deployments; opt into learning by leaving `read_only=False` only when you
have an explicit fatigue story (you probably want to also wire A8
`summarize-batch`).

## Policy shape (the learning is in the assistant, not the policy)

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*" }
        action: allow_and_audit
      - match: { tool: "fs.write*" }
        action: assist:learned-policy         # A10 — routes delegation here
      - match: { tool: "shell.*" }
        action: prompt
```

The `assist:learned-policy` action routes to A10 by name (named-assistant routing — an unresolved name fails closed with a safe
`DENY` + audit). Without `read_only`, A10 will accrue user observations
and auto-resolve high-agreement calls.

## What this guards against

- A broad allow sneaking into the persisted-rule overlay — the gateway's H3
  narrowness assertion rejects it at insert time.
- A fatigue-induced capricious auto-resolve — A10's
  disagreement-aware tally falls back to A7 on conflicting observations.
- Cap on host poisoning — `read_only=True` blocks the write path entirely.

## What this does NOT guard against

- A malicious `record_decision` intercepting the host code path and writing
  a side store. Read-only affects only A10's store; an out-of-process
  attacker with code execution is outside Custos's threat surface entirely.
- A10 attaching its `learned-policy` name to a policy rule whose match
  criteria are looser than the operator intended. Audit: a
  `custos audit tail audit.jsonl` review will surface LLM decisions by
  routing label.

## How to test this recipe in CI

```bash
pytest tests/assistants/test_learned_policy.py -k read_only
custos eval --suite adversarial           # learned-policy poisoning sub-suite (6 cells)
```