# Recipe: read-only auto-allow

The standing default-allow-read layer most agents start from. Every
read-only tool call passes through with an audit record; every write is
prompted. Produces the lowest prompt count for a normal agent workload.

## Policy

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*", side_effects: [read] }
        action: allow_and_audit
      - match: { tool: "shell.cat", side_effects: [read] }
        action: allow_and_audit
      - match: { tool: "shell.*" }
        action: prompt
      - match: { tool: "fs.write*" }
        action: prompt
      - match: { any: true }
        action: deny
```

- `side_effects: [read]` intersected with the tool descriptor's declared side
  effects. A tool declaring only `read` matches.
- The final `any: true -> deny` matches everything unmatched (the
  `default: deny` is the same guarantee made explicit at the rule layer).
- `allow_and_audit`  short-circuits with an audit emit; no
  responder and no assistant are consulted. Latency is p99 < 50ms .

## Wiring

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.audit import FileAuditSink
from custos.responders import CLIResponder

policy = Policy.from_yaml("policy.yaml")
gw = Gateway(policy=policy,
    assistant=RulePolicy,         # A7 — only invoked on assist:*; nothing here
    responder=CLIResponder(timeout=30),
    audit_sink=FileAuditSink("audit.jsonl"),)
```

## What this guards against

- A noisy agent loop reading hundreds of files: zero prompts, every read
  audited . Audit volume is the cost; rotate the file with the
  keylio pipeline of your choice (the `HashChainedAuditSink` from
  preserves tamper-evidence across rotations).
- An agent writing a file surreptitiously: `fs.write*` falls through to the
  CLI `prompt` and you say no.

## What this does NOT guard against

- A tool that **lies** about its `side_effects` descriptor (`SideEffect.READ`
  declared but the body calls `os.unlink`). Custos governs on the *declared*
  descriptor; the tool-spoofing adversarial cell asserts the gateway also
  evaluates on `invocation.tool` (not the descriptor's lying `name`), but
  descriptor-internal lies are an out-of-band code-review concern. Mitigation
  in v1.1: typed tool descriptors with verifier signatures.
- An agent that learns the `allow_and_audit` shape and never asks for a
  write. The audit trail is the backstop — review it before shipping
  artifacts.

## How to test this recipe in CI

```bash
custos eval --suite adversarial           # zero false-allows expected
custos audit tail audit.jsonl -n 200      # grep for "decision": "allow" writes
```