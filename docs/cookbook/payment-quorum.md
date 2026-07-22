# Recipe: payment quorum (separation of duties)

Two distinct approver roles must both approve before `payment.*` calls run.
Uses the   surface: a rule-level `quorum` + `approver_roles`
hint, the `MultiApproverResponder`, and the audit `quorum_state` field.

> This recipe is the canonical end-to-end demo. The runnable script lives
> at `examples/quorum_demo.py` (shipped at).

## Policy

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*" }
        action: allow_and_audit
      - match: { tool: "payment.refund" }
        action: prompt
        options: [allow_once, deny]
        quorum: 2
        approver_roles: [finance, security]
```

- `quorum: 2` requires 2 distinct approvers (separation of duties).
- `approver_roles: [finance, security]` — each role counts once toward the
  quorum. Two `finance` approvals count as 1, not 2.
- `options: [allow_once, deny]` excludes standing allows; even on a `met`
  quorum, the decision is one-shot. This is the "no standing allows for
  payments" non-goal from .

## Wiring

```python
from custos import Gateway, Policy
from custos.audit import FileAuditSink
from custos.responders import CLIResponder, MultiApproverResponder
from custos.schema import SubjectContext
from custos.sdk import set_default_context

policy = Policy.from_yaml("policy.yaml")

# Compose two child CLI responders, each one "role". In a real deployment
# the child responders are Slack / web / out-of-band so the two roles are
# distinct humans at distinct screens.
finance = CLIResponder(timeout=300, approver="alice@finance")
security = CLIResponder(timeout=300, approver="bob@security")

quorum = MultiApproverResponder(children=[finance, security])

gw = Gateway(policy=policy,
    responder=quorum,
    audit_sink=FileAuditSink("audit.jsonl"),)
set_default_context(SubjectContext(user_id="agent", goal_id="refund-flow"))
```

## Decision flow

1. `payment.refund` matches the quorum rule. The gateway extracts `quorum=2`,
   `approver_roles=[finance, security]` and forwards via `PromptRequest`
   (the rule-level responder hint ; NOT a MatchSpec predicate).
2. `MultiApproverResponder.prompt` fans the request out to both children.
3. Each child attests the approver identity (H12 — `PromptResponse.approver`
   for CLI is the configured `approver` param; for Slack it's
   `payload.user.id`; the audit log records it).
4. The `quorum_state` machine:
   - **finance-alone approves, security not yet** -> `pending` -> responder
     returns `DEFER` to the agent. The agent is expected to retry (capped,
     exponential backoff per  responder-failure-mode).
   - **both approve from disjoint roles** -> `met` -> `ALLOW`. Approver
     list is comma-joined sorted in `PromptResponse.approver`.
   - **any one denies OR the responder errored** -> `failed` -> `DENY`.
     `quorum_state="failed"` is recorded on the `AuditEvent` (audit field; see `AuditEvent.to_dict`).

## Approval allowlist (optional)

A policy overlay can additionally restrict approver ids to an allowlist:

```yaml
      - match: { tool: "payment.refund" }
        action: prompt
        options: [allow_once, deny]
        quorum: 2
        approver_roles: [finance, security]
        approver_allowlist: [alice, bob, carol]
```

Approvals from any id outside the allowlist are counted as zero toward the
quorum (a flaky approver surface cannot stall the quorum — they're simply
ignored rather than blocking).

## What this guards against

- A single rogue approver inside `finance` approving a hostile refund —
  separation of duties forces `security` to also sign off.
- An attacker faking one Slack `user.id` (H12 identity attestation pairs
  with the Slack v0 signature; see the threat model  forward-looking
  threats — phantom-approver token hardening is a v1.1 target).
- An audit gap: `quorum_state` is on every `AuditEvent` for the prompt
  path, so a compliance review can correlate WHY a quorum resolved allow
  vs. deny vs. pending.

## What this does NOT guard against

- A second rogue approver inside `security`. Quorum is a structural bar,
  not a fix for insider compromise of N-of-M roles.
- A responder that swallows its raise (responders are exception-safe per H8
  — the gateway converts a responder/assistant/fatigue exception to a safe
  `DENY` with `reasoning="responder|assistant error: ..."`; audit + seam C
  always run).

## How to test this recipe in CI

```bash
python examples/quorum_demo.py
custos eval --suite adversarial
```