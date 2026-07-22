# Custos quickstart

Custos is a drop-in permission middleware for AI agents. This walk shows the
5-line integration, a runnable policy, and how to inspect the audit log.

## Install

```bash
pip install custos-middleware                     # runtime (jsonschema only)
pip install "custos-middleware[yaml]"             # + PyYAML for Policy.from_yaml
pip install "custos-middleware[llm]"              # + litellm for LLM-backed assistants (A5/A6)
pip install "custos-middleware[langchain]"        # + langchain-core for the LangChain adapter
pip install "custos-middleware[dev]"              # + pytest/ruff/mypy for local dev
```

## 5-line integration

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.audit import FileAuditSink
from custos.responders import NoopResponder
from custos.sdk import set_default_context
from custos.schema import SubjectContext

policy = Policy.from_yaml("policy.yaml")
gw = Gateway(policy=policy,
    assistant=RulePolicy,
    responder=NoopResponder,
    audit_sink=FileAuditSink("audit.jsonl"),)
set_default_context(SubjectContext(user_id="alice", goal_id="g1"))

# Wrap any plain callables; each call now flows through Gateway.decide.
gated = gw.wrap([read_file, write_file, send_email])
decision = gated[0]("/etc/hosts")        # read_file -> allow_and_audit
```

## Policy file (YAML)

Custos policy is a declarative ruleset evaluated top-down, first-match-wins
. Match criteria are AND-ed; an absent criterion matches everything.

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*", side_effects: [read] }
        action: allow_and_audit
      - match: { tool: "fs.write*", side_effects: [write] }
        action: assist:risk-assessment      # hand to the A5 assistant
      - match: { tool: "shell.*", risk_tier: [4, 5] }
        action: prompt                      # ask the user (CLI/web/webhook)
      - match: { tool: "payment.*" }
        action: prompt
        options: [allow_once, deny]          # no standing allows for payments
      - match:
          tool: "email.send"
          args: { recipient_domain: { in: [trusted.org] } }
        action: allow_and_audit
```

Match criteria :

- `tool` - glob via `fnmatch` (e.g. `fs.read*` matches `fs.read_file`).
- `risk_tier` - int (exact) or `[min, max]` (inclusive range).
- `side_effects` - list; rule matches if the tool's side_effects intersect it
  (any-of). Values: `read, write, network, payment, destructive, pii`.
- `args` - per-arg predicates: a bare scalar means `==`; a `{op: value}`
  dict applies one of `==, !=, >, <, >=, <=, in, not_in, contains,
  not_contains, matches` (regex anchored via `re.match`).
- `goal_id`, `delegation_depth` - exact match against the subject context.
- `any: true` - wildcard.

Actions : `allow`, `deny`, `prompt`, `assist:<name>`,
`allow_and_audit`, `deny_and_alert`.

## The decision pipeline

Every tool call flows through the 8-step pipeline (sec 9.2):

1. Parse the invocation.
2. Policy evaluation (deterministic, pure -).
3. If `ASSIST`: invoke the named permission assistant (may be non-deterministic
   via LLM; this is the only allowed source of non-determinism).
4. If `PROMPT`: hand a redacted request to the responder (CLI / web / webhook
   / noop).
5. Fatigue layer (: batching, dedup, suppression windows).
6. Timeout enforcement (deny on expiry unless policy says otherwise).
7. Audit the decision + full reasoning chain.
8. Return the `Decision` to the agent.

The floor/ceiling invariant : a policy `deny` is final - an assistant
can only ESCALATE strictness, never relax a denial. Assistant output is
untrusted.

## Assistants

A1-A11 implement the `Assistant` Protocol (sec 9.4).  ships:

- A7 `RulePolicy` - pure deterministic rules, no LLM (fast path).
- A5 `RiskAssessment` - goal-aware LLM risk scoring; `risk <= tolerance` ->
  `allow_once`, else `prompt` (2 LLM calls; requires `custos[llm]`).
- A6 `RiskAssessmentAutonomous` - same as A5 but never prompts (denies on
  above-tolerance).

```python
from custos.assistants import RiskAssessment
from custos.integrations.litellm_ import LiteLLMClient

llm = LiteLLMClient(model="openai/gpt-4o-mini")
assistant = RiskAssessment(tolerance=0.35, llm=llm)
assistant.observe_user_message("send an email to the team")  # extracts goals
gw = Gateway(policy=policy, assistant=assistant, responder=CLIResponder)
```

## Inspect the audit log

```bash
custos audit tail audit.jsonl -n 20   # pretty-print the last 20 events
```

Every event is a JSON line :

```json
{
  "ts_unix_ms": 1783980725001,
  "invocation": {"tool": "fs.read", "args": {"path": "/etc/hosts"}, ...},
  "decision": "allow",
  "policy_match": "base:allow_and_audit",
  "reasoning": "policy: allow",
  "latency_ms": 0,
  "subject": {"user_id": "alice", "goal_id": "g1", ...}
}
```

Secret/PII fields (JSON-schema `secret: true` or `format: password`) are
redacted to `"[REDACTED]"` before they reach the responder or the audit log
.

## Run the demo

```bash
python examples/demo.py --audit /tmp/custos-audit.jsonl
```

Runs three invocations exercising allow / assist->allow_once / prompt->deny
with the rule-policy assistant and the noop responder. No API key needed.