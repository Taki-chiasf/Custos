# Recipe: air-gapped profile

For deployments where the LLM provider is unreachable (air-gapped) or
where sending args across the network is never acceptable. The air-gapped
profile refuses to instantiate any assistant with `exfiltrates_args=True` and
routes every `assist:*` action to either an in-process assistant (A7/A10/A11)
or `prompt`/`deny`.

## Profile activation

There is no global `custos.local_only = True` config flag in the Python
package's public surface yet; the air-gapped profile is declared via the
gateway constructor by only ever passing an `exfiltrates_args=False`
assistant. The convention is locked in `AssistantBase.exfiltrates_args`.

| Assistant | `exfiltrates_args` | Air-gapped-safe |
|---|---|---|
| A1 `auto-approve` | False | yes |
| A2 `user-confirmation` | False | yes |
| A3 `constitution` | True | no |
| A4 `policy-suggestion` | True | no |
| A5 `risk-assessment` | True | no |
| A6 `risk-assessment-autonomous` | True | no |
| A7 `rule-policy` | False | yes |
| A8 `summarize-batch` | False | yes (deterministic summarizer) |
| A9 `context-adaptive` | True | no |
| A10 `learned-policy` | False | yes |
| A11 `delegation-aware` | False | yes |

A helper that the lint policy can inspect:

```python
from custos.assistants.base import AssistantBase

def assert_airgapped(assistant: AssistantBase) -> None:
    """Refuse to instantiate an assistant that exfiltrates args.
    Use as a defensive guard at constructor time for air-gapped deployments.
    """
    if getattr(assistant, "exfiltrates_args", False):
        raise RuntimeError(f"air-gapped profile: assistant {assistant.name!r} "
            f"exfiltrates_args=True; refusing to instantiate")

from custos.assistants import RulePolicy, DelegationAwareAssistant, LearnedPolicyAssistant
assert_airgapped(RulePolicy)
assert_airgapped(DelegationAwareAssistant)
assert_airgapped(LearnedPolicyAssistant)      # read_only defaults to False; A10 is in-process
```

## Policy

In air-gapped mode, every `assist:*` route targets an in-process assistant.
LLM-backed `assist:risk-assessment` and `assist:context-adaptive` are
**NOT** used — the gateway short-circuits a restricted-arg call to `prompt`
on `exfiltrates_args=True` (H4), and an air-gapped deployment refuses to
instantiate those assistants in the first place.

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*" }
        action: allow_and_audit
      - match: { tool: "shell.*" }
        action: assist:rule-policy            # A7 — deterministic table
      - match: { tool: "fs.write*" }
        action: assist:delegation-aware       # A11 — gradient by delegation depth
      - match: { tool: "http.*" }
        action: prompt                          # human approval for any egress
      - match: { any: true }
        action: deny                            # default-deny belt-and-suspenders
```

## Wiring

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.audit import FileAuditSink
from custos.responders import CLIResponder
from custos.schema import SubjectContext
from custos.sdk import set_default_context

policy = Policy.from_yaml("policy.yaml")
gw = Gateway(policy=policy,
    assistant=RulePolicy,           # A7 — the only assistant instantiated
    responder=CLIResponder(timeout=30),
    audit_sink=FileAuditSink("audit.jsonl"),)
set_default_context(SubjectContext(user_id="airgap-operator", goal_id="airgap"))
```

## How the exfiltration gate interacts with this profile

When `assist:risk-assessment` (A5, `exfiltrates_args=True`) is referenced by
a rule and the call bears `secret: true` / `format: password` args OR
`SideEffect.PII`, the gateway routes to `prompt` instead of invoking A5
(H4 LLM-assistant exfiltration bullet 8). The air-gapped profile is
a stricter posture: A5 is never instantiated at all, so even a
mis-routed `assist:risk-assessment` action with no restricted args to fall
back on still won't trigger an LLM call (the  named-assistant
routing fails closed to `DENY` for any unregistered `name`).

## Telemetry

Even the air-gapped profile can still emit OTLP + Prometheus metrics — but
ONLY if the operator installs `custos-middleware[telemetry]` and explicitly opts in.
With no extras installed, `import custos` produces no telemetry spans or
metrics (+ the  default-off regression test). See
[`docs/telemetry.md`](../telemetry.md).

## What this guards against

- An LL-backed assistant being added later by a teammate and silently
  exfiltrating args. The defensive `assert_airgapped` helper at
  constructor time refuses the instantiation; the  floor remains
  intact regardless.
- A mis-routed `assist:<unknown>` action failing open.
  fail-closes any unregistered name to `DENY` + audit.

## What this does NOT guard against

- A tool **descriptor** lying about `SideEffect.PII`. Custos governs on
  declared metadata. In air-gapped mode the worst case is a PII-declared
  tool route to `prompt`; the user sees the redacted args. See the threat
  model  forward-looking "assistant prompt-injection from args" for the
  deeper v1.1 hardening.

## How to test this recipe in CI

```bash
pytest -k airgapped           # if the helper + guard has an equivalent test
custos eval --suite adversarial
```