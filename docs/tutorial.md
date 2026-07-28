# Onboarding tutorial

This walk takes 20 to 30 minutes; it goes from zero to a Custos-gated agent
that runs an eval scenario against the keyless adversarial suite, then exports
an audit log you can verify. The 5-line integration lives in
[Quickstart](quickstart.md); this tutorial is the longer read-through.

The tutorial assumes Python 3.10 or later (`python --version`). Node 20+ is
only required for the TypeScript SDK + sidecar client (covered at the end).

## 1. Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install "custos-middleware[yaml]"          # runtime + PyYAML for Policy.from_yaml
pip install "custos-middleware[dev]"           # pytest/ruff/mypy (for step 6)
```

Custos is **runtime-dep-free** beyond a JSON-schema validator (`jsonschema`,
the only hard dep —). Every framework adapter (LangChain, MCP, OpenAI
Agents, Anthropic, AutoGen, Google ADK, LlamaIndex) and the eval / telemetry
/ sidecar surfaces are **optional extras**.

| Goal | Extra |
|---|---|
| YAML policy loading | `custos-middleware[yaml]` |
| LLM-backed assistants A5/A6/A9 + `LiteLLMClient` | `custos-middleware[llm]` (or local Ollama in the eval harness) |
| LangChain adapter | `custos-middleware[langchain]` |
| MCP in-process adapter | `custos-middleware[mcp]` |
| OpenAI Agents SDK adapter | `custos-middleware[openai-agents]` |
| Anthropic messages-API adapter | `custos-middleware[anthropic]` |
|  carry-forward adapters | `custos-middleware[autogen]`, `custos-middleware[google-adk]`, `custos-middleware[llamaindex]` |
| gRPC sidecar | `custos-middleware[sidecar]` |
| OTLP + Prometheus metrics (opt-in, default-off) | `custos-middleware[telemetry]` |
| Eval harness + Janus parity suite | `custos-middleware[eval]` (uses local Ollama by default) |
| This docs site | `custos-middleware[docs]` (mkdocs-material) |

## 2. Your first policy

`policy.yaml`:

```yaml
version: 1
default: deny

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*", side_effects: [read] }
        action: allow_and_audit
      - match: { tool: "fs.write*" }
        action: assist:risk-assessment      # A5 hands risky writes to the user
      - match: { tool: "shell.*" }
        action: prompt                      # ask the user (CLI default)
      - match: { tool: "payment.*" }
        action: prompt
        options: [allow_once, deny]          # no standing allows for payments
  - id: fatigue
    rules:
      - match: { any: true }
        action: assist:summarize-batch
        batching:
          window_ms: 2000
          max_per_minute: 10
```

Policy is evaluated **top-down, first-match-wins** . Match criteria
AND together; an absent criterion matches everything. The deterministic
`default: deny` is the standing floor — anything unmatched is refused.

## 3. Build the gateway

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy           # A7 — deterministic fast path
from custos.audit import FileAuditSink
from custos.responders import CLIResponder
from custos.sdk import set_default_context, wrap_callables
from custos.schema import SubjectContext

policy = Policy.from_yaml("policy.yaml")
gw = Gateway(policy=policy,
    assistant=RulePolicy,                          # A7 — happens before A5
    responder=CLIResponder(timeout=30),
    audit_sink=FileAuditSink("audit.jsonl"),)
set_default_context(SubjectContext(user_id="alice", goal_id="onboarding"))
```

The decision pipeline (detailed in the [Quickstart](quickstart.md#the-decision-pipeline)):

1. Parse the invocation.
2. Policy evaluation (deterministic, pure).
3. If `ASSIST`: invoke the named permission assistant (the only allowed source
   of non-determinism).
4. If `PROMPT`: hand a redacted request to the responder (CLI / web / webhook
   / noop).
5. Fatigue layer (batching, dedup, suppression, rate limit).
6. Timeout enforcement (deny on expiry unless policy says otherwise).
7. Audit the decision + full reasoning chain.
8. Return the `Decision` to the agent.

## 4. Wrap a tool registry

```python
def fs_read(path: str) -> str:
    return open(path).read

def fs_write(path: str, content: str) -> None:
    with open(path, "w") as fh:
        fh.write(content)

def shell_exec(cmd: str) -> int:
    import subprocess
    return subprocess.call(cmd, shell=True)

gated_read, gated_write, gated_shell = gw.wrap([fs_read, fs_write, shell_exec])

gated_read("/etc/hosts")        # fs.read match -> allow_and_audit
gated_write("/tmp/x", "hi")     # fs.write -> assist:risk-assessment
gated_shell("rm -rf /")         # shell.* -> prompt; you say N at the CLI -> deny
```

On a `deny` or `defer` decision the wrapper raises
`custos.exceptions.PermissionDenied` (carries the tool name + decision value).

## 5. Inspect and verify the audit log

```bash
custos audit tail audit.jsonl -n 20
```

Each event is one JSON line . For a tamper-evident log, swap the sink:

```python
from custos.audit import HashChainedAuditSink
gw = Gateway(policy=policy, assistant=RulePolicy, responder=CLIResponder,
             audit_sink=HashChainedAuditSink("audit.jsonl", signing_key=b"shared-secret"))
```

Then `custos audit verify audit.jsonl --hmac-key shared-secret` exits 0 OK, 1 on
chain tamper, or 2 on a `--pubkey`-only attempt (a v1.1 target).

## 6. Run the keyless adversarial suite in CI

```bash
custos eval --suite adversarial
```

No API key required (the suite exercises the production `Gateway` with the
deterministic `RulePolicy` A7 and a `NoopResponder`). The suite exits 1 on any
false-allow; v1.0 cuts with 53 cells  covering prompt injection,
confused deputy, tool spoofing, delegation-depth abuse, and learned-policy
poisoning.

## 7. Pick an assistant

By default `RulePolicy` (A7) handles every `assist:*` action deterministically.
For LLM-backed risk scoring, install `custos-middleware[llm]` and swap in A5:

```python
from custos.assistants import RiskAssessment
from custos.integrations.litellm_ import LiteLLMClient

llm = LiteLLMClient(model="openai/gpt-4o-mini")
assistant = RiskAssessment(tolerance=0.35, llm=llm)
assistant.observe_user_message("draft and send the weekly team update")
gw = Gateway(policy=policy, assistant=assistant, responder=CLIResponder)
```

A5 adds two LLM calls per denied call (one goal-extraction up-front, one
risk-judge on the deny). `risk <= tolerance -> allow_once`; otherwise it
hands to the responder. **The  floor is unchanged**: an A5 `allow` can
never relax a policy `deny`. See the [assistant catalog](assistants.md).

## 8. Run the sidecar (gRPC) — optional

For runtimes that cannot be wrapped in-process (e.g. an agent running in
another language):

```bash
pip install "custos-middleware[sidecar]"
custos sidecar --policy policy.yaml \
  --tls-cert server.pem --tls-key server.key --tls-ca clients-ca.pem \
  --bearer "${CUSTOS_BEARER}" \
  --verdict-hmac-key "${CUSTOS_HMAC}" \
  --audit audit.jsonl
```

mTLS is **mandatory** for v1.0 — the server refuses to start without
`--tls-cert/--tls-key/--tls-ca` (a plaintext sidecar is a  violation).
Bearer + `caller_id` + per-call `request_id` (nonce) are replay-guarded.
The TypeScript SDK reaches the same gateway via the `@taqiy/custos-grpc` package;
its `Gateway.decide` re-applies the policy locally so a tampered sidecar
cannot smuggle an allow past the floor. See [Sidecar](sidecar.md).

## 9. Turn on telemetry — optional, default-off

```bash
pip install "custos-middleware[telemetry]"
```

```python
from custos.telemetry import OTLPAuditSink, PrometheusCollector

gw = Gateway(policy=policy,
    assistant=RulePolicy,
    responder=CLIResponder,
    audit_sink=[
        FileAuditSink("audit.jsonl"),
        OTLPAuditSink(endpoint="http://localhost:4317", service_name="my-custos"),
    ],
    metrics=PrometheusCollector,     # scrapable on /metrics)
```

The telemetry surface is **off by default**; an `import custos` with no
extras produces no OTLP spans and no Prometheus registry. See
[Telemetry](telemetry.md) .

## 10. Read the threat model

Before shipping to production, read [`THREAT_MODEL.md`](THREAT_MODEL.md). It is
normative: every  bullet is mapped to a STRIDE threat + mitigation,
plus the open forward-looking threats (side-channel timing, assistant
prompt-injection from args, phantom Slack approvers).

## 11. TypeScript quickstart (D17 deterministic subset)

```bash
npm i @taqiy/custos-core
```

```typescript
import { Gateway, Policy, RulePolicy, CLIResponder } from "@taqiy/custos-core";

const gw = new Gateway({
  policy: Policy.fromYamlFile("policy.yaml"),
  assistant: new RulePolicy,
  responder: new CLIResponder,
});

const gatedRead = gw.wrap(async (path: string) => fs.readFile(path, "utf8"));
await gatedRead("/etc/hosts");
```

The TS SDK ships A1/A2/A7/A11 + dedup fatigue + CLI/noop responders as the
deterministic in-process subset. LLM-backed assistants (A5/A6/A9/A10) and
out-of-band responders (Slack/web/webhook) are reached via the gRPC sidecar
using `sidecarAssistant(transport)`; the TS `Gateway.decide` re-runs the
policy locally on every verdict and drops a sidecar `allow*` if local policy
says `deny` (floor-is-local rule).

## Where to go next

- The [policy cookbook](cookbook/index.md) — five runnable recipes
  (read-allow, network-egress prompt, payment quorum, learned-policy opt-out,
  air-gapped profile).
- The [assistant catalog](assistants.md) — A1–A11 with `exfiltrates_args`
  flags and `name` identifiers.
- The [eval harness guide](eval.md) — janus-v1 parity + adversarial CI suites.
- The [IR contract](../IR_CONTRACT.md) — the cross-language pinning for
  Python ↔ TS byte-parity.