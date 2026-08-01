# Custos

Drop-in permission middleware for AI agents.

[![Python](https://img.shields.io/badge/python-%3E%3D3.10-blue.svg)](https://pypi.org/project/custos-middleware/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.1-blue.svg)](https://pypi.org/project/custos-middleware/)

---

## What is Custos?

Modern AI agents make tool calls — they read your files, send emails, query
databases, run shell commands, and call APIs. A single misdirected prompt can
cause real damage: data exfiltration, unintended writes, or privilege escalation.

**Custos sits between your agent and the tools it calls**, intercepting every
invocation and deciding whether to allow, deny, ask you, or quarantine the call
when indirect prompt injection is detected — based on a declarative policy you control.

Think of it as OAuth-style consent, but for autonomous LLM agents.

```
  ┌───────┐      ┌────────────────────┐      ┌──────────┐
  │ Agent │─────>│      Custos        │─────>│  Tools   │
  └───────┘      │                    │      └──────────┘
                 │  policy evaluator  │
                 │  + IPI defence     │
                 │  + AI assistant    │
                 │  + your approval   │
                 │  + audit trail     │
                 └────────────────────┘
```

**Key principles:**

- **Default-deny.** Anything not explicitly allowed in policy is blocked.
- **Policy is the floor.** An AI assistant or context inspector can escalate
  strictness, but can never override a `deny`.
- **Transparent wrapping.** The agent sees the same tool signatures it always
  did. Gating is invisible to the agent code.
- **Zero runtime deps** beyond a JSON-schema validator. Every framework
  adapter, LLM backend, and eval suite is an optional extra.

---

## How it works

Every tool call flows through a single decision pipeline:

```
    Tool call
       │
  ┌────▼─────┐
  │ 1. Policy│  Deterministic. Evaluates your YAML rules.
  │   engine │  First-match-wins. Returns allow/deny/assist/prompt/inspect.
  └────┬─────┘
       │
  ┌────▼─────┐
  │ 2. Context│ (optional) If policy says "inspect:<name>", an inspector
  │   insp.  │  scans full agent context for indirect prompt injection.
  └────┬─────┘
       │
  ┌────▼─────┐
  │ 3. AI    │  (optional) If policy says "assist:<name>", an LLM-driven
  │   asst.  │  assistant scores risk and returns a recommendation.
  └────┬─────┘
       │
  ┌────▼─────┐
  │ 4. User  │  (optional) If still unresolved, prompts you via CLI,
  │   prompt │  Slack, web widget, or webhook. You decide.
  └────┬─────┘
       │
  ┌────▼─────┐
  │ 5. Fatigue│  Deduplicates repeated prompts, batches similar calls,
  │   layer  │  enforces rate limits, supports "ask me later".
  └────┬─────┘
       │
  ┌────▼─────┐
  │ 6. Audit │  Every decision is logged — what, who, why, how long.
  │   + return│  Hash-chained, tamper-evident, verifiable.
  └────┬─────┘
       │
  Decision: allow / allow_once / allow_and_persist / deny / prompt / defer
            + quarantine (injection detected — block + memory wipe)
```

### Decision types

| Decision | Meaning |
|----------|---------|
| `allow` | Matched a standing policy rule. Execute immediately. |
| `allow_once` | Execute this one time. Future identical calls will be re-evaluated. |
| `allow_and_persist` | Execute and save a new policy rule for future calls. |
| `deny` | Blocked. Final — no assistant or responder can override. |
| `prompt` | Hand to the responder. Ask the user what to do. |
| `defer` | Rate-limited or batched. Try again later. |
| `quarantine` | Injection detected. Block call + trigger SDK memory wipe. |

---

## Quick example

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.responders import CLIResponder
from custos.audit import FileAuditSink

# 1. Load your rules
policy = Policy.from_yaml("policy.yaml")

# 2. Assemble the gateway
gw = Gateway(
    policy=policy,
    assistant=RulePolicy,                # deterministic fast path (A7)
    responder=CLIResponder(timeout=30),  # ask you in the terminal
    audit_sink=FileAuditSink("audit.jsonl"),
)

# 3. Wrap your tools — they keep the same signatures
gated_read, gated_write, gated_send = gw.wrap([read_file, write_file, send_email])

# 4. Agent code calls tools normally; Custos gates transparently
gated_read("/etc/hosts")   # policy match -> allowed, silently audited
gated_send(  "/hi")        # no policy match -> prompt: y/N/a/A/l/d
```

A minimal `policy.yaml`:

```yaml
version: 1
default: deny                    # everything blocked by default

overlays:
  - id: base
    rules:
      - match: { tool: "fs.read*" }
        action: allow_and_audit

      - match: { tool: "fs.write*", side_effects: [write] }
        action: assist:risk-assessment    # hand to AI risk scorer

      - match: { tool: "shell.*", risk_tier: [4, 5] }
        action: prompt                    # ask the user

      - match: { tool: "payment.*" }
        action: prompt
        options: [allow_once, deny]       # no standing allows

      - match: { tool: "email.send" }
        action: inspect:ipi-defender      # scan for prompt injection first
```

On a `deny` or `defer`, the wrapper raises `custos.exceptions.PermissionDenied`.
For async frameworks (OpenAI Agents, Anthropic, MCP, AutoGen), use
`AsyncGateway` — same pipeline, native-async.

---

## Custos vs. what exists

| Approach | Autonomy | Safety | User fatigue | How Custos compares |
|----------|----------|--------|--------------|---------------------|
| **No guardrails** | Full | None | Zero | Custos adds a safety floor without breaking tool signatures |
| **Manual review** | None | Maximum | Severe | Custos automates the routine; prompts only on high-risk calls |
| **System prompts only** | Full | Brittle | Zero | Prompts are advice, not enforcement. Custos is a hard gate |
| **[Janus](https://arxiv.org/abs/2607.01510)** | Configurable | Configurable | Configurable | Academic reference. Custos is a production-grade reimplementation |
| **Custos** | Configurable | Configurable | Tunable (fatigue layer) | Policy floor + AI assistant + user prompt + audit, all in one |

---

## Install

The runtime has zero hard dependencies beyond `jsonschema`. Pick the extra that
matches what you need:

```bash
# Start here — runtime-only, policy via Python dicts or YAML
pip install "custos-middleware[yaml]"       # + PyYAML (recommended)
pip install custos-middleware               # programmatic policies only

# LLM-backed AI assistants (A3-A6, A9)
pip install "custos-middleware[llm]"        # + LiteLLM

# Framework adapters — pick your agent framework
pip install "custos-middleware[langchain]"   # LangChain
pip install "custos-middleware[mcp]"         # MCP in-process
pip install "custos-middleware[openai-agents]"   # OpenAI Agents SDK
pip install "custos-middleware[anthropic]"   # Anthropic messages API

# Eval harness + CI test suites
pip install "custos-middleware[eval]"        # google-adk, litellm (dev/test)

# Local development
pip install "custos-middleware[dev]"         # pytest, ruff, mypy
```

All extras are additive: `pip install "custos-middleware[yaml,llm,langchain]"`.

### Which one do I need?

| You want to... | Install |
|----------------|---------|
| Try it out, read the docs | `custos-middleware[yaml]` |
| Add LLM-powered risk scoring | add `[llm]` |
| Protect a LangChain agent | add `[langchain]` |
| Run the adversarial eval suite in CI | add `[eval]` |
| Develop Custos itself | add `[dev]` |

---

## Components

Custos is assembled from interchangeable pieces. Wire what you need, skip what
you don't.

### Policy engine
A deterministic, pure-function rules engine. Write rules in YAML or construct
them programmatically. First-match-wins, default-deny. Hot-reloadable.
Supports tool-name globs, arg predicates, risk tiers, delegation depth,
and side-effect matching. [Docs →](docs/policy.md)

### Permission assistants (A1–A12)
Pluggable AI assistants that handle policy escalations. A1–A6 reproduce the
Janus reference designs; A7–A12 are Custos extensions:

| ID | Name | Strategy | Needs LLM? |
|----|------|----------|------------|
| A1 | Auto-approve | Always yes. Baseline. | No |
| A2 | User confirmation | Always ask. Maximum safety. | No |
| A3 | Constitution | Check against a written constitution doc. | Yes |
| A4 | Policy suggestion | Draft generalized ABAC rules for you. | Yes |
| A5 | Risk assessment | Score risk against task goals; escalate to user. | Yes |
| A6 | Risk assessment autonomous | Same as A5, but deny instead of prompting. | Yes |
| A7 | Rule policy | Pure deterministic rules. Fast path. | No |
| A8 | Summarize batch | Batch similar calls into one prompt. | No |
| A9 | Context adaptive | Choose prompt granularity by sensitivity. | Yes |
| A10 | Learned policy | Learn from your past decisions. | No |
| A11 | Delegation aware | Stricter rules for deeper delegation chains. | No |
| A12 | IPI defender | Context inspector. Detects indirect prompt injection via pattern matching + leave-one-out causal attribution. | configurable |

[Docs →](docs/assistants.md)

### Responders
User-facing prompt backends. One gateway can route to different responders per
tool or risk tier.

- **CLI** — yn/A/a/L/d prompt in the terminal
- **Noop** — silent deny (for CI/headless)
- **Web** — SSE-backed web widget, embeddable
- **Webhook** — HMAC-signed HTTP callbacks with nonce replay protection
- **Slack** — Block Kit messages with signed interactions
- **Multi-approver** — Quorum: requires N distinct approvers from disjoint roles

[Docs →](docs/responders.md)

### Fatigue layer
Prevents prompt storms. Deduplicates repeated tool calls (SHA-256 args hash),
batches similar calls into a single prompt, enforces per-minute rate limits,
and supports "ask me later" via `defer`. [Docs →](docs/audit.md)

### Audit
Structured, append-only JSONL decision log. Every event records: what tool was
called, by whom, what the policy said, what the assistant recommended, what you
decided, and how long it took. Hash-chained mode adds tamper evidence with
`custos audit verify`. Secret/PII fields in tool args are redacted before they
reach the audit log or any responder. [Docs →](docs/audit.md)

### Framework adapters
In-process wrappers that make Custos transparent to the agent framework. The
agent sees normal tool signatures; Custos sits inside as a gating layer.

- **LangChain** — `wrap_langchain_tools(gw, agent.tools)`
- **MCP** — `gated_tool` decorator and `wrap_mcp_tools` for FastMCP servers
- **OpenAI Agents SDK** — `gated_function_tool` decorator
- **Anthropic** — `gated_anthropic_tool` for the messages-API dispatch loop
- **AutoGen, Google ADK, LlamaIndex** — v1.0 carry-forward adapters

[Docs →](docs/adapters.md)

### Eval harness
`custos eval` CLI for CI. Two suites: (1) a Janus v1 parity matrix reproducing
the published 72-cell evaluation, and (2) a Custos-authored adversarial suite
(53+ cells covering prompt injection, IPI detection, confused deputy, tool spoofing,
delegation abuse, policy poisoning, and quorum bypass). Default backend is
local Ollama — no API spend. [Docs →](docs/eval.md)

---

## Relationship to Janus

Janus (arXiv:2607.01510, Brigham et al., U. Washington) is the academic
reference implementation that established the permission-assistant design space.
It introduces the concept of plug-and-play permission assistants and the
six-assistant catalog (Auto-Approve, User Confirmation, Constitution, Policy
Suggestion, Risk Assessment, Risk Assessment Autonomous).

**Custos** is an independent, production-grade reimplementation of the Janus
concept. It is not affiliated with the Janus authors and does not vendor any
Janus code (Apache-2.0). Key differences:

- **Production runtime** — Zero hard deps beyond `jsonschema`. Janus depends on
  Google ADK and LiteLLM.
- **6 additional assistants** — A7 (rule-policy), A8 (summarize-batch), A9
  (context-adaptive), A10 (learned-policy), A11 (delegation-aware), A12
  (ipi-defender).
- **7 decision types** — Janus has 3 (approve_once / create_policy / reject).
  Custos adds `allow`, `prompt`, `defer`, and `quarantine`.
- **Cross-language** — Python SDK, TypeScript SDK (`@taqiy/custos-core`), and a
  gRPC sidecar for out-of-process deployment.
- **Audit tamper evidence** — Hash-chained JSONL with HMAC signing and
  `custos audit verify`.
- **Deterministic policy engine** — Pure, no side effects, hot-reloadable.
  Janus policy is runtime-coupled to the ADK session.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Documentation

| Document | What it covers |
|----------|---------------|
| [Quickstart](docs/quickstart.md) | 5-line integration, policy YAML, audit log |
| [Tutorial](docs/tutorial.md) | 20-30 minute walk from zero to gated agent |
| [Policy schema](docs/policy.md) | Full YAML reference: match criteria, actions, overlays |
| [Policy cookbook](docs/cookbook/index.md) | 5 runnable recipes for common patterns |
| [Assistant catalog](docs/assistants.md) | A1-A12 with `exfiltrates_args` flags |
| [Context inspectors](docs/inspectors.md) | A12 IPI defence + leave-one-out attribution |
| [Responder reference](docs/responders.md) | CLI, web, Slack, webhook, multi-approver |
| [Audit reference](docs/audit.md) | Sinks, hash-chaining, `custos audit verify` |
| [Eval harness](docs/eval.md) | Janus-v1 parity + adversarial CI suites |
| [Adapters](docs/adapters.md) | Per-framework integration details |
| [Sidecar (gRPC)](docs/sidecar.md) | Cross-language deployment surface |
| [Threat model](docs/THREAT_MODEL.md) | Normative: every mapped to a STRIDE threat |
| [IR contract](IR_CONTRACT.md) | Cross-language pinning: Python-TS byte parity |
| [Changelog](CHANGELOG.md) | Phased release history |
| [Contributing](CONTRIBUTING.md) | Code style, runtime-dep discipline, test policy |
| [Security](SECURITY.md) | Vulnerability disclosure policy |
