# Custos

Drop-in permission middleware for AI agents. Custos sits between an agent and
the tools it calls, intercepts every tool invocation, and decides whether to
allow, deny, batch-prompt the user, or auto-approve with audit - based on a
deterministic policy plus an optional LLM-driven permission assistant.

**One-line pitch:** OAuth-style consent and authorization, but for autonomous
LLM agents.

> Status: **v1.0 release candidate (v1.0.0rc1)**. The runtime targets Python
> >=3.10 with zero hard dependencies beyond a JSON-schema validator (>). Custos is an independent, production-grade reimplementation and
> extension of the Janus concept (arXiv:2607.01510, Brigham et al., U.
> Washington); it is not affiliated with the Janus authors. Janus is treated
> as a design reference only - no Janus code is vendored (Apache-2.0).

## Install

```bash
pip install "custos[yaml]"              # runtime + YAML policy loading (recommended)
pip install custos                      # runtime only (programmatic policies, no YAML)
pip install "custos[dev]"               # local development (pytest, ruff, mypy)
pip install "custos[eval]"              # eval-harness parity stack (dev/test-only)
pip install "custos[mcp]"               # MCP in-process adapter
pip install "custos[openai-agents]"     # OpenAI Agents SDK adapter
pip install "custos[anthropic]"         # Anthropic messages-API adapter
```

### Extras

| Extra | Adds | When you need it |
|---|---|---|
| `custos` (no extra) | JSON-schema validator only | Programmatic `Policy.from_spec` |
| `custos[yaml]` | PyYAML | `Policy.from_yaml("policy.yaml")` |
| `custos[llm]` | LiteLLM | Remote-LLM assistants (A5/A6/A9) |
| `custos[langchain]` | langchain-core | `Gateway.wrap(langchain_tools)` |
| `custos[mcp]` | mcp>=1.14,<2 | `gated_tool(MCP_server, ...)` |
| `custos[openai-agents]` | openai-agents>=0.18,<1 | `gated_function_tool(...)` |
| `custos[anthropic]` | anthropic>=0.40,<1 | `gated_anthropic_tool(...)` |
| `custos[eval]` | google-adk, litellm, mcp | `custos eval` + `custos audit replay` |

> The **runtime** (embedded in an agent) has zero hard deps beyond `jsonschema`
> . All LLM, YAML, adapter, and eval dependencies are optional extras.

## Quick start

```python
from custos import Gateway, InMemoryFatigueLayer, Policy
from custos.assistants import RulePolicy
from custos.responders import CLIResponder

policy = Policy.from_yaml("policy.yaml")
gw = Gateway(policy=policy,
    assistant=RulePolicy,
    responder=CLIResponder(timeout=30),
    fatigue=InMemoryFatigueLayer(dedup_ttl_s=300, max_per_minute=10),
    audit_sink="audit.jsonl",)

tools = gw.wrap(agent_tools)  # agent now sees identical signatures; gating is transparent
```

### Async runtime

For native-async agent frameworks (MCP, OpenAI Agents, Anthropic), use
`AsyncGateway` - the bridge contract lets you pass sync or async impls:

```python
import asyncio
from custos import AsyncGateway, Policy

gw = AsyncGateway(policy=Policy.from_yaml("policy.yaml"))

async def main:
    decision = await gw.decide(invocation)
asyncio.run(main)
```

### Quorum / separation of duties

For high-risk calls (e.g. `payment.*`), require multiple distinct approver
roles via the `MultiApproverResponder`:

```python
from custos.responders import MultiApproverResponder

multi = MultiApproverResponder(children=[finance_responder, security_responder],
    child_roles=["finance", "security"],)
# policy rule carries quorum: 2 + approver_roles: [finance, security]
```

## Components

- **Policy engine** - deterministic ruleset evaluated before any LLM call .
  Adapted in : factored shared ABAC operator primitives to
  `custos.policy.operators` so the production engine + the eval-harness's
  Janus-parity engine share one implementation (no dual-engine drift).
- **Permission assistants** - pluggable `Assistant` implementations (A1-A11).  Implemented: A5 risk-assessment, A6 risk-assessment-autonomous,
  A7 rule-policy, A8 summarize-batch, A9 context-adaptive, **A10 learned-policy**
  (; per-user learned rules with disagreement-aware fallback),
  **A11 delegation-aware** (; depth-tiered threshold scaling).
- **Responders** - CLI / web / webhook / Slack / noop user-prompt backends
  . Implemented: CLI (y/N/a/A/l/d), noop, webhook (HMAC + nonce +
  timestamp), Slack (Block Kit + signed interactions), web widget (SSE).
  **`MultiApproverResponder` ** for quorum + separation-of-duties
  : `quorum: N` distinct approvers from disjoint roles.
- **Async runtime ** - `AsyncGateway` + `AssistantAsync` /
  `ResponderAsync` / `FatigueLayerAsync` Protocols. Native-async impls awaited
  inline; sync impls bridged via `asyncio.to_thread`. Sync `Gateway` stays as
  the compatibility surface for scripts + CLI.
- **Fatigue layer** - batching, dedup, suppression, rate limits, ask-me-later
  . `InMemoryFatigueLayer` with per-rule `batching` config.
- **Audit sink** - structured, append-only decision log + `quorum_state` field
  for compliance observability .
- **Framework adapters** - in-process wrappers for:
  - **MCP** (`custos[mcp]`) - `gated_tool` decorator + `wrap_mcp_tools` post-hoc
    re-wrap; `FastMCP` servers.
  - **OpenAI Agents** (`custos[openai-agents]`) - `gated_function_tool`
    decorator + `wrap_openai_agent_tools`; produces model-visible tool errors
    on deny.
  - **Anthropic** (`custos[anthropic]`) - `gated_anthropic_tool` +
    `wrap_anthropic_tool_handlers`; gates the handler side of the
    messages-API dispatch loop.
  - **LangChain** (`custos[langchain]`) - `wrap_langchain_tools`.
- **Eval harness** - `custos eval` CI suite reproducing the Janus v1 parity
  matrix  and a Custos-authored adversarial regression suite
  . The adversarial suite covers N>=50 cells (expansion)
  across prompt-injection, confused-deputy, tool-spoofing,
  delegation-depth-abuse, learned-policy-poisoning, LLM-injection, and quorum,
  with positive `ALLOW` controls . Default backend is local Ollama
  (no API spend); HTML+JSON reports ; CI exit codes . Plus
  `custos audit replay` for policy what-if analysis . See `eval/README.md`.

## Decision semantics

`Decision` enum: `allow`, `allow_once`, `allow_and_persist`, `deny`, `prompt`,
`defer` . A policy `deny` is final - an assistant may only escalate
strictness, never relax a denial (floor/ceiling invariant).

The Janus-parity harness (under `custos.eval.harness`) uses its own
`JanusAssistantVerdict` enum (`approve_once`, `create_policy`, `reject`) so
parity CSV stays comparable to the published Janus numbers; the mapping is
locked in `custos.policy.operators.to_custos_decision` and machine-checked
in `tests/eval/test_janus_decision_mapping.py`.

## License

Apache-2.0. See `LICENSE`.