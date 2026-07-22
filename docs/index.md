# Custos

Drop-in permission middleware for AI agents. Custos sits between your agent
and the tools it calls — it intercepts every tool invocation, evaluates it
against a configurable permission policy and an optional LLM-driven
permission assistant, and decides whether to allow, deny, batch-prompt the
user, or auto-approve with audit.

> "OAuth-style consent and authorization, but for autonomous LLM agents."

- Runtime dep-free beyond `jsonschema` ; every framework adapter is
  an optional extra.
- Policy is the floor : an assistant can only escalate strictness,
  never relax a `deny`.
- Audit is tamper-evident : hash-chained JSONL + HMAC signing +
  `custos audit verify`.
- v1.0 ships Python + TypeScript SDKs + a gRPC sidecar; eval suite usable
  in CI; 53-cell adversarial regression set.

## Start here

- [Quickstart](quickstart.md) — the 5-line integration.
- [Onboarding tutorial](tutorial.md) — 20-to-30-minute walk from zero to a
  Custos-gated agent running the keyless adversarial eval suite.
- [Threat model](THREAT_MODEL.md) — normative; every mapped to a STRIDE threat.
- [License audit](LICENSE_AUDIT.md) — normative; the v1.0 license-audit
  artifact .

## Reference

- [Policy schema](policy.md) — match criteria, actions, the full YAML
  schema reference .
- [Policy cookbook](cookbook/index.md) — five runnable recipes.
- [Assistants](assistants.md) — the A1–A11 catalog.
- [Responders](responders.md) — CLI / web / Slack / webhook / multi-approver.
- [Audit](audit.md) — sinks, hash-chaining, `custos audit verify`.
- [Eval harness](eval.md) — janus-v1 parity + adversarial CI.
- [Telemetry (opt-in)](telemetry.md) — OTLP + Prometheus (default-off).
- [Adapters](adapters.md) — LangChain, MCP, OpenAI Agents, Anthropic,
  AutoGen, Google ADK, LlamaIndex.
- [Sidecar (gRPC)](sidecar.md) — the cross-language deployment surface.
- [IR contract](../IR_CONTRACT.md) — the cross-language pinning.

## Project

- [CHANGELOG](../CHANGELOG.md) — phased release history.
- [CONTRIBUTING](../CONTRIBUTING.md) — code style, the import-shadowing
  filename rule runtime-dep discipline.
- [SECURITY](../SECURITY.md) — vulnerability disclosure policy.

## License

Apache-2.0. Custos re-implements concepts behind clean interfaces and
never vendors unlicensed third-party code.