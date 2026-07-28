# Custos

Drop-in permission middleware for AI agents.

AI agents make tool calls — they read your files, send emails, run shell
commands, and query databases. Custos sits between your agent and the tools it
calls, intercepting every invocation and deciding whether to allow, deny, or
ask you — based on a declarative policy you control.

> "OAuth-style consent and authorization, but for autonomous LLM agents."

- **Runtime dep-free** beyond `jsonschema`. Every framework adapter and LLM
  backend is an optional extra.
- **Policy is the floor.** An assistant can only escalate strictness, never
  relax a `deny`.
- **Audit is tamper-evident.** Hash-chained JSONL with HMAC signing and
  `custos audit verify`.
- **Python + TypeScript SDKs** plus a gRPC sidecar for out-of-process
  deployment.
- **53-cell adversarial regression set** usable in CI with zero API spend.

## Start here

- [Quickstart](quickstart.md) — the 5-line integration with a runnable policy.
- [Onboarding tutorial](tutorial.md) — 20-to-30-minute walk from zero to a
  Custos-gated agent running the keyless adversarial eval suite.
- [Threat model](THREAT_MODEL.md) — normative: every mapped to a STRIDE threat
  with mitigations.
- [License audit](LICENSE_AUDIT.md) — normative: the v1.0 license-audit
  artifact.

## Reference

- [Policy schema](policy.md) — match criteria, actions, the full YAML
  schema reference.
- [Policy cookbook](cookbook/index.md) — five runnable recipes for common
  patterns.
- [Assistants](assistants.md) — the A1-A11 catalog with `exfiltrates_args`
  flags.
- [Responders](responders.md) — CLI, web, Slack, webhook, multi-approver.
- [Audit](audit.md) — sinks, hash-chaining, `custos audit verify`.
- [Eval harness](eval.md) — Janus-v1 parity matrix and adversarial CI suite.
- [Telemetry (opt-in)](telemetry.md) — OTLP spans and Prometheus metrics
  (off by default).
- [Adapters](adapters.md) — LangChain, MCP, OpenAI Agents, Anthropic,
  AutoGen, Google ADK, LlamaIndex.
- [Sidecar (gRPC)](sidecar.md) — the cross-language deployment surface.
- [IR contract](../IR_CONTRACT.md) — cross-language byte-parity pinning.

## Project

- [Changelog](../CHANGELOG.md) — phased release history.
- [Contributing](../CONTRIBUTING.md) — code style, runtime-dep discipline,
  test policy.
- [Security](../SECURITY.md) — vulnerability disclosure policy.

## License

Apache-2.0. Custos re-implements concepts behind clean interfaces and
never vendors unlicensed third-party code.
