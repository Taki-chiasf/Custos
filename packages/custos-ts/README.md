# @custos/core

Drop-in permission middleware for AI agents — TypeScript SDK (deterministic
subset).

This package is the TypeScript port of the Python [`custos`](https://github.com/Taki-chiasf/Custos)
library's **deterministic subset** (per the
[`IR_CONTRACT.md`](./IR_CONTRACT.md) v1.0 pinned at). It runs
in-process with zero runtime dependencies (-equivalent) and routes
LLM-backed permission assistants to a `custos sidecar` gRPC server
via the transport-injected `sidecarAssistant(transport)` factory.

## Install

```bash
npm install @custos/core
```

Requires Node >= 20. Zero runtime dependencies; the only hard dep is the
Node standard library (`node:crypto`, `node:fs`, `node:readline`).

## Quickstart

```ts
import {
  Gateway, Policy,
  RulePolicyAssistant, AutoApproveAssistant,
  NoopResponder, FileAuditSink, InMemoryFatigueLayer,
} from "@custos/core";

const policy = Policy.fromSpec({
  rules: [
    { match: { tool: "fs.read*", side_effects: ["read"] }, action: "allow_and_audit" },
    { match: { tool: "fs.write*" }, action: "assist:rule-policy" },
    { match: { tool: "shell.*" }, action: "deny" },
  ],
  default: "deny",
});

const gw = new Gateway({
  policy,
  assistant: new RulePolicyAssistant(Policy.fromSpec({ rules: [], default: "deny" })),
  responder: new NoopResponder,
  auditSink: new FileAuditSink("./audit.jsonl"),
  fatigue: new InMemoryFatigueLayer({ dedupTtlS: 300 }),
  defaultContext: {
    user_id: "alice",
    goal_id: null,
    task_id: null,
    delegation_chain: [],
    session_ttl: null,
    extra: {},
  },
});

const { decision, audit } = await gw.decide("fs.read_file", { path: "/etc/hosts" });
// decision === "allow"
// audit.decision, audit.invocation, audit.ts_unix_ms, audit.schema_version === "1.0"
```

## What's in-process vs. sidecar

Per the **D17** design decision (plan step, 2026-07-20), the
v1.0 TS SDK ships the **deterministic subset** in-process:

- `Gateway`, `Policy`, `MatchSpec` (all 11 ABAC operators), `Rule.matches`
- Fatigue dedup cache (no `BatchWindow` — A8 routes via the sidecar)
- Audit JSONL sink + `NullAuditSink`
- CLI + noop responders
- Assistants **A1** `auto-approve`, **A2** `user-confirmation`,
  **A7** `rule-policy`, **A11** `delegation-aware`

LLM-backed assistants (**A3** constitution, **A4** policy-suggestion,
**A5** risk-assessment, **A6** risk-assessment-autonomous, **A9**
context-adaptive, **A10** learned-policy) + out-of-band responders
(Slack, web, webhook, multi-approver quorum) reach via the  gRPC
sidecar:

```ts
import { sidecarAssistant, Gateway, Policy } from "@custos/core";

const riskAssessment = sidecarAssistant({
  name: "risk-assessment",
  transport: yourGrpcTransport,  // injected — @custos/core stays zero-dep
  callerId: "ts-agent",
});

const gw = new Gateway({
  policy: Policy.fromSpec({
    rules: [{ match: { tool: "fs.write*" }, action: "assist:risk-assessment" }],
    default: "deny",
  }),
  assistant: riskAssessment,
  responder: null,
  ...
});
```

The sibling `@custos/grpc` package (ships at) provides the real
gRPC transport implementation. The ** floor-is-local rule**
(IR_CONTRACT) is enforced by `Gateway.decide` on every sidecar
verdict: if the local policy says `deny`, the sidecar's `allow*` is
dropped and the final decision is `deny`. Assistant output is untrusted
across the boundary.

## Cross-language parity

The TS port is **byte-identical** to the Python `custos` package across
the surfaces pinned in `IR_CONTRACT.md`:

- `_args_hash` SHA-256 (canonicalizer)
- 11 ABAC operators incl. the JS-foreign cases (`string`-in-`string`,
  `>` across `number|string`, `bool`↔`int` equality per)
- `fnmatchCase` glob (Python `fnmatch` semantics, NOT JS `minimatch`)
- `matches` start-anchored regex (not fullmatch)
- Full `AuditEvent`/`ToolDescriptor`/`SubjectContext`/`Invocation`/
  `PromptRequest`/`PromptResponse` JSON wire shapes
- `Decision` enum + the Janus verdict mapping

The parity test set
([`test/parity/`](./test/parity/)) runs 168 tests against Python-generated
fixtures and asserts byte-equal output for every pinned row. A row
failing blocks the v1.0 cut .

## Verifying

```bash
npm install
npm run typecheck    # tsc --noEmit
npm test             # vitest run — 168 tests
npm run build        # tsc -p tsconfig.build.json — emits dist/esm/
```

## License

Apache-2.0 . See `LICENSE` at the repo root.