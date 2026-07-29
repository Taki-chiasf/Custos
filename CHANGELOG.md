# Changelog

All notable changes to Custos are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (v1.1.0a1)
- **A12 `ipi-defender`** — context inspector for selective IPI defence.
  Fast-path pattern matching + n-gram similarity against known injection
  markers; optional deep-path leave-one-out causal attribution via LLM.
  `Decision.QUARANTINE` blocks calls + triggers SDK memory wipe.
- `ContextInspector` protocol + `InspectorRegistry` — pluggable pre-assistant
  inspection of full agent conversation context.
- `InspectionVerdict` enum (SAFE / SUSPICIOUS / INJECTION), `InputSource`,
  `ContextSnapshot`, `InjectionFinding`, `InspectionResult` data types.
- `MemoryWipe` + `ContextProvider` protocols in SDK for post-QUARANTINE
  context sanitisation.
- `inspector=` parameter on `Gateway` and `AsyncGateway` for global coverage;
  policy `inspect:<name>` action for per-tool routing.
- `PolicyOutcome.INSPECT` — new policy evaluation outcome.
- `AuditEvent.inspector` — inspector name in audit trail.
- Adapter support for context provider + memory wipe in LangChain, OpenAI
  Agents, and Anthropic adapters.

### Remaining
- Full 1440-cell Janus-v1 parity matrix run.

## [1.0.1] — 2026-07-28

Patch release: code hardening from council review, documentation overhaul.

### Fixed
- Gateway and AsyncGateway decision pipeline: exception safety, audit sink
  type handling, fatigue cacheable flag thread safety.
- Audit: `HashChainedAuditSink` hash-chain verification with genesis sentinel,
  `CapturingAuditSink` thread-local clearing, schema version in audit events.
- Fatique: dedup and suppression cache invalidation on policy reload.
- Responders: `MultiApproverResponder` deterministic result ordering, circuit
  breaker fallback chain.
- Sidecar: gRPC server auth error handling and replay cache bounds.
- Integration adapters: standardized error message format across Anthropic,
  AutoGen, Google ADK, LangChain, LlamaIndex, MCP, and OpenAI Agents adapters.
- SDK: `set_default_context` thread safety.
- Policy engine: rule evaluation edge cases with null/missing args.
- Exceptions: `PermissionDenied` str/repr parity.
- Risk assessment assistant: missing goal fallback.

### Added
- Release workflow: automated GitHub Release on tag push with Python wheel/sdist
  and SBOM artifacts. PyPI publish via OIDC trusted publishing; npm publish
  (@taqiy/custos-core, @taqiy/custos-grpc) via provenance-signed CI.
- 79-line hash-chain verification test suite; 202 lines of gateway edge-case
  regression tests.
- Added comparison link references to CHANGELOG.

### Changed
- Rewrote README with problem-first structure: architecture flow diagram,
  decision pipeline overview, comparison table, assistant LLM-needs table,
  install decision guide, and documentation link table.
- Removed stale internal PRD annotation tags from all user-facing docs
  (quickstart, tutorial, policy, sidecar, eval, index, README).
- Bumped `@taqiy/custos-grpc` 1.0.0-rc1.0 → 1.0.0 for GA.

## [1.0.0] — 2026-07-22

v1.0 GA. 604 Python tests + 172 TS tests pass. ruff + mypy --strict clean.
`pip-audit` clean; CycloneDX SBOM shipped.

### Security fixes
- Slack inbound `do_POST` resolved interactions correctly (was dropping real
  callbacks to DENY).
- TS sidecar verdict signature verification enforced — missing/empty
  signature downgrades to deny.
- WebResponder usable in browsers: SSE query-token auth, inverted Origin
  check, fixed `getToken` operator precedence.
- Air-gapped `local_only` profile + `allow_external_data` policy field
  wired into enforcement.

### Architecture fixes
- TS `Gateway.decide` reordered to evaluate policy before fatigue.
- AsyncGateway `audit_sink` accepts `list | tuple` for telemetry typing.

### Code quality fixes
- `CapturingAuditSink` thread-local cleared between calls; anomaly → DENY.
- Fatigue cacheable flag thread-safe under AsyncGateway concurrency.
- `MultiApproverResponder` deterministic result ordering (DENY < DEFER < ALLOW).

### Added
- IR_CONTRACT.md v1.0 (cross-language wire-format pinning).
- TypeScript SDK `@taqiy/custos-core` (deterministic assistants; LLM-backed via sidecar).
- Sidecar/gRPC mode with mTLS, bearer/OIDC, nonce, per-tenant rate limit.
- Audit tamper-evidence (`HashChainedAuditSink` + `custos audit verify`).
- Docs site (MkDocs Material: threat model, tutorial, cookbook).
- AutoGen, Google ADK, LlamaIndex adapter integrations.
- OTLP + Prometheus telemetry, `custos-middleware[telemetry]` extra, default-off.
- Python 3.13 stdin-capture fix; full license audit.
- Janus-v1 harness hardening (incremental flush+fsync, 5-tuple resume,
  partial-tail repair; qwen2.5:7b-instruct smoke green).

### Changed
- `custos.__version__` 1.0.0rc1 → 1.0.0.
- `@taqiy/custos-core` version 1.0.0-rc1.0 → 1.0.0.
- `pyproject.toml` classifier: Beta → Production/Stable.
- Pinned risk_score canonical float repr; missing-signature = failed-verification.

## [1.0.0rc1] — 2026-07-20

Ecosystem — Python-only v1.0 RC. MCP + OpenAI Agents SDK + Anthropic adapters
in-process. 492 tests pass; ruff + mypy --strict clean across 75 source files.

### Added — Async runtime
- `AsyncGateway.decide` mirrors the sync 8-step pipeline with all I/O seams
  awaited; `AssistantAsync` / `ResponderAsync` / `FatigueLayerAsync` protocols.
- Native-async implementations awaited inline; sync implementations run in a
  worker thread (350-test sync suite green unchanged).

### Added — Assistants A10 / A11
- A10 learned-policy: per-user learned decision model; disagreement-aware
  fallback; air-gapped-safe (`exfiltrates_args=False`). Poisoning mitigation:
  broad persisted rules rejected at insert time.
- A11 delegation-aware: pure-deterministic depth-tier table; escalation to
  PROMPT at depth ≥2, DENY at depth ≥4 (deep-chain exfiltration guard).

### Added — Quorum / separation-of-duties
- `MultiApproverResponder` composing N child responders; `met` / `failed` /
  `pending` state machine; DEFER for pending. Rule-level `quorum`,
  `approver_roles`, `approver_allowlist` hints. Approver identity attested by
  each child; single-approver path unchanged.

### Added — Framework adapters (MCP / OpenAI / Anthropic)
- `custos-middleware[mcp]` — MCP in-process adapter: `gated_tool` + `wrap_mcp_tools`.
- `custos-middleware[openai-agents]` — OpenAI Agents SDK adapter: `gated_function_tool`.
- `custos-middleware[anthropic]` — Anthropic messages-API adapter: `gated_anthropic_tool`.
- All adapters isolate vendor imports inside function bodies for runtime dep-freedom.

### Added — Shared operator primitives
- ABAC operator primitives in `src/custos/policy/operators.py` shared by
  production engine and eval harness. Machine-checked mapping test guards
  against drift.

### Added — Adversarial suite expansion
- Adversarial regression set grew from N=5 → N=53 cells across 8 categories:
  prompt injection, confused deputy, tool spoofing, delegation depth abuse,
  LLM injection, learned policy poisoning, quorum, positive controls.

### Deferred to GA
- TypeScript SDK, sidecar/gRPC mode, AutoGen/Google ADK/LlamaIndex adapters.
- Full 1440-cell Janus-v1 matrix run.

## [0.4.0] — 2026-07-16

Hardening cut. Every fix has a regression test.

### Added
- Cacheable-decision invariant: only user-resolved decisions enter the
  dedup/suppression cache; rate-limit DENY does not poison a triple.
- `FatigueLayer.clear` in the protocol seam; `Gateway.reload_policy`
  invalidates caches. `Policy._rules` mutations guarded by `threading.RLock`.
- Responder surface defaults: CLI 30 s, Slack 300 s, Web 90 s, Webhook ≤300 s.
- Approver identity in every `PromptResponse` (CLI UID, Slack user ID, webhook
  key-id/OIDC, web-session subject). Policy rules may specify `approver_allowlist`.
- Responder circuit breaker: open after N consecutive failures → DENY + audit
  alert; optional secondary-responder fallback chain.
- Deep arg redaction: recurses through `properties`, `items`, `patternProperties`,
  `allOf`/`anyOf`/`$ref`.
- Approver recorded in every audit event.
- Eval harness fixes: adversarial positive-control cells; `custos eval` /
  `custos audit replay` importable from a wheel install.

## [0.3.0] — 2026-07-16

Eval harness + adversarial suite, CI-usable. 351 tests pass.

### Added
- `custos eval` CLI with Janus-v1 suite: 3 scenarios × 4 subscenarios × 3
  synthetic responders × 2 risk tolerances (smoke = 3 cells, full = 1440).
- Parity diff tool (`eval/parity/compare.py`): ±5% threshold, exit 0/1/2.
- Adversarial suite: prompt injection, confused deputy, tool spoofing,
  delegation depth abuse — 5 attack cells against the production Gateway.
- Metrics: precision/recall of denials, prompts-per-session, cognitive load,
  false-allow rate.
- CI exit codes (0/1/2/3); HTML + JSON report artifacts.
- `custos audit replay` for what-if policy analysis.

## [0.2.0] — 2026-07-14

Fatigue mitigation + user-facing surfaces. 298 tests pass.

### Added
- Fatigue layer (`InMemoryFatigueLayer`): batching (window-based, daemon timer,
  deterministic batch summaries), dedup (SHA-256 args hash, monotonic TTL),
  suppression window, prompt rate limit, DEFER semantics.
- Responders: CLI (F1 banner, y/N/a/A/l/d, thread timeout), web (SSE + embedded
  HTML), webhook (HMAC-SHA256, nonce replay tracking), Slack (button-card),
  noop (test/headless).
- Assistants A8 (summarize-batch) and A9 (context-adaptive: goal extraction +
  sensitivity scoring).

## [0.1.0] — 2026-07-13

Core middleware. 183 tests pass.

### Added
- `Gateway.decide` 8-step pipeline (parse → policy → assistant → responder →
  fatigue → timeout → audit → return). Floor/ceiling invariant enforced.
- `Decision` enum (allow / allow_once / allow_and_persist / deny / prompt / defer).
- Policy engine: first-match-wins, YAML + programmatic spec, hot-reload,
  default-deny, deterministic evaluation.
- Audit: `FileAuditSink` / `StdoutAuditSink` JSONL sinks; PII arg redaction.
- Assistants A5 (risk-assessment), A6 (autonomous), A7 (rule-policy).
- LLM client protocol seam; LiteLLM adapter.
- Python SDK `Gateway.wrap` with `functools.wraps` signature preservation.
- LangChain adapter (`custos-middleware[langchain]` extra).

[Unreleased]: https://github.com/Taki-chiasf/Custos/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/Taki-chiasf/Custos/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Taki-chiasf/Custos/compare/v1.0.0rc1...v1.0.0
[1.0.0rc1]: https://github.com/Taki-chiasf/Custos/compare/v0.4.0...v1.0.0rc1
[0.4.0]: https://github.com/Taki-chiasf/Custos/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Taki-chiasf/Custos/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Taki-chiasf/Custos/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Taki-chiasf/Custos/releases/tag/v0.1.0
