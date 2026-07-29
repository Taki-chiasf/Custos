# Custos threat model (v1.0)

This document is the standalone threat model for Custos referenced by sec 15. It enumerates the actors, trust boundaries, assets, and a STRIDE
table that maps every security bullet in sec 15 to a threat + mitigation.

Scope: the Custos in-process runtime (Python `custos` and TS `@taqiy/custos-core`),
the  gRPC sidecar (`custos-middleware[sidecar]`), and the  telemetry surface
(`custos-middleware[telemetry]`, default-off). The  adapters (AutoGen, Google ADK,
LlamaIndex) are droppable integration surfaces; their threat entry appears in
the STRIDE table at the "process \| agent framework" boundary and is referenced
where relevant. The document is normative: a that does NOT
appear here is a documentation bug.

Custos is permission middleware, not an authorization system (sec 5
Non-Goals). It governs agent-initiated tool calls against a configured policy
and an optional LLM permission assistant. It complements, never replaces,
existing human IAM / OAuth.

## 1. Actors

| ID | Actor | Trust posture | Compromise impact |
|---|---|---|---|
| A1 | Operator | Trusted. Holds signing keys, policy files, mTLS material, verifier HMAC keys, telemetry push endpoints. Deploys Custos. | Full. A malicious operator can re-emit unsigned policies, drop tamper-evidence, or reconfigure responders to allow-by-default. Detection is out-of-band (RBAC on the host, signed releases). |
| A2 | Agent framework | Process-trusted for in-process integration; untrusted at the sidecar boundary (assumed hostile across the network). Best-effort isolation in-process; the policy floor protects against an agent that lies to Custos (tool-spoofing cell covers the descriptor label). | Lateral. Can produce arbitrary tool invocations, lying tool names, hostile reasoning strings. Policy + assistant untrust + deny-floor contain this. |
| A3 | End user (P4) | Trusted for *their own* consent decisions. Indirect: never installs Custos. | Fatigue-only. Can rubber-stamp prompts (defeats A2/A5 by consent); cannot escalate past the deny-floor. |
| A4 | Approver | Trusted for *their attested identity* . Identity attested by each responder: CLI UID, Slack `user.id`, webhook HMAC-key-id, web-session subject. | A rogue approver inside the allowlist can approve hostile calls; mitigated by quorum + separation-of-duties . |
| A5 | LLM provider | Remote semi-trusted. Receives prompts + (per `exfiltrates_args`) call args during assistant evaluation. Air-gapped profile refuses instantiation; governance is `exfiltrates_args` + policy `allow_external_data: false`. | Quasi-confidential data exfiltration is the threat surface. Mitigated by H4 (sec 15 LLM-assistant exfiltration), deep redaction, and the air-gapped profile. |
| A6 | Network adversary | Untrusted. Active adversary on the path between Custos and the LLM, webhook, or sidecar. | Man-in-the-middle, replay, downgrade. Mitigated by mTLS (sidecar), HMAC + nonce + timestamp (webhook), TLS for LLM egress (operator responsibility). |
| A7 | Malicious community-assistant author | Untrusted. Third-party `Assistant` implementation installed into a Custos deployment (registry pattern). | Can attempt to relax a denial (rejected by the floor), exfiltrate args (gate by `exfiltrates_args`), or poison the persisted-rule overlay (H3 narrowness rejects broad globs at insert time). |
| A8 | Sidecar caller | Untrusted across the network. A peer agent runtime invoking `CustosGateway.Decide`. | Replay, identity spoofing, noisy-tenant starvation. Mitigated by mTLS, bearer + replay cache + per-tenant rate limit (/ sec 15 sidecar / gRPC boundary). |

## 2. Trust boundaries

Boundaries are explicit chokepoints where data crosses an untrusted domain. A
mitigation MUST name which boundary it enforces.

| Boundary | Crossings | Default-enforced? |
|---|---|---|
| Process \| agent framework | in-process `Gateway.decide`, `AsyncGateway.decide`, adapter `wrap_*` calls. Tool calls and arg dicts cross here. | Yes — policy floor, redaction, audit |
| Process \| responder | CLI stdin/stdout, web `/respond`, Slack interaction, webhook POST. Redacted prompt requests cross outbound; `PromptResponse.approver` crosses inbound. | Yes — bearers, allowlist, HMAC, XSS escaping |
| Process \| LLM provider | LiteLLM / Ollama egress for LLM-backed assistants (A3–A6, A9). Call args + reasoning prompts cross outbound. | Conditional — `exfiltrates_args` + `allow_external_data: false` |
| Process \| policy file | YAML / programmatic policy load, hot-reload. Rule-text crosses from filesystem to in-memory policy. | Yes for prod mode (signed policies); the v1.0 cut is unsigned (documented gap, mitigated by operator permissions on the file) |
| Process \| audit log | JSONL emit (file/stdout/OTLP/S3/hash-chained). AuditEvents cross outbound only; never inbound. | Yes — append-only, hash-chained optional, HMAC-signable |
| Sidecar API \| caller | gRPC `CustosGateway.Decide`. `caller_id` + bearer + `request_id` + tenant_id cross the wire. | Yes — mTLS mandatory, bearer + nonce replay cache + tenant rate limit |
| Process \| telemetry backend | OTLP / Prometheus scrape. Aggregated counters and spans cross outbound. | Opt-in only (`custos-middleware[telemetry]`, default-off) |

## 3. Assets

| Asset | Custody | Compromise consequence | Primary mitigation |
|---|---|---|---|
| Policy | Operator filesystem; loaded in-process | Malicious overrides; relax denials | Signed policies (prod path); file perms; `Policy.reload` atomic-swap + persisted-rule re-apply (addendum) |
| Audit log | Operator filesystem (or OTLP/S3) | Loss of accountability | Hash-chained sink ; HMAC per-line; `custos audit verify` |
| Secret args | Process memory; cross to responder (redacted) + to LLM (conditional) | Exfiltration of PII | Deep redaction (H5); `exfiltrates_args` gate (H4); air-gapped profile |
| Signing keys | Operator secrets store | Forge responses, policies, audit | Out-of-band RBAC; HMAC `signing_key` from a vault; **never logged** |
| Fatigue state | In-process `InMemoryFatigueLayer` | Cache-poisoning: a stale allow shadowing a fresh deny | Cacheable-decision invariant ; `Gateway.reload_policy` calls `fatigue.clear` (H6) |
| Telemetry state | In-process metrics registry  | Cardinality blow-up; key leakage | Labels are bounded enumerations (`decision`, `tool_name_pattern` bucketed, `responder`); no secret labels; opt-in extra |

## 4. STRIDE table (every  mapped)

Each row maps a  to the corresponding STRIDE category, names the
boundary, the threat, the mitigation already shipped in v1.0, and any open
gap. The bullet headers are verbatim from sec 15; the "Impl" pointers
are referenced at the end.

| # |  | STRIDE | Boundary | Threat | Mitigation (shipped) | Open gap |
|---|---|---|---|---|---|---|
| 1 | Confused-deputy hardening | Elevation of privilege | Process \| assistant | Assistant.returned `allow` bypasses a policy `deny`. | Policy floor: policy DENY short-circuits; assistant is never invoked on a DENY match. Assistant *output* is untrusted;  floor + ceiling invariant in `Gateway._apply_assistant_output_impl` (`sync`) and `AsyncGateway.decide` (`async`). Adversarial suite `confused_deputy` cell. | None. |
| 2 | Prompt injection | Tampering | Process \| assistant -> responder | Hostile reasoning string manipulates the approver UI / payload. | Responder surface hardening (H10): `textContent` interpolation in the web widget (no `innerHTML`); Slack `Context` block (Block Kit, no arbitrary markup); HMAC-signed prompts (webhook); policy-floor caps which tool+args reach the responder at all. Assistant reasoning never influences responder *options*. | None. |
| 3 | Delegation abuse | Elevation of privilege | Process \| agent framework -> assistant | A deep delegation chain smuggles an allow past a would-be-prompt. | A11 `DelegationAwareAssistant` depth-tier table (depth>=3 -> PROMPT, depth>=4 -> DENY); Policy `delegation_depth` exact-match criterion (hard cutoff); adversary cell `delegation_depth_abuse` enforces depth=4 hard-deny at the policy layer. Floor respected — base DENY never relaxed. | None. |
| 4 | Secret leakage | Information disclosure | Process \| responder, \| LLM, \| audit | `secret: true` / `password` args leak into a prompt payload, an LLM prompt, or the audit log. | Deep redaction (H5): `_redact_args` recurses `properties/items/patternProperties/additionalProperties/allOf/anyOf/$ref`; bare `SideEffect.PII` redacts ALL args for responder + audit + LLM paths; `SubjectContext.extra` filtered by `AUDIT_SUBJECT_FIELDS` allowlist. Original `Invocation` frozen + untouched. | None. |
| 5 | Policy tampering | Tampering | Process \| policy file | Unsigned policy reload relaxes denials mid-session. | `Policy.reload` is mtime-based, atomic-swap, malformed-file-safe . Persisted-rule overlay (rules inserted via `allow_and_persist`) is re-applied on top of file rules so in-session learning survives a reload (addendum + H6). | Signing is documented ("in prod mode, policy files are signature-checked") but the v1.0 cut does not ship a signed-policy verifier — operator-managed file perms are the standing mitigation. Signing is an operator / v1.1 gap (risk row). |
| 6 | Replay | Repudiation + spoofing | Process \| responder (webhook, Slack, sidecar caller) | A captured approval response is replayed to authorize a new invocation. | Webhook: HMAC over `choice:ttl:nonce:timestamp` validated via `hmac.compare_digest`; nonce replay-tracking; timestamp stale-check. Slack: v0 signing scheme. Web widget: short-lived session, bearer token. Sidecar: `(caller_id, request_id)` `ReplayCache` rejects replayed AND missing nonces (sec 15 sidecar boundary). | Cache eviction for the webhook nonce set is in-process; v1.1 with Redis-backed caches  for HA. |
| 7 | Persisted-rule narrowness | Tampering + elevation | Process \| assistant -> policy | `allow_and_persist` poisons the policy with a broad allow (`any:true`, `tool:"*"`, bare `allow`) that shadows later denies. | H3 narrowness in `Gateway._persist_assistant_rule_impl`: rejects broad globs, `any:true`, bare `allow` actions, `matches` regex; persisted rule inserted BEFORE the matched rule (earlier denies preserved); also rejects when match-set intersects any LATER `deny*` rule's match-set. Adversarial sub-suite (6 poisoning shapes). | None. |
| 8 | LLM-assistant exfiltration | Information disclosure | Process \| LLM provider | An LLM-backed assistant ships restricted args to a remote provider. | H4 `AssistantBase.exfiltrates_args` (True on A3/A4/A5/A6/A9); gateway routes restricted-arg + `exfiltrates_args=true` calls to `prompt` (or `deny` if no responder) without invoking the assistant; air-gapped profile refuses to instantiate any `exfiltrates_args=true` assistant. Policy `allow_external_data: false` is the rule-level opt-out. | A10/A11 are `exfiltrates_args=False` by construction (pure-deterministic; A10 has no LLM, A11 is pure-deterministic). A1/A2/A7/A8 (in-process) are `False` implicitly. |
| 9 | Deep redaction | Information disclosure | Process \| audit, \| responder, \| LLM | A nested PII field (`properties.address.zip`) leaks past shallow redaction. | H5 deep recursion through `properties/items/patternProperties/additionalProperties/allOf/anyOf/$ref` (shallow-resolved). `SideEffect.PII` with no per-field spec redacts ALL args. `SubjectContext.extra` allowlisted. Frozen input `Invocation` never mutated. | None (covered by H5 regression tests in `tests/audit/test_redaction.py`). |
| 10 | Responder exception safety | Denial of service + repudiation | Process \| responder, \| assistant, \| fatigue layer | A responder / assistant / fatigue-layer exception is raised mid-decision; audit + fatigue seam C (`after_prompt`) get skipped, leaving the call unaudited. | H8 in `Gateway.decide`: ASSIST/PROMPT branch wrapped in try/finally; any exception caught at the pipeline boundary -> safe `DENY` `PromptResponse` with `reasoning="responder|assistant error: ..."`; audit event AND seam C ALWAYS run. Mirrored in `AsyncGateway.decide`. | Repudiating a malicious responder that swallows its own raise is out of scope: H8 audits the error string; the audit log records that something blew up. |
| 11 | Responder surface hardening | Tampering + elevation + information disclosure | Process \| responder | The web widget binds 0.0.0.0 by default, accepts any POST, interpolates reasoning via `innerHTML` (XSS). | H10: default bind `127.0.0.1`; explicit `host="0.0.0.0"` opt-in; bearer token on `/`,`/events`,`/respond`; `Origin`/`Sec-Fetch-Site` check on `/respond`; widget rewritten with `textContent` rendering (no `innerHTML`); `args_redacted` rendered via `JSON.stringify`+escape. Slack: `application/x-www-form-urlencoded` `payload=` (H2); `_escape_mrkdwn`; `approver_allowlist`. | None. |
| 12 | Sidecar / gRPC boundary | Elevation + spoofing + repudiation + DoS | Sidecar API \| caller | A caller spoofs identity, replays a request, or starves the gateway with noise. |  (sec 15 sidecar bullet): mTLS mandatory (server refuses plaintext); bearer token (or delegated OIDC); `ReplayCache` rejects replayed `(caller_id, request_id)` nonces AND missing `request_id`; `TenantRateLimiter` sliding-window per-tenant per-minute cap; `verdict_signature = HMAC-SHA256(decision|request_id|ts_unix_ms|risk_score)` so the TS sidecar client can verify the verdict was emitted by THIS sidecar for THIS call;  floor-is-local rule on the TS `Gateway.decide` re-evaluates policy locally and drops a sidecar `ALLOW*` when local policy says `DENY`. | Multi-tenant isolation boundary is single-tenant per D19 (Redis-backed isolation is /v1.1). The per-tenant rate limit is a guard rail; cross-tenant starvation is not in scope for v1.0. |
| 13 | Threat model (this document) | Documentation + audit | n/a | A reviewer cannot reconstruct why a sec 15 mitigation is shaped the way it is. | This file. | None (this is the artifact). |

## 5. Threats not currently in sec 15 (forward-looking)

These are noted here so a future review can promote them into sec 15.
None is a issue for v1.0 per the locked  plan (D16–D19).

- **Side-channel timing** on the policy engine: a remote adversary measuring
  `latency_ms` of `Gateway.decide` over the sidecar to distinguish
  policy-hit short-circuits from a full assistant round-trip. Mitigation:
  v1.1 could add a per-decision constant-time ceiling (a fixed minimum
  latency floor) when the sidecar is exposed remotely.
- **Assistant prompt-injection from args**: a hostile tool / args string
  injected into an LLM assistant's judge prompt could attempt to flip the
  verdict to `allow`. Mitigation today is the  floor (an assistant
  `allow` cannot bypass a policy `deny`). **v1.1 adds A12
  `ipi-defender`** — a context inspector with fast-path pattern matching
  + leave-one-out causal attribution that runs before the assistant
  (policy ``inspect:ipi-defender`` action). See
  `docs/inspectors.md`. A deeper structured-input-only assistant protocol
  is a candidate for v1.2.
- **Phantom approver on Slack** where a `payload.user.id` is spoofed inside
  a forged Slack signature. Mitigation today is the Slack v0 signature
  validation + `approver_allowlist`. A second layer (per-approver
  per-decision one-time tokens) is a v1.1 quorum-hardening target.

## 6. Impl pointers

The sec 15 bullets are implemented in (cross-references to the `> Impl:`
notes, kept in sync):

- Confused-deputy / floor / ceiling: `src/custos/gateway.py:Gateway.decide`,
  `src/custos/async_gateway.py:AsyncGateway.decide`,
  `src/custos/gateway.py:_apply_assistant_output_impl` /
  `_persist_assistant_rule_impl` (shared sync/async).
- Persisted-rule narrowness (H3): same `_persist_assistant_rule_impl`.
- LLM-assistant exfiltration (H4): `src/custos/gateway.py:_resolve_exfiltration`
  path; `src/custos/assistants/base.py:AssistantBase.exfiltrates_args`.
- Deep redaction (H5): `src/custos/schema.py:_redact_args` (recursive) +
  `AUDIT_SUBJECT_FIELDS` allowlist.
- Hot-reload / fatigue coherence (H6): `src/custos/policy/engine.py:Policy.reload`
  + `src/custos/fatigue/base.py:FatigueLayer.clear`.
- Cacheable-decision (H7): `src/custos/fatigue/__init__.py:FatigueDecision.cacheable`.
- Exception safety (H8): `src/custos/gateway.py` try/finally.
- Policy thread-safety (H9): `src/custos/policy/engine.py:Policy` RLock +
  frozen-tuple snapshot.
- Responder surface hardening (H10): `src/custos/responders/web.py`,
  `src/custos/responders/slack.py`.
- Named-assistant routing (H11): `src/custos/assistants/base.py:AssistantRegistry`.
- Approver identity (H12): `src/custos/schema.py:PromptResponse.approver` +
  `AuditEvent.approver`.
- A11 delegation-aware (3): `src/custos/assistants/delegation_aware.py`.
- Adversarial-suite coverage: `src/custos/eval/suites/adversarial/` (53 cells at
  v1.0rc1 ; M8 reported as "zero false-allows AND zero false-denies").
- Sidecar auth envelope: `src/custos/sidecar/server.py:GatewayServicer` +
  `ReplayCache` + `TenantRateLimiter` + `verdict_signature`; TS surface in
  `packages/custos-ts/` `@taqiy/custos-grpc` `GrpcSidecarTransport`.
- Telemetry opt-in : `src/custos/telemetry/` behind `custos-middleware[telemetry]`,
  default-off.