# Security Policy

Custos is permission middleware for AI agents — security is the product,
not an adjacent concern. This document covers supported versions,
vulnerability disclosure, the security model, and the invariants we will
not regress.

## Supported versions

| Version | Supported | Notes |
|---|---|---|
| `1.1.x` | Yes | v1.1 (A12 IPI defence + context inspectors). |
| `1.0.x` | Yes | v1.0 GA . |
| `1.0.0rc1` | Security fixes only | Pre-release. |
| `0.4.x` | Best-effort | Hardening cut; LTS not promised. |
| `0.3.x` / `0.2.x` / `0.1.x` | No | Pre-hardening; upgrade. |

Phase numbering refers to . The supported line tracks the latest
`1.0.x` / latest release candidate. Backports to `0.4.x` are best-effort
and depend on impact.

## Reporting a vulnerability

**Please do NOT open a public GitHub issue for a security vulnerability.**

Report vulnerabilities privately:

- Email: **security@Taki-chiasf.github**
- PGP-encrypted reports are preferred. The current PGP public key is
  published at the repository root as `SECURITY_PGP.pub` (and on the
  owner's keyserver). Fingerprints are listed below.

| Contact | Fingerprint |
|---|---|
| Custos security (owner) | _(owner action: paste key fingerprint here before the v1.0.0 cut —  placeholder)_ |

>  owner action: generate / publish the PGP key fingerprint and
> attach the public-key block to `SECURITY_PGP.pub`. The v1.0.0 GA cut
>  is gated on a real fingerprint being published here.

### Response SLO

We will acknowledge receipt within **2 business days** and aim to ship a
fix or documented mitigation within **14 days** for High-severity issues
and **30 days** for Medium. Severity is assessed by the maintainers using
the following model; reporters are welcome to propose a rating.

We ask reporters not to disclose the issue publicly until a fix is
released and the reporter has been credited (or has chosen to remain
anonymous). We will credit reporters in `CHANGELOG.md` entries and in the
GitHub Security Advisory unless they decline.

## Threat model

The full threat model ships at `docs/THREAT_MODEL.md` (deliverable).
The operational summary:

- **Assets**: policy file, audit log, secret args, signing keys, signing
  nonce state, fatigue (dedup / suppression) state, learning store (A10).
- **Actors**: operator (you), the agent framework / host, the end user
  (P4), the approver, the LLM provider, a network adversary, a malicious
  community-assistant author, a sidecar caller (sidecar mode).
- **Trust boundaries**: process ↔ responder ↔ LLM ↔ policy file ↔
  sidecar API .

A standalone STRIDE table mapping every  bullet to threats + mitigations
lands with `docs/THREAT_MODEL.md`. Until then, the  bullets in the are the authoritative invariants list.

## Security invariants  — the floor

These cannot be regressed by a contribution; any change that weakens one of
them MUST be flagged in the PR for explicit owner sign-off and updated in
:

1. **Policy is the floor.** An assistant can ONLY escalate strictness,
   never relax a `deny`. Assistant output is untrusted — including
   across the sidecar boundary (the local  floor applies even on
   sidecar-returned verdicts).
2. **Persisted-rule narrowness (H3).** A rule persisted by
   `allow_and_persist` MUST be structurally narrower than the rule it
   escalates from; broad globs / `any:true` / `allow` actions are
   rejected at insert time. The persisted rule's match-set MUST NOT
   intersect any later `deny*` rule's match-set.
3. **Replay.** Webhook responses carry a nonce + timestamp; expired /
   replayed responses are denied. Sidecar calls  carry a
   `request_id` / nonce + mTLS transport + bearer/OIDC caller identity.
4. **Secret leakage.** Args matching a `secret: true` or
   `format: password` schema field are redacted before the responder
   and the audit sink. Redaction is recursive (`properties`, `items`,
   `allOf`/`anyOf`/`$ref`, `patternProperties`, `additionalProperties`).
   A tool declaring `SideEffect.PII` without a per-field spec redacts
   ALL arg values.
5. **LLM-assistant exfiltration gating.** Assistants self-declare
   `exfiltrates_args: bool`. A rule MAY declare
   `allow_external_data: false` (default `false` for any call bearing
   `secret` / `password` args or `SideEffect.PII`). The air-gapped
   profile (`custos.local_only = true`) refuses to instantiate any
   `exfiltrates_args=true` assistant.
6. **Responder exception safety.** `Gateway.decide` is exception-safe:
   assistant / responder / fatigue-layer exceptions are caught at the
   pipeline boundary, converted to a safe `DENY`, and the audit event
   + fatigue seam C (`after_prompt`) ALWAYS run (`try/finally`).
7. **Approver authority .** Every `PromptResponse` carries the
   responder-attested approver identity; a decision emitted without an
   approver on a `prompt`-resolved path is itself an audit anomaly.
   Policy rules MAY specify an `approver_allowlist` and  a
   `quorum` + `approver_roles` for separation of duties.

## Default-deny and fail-closed defaults

- `Policy(..., default="deny")` is the documented default; a stray
  `default="allow"` is a dev-mode escape hatch and SHOULD NOT ship in a
  production policy file.
- Any responder failure / signing-secret misconfig / repeated timeouts
  trip a circuit breaker → permanent `DENY` + audit alert .
- Webhook and sidecar verification failures always fail closed (`DENY`).

## Audit and tamper-evidence

- Every `Gateway.decide` path emits an `AuditEvent`
   with `{ts, invocation, decision, policy_match, assistant,
  risk_score, reasoning, responder, approver, latency_ms, subject,
  quorum_state?, schema_version}`.
- The default `FileAuditSink` is **not** tamper-evident — documented. A
  `HashChainedAuditSink` + `custos audit verify <file>` land in  for
  the P3 compliance claim .

## Dependency posture

- : the **runtime** has zero hard deps beyond `jsonschema>=4.21`.
  Adapter / harness vendor SDKs are gated behind optional extras.
- `pip-audit` runs in CI on High CVEs (`.github/workflows/ci.yml`).
- A CycloneDX SBOM is generated for the runtime +
  `[llm]` / `[eval]` / `[sidecar]` / `[telemetry]` extras at the v1.0.0
  cut .

## Disclosure credits

Vulnerability reporters are credited in the relevant `CHANGELOG.md`
section and in the GitHub Security Advisory unless they request
anonymity.