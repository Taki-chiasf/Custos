# Sidecar (gRPC)

Custos ships a standalone gRPC gateway mode  for runtimes
that can't be wrapped in-process (a TS agent, a Ruby agent, a separate
language service). The same in-process `Gateway.decide` is exposed over
gRPC with the sec 15 sidecar auth envelope: mTLS for transport, bearer
token (or delegated OIDC) for caller identity, per-call `request_id` / nonce
for replay detection, per-tenant rate limit.

## Install

```bash
pip install "custos-middleware[sidecar]"     # adds grpcio + protobuf (tested-minimum)
```

 unchanged — the runtime dep set stays `jsonschema`-literal; the
sidecar gate is the `custos[sidecar]` extra.

## Run

```bash
custos sidecar --policy policy.yaml \
  --tls-cert server.pem --tls-key server.key --tls-ca clients-ca.pem \
  --bearer "${CUSTOS_BEARER}" \
  --verdict-hmac-key "${CUSTOS_HMAC}" \
  --rate-limit-per-minute 600 \
  --audit audit.jsonl
```

mTLS is **mandatory** for v1.0 — the server refuses to start without
`--tls-cert/--tls-key/--tls-ca` (a plaintext sidecar is a sec 15 violation:
bearer + nonce are post-TLS primitives, not transport primitives).

## Auth envelope

| Primitive | Purpose | Failure behavior |
|---|---|---|
| mTLS | transport auth + caller cert | server rejects the connection before gRPC handler runs |
| Bearer (`--bearer`) | caller identity; empty allowlist = accept any non-empty bearer; empty bearer denied unless caller mTLS principal is in `anonymous_mtls_allowlist` | UNAUTHENTICATED |
| `caller_id` + `request_id` | replay detection via in-process `ReplayCache` (rejects replayed AND missing `request_id`) | DENY + audit anomaly |
| Tenant rate limit | sliding window per-tenant per-minute cap (single-tenant guard rail per D19 — NOT a multi-tenant isolation boundary; Redis-backed isolation is  / v1.1) | rate-limited DENY + audit alert |
| `verdict_signature = HMAC-SHA256(decision\|request_id\|ts_unix_ms\|risk_score)` | TS `@taqiy/custos-grpc` client verifies the verdict was emitted by THIS sidecar for THIS call | client downgrades to safe `deny` on mismatch |

## TS client

```typescript
import { GrpcSidecarTransport, sidecarAssistant } from "@taqiy/custos-grpc";
import { Gateway, Policy } from "@taqiy/custos-core";

const transport = new GrpcSidecarTransport({
  address: "my-sidecar.internal:7443",
  rootCert: fs.readFileSync("clients-ca.pem"),
  clientCertKey: ...,
  bearer: process.env.CUSTOS_BEARER!,
});

const assistant = sidecarAssistant(transport);   // routes assist:* over gRPC
const gw = new Gateway({
  policy: Policy.fromYamlFile("policy.yaml"),
  assistant,
  // responder in-process (CLI / noop) for the deterministic subset
});
```

The TS `Gateway.decide` re-evaluates policy locally on every sidecar
verdict and drops a sidecar `ALLOW*` when local policy says `DENY` (IR
contract sec 9.3 floor-is-local rule extended across the
boundary). See [adapters](adapters.md) + [IR contract](../IR_CONTRACT.md).

## Operate

```bash
custos audit verify audit.jsonl --hmac-key "${CUSTOS_HMAC}"     # if signed
custos audit tail audit.jsonl -n 50
```

A `CapturingAuditSink` mounts beneath the operator's configured sink so
the `DecideResponse.audit_event` echoes the in-process decision — the
sidecar is the transport surface, not the audit sink replacement. Operators
with a tamper-evident audit story should use `HashChainedAuditSink`
under their gateway config.

## See also

- [Threat model](THREAT_MODEL.md) row 12 — STRIDE mapping.
- [IR contract](../IR_CONTRACT.md) sec 9 — the cross-language gRPC schema.
- [Cookbook: air-gapped profile](cookbook/air-gapped-profile.md) — refuses
  LLM-backed assistants, complementing a sidecar that hosts the full Python
  stack somewhere the operator controls.