# @taqiy/custos-grpc

gRPC transport for the Custos sidecar — the `SidecarTransport`
implementation consumed by [`@taqiy/custos-core`](../custos-ts/)'s
`sidecarAssistant(transport)` factory.

The Python [`custos`](https://github.com/Taki-chiasf/Custos) package's
`custos[sidecar]` extra runs the gateway server-side (`custos sidecar`
CLI subcommand); this package is the matching TS client transport. It
carries caller attestation (mTLS material + bearer + per-call nonce) and
forwards `DecideRequest` messages over gRPC. The ** floor-is-local
rule** (IR_CONTRACT) is re-applied by `Gateway.decide` at the
caller side on returned verdicts — a sidecar `allow*` is dropped when
local policy says `deny`. Assistant output is untrusted across the
boundary.

## Install

```bash
npm install @taqiy/custos-core @taqiy/custos-grpc
# Plus the gRPC peer deps (operator pins the tested-minimum versions):
npm install @grpc/grpc-js @grpc/proto-loader
```

Runtime deps: `@grpc/grpc-js` + `@grpc/proto-loader` (peer deps, so the
operator pins the tested-minimum versions; `@taqiy/custos-grpc` itself does NOT
bundle them — mirrors the Python `custos[sidecar]` extra gate keeping the
runtime dep set literal). `@taqiy/custos-core` is a `workspace:*` dependency;
install it alongside.

## Quickstart

```ts
import { sidecarAssistant } from "@taqiy/custos-core";
import { GrpcSidecarTransport } from "@taqiy/custos-grpc";
import { readFileSync } from "node:fs";

const transport = new GrpcSidecarTransport({
  address: "localhost:7443",
  // mTLS material (operator-managed PEMs).
  tlsCa: readFileSync("./client-ca.pem", "utf-8"),
  tlsCert: readFileSync("./client.crt", "utf-8"),
  tlsKey: readFileSync("./client.key", "utf-8"),
  // Optional: skip the hostname check against a self-signed test cert.
  // tlsServerNameOverride: "localhost",
  // Caller attestation.
  callerId: "ts-agent",
  bearer: process.env.CUSTOS_SIDECAR_BEARER!,
  // Verifier for the sidecar's `verdict_signature` HMAC —  replay
  // guard at the boundary. A failed verification downgrades to local
  // `DENY` per  inside `sidecarAssistant`.
  verdictHmacKey: Buffer.from(process.env.CUSTOS_VERDICT_HMAC_KEY!, "utf-8"),
});

const riskAssessment = sidecarAssistant({
  name: "risk-assessment",
  transport,
  callerId: "ts-agent",
  bearer: process.env.CUSTOS_SIDECAR_BEARER!,
  verdictHmacKey: Buffer.from(process.env.CUSTOS_VERDICT_HMAC_KEY!, "utf-8"),
});

// Use it via the @taqiy/custos-core Gateway:
//   new Gateway({ policy, assistant: riskAssessment, ... })
```

## What the transport does NOT do

- The  floor-is-local rule is `@taqiy/custos-core`'s job (apply a local policy
  `deny` even if the sidecar returns `allow*`). This package only carries
  the wire payload.
- Verdict-signature VERIFICATION is also `@taqiy/custos-core`'s job (inside
  `sidecarAssistant`); this package surfaces the
  `verdict_signature` bytes and the operator-supplied key, but does not
  run the HMAC.
- Multi-tenant isolation: per-tenant rate-limit is a guard rail at the
  sidecar (D19). This package surfaces a `tenant_id` field; the operator
  owns rate-limit policy server-side.

## Vendoring the proto

The registered proto lives at `proto/custos_v1.proto` (vendored; shipped
in the package `files` set so an npm install of `@taqiy/custos-grpc` carries it).
A user can pass `protoPath` to override with a custom path.

## Verifying

```bash
npm install
npm run typecheck
npm test           # unit tests (vitest)
npm run build      # tsc -p tsconfig.build.json — emits dist/esm/
```

## License

Apache-2.0 . See `LICENSE` at the repo root.