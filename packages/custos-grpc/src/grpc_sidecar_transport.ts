// `GrpcSidecarTransport` — the `SidecarTransport` implementation for
// `@custos/core`'s `sidecarAssistant(transport)` factory .

// Mirrors the Python `custos[sidecar]` extra at the OTHER end of the wire.
// The TS transport carries caller attestation (mTLS material + bearer +
// per-call nonce) and forwards `DecideRequest` messages over gRPC; the
//  floor-is-local rule (IR_CONTRACT) is re-applied by
// `Gateway.decide` at the caller side on returned verdicts (a sidecar
// `allow*` is dropped when local policy says `deny`). Assistant output is
// untrusted across the boundary.

// Runtime deps: `@grpc/grpc-js` + `@grpc/proto-loader` (peer deps so the
// operator pins the tested-minimum versions; `@custos/grpc` itself does
// NOT bundle them — mirrors the Python `custos[sidecar]` extra gate
// keeping the runtime dep set literal).

import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { existsSync } from "node:fs";

export interface GrpcSidecarTransportOptions {
  // Server address (host:port). Required.
  address: string;
  // mTLS material (PEM strings or buffers).
  tlsCa?: string | Uint8Array | null;
  tlsCert?: string | Uint8Array | null;
  tlsKey?: string | Uint8Array | null;
  // Override the target hostname for the TLS SNI check (e.g. when the
  // server cert CN is "localhost" but the address is "127.0.0.1").
  tlsServerNameOverride?: string | null;
  // Caller attestation.
  callerId: string;
  bearer: string;
  // Per-tenant rate-limit key (single-tenant guard rail for v1.0 per D19).
  tenantId?: string;
  // Optional verifier for the `verdict_signature` HMAC the sidecar emits.
  // A failed verification in `@custos/core`'s `sidecarAssistant` is
  // downgraded to local `DENY` per  — see IR_CONTRACT  + .
  // (Passed through to `sidecarAssistant({ verdictHmacKey })`; this
  // transport surfaces the bytes only, NOT the verification itself, to
  // keep the  replay guard at the assistant boundary where the
  // floor-is-local rule lives.)
  verdictHmacKey?: Uint8Array | null;
  // Path to the proto file. Defaults to the vendored `proto/custos_v1.proto`.
  protoPath?: string | null;
}

// The shape `@custos/core`'s `sidecarAssistant(transport)` factory expects
// (re-declared here to avoid a hard dep at type-check time; the type
// re-export at package index pulls it from `@custos/core`). The fields
// mirror the proto3 `DecideRequest` / `DecideResponse` from
// IR_CONTRACT . The transport translates from the snake_case
// (`request_id`, `caller_id`, `tenant_id`) the caller supplies (matching
// the proto field names) to the camelCase form proto-loader expects on
// its JS surface when `keepCase: false` (the chosen option). The
// translation is at-the-boundary so callers don't pay a naming-convention
// conversion tax.
export interface SidecarTransportLike {
  decide(req: SidecarDecideRequest): Promise<SidecarDecideResponse>;
}

export interface SidecarDecideRequest {
  invocation: {
    tool: string;
    args: Record<string, unknown>;
    context: {
      user_id: string;
      goal_id?: string | null;
      task_id?: string | null;
      delegation_chain?: string[];
      session_ttl?: number | null;
      extra?: Record<string, unknown>;
    };
    descriptor?: {
      name: string;
      risk_tier: number;
      reversible: boolean;
      side_effects: string[];
      schema?: Record<string, unknown>;
    } | null;
    request_id?: string | null;
  };
  caller_id: string;
  bearer: string;
  request_id: string;
  tenant_id: string;
}

export interface SidecarDecideResponse {
  decision: "allow" | "allow_once" | "allow_and_persist" | "deny" | "prompt" | "defer";
  audit_event: unknown | null;
  server_latency_ms: number;
  verdict_cache_ms: number;
  verdict_signature: Uint8Array | null;
  risk_score: number;
  reasoning: string;
}

// Lazy module-level caches — kept OUTSIDE the function bodies so they
// load once per process. The imports happen INSIDE the class methods so
// a host that installs `@custos/grpc` but never instantiates a transport
// never pays the `@grpc/*` import cost (a server-only install pattern;
// mirrors the Python "vendor imports inside the sidecar extra" rule).
let _grpcPromise: Promise<typeof import("@grpc/grpc-js")> | null = null;
let _protoLoaderPromise: Promise<typeof import("@grpc/proto-loader")> | null = null;

// Walk up from this module's location searching for the vendored
// `proto/custos_v1.proto` so the path resolves the same whether the
// caller loads the source (vitest development: `src/`) or the ESM
// build (`dist/esm/`). Both are two levels below the package root,
// but the dist layout is the canonical locator.
function resolveProtoPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // Both `src/` and `dist/esm/` are at most three levels below the
  // package root; the proto lives at `<pkgRoot>/proto/custos_v1.proto`.
  // Walk up at most four levels, returning the first match.
  let cursor = here;
  for (let i = 0; i < 4; i++) {
    const candidate = join(cursor, "proto", "custos_v1.proto");
    if (existsSync(candidate)) return resolve(candidate);
    cursor = dirname(cursor);
    if (cursor === dirname(cursor)) break; // reached root
  }
  // Last-resort: the dist layout default.
  return join(here, "..", "..", "proto", "custos_v1.proto");
}

async function loadGrpc() {
  if (!_grpcPromise) _grpcPromise = import("@grpc/grpc-js");
  return _grpcPromise;
}

async function loadProtoLoader() {
  if (!_protoLoaderPromise) _protoLoaderPromise = import("@grpc/proto-loader");
  return _protoLoaderPromise;
}

function toBytes(v: string | Uint8Array | null | undefined): Buffer | null {
  if (v === null || v === undefined) return null;
  if (typeof v === "string") return Buffer.from(v, "utf-8");
  return Buffer.from(v);
}

export class GrpcSidecarTransport implements SidecarTransportLike {
  readonly address: string;
  readonly callerId: string;
  readonly bearer: string;
  readonly tenantId: string;
  readonly verdictHmacKey: Uint8Array | null;
  readonly protoPath: string;

  private readonly _tlsCa: Buffer | null;
  private readonly _tlsCert: Buffer | null;
  private readonly _tlsKey: Buffer | null;
  private readonly _tlsServerNameOverride: string | null;

  // Cached gRPC client (built once on first `decide`).
  private _client: unknown | null = null;

  constructor(opts: GrpcSidecarTransportOptions) {
    this.address = opts.address;
    this.callerId = opts.callerId;
    this.bearer = opts.bearer;
    this.tenantId = opts.tenantId ?? "";
    this.verdictHmacKey = opts.verdictHmacKey ?? null;
    this._tlsCa = toBytes(opts.tlsCa);
    this._tlsCert = toBytes(opts.tlsCert);
    this._tlsKey = toBytes(opts.tlsKey);
    this._tlsServerNameOverride = opts.tlsServerNameOverride ?? null;

    // Resolve the proto path. The vendored `proto/custos_v1.proto` ships
    // with the package (in `files`); a caller can override with an
    // absolute path. We resolve it by walking up from this module's
    // location so the path is correct regardless of whether the caller
    // imports the dist build (`dist/esm/`) or the source (vitest in
    // development, `src/`).
    if (opts.protoPath !== null && opts.protoPath !== undefined) {
      this.protoPath = opts.protoPath;
    } else {
      this.protoPath = resolveProtoPath();
    }
  }

  async decide(req: SidecarDecideRequest): Promise<SidecarDecideResponse> {
    const client = await this._getClient();
    // Translate the snake_case DecideRequest surface the caller supplies
    // (and that `@custos/core`'s AssistantOutput wire expects) to the
    // camelCase form proto-loader expects on its JS surface (we load with
    // `keepCase: false`). The translation is at-the-boundary so callers
    // don't pay a naming-convention conversion tax for every RPC.
    const wireReq = _toWireCase(req);
    // Forward the Decide RPC. `@grpc/proto-loader` returns a Promise-shaped
    // callback surface; we bridge to async via util.promisify.
    return new Promise<SidecarDecideResponse>((resolve, reject) => {
      const invoke = (client as { Decide: (
        req: unknown,
        cb: (err: Error | null, resp: unknown) => void
      ) => void }).Decide;
      invoke.call(client, wireReq, (err, resp) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(this._coerceResponse(resp));
      });
    });
  }

  // Bridge a proto-loader dynamic object to the typed response shape.
  private _coerceResponse(resp: unknown): SidecarDecideResponse {
    const r = resp as {
      decision: number;
      auditEvent?: Record<string, unknown> | null;
      serverLatencyMs?: number;
      verdictCacheMs?: bigint | number | string;
      verdictSignature?: Uint8Array | null;
      riskScore?: number;
      reasoning?: string;
    };
    // Normalize the audit event to the IR_CONTRACT  wire shape (snake_case
    // field names) so @custos/core's `verifyVerdictSignature` can read
    // `ts_unix_ms` directly. proto-loader with `keepCase: false` returns
    // camelCase names — translate them.
    const auditWire: Record<string, unknown> | null = r.auditEvent
      ? _auditEventToWire(r.auditEvent)
      : null;
    return {
      decision: _decisionFromProtoEnum(r.decision),
      audit_event: auditWire,
      server_latency_ms: r.serverLatencyMs ?? 0,
      // protobuf int64 maps to `bigint` under proto-loader's longorstring=false
      // default; accept any and normalize.
      verdict_cache_ms: typeof r.verdictCacheMs === "bigint" ? Number(r.verdictCacheMs) : Number(r.verdictCacheMs ?? 0),
      verdict_signature: (r.verdictSignature as Uint8Array | null) ?? null,
      risk_score: r.riskScore ?? 0,
      reasoning: r.reasoning ?? "",
    };
  }

  private async _getClient(): Promise<unknown> {
    if (this._client) return this._client;
    const grpc = await loadGrpc();
    const protoLoader = await loadProtoLoader();

    const packageDef = await protoLoader.load(this.protoPath, {
      keepCase: false, // camelCase field names (matches our _coerceResponse).
      longs: Number,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    const protoDescriptor = grpc.loadPackageDefinition(packageDef);
    // The dynamic GrpcObject shape from `loadPackageDefinition` doesn't
    // statically declare the nested `custos.v1.CustosGateway` ctor; coerce
    // via `unknown` so TS doesn't flag the assertion. The generated client
    // ctor is `(address, credentials, options?)` — `options` is the
    // `ChannelOptions` hash so we can pass `grpc.ssl_target_name_override`.
    const CustosGateway = (protoDescriptor as unknown as {
      custos: { v1: { CustosGateway: new (address: string, creds: unknown, options?: Record<string, unknown>) => unknown } };
    }).custos.v1.CustosGateway;

    // TLS credentials. If the operator does NOT supply TLS material, we
    // REFUSE to instantiate the client — IR_CONTRACT  mandates mTLS.
    // Production callers MUST pass tlsCa + tlsCert + tlsKey.
    if (!this._tlsCa || !this._tlsCert || !this._tlsKey) {
      throw new Error(
        "GrpcSidecarTransport: mTLS material REQUIRED (tlsCa + tlsCert + tlsKey); "
        + "a plaintext sidecar is a security-policy violation."
      );
    }

    const creds = grpc.credentials.createSsl(
      this._tlsCa,
      this._tlsKey,
      this._tlsCert
    );
    const options: Record<string, unknown> = {};
    if (this._tlsServerNameOverride) {
      options["grpc.ssl_target_name_override"] = this._tlsServerNameOverride;
    }
    this._client = new CustosGateway(this.address, creds, options);
    return this._client;
  }

  // Test hook: drop the cached client (used by the integration test to
  // force a reconnect against a fresh server).
  _reset(): void {
    this._client = null;
  }
}

const DECISION_NAMES = [
  "DECISION_UNSPECIFIED",
  "allow",
  "allow_once",
  "allow_and_persist",
  "deny",
  "prompt",
  "defer",
] as const;

function _decisionFromProtoEnum(n: number | string): SidecarDecideResponse["decision"] {
  // proto-loader with `enums: String` returns the enum NAME string
  // (UPPERCASE proto-defined names: `ALLOW_ONCE` etc.); IR_CONTRACT
  // pins the lowercase wire form. Normalize string inputs to lowercase
  // so the @custos/core Decision enum matches exactly.
  if (typeof n === "string") {
    const lower = n.toLowerCase();
    if (lower === "decision_unspecified") return "deny"; //  safe DENY
    return lower as SidecarDecideResponse["decision"];
  }
  if (n < 1 || n > 6) {
    // : DECISION_UNSPECIFIED (0) -> safe DENY locally.
    return "deny";
  }
  return DECISION_NAMES[n] as SidecarDecideResponse["decision"];
}

// Translate the snake_case `DecideRequest` surface (matching the proto
// field names + the canonical Python wire shape) into the camelCase form
// proto-loader expects on its JS surface when `keepCase: false` (the
// chosen option). This boundary-level translation keeps the wire shape
// canonical and isolates the naming-convention quirk to the transport.
function _toWireCase(req: SidecarDecideRequest): Record<string, unknown> {
  const inv = req.invocation;
  const ctx = inv.context;
  const desc = inv.descriptor;
  const wireInv: Record<string, unknown> = {
    tool: inv.tool,
    args: inv.args,
    context: {
      userId: ctx.user_id,
      goalId: ctx.goal_id ?? "",
      taskId: ctx.task_id ?? "",
      delegationChain: ctx.delegation_chain ?? [],
      sessionTtl: ctx.session_ttl ?? 0,
      extra: ctx.extra ?? {},
    },
    requestId: inv.request_id ?? "",
  };
  if (desc) {
    wireInv["descriptor"] = {
      name: desc.name,
      riskTier: desc.risk_tier,
      reversible: desc.reversible,
      sideEffects: desc.side_effects,
      schema: desc.schema ?? {},
    };
  }
  return {
    invocation: wireInv,
    callerId: req.caller_id,
    bearer: req.bearer,
    requestId: req.request_id,
    tenantId: req.tenant_id,
  };
}

// Translate a proto-loader AuditEvent dynamic object (camelCase fields
// — `keepCase: false`) to the IR_CONTRACT  wire shape (snake_case).
// We only normalize the top-level fields `@custos/core`'s
// `verifyVerdictSignature` reads (`ts_unix_ms`) and a few other top-level
// fields for caller observability; nested sub-objects are passed through
// untouched (the caller does not need a fully-flat copy).
function _auditEventToWire(ae: Record<string, unknown>): Record<string, unknown> {
  return {
    ts_unix_ms: ae["tsUnixMs"] ?? ae["ts_unix_ms"],
    decision: _decisionFromProtoEnum(Number((ae["decision"] as number | string | undefined) ?? 0)),
    policy_match: ae["policyMatch"] ?? ae["policy_match"] ?? null,
    assistant: ae["assistant"] ?? null,
    risk_score: ae["riskScore"] ?? ae["risk_score"] ?? 0,
    reasoning: ae["reasoning"] ?? "",
    responder: ae["responder"] ?? null,
    latency_ms: ae["latencyMs"] ?? ae["latency_ms"] ?? 0,
    approver: ae["approver"] ?? null,
    quorum_state: ae["quorumState"] ?? ae["quorum_state"] ?? null,
    schema_version: ae["schemaVersion"] ?? ae["schema_version"] ?? "1.0",
  };
}