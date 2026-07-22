// `sidecarAssistant(transport)` — IR_CONTRACT  .

// The TS `@taqiy/custos-core` ships A1/A2/A7/A11 in-process per D17; LLM-backed
// A3/A4/A5/A6/A9/A10 are reachable via the  gRPC sidecar, which hosts
// the full Python assistant stack server-side. `@taqiy/custos-core` stays
// zero-dep (-equivalent) by NOT pulling `@grpc/grpc-js`; the
// transport is injected. The sibling `@taqiy/custos-grpc` package (ships at
//) provides the real gRPC transport. A user can also plug in their
// own transport (test, REST-bridge, in-memory loopback).

//  floor-is-local rule : the TS `Gateway.decide` re-runs the
// policy engine LOCALLY on the same invocation; if the local policy
// says `deny`, the sidecar's `allow*` is dropped and the final decision
// is `deny`. Assistant output is untrusted across the boundary.

// The factory returns an `AssistantAsync` because the transport call is
// inherently async. The sync `Assistant.decide` contract is satisfied
// by returning a Promise (the gateway `await`s it).

import type { Assistant, AssistantAsync } from "./base.ts";
import type {
  AssistantOutput,
  Invocation,
  SubjectContext,
} from "../schema.ts";

export interface DecideRequestWire {
  invocation: Invocation;
  caller_id: string;
  bearer: string;
  request_id: string;
  tenant_id: string;
}

export interface DecideResponseWire {
  decision: "allow" | "allow_once" | "allow_and_persist" | "deny" | "prompt" | "defer";
  audit_event: unknown | null;
  server_latency_ms: number;
  verdict_cache_ms: number;
  verdict_signature: Uint8Array | null;
  risk_score: number;
  reasoning: string;
}

export interface SidecarTransport {
  decide(req: DecideRequestWire): Promise<DecideResponseWire>;
}

export interface SidecarAssistantOptions {
  name: string; // the assistant name to route to (e.g. "risk-assessment")
  transport: SidecarTransport;
  callerId: string;
  bearer?: string;
  tenantId?: string;
  // Optional HMAC key for verifying `verdict_signature`. If provided, a
  // failed verification downgrades the verdict to `deny` per .
  verdictHmacKey?: Uint8Array | null;
}

export function sidecarAssistant(opts: SidecarAssistantOptions): AssistantAsync {
  return new SidecarAssistant(opts);
}

class SidecarAssistant implements Assistant {
  readonly name: string;
  readonly exfiltratesArgs = true; // routes args over the network -> true per
  private readonly transport: SidecarTransport;
  private readonly callerId: string;
  private readonly bearer: string;
  private readonly tenantId: string;
  private readonly verdictHmacKey: Uint8Array | null;

  constructor(opts: SidecarAssistantOptions) {
    this.name = opts.name;
    this.transport = opts.transport;
    this.callerId = opts.callerId;
    this.bearer = opts.bearer ?? "";
    this.tenantId = opts.tenantId ?? "";
    this.verdictHmacKey = opts.verdictHmacKey ?? null;
  }

  async decide(inv: Invocation, _ctx: SubjectContext): Promise<AssistantOutput> {
    const req: DecideRequestWire = {
      invocation: inv,
      caller_id: this.callerId,
      bearer: this.bearer,
      request_id: inv.request_id ?? "",
      tenant_id: this.tenantId,
    };
    let resp: DecideResponseWire;
    try {
      resp = await this.transport.decide(req);
    } catch (err) {
      // Transport failure -> safe `deny` per  (responder exception safety,
      // extended to the sidecar transport). Audit anomaly recorded by the
      // gateway's exception-safety boundary.
      return {
        decision: "deny",
        risk: 1.0,
        reasoning: `sidecar transport error: ${(err as Error).message}`,
        fatigue_hint: false,
        persist_rule: null,
      };
    }

    // : verify the verdict signature when a key was provided. A failed
    // verification downgrades to `deny` locally (assistant output is
    // untrusted across the boundary, and so is sidecar output). An ABSENT or
    // empty signature when a key is configured is strictly stronger than a
    // mismatch (no signature = no trust) -> `deny` (C2 regression, council
    // 2026-07-22): a network middleman that strips the field cannot make
    // verification silently pass.
    if (this.verdictHmacKey !== null) {
      const requestId = inv.request_id ?? "";
      if (
        resp.verdict_signature === null
        || resp.verdict_signature.length === 0
        || !await verifyVerdictSignature(resp, requestId, this.verdictHmacKey)
      ) {
        return {
          decision: "deny",
          risk: 1.0,
          reasoning:
            "sidecar verdict signature missing or verification failed (replay guard)",
          fatigue_hint: false,
          persist_rule: null,
        };
      }
    }

    return {
      decision: resp.decision,
      risk: clamp01(resp.risk_score),
      reasoning: resp.reasoning || `sidecar assistant ${this.name}`,
      fatigue_hint: false,
      persist_rule: null, // sidecar-hosted assistants emit `allow_and_persist` server-side; persistence is server-side.
    };
  }
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) return 1.0;
  return Math.max(0, Math.min(1, n));
}

// HMAC-SHA256 over `decision|request_id|ts_unix_ms|risk_score` (IR_CONTRACT).
// Lazy-import `node:crypto` to keep `@taqiy/custos-core` importable without
// bundling when the user opts out of verdict signing. The `request_id`
// is provided by the caller because the DecideResponse does not echo it
// back; the Python sidecar signed with the same value (see
// `server.py:_verdict_signature`).
async function verifyVerdictSignature(
  resp: DecideResponseWire,
  requestId: string,
  key: Uint8Array
): Promise<boolean> {
  const { createHmac, timingSafeEqual } = await import("node:crypto");
  // proto-loader deserializes `ts_unix_ms` (int64) as either a `number`
  // or a `Long` depending on the `longs` option. The audit_event field
  // is a `Struct` from `google.protobuf.Struct`; TS sidecar responses
  // from @grpc/grpc-js surface it as a plain JS object where the int64
  // is a string/number per proto-loader defaults. We coerce defensively.
  const tsUnixMs = Number(
    (resp.audit_event as { ts_unix_ms?: number | string | bigint | null } | null)?.ts_unix_ms ?? 0
  );
  const canonical = `${resp.decision}|${requestId}|${tsUnixMs}|${resp.risk_score}`;
  const expected = createHmac("sha256", key).update(canonical).digest();
  if (expected.length !== resp.verdict_signature!.length) return false;
  try {
    return timingSafeEqual(expected, resp.verdict_signature! as Uint8Array & Buffer);
  } catch {
    return false;
  }
}