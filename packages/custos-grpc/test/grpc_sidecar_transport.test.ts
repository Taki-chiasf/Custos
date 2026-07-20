// Unit tests for `GrpcSidecarTransport` (no live server).

// The live gRPC round-trip is covered by `test/integration.test.ts`,
// which spins up the Python sidecar. These tests verify the static
// contract: construction errors, the decision-enum normalization, the
// `_coerceResponse` shape that bridges proto-loader's dynamic object.

import { describe, it, expect } from "vitest";
import { GrpcSidecarTransport } from "../src/grpc_sidecar_transport.ts";

const TLS_MATERIAL = {
  tlsCa: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
  tlsCert: "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
  tlsKey: "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
};

describe("GrpcSidecarTransport — construction", () => {
  it("refuses to instantiate without mTLS material", async () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      // no tlsCa / tlsCert / tlsKey
      callerId: "ts-agent",
      bearer: "b",
    });
    await expect(t.decide(makeDecideRequest())).rejects.toThrow(/mTLS material REQUIRED/);
  });

  it("sets the attestation fields on the instance", () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: " bearer-value ",
      tenantId: "t1",
      verdictHmacKey: new Uint8Array([1, 2, 3]),
    });
    expect(t.callerId).toBe("ts-agent");
    expect(t.bearer).toBe(" bearer-value ");
    expect(t.tenantId).toBe("t1");
    expect(t.verdictHmacKey).toEqual(new Uint8Array([1, 2, 3]));
  });

  it("defaults the tenant_id to empty (single-tenant default per D19)", () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: "b",
    });
    expect(t.tenantId).toBe("");
  });

  it("defaults the verdictHmacKey to null when not provided", () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: "b",
    });
    expect(t.verdictHmacKey).toBeNull();
  });
});

describe("GrpcSidecarTransport — decision enum normalization", () => {
  // The conversion is private; we exercise it indirectly through the
  // proto-loader dynamic shape by constructing a synthetic `decide`
  // path with a mocked client (avoids needing the gRPC libs at the
  // typecheck surface — proto-loader returns a dynamic `any` shape).
  it("returns DECISION_UNSPECIFIED (0) -> safe deny", async () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: "b",
    });
    // Inject a fake client. We bypass `_getClient` via a private cast.
    (t as unknown as { _client: unknown })._client = {
      Decide(_req: unknown, cb: (err: Error | null, resp: unknown) => void): void {
        cb(null, { decision: 0, reasoning: "sentinel" });
      },
    };
    const resp = await t.decide(makeDecideRequest());
    expect(resp.decision).toBe("deny"); // safe downgrade
  });

  it("passes through a string decision from proto-loader enums:String", async () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: "b",
    });
    (t as unknown as { _client: unknown })._client = {
      Decide(_req: unknown, cb: (err: Error | null, resp: unknown) => void): void {
        cb(null, {
          decision: "allow_once",
          auditEvent: { tsUnixMs: 1 },
          serverLatencyMs: 2,
          verdictCacheMs: 3,
          verdictSignature: new Uint8Array([9, 9]),
          riskScore: 0.1,
          reasoning: "ok",
        });
      },
    };
    const resp = await t.decide(makeDecideRequest());
    expect(resp.decision).toBe("allow_once");
    expect(resp.server_latency_ms).toBe(2);
    expect(resp.verdict_cache_ms).toBe(3);
    expect(resp.risk_score).toBe(0.1);
    expect(resp.reasoning).toBe("ok");
    expect(resp.verdict_signature).toEqual(new Uint8Array([9, 9]));
  });

  it("coerces a numeric decision > 6 to safe deny", async () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: "b",
    });
    (t as unknown as { _client: unknown })._client = {
      Decide(_req: unknown, cb: (err: Error | null, resp: unknown) => void): void {
        cb(null, { decision: 99 });
      },
    };
    const resp = await t.decide(makeDecideRequest());
    expect(resp.decision).toBe("deny");
  });

  it("passes through a transport error", async () => {
    const t = new GrpcSidecarTransport({
      address: "localhost:7443",
      ...TLS_MATERIAL,
      callerId: "ts-agent",
      bearer: "b",
    });
    (t as unknown as { _client: unknown })._client = {
      Decide(_req: unknown, cb: (err: Error | null, _resp: unknown) => void): void {
        cb(new Error("rpc failed"), null);
      },
    };
    await expect(t.decide(makeDecideRequest())).rejects.toThrow("rpc failed");
  });
});

function makeDecideRequest(): Parameters<GrpcSidecarTransport["decide"]>[0] {
  return {
    invocation: {
      tool: "fs.write_log",
      args: { msg: "x" },
      context: { user_id: "alice", delegation_chain: [] },
      request_id: "req-test",
    },
    caller_id: "ts-agent",
    bearer: "b",
    request_id: "req-test",
    tenant_id: "",
  };
}