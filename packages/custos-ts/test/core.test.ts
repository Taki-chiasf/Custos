// Core suite: `Gateway.decide` 8-step pipeline +  floor + assistants
// + redaction + SDK wrap. Mirrors the Python sync suite for the
// deterministic subset (A1/A2/A7/A11 in-process per D17).

import { describe, it, expect } from "vitest";

import { Gateway } from "../src/gateway.ts";
import { Policy, type RuleSpec } from "../src/policy/engine.ts";
import {
  AutoApproveAssistant,
  UserConfirmationAssistant,
  RulePolicyAssistant,
  DelegationAwareAssistant,
  DEFAULT_DEPTH_THRESHOLDS,
} from "../src/assistants/index.ts";
import { NoopResponder } from "../src/responders/index.ts";
import { FileAuditSink, NullAuditSink } from "../src/audit/sink.ts";
import { InMemoryFatigueLayer } from "../src/fatigue/dedup.ts";
import type { AuditEvent, SubjectContext, ToolDescriptor } from "../src/schema.ts";
import { PermissionDenied } from "../src/exceptions.ts";

function ctx(uid = "alice"): SubjectContext {
  return {
    user_id: uid,
    goal_id: null,
    task_id: null,
    delegation_chain: [],
    session_ttl: null,
    extra: {},
  };
}

const fsReadDescriptor: ToolDescriptor = {
  name: "fs.read",
  risk_tier: 2,
  reversible: false,
  side_effects: ["read"],
  schema: { type: "object", properties: { path: { type: "string" } } },
};

const emailSendDescriptor: ToolDescriptor = {
  name: "email.send",
  risk_tier: 4,
  reversible: false,
  side_effects: ["write", "network", "pii"],
  schema: {
    type: "object",
    properties: {
      to: { type: "string", secret: true, format: "password" },
      subject: { type: "string" },
      body: { type: "string" },
    },
  },
};

const basePolicyRules: RuleSpec[] = [
  { match: { tool: "fs.read*", side_effects: ["read"] }, action: "allow_and_audit" },
  { match: { tool: "fs.write*", risk_tier: [4, 5] }, action: "prompt" },
  { match: { tool: "email.send" }, action: "deny" },
  { match: { tool: "shell.*", risk_tier: [4, 5] }, action: "prompt" },
];

function basePolicy(): Policy {
  return Policy.fromSpec({ rules: basePolicyRules, default: "deny" });
}

describe("Gateway — policy floor", () => {
  it("policy `deny` is final — even with an assistant that would allow", async () => {
    const gw = new Gateway({
      policy: basePolicy(),
      assistant: new AutoApproveAssistant(),
      responder: new NoopResponder(),
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("email.send", { to: "a@b" });
    //  floor: policy DENY is final; A1 cannot relax.
    expect(decision).toBe("deny");
    expect(audit.decision).toBe("deny");
  });

  it("policy `allow` short-circuits (no assistant, no responder)", async () => {
    const gw = new Gateway({
      policy: basePolicy(),
      assistant: new AutoApproveAssistant(),
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("fs.read_file", {
      path: "/etc/hosts",
    }, { descriptor: fsReadDescriptor });
    expect(decision).toBe("allow");
    expect(audit.assistant).toBeNull();
  });

  it("policy `deny` skips the responder", async () => {
    const gw = new Gateway({
      policy: basePolicy(),
      assistant: null,
      responder: new NoopResponder(),
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("email.send", { to: "a@b" });
    expect(decision).toBe("deny");
    expect(audit.responder).toBeNull();
  });

  it("default-deny when no rule matches (FR-9.4)", async () => {
    const gw = new Gateway({
      policy: basePolicy(),
      assistant: null,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("unmatched.tool", {});
    expect(decision).toBe("deny");
  });

  it("default-allow dev mode (FR-9.4)", async () => {
    const gw = new Gateway({
      policy: Policy.fromSpec({ rules: [], default: "allow" }),
      assistant: null,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("anything", {});
    expect(decision).toBe("allow");
  });
});

describe("Gateway — assistant escalation", () => {
  it("an assistant may emit `deny` (escalate) on an ASSIST rule", async () => {
    const rules: RuleSpec[] = [
      { match: { tool: "fs.write*" }, action: "assist:auto-approve" },
    ];
    // A7 with a rule-table that denies everything.
    const a7Deny = new RulePolicyAssistant(
      Policy.fromSpec({ rules: [{ match: { any: true }, action: "deny" }], default: "deny" })
    );
    const gw = new Gateway({
      policy: Policy.fromSpec({ rules, default: "deny" }),
      assistant: a7Deny,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("fs.write_log", { msg: "x" });
    expect(decision).toBe("deny");
  });

  it("A1 `auto-approve` allows every ASSIST-routed call", async () => {
    const rules: RuleSpec[] = [
      { match: { tool: "fs.write*" }, action: "assist:auto-approve" },
    ];
    const gw = new Gateway({
      policy: Policy.fromSpec({ rules, default: "deny" }),
      assistant: new AutoApproveAssistant(),
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("fs.write_log", { msg: "x" });
    expect(decision).toBe("allow_once");
    expect(audit.assistant).toBe("auto-approve");
  });

  it("A2 `user-confirmation` routes to the responder", async () => {
    const rules: RuleSpec[] = [
      { match: { tool: "fs.write*" }, action: "assist:user-confirmation" },
    ];
    const gw = new Gateway({
      policy: Policy.fromSpec({ rules, default: "deny" }),
      assistant: new UserConfirmationAssistant(),
      responder: new NoopResponder(), // auto-denies
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("fs.write_log", { msg: "x" });
    expect(decision).toBe("deny");
  });

  it("assistant exception -> safe `deny`", async () => {
    const throwingAssistant = {
      name: "throwy",
      exfiltratesArgs: false,
      decide(): never { throw new Error("boom"); },
    };
    const rules: RuleSpec[] = [{ match: { tool: "*" }, action: "assist:throwy" }];
    const gw = new Gateway({
      policy: Policy.fromSpec({ rules, default: "deny" }),
      assistant: throwingAssistant,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("fs.write_log", { msg: "x" });
    expect(decision).toBe("deny");
    expect(audit.reasoning).toContain("assistant error: boom");
  });

  it("FR-9.30c: an unresolved `assist:<name>` fails closed (safe deny)", async () => {
    const rules: RuleSpec[] = [
      { match: { tool: "fs.write*" }, action: "assist:risk-assessment" },
    ];
    const gw = new Gateway({
      policy: Policy.fromSpec({ rules, default: "deny" }),
      assistant: new AutoApproveAssistant(), // name != "risk-assessment"
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("fs.write_log", { msg: "x" });
    expect(decision).toBe("deny");
    expect(audit.reasoning).toContain("routed but configured assistant is auto-approve");
  });
});

describe("Gateway — fatigue dedup (FR-9.12, FR-9.12a)", () => {
  it("user-resolved decisions are cached and replayed (dedup)", async () => {
    const fatigue = new InMemoryFatigueLayer({ dedupTtlS: 10 });
    let calls = 0;
    const trackingSink = {
      name: "tracking",
      emit(_e: AuditEvent) { calls++; },
    };
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.read*" }, action: "allow_and_audit" }],
        default: "deny",
      }),
      assistant: null,
      responder: null,
      auditSink: trackingSink,
      fatigue,
      defaultContext: ctx(),
    });
    const r1 = await gw.decide("fs.read_x", {});
    expect(r1.decision).toBe("allow");
    const r2 = await gw.decide("fs.read_x", {});
    expect(r2.decision).toBe("allow");
    // Different args -> not deduped.
    const r3 = await gw.decide("fs.read_x", { other: 1 });
    expect(r3.decision).toBe("allow");
  });

  it("fatigue.clear() invalidates the cache (FR-9.12b)", async () => {
    const fatigue = new InMemoryFatigueLayer({ dedupTtlS: 10 });
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.read*" }, action: "allow_and_audit" }],
        default: "deny",
      }),
      assistant: null,
      responder: null,
      auditSink: new NullAuditSink(),
      fatigue,
      defaultContext: ctx(),
    });
    expect((await gw.decide("fs.read_x", {})).decision).toBe("allow");
    // Hot-reload to a stricter policy + invalidates the cache.
    gw.reloadPolicy(
      Policy.fromSpec({ rules: [{ match: { tool: "fs.read*" }, action: "deny" }], default: "deny" })
    );
    expect((await gw.decide("fs.read_x", {})).decision).toBe("deny");
  });

  // Arch #1 regression (council 2026-07-22): the TS gateway MUST evaluate
  // policy BEFORE the fatigue cache. A cached user-resolved `allow` must NOT
  // shadow a freshly-tightened policy (here: swapping gw.policy to `deny`
  // WITHOUT calling reloadPolicy). The Python gateway is policy-first by
  // construction; the TS port had fatigue-first, which let a stale cache
  // bypass a tightened floor.
  it("policy is evaluated before the fatigue cache (arch #1)", async () => {
    const fatigue = new InMemoryFatigueLayer({ dedupTtlS: 10 });
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.read*" }, action: "allow_and_audit" }],
        default: "deny",
      }),
      assistant: null,
      responder: null,
      auditSink: new NullAuditSink(),
      fatigue,
      defaultContext: ctx(),
    });
    expect((await gw.decide("fs.read_x", {})).decision).toBe("allow");
    // Tighten the policy by replacing it directly (no reloadPolicy ->
    // fatigue cache is NOT cleared). The floor MUST still win.
    gw.policy = Policy.fromSpec({
      rules: [{ match: { tool: "fs.read*" }, action: "deny" }],
      default: "deny",
    });
    expect((await gw.decide("fs.read_x", {})).decision).toBe("deny");
  });
});

describe("Gateway — Audit", () => {
  it("audit sink failure surfaces to stderr but does not change the decision", async () => {
    const failingSink = {
      name: "failing",
      emit(): never { throw new Error("audit broken"); },
    };
    const gw = new Gateway({
      policy: basePolicy(),
      assistant: null,
      responder: null,
      auditSink: failingSink,
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("fs.read", {}, { descriptor: fsReadDescriptor });
    expect(decision).toBe("allow");
  });

  it("FileAuditSink writes JSONL", async () => {
    const tmp = `/tmp/custos-ts-test-${Date.now()}.jsonl`;
    const sink = new FileAuditSink(tmp);
    const gw = new Gateway({
      policy: basePolicy(),
      assistant: null,
      responder: null,
      auditSink: sink,
      defaultContext: ctx(),
    });
    await gw.decide("fs.read_file", { path: "/etc/hosts" }, { descriptor: fsReadDescriptor });
    const { readFileSync, unlinkSync } = await import("node:fs");
    const lines = readFileSync(tmp, "utf8").trim().split("\n");
    expect(lines.length).toBe(1);
    const evt = JSON.parse(lines[0]!);
    expect(evt.decision).toBe("allow");
    expect(evt.invocation.tool).toBe("fs.read_file");
    expect(evt.schema_version).toBe("1.0");
    unlinkSync(tmp);
  });
});

describe("Redaction", () => {
  it("secret:true + format:password fields are redacted before responder", async () => {
    let observedArgs: Record<string, unknown> | null = null;
    const capturingResponder = {
      name: "capturing",
      async prompt(req: { args_redacted: Record<string, unknown> }) {
        observedArgs = req.args_redacted;
        return { choice: "deny" as const, ttl: null, signature: null, nonce: null, approver: null };
      },
    };
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "email.send" }, action: "prompt" }],
        default: "deny",
      }),
      assistant: null,
      responder: capturingResponder as any,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    await gw.decide("email.send", {
      to: "secret@x.com",
      subject: "hi",
      body: "secret body",
    }, { descriptor: emailSendDescriptor });
    expect(observedArgs!.to).toBe("[REDACTED]");
    expect(observedArgs!.subject).toBe("hi");
  });

  it("SideEffect.PII without per-field spec redacts ALL values", async () => {
    let observedArgs: Record<string, unknown> | null = null;
    const capturingResponder = {
      name: "capturing",
      async prompt(req: { args_redacted: Record<string, unknown> }) {
        observedArgs = req.args_redacted;
        return { choice: "deny" as const, ttl: null, signature: null, nonce: null, approver: null };
      },
    };
    const piiDescriptor: ToolDescriptor = {
      name: "pii.tool",
      risk_tier: 3,
      reversible: false,
      side_effects: ["pii"],
      schema: { type: "object" }, // no properties -> no per-field spec
    };
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "pii.tool" }, action: "prompt" }],
        default: "deny",
      }),
      assistant: null,
      responder: capturingResponder as any,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    await gw.decide("pii.tool", { a: 1, b: "x" }, { descriptor: piiDescriptor });
    expect(observedArgs!.a).toBe("[REDACTED]");
    expect(observedArgs!.b).toBe("[REDACTED]");
  });
});

describe("A11 delegation-aware", () => {
  it("depth 0-1: base passthrough", async () => {
    const base = new RulePolicyAssistant(
      Policy.fromSpec({
        rules: [{ match: { tool: "fs.read*" }, action: "allow" }],
        default: "deny",
      })
    );
    const a11 = new DelegationAwareAssistant({ base });
    const out = await Promise.resolve(a11.decide(
      { tool: "fs.read_x", args: {}, context: ctx(), descriptor: fsReadDescriptor, request_id: null },
      { ...ctx(), delegation_chain: ["alice"] }
    ));
    expect(out.decision).toBe("allow_once");
  });

  it("depth >= 4: forced DENY (deep-chain guard)", async () => {
    const base = new RulePolicyAssistant(
      Policy.fromSpec({ rules: [{ match: { tool: "fs.read*" }, action: "allow" }], default: "deny" })
    );
    const a11 = new DelegationAwareAssistant({ base });
    const out = await Promise.resolve(a11.decide(
      { tool: "fs.read_x", args: {}, context: ctx(), descriptor: fsReadDescriptor, request_id: null },
      { ...ctx(), delegation_chain: ["a", "b", "c", "d"] } // depth 4
    ));
    expect(out.decision).toBe("deny");
  });

  it("depth 2: base DENY preserved", async () => {
    const base = new RulePolicyAssistant(
      Policy.fromSpec({ rules: [{ match: { tool: "shell.*" }, action: "deny" }], default: "deny" })
    );
    const a11 = new DelegationAwareAssistant({ base });
    const out = await Promise.resolve(a11.decide(
      { tool: "shell.exec", args: {}, context: ctx(), descriptor: null, request_id: null },
      { ...ctx(), delegation_chain: ["a", "b"] } // depth 2
    ));
    // A11 escalates above-base to PROMPT, but a base DENY is preserved.
    expect(out.decision).toBe("deny");
  });

  it("DEFAULT_DEPTH_THRESHOLDS table matches the specification", () => {
    expect(DEFAULT_DEPTH_THRESHOLDS).toEqual([
      { min_depth: 0, decision: "passthrough" },
      { min_depth: 2, decision: "prompt" },
      { min_depth: 3, decision: "prompt" },
      { min_depth: 4, decision: "deny" },
    ]);
  });
});

describe("Gateway.wrap (SDK, FR-9.31)", () => {
  it("wraps a plain function; `deny` raises PermissionDenied", async () => {
    let underlying = 0;
    function readX(path: string): number { underlying = path.length; return underlying; }

    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.read*" }, action: "allow" }],
        default: "deny",
      }),
      assistant: null,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const wrapped = gw.wrap(readX, { tool: "fs.read_x" });
    expect(await wrapped("/etc/hosts")).toBe(10);
    expect(underlying).toBe(10);

    const denyGw = new Gateway({
      policy: Policy.fromSpec({ rules: [], default: "deny" }),
      assistant: null,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const denyWrapped = denyGw.wrap(readX, { tool: "shell.exec" });
    await expect(denyWrapped("rm -rf /")).rejects.toBeInstanceOf(PermissionDenied);
  });
});

describe("sidecarAssistant", () => {
  it("a sidecar `allow*` is dropped when local policy is `deny`", async () => {
    const { sidecarAssistant } = await import("../src/assistants/sidecar.ts");
    const transport = {
      async decide() {
        return {
          decision: "allow_once" as const,
          audit_event: null,
          server_latency_ms: 1,
          verdict_cache_ms: 0,
          verdict_signature: null,
          risk_score: 0.1,
          reasoning: "sidecar says allow",
        };
      },
    };
    const sidecar = sidecarAssistant({
      name: "risk-assessment",
      transport,
      callerId: "ts-agent",
    });
    // Local policy is DENY -> sidecar ALLOW* must be dropped by the gateway.
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "shell.*" }, action: "deny" }],
        default: "deny",
      }),
      assistant: sidecar,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    // EVEN WITH an ASSIST rule pointing at the sidecar, the policy floor
    // above it (DENY) short-circuits the pipeline at step 2.
    const { decision } = await gw.decide("shell.exec", { cmd: "ls" });
    expect(decision).toBe("deny");
  });

  it("transport failure -> safe `deny`", async () => {
    const { sidecarAssistant } = await import("../src/assistants/sidecar.ts");
    const transport = {
      async decide(): Promise<never> {
        throw new Error("network down");
      },
    };
    const sidecar = sidecarAssistant({
      name: "risk-assessment",
      transport,
      callerId: "ts-agent",
    });
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.write*" }, action: "assist:risk-assessment" }],
        default: "deny",
      }),
      assistant: sidecar,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("fs.write_log", {});
    expect(decision).toBe("deny");
    expect(audit.reasoning).toContain("sidecar transport error");
  });

  it("exfiltratesArgs = true (routes args over the network)", async () => {
    const { sidecarAssistant } = await import("../src/assistants/sidecar.ts");
    const transport = { async decide() { return {} as never; } };
    const sidecar = sidecarAssistant({
      name: "risk-assessment",
      transport,
      callerId: "ts-agent",
    });
    expect(sidecar.exfiltratesArgs).toBe(true);
  });

  // C2 regression (council 2026-07-22): when a verdictHmacKey is configured,
  // a missing/empty verdict_signature is treated as failed verification ->
  // `deny`. A network middleman that strips the field cannot make
  // verification silently pass.
  it("a stripped signature -> deny when a verdictHmacKey is configured (C2)", async () => {
    const { sidecarAssistant } = await import("../src/assistants/sidecar.ts");
    const transport = {
      async decide() {
        return {
          decision: "allow_once" as const,
          audit_event: { ts_unix_ms: 123 },
          server_latency_ms: 1,
          verdict_cache_ms: 0,
          verdict_signature: null, // stripped in transit
          risk_score: 0.1,
          reasoning: "sidecar says allow but unsigned",
        };
      },
    };
    const sidecar = sidecarAssistant({
      name: "risk-assessment",
      transport,
      callerId: "ts-agent",
      verdictHmacKey: new Uint8Array([1, 2, 3, 4]),
    });
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.*" }, action: "assist:risk-assessment" }],
        default: "deny",
      }),
      assistant: sidecar,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision, audit } = await gw.decide("fs.write_log", {});
    expect(decision).toBe("deny");
    expect(audit.reasoning).toContain("signature missing");
  });

  it("an empty signature -> deny when a verdictHmacKey is configured (C2)", async () => {
    const { sidecarAssistant } = await import("../src/assistants/sidecar.ts");
    const transport = {
      async decide() {
        return {
          decision: "allow" as const,
          audit_event: { ts_unix_ms: 0 },
          server_latency_ms: 0,
          verdict_cache_ms: 0,
          verdict_signature: new Uint8Array(0),
          risk_score: 0,
          reasoning: "unsigned allow",
        };
      },
    };
    const sidecar = sidecarAssistant({
      name: "risk-assessment",
      transport,
      callerId: "ts-agent",
      verdictHmacKey: new Uint8Array([9, 9, 9]),
    });
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.*" }, action: "assist:risk-assessment" }],
        default: "deny",
      }),
      assistant: sidecar,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("fs.read", {});
    expect(decision).toBe("deny");
  });

  it("a forged signature -> deny when a verdictHmacKey is configured (C2)", async () => {
    const { sidecarAssistant } = await import("../src/assistants/sidecar.ts");
    const key = new Uint8Array([42, 42, 42, 42]);
    const transport = {
      async decide() {
        return {
          decision: "allow_once" as const,
          audit_event: { ts_unix_ms: 7 },
          server_latency_ms: 0,
          verdict_cache_ms: 0,
          verdict_signature: new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0]), // wrong
          risk_score: 0.2,
          reasoning: "forged",
        };
      },
    };
    const sidecar = sidecarAssistant({
      name: "risk-assessment",
      transport,
      callerId: "ts-agent",
      verdictHmacKey: key,
    });
    const gw = new Gateway({
      policy: Policy.fromSpec({
        rules: [{ match: { tool: "fs.*" }, action: "assist:risk-assessment" }],
        default: "deny",
      }),
      assistant: sidecar,
      responder: null,
      auditSink: new NullAuditSink(),
      defaultContext: ctx(),
    });
    const { decision } = await gw.decide("fs.write_log", {});
    expect(decision).toBe("deny");
  });
});