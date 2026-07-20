// Parity test: AuditEvent wire shape — IR_CONTRACT .

// Reads the Python-generated fixture (`wire.json`) and asserts the TS
// `auditEventToDict` produces a deep-equal object. The Python reference
// serializes via `AuditEvent.to_dict` (incl. `SubjectContext.to_dict`'s
// `AUDIT_SUBJECT_FIELDS` filter on `extra`); the TS port must match.

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { auditEventToDict } from "../../src/audit/sink.ts";
import type { AuditEvent, Invocation, SubjectContext, ToolDescriptor } from "../../src/schema.ts";
import { SIDE_EFFECT_VALUES } from "../../src/schema.ts";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixtures: Array<{ label: string; expected: Record<string, unknown> }> =
  JSON.parse(readFileSync(join(__dirname, "fixtures", "wire.json"), "utf8"));

function buildFixtureEvent(): AuditEvent {
  const ctx: SubjectContext = {
    user_id: "alice",
    goal_id: "task-42",
    task_id: null,
    delegation_chain: ["alice", "bob", "carol"],
    session_ttl: 3600,
    extra: { user_id: "alice", secret_label: "should_be_filtered" },
  };
  const descriptor: ToolDescriptor = {
    name: "fs.read",
    risk_tier: 2,
    reversible: false,
    side_effects: ["read"],
    schema: { type: "object", properties: { path: { type: "string" } } },
  };
  const inv: Invocation = {
    tool: "fs.read",
    args: { path: "/etc/hosts" },
    context: ctx,
    descriptor,
    request_id: "req_abc",
  };
  return {
    ts_unix_ms: 1721476800000,
    invocation: inv,
    decision: "allow_once",
    policy_match: "base:fs.read-only",
    assistant: "risk-assessment",
    risk_score: 0.21,
    reasoning: "low-risk read within goal scope",
    responder: null,
    latency_ms: 31,
    subject: ctx,
    approver: null,
    quorum_state: null,
  };
}

describe("parity / wire shape", () => {
  it("auditEventToDict matches Python AuditEvent.to_dict() byte-shape", () => {
    const fx = fixtures[0]!;
    const got = auditEventToDict(buildFixtureEvent());
    expect(got).toEqual(fx.expected);
  });

  it("SubjectContext.extra is filtered to AUDIT_SUBJECT_FIELDS", () => {
    const got = auditEventToDict(buildFixtureEvent()) as {
      subject: { extra: Record<string, unknown> };
    };
    expect(got.subject.extra).toEqual({ user_id: "alice" });
    expect("secret_label" in got.subject.extra).toBe(false);
  });

  it("side_effects serialized sorted lexicographically", () => {
    const evt = buildFixtureEvent();
    (evt.invocation.descriptor as ToolDescriptor).side_effects = ["write", "read", "network"] as
      typeof SIDE_EFFECT_VALUES[number][];
    const got = auditEventToDict(evt) as {
      invocation: { descriptor: { side_effects: string[] } };
    };
    expect(got.invocation.descriptor.side_effects).toEqual(["network", "read", "write"]);
  });

  it("schema_version defaults to '1.0' when absent", () => {
    const evt = buildFixtureEvent();
    // `schema_version` is optional on the input type; the audit sink MUST
    // default to '1.0' per IR_CONTRACT . Build a fresh event without
    // passing it explicitly (the buildFixtureEvent helper omits it).
    const got = auditEventToDict(evt) as { schema_version: string };
    expect(got.schema_version).toBe("1.0");
  });
});