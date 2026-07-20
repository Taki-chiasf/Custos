// Audit sinks —  . Sink Protocol + File / Stdout / Null.

// Mirrors `custos.audit` (Python). `FileAuditSink` appends JSONL; the
// default is NOT tamper-evident — documented. The `HashChainedAuditSink`
// + `audit verify` ship at  .

import { appendFileSync, writeFileSync } from "node:fs";
import type { AuditEvent } from "../schema.ts";

export interface AuditSink {
  readonly name: string;
  emit(event: AuditEvent): void;
}

export class NullAuditSink implements AuditSink {
  readonly name = "null";
  emit(_event: AuditEvent): void {
    // No-op.
  }
}

export class StdoutAuditSink implements AuditSink {
  readonly name = "stdout";
  emit(event: AuditEvent): void {
    process.stdout.write(JSON.stringify(auditEventToDict(event)) + "\n");
  }
}

export class FileAuditSink implements AuditSink {
  readonly name: string;
  private readonly path: string;

  constructor(path: string) {
    this.name = `file:${path}`;
    this.path = path;
    // Truncate-or-create; matches the v1.0rc1 Python impl default.
    try {
      appendFileSync(this.path, "");
    } catch {
      try { writeFileSync(this.path, ""); } catch { /* ignore */ }
    }
  }

  emit(event: AuditEvent): void {
    try {
      appendFileSync(this.path, JSON.stringify(auditEventToDict(event)) + "\n");
    } catch {
      // Silent drop — caller can overlay a StdoutSink for fail-loud.
    }
  }
}

// `AuditEvent.to_dict` (Python) — IR_CONTRACT . The `schema_version`
// field is OPTIONAL in v1.0rc1; TS emits `"1.0"` from day one per the
// contract (forward-field).
export function auditEventToDict(e: AuditEvent): Record<string, unknown> {
  return {
    ts_unix_ms: e.ts_unix_ms,
    invocation: invocationToDict(e.invocation),
    decision: e.decision,
    policy_match: e.policy_match,
    assistant: e.assistant,
    risk_score: e.risk_score,
    reasoning: e.reasoning,
    responder: e.responder,
    latency_ms: e.latency_ms,
    subject: subjectToDict(e.subject),
    approver: e.approver,
    quorum_state: e.quorum_state,
    schema_version: e.schema_version ?? "1.0",
  };
}

function subjectToDict(s: AuditEvent["subject"]): Record<string, unknown> {
  // Filter `extra` by AUDIT_SUBJECT_FIELDS (deep redaction).
  const allowlist = new Set(["user_id", "goal_id", "task_id"]);
  const extraF: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(s.extra)) {
    if (allowlist.has(k)) extraF[k] = v;
  }
  return {
    user_id: s.user_id,
    goal_id: s.goal_id,
    task_id: s.task_id,
    delegation_chain: [...s.delegation_chain],
    session_ttl: s.session_ttl,
    extra: extraF,
  };
}

function invocationToDict(inv: AuditEvent["invocation"]): Record<string, unknown> {
  return {
    tool: inv.tool,
    args: { ...inv.args }, // already redacted upstream (Invocation built with redacted args)
    request_id: inv.request_id,
    descriptor: inv.descriptor ? descriptorToDict(inv.descriptor) : null,
  };
}

function descriptorToDict(d: NonNullable<AuditEvent["invocation"]["descriptor"]>): Record<string, unknown> {
  return {
    name: d.name,
    risk_tier: d.risk_tier,
    reversible: d.reversible,
    side_effects: d.side_effects.slice().sort(),
  };
}