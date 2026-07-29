// Custos wire-shape types — IR_CONTRACT.md  .

// Mirrors `custos.schema` (Python): SideEffect, ToolDescriptor,
// SubjectContext, Invocation, AssistantOutput, PromptRequest,
// PromptResponse, AuditEvent. JSON shapes are the canonical wire form
// and MUST match the Python `to_dict` output byte-for-byte (parity
// test pins this).

import type { Decision } from "./decision.ts";

export const SIDE_EFFECT_VALUES = [
  "none",
  "read",
  "write",
  "network",
  "payment",
  "destructive",
  "pii",
] as const;

export type SideEffect = (typeof SIDE_EFFECT_VALUES)[number];

export function asSideEffect(s: string): SideEffect {
  if (!SIDE_EFFECT_VALUES.includes(s as SideEffect)) {
    throw new Error(`unknown side_effect: ${JSON.stringify(s)}`);
  }
  return s as SideEffect;
}

// IR_CONTRACT
export interface ToolDescriptor {
  name: string;
  risk_tier: number; // 1..5
  reversible: boolean;
  side_effects: SideEffect[]; // sorted lexicographically
  schema?: Record<string, unknown>; // JSON-schema dict; optional in the wire shape
}

export function validateToolDescriptor(d: ToolDescriptor): void {
  if (!Number.isInteger(d.risk_tier) || d.risk_tier < 1 || d.risk_tier > 5) {
    throw new RangeError(`risk_tier must be an int in 1..5, got ${d.risk_tier}`);
  }
}

// IR_CONTRACT
export const AUDIT_SUBJECT_FIELDS = new Set(["user_id", "goal_id", "task_id"]);

export interface SubjectContext {
  user_id: string;
  goal_id: string | null;
  task_id: string | null;
  delegation_chain: string[]; // shallowest first
  session_ttl: number | null;
  extra: Record<string, unknown>; // filtered to AUDIT_SUBJECT_FIELDS before audit
}

export function delegationDepth(ctx: SubjectContext): number {
  return ctx.delegation_chain.length;
}

// Apply the  deep-redaction `AUDIT_SUBJECT_FIELDS` allowlist before
// emitting the subject to the audit log.
export function subjectToAuditDict(ctx: SubjectContext): Record<string, unknown> {
  const extraFiltered: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(ctx.extra)) {
    if (AUDIT_SUBJECT_FIELDS.has(k)) extraFiltered[k] = v;
  }
  return {
    user_id: ctx.user_id,
    goal_id: ctx.goal_id,
    task_id: ctx.task_id,
    delegation_chain: [...ctx.delegation_chain],
    session_ttl: ctx.session_ttl,
    extra: extraFiltered,
  };
}

// IR_CONTRACT
export interface Invocation {
  tool: string;
  args: Record<string, unknown>;
  context: SubjectContext;
  descriptor: ToolDescriptor | null;
  request_id: string | null;
}

// IR_CONTRACT
export interface AuditEvent {
  ts_unix_ms: number;
  invocation: Invocation;
  decision: Decision;
  policy_match: string | null;
  assistant: string | null;
  risk_score: number;
  reasoning: string;
  responder: string | null;
  latency_ms: number;
  subject: SubjectContext;
  approver: string | null;
  quorum_state: "met" | "failed" | null;
  // Forward field : absent in v1.0rc1 Python impl,
  // "1.0" from day one on the TS side. Optional until .
  schema_version?: string;
  // A12 context inspector name  — emitted on `inspect:<name>` paths.
  inspector?: string | null;
}

// Assistant output  — produced by an assistant, consumed
// by the gateway. Treated as UNTRUSTED input .
export interface AssistantOutput {
  decision: Decision;
  risk: number; // 0.0..1.0
  reasoning: string;
  fatigue_hint: boolean;
  persist_rule: { match: Record<string, unknown>; action: string } | null;
}

// IR_CONTRACT
export interface PromptRequest {
  tool: string;
  args_redacted: Record<string, unknown>;
  risk: number;
  reasoning: string;
  options: Decision[];
  request_id: string | null;
  deadline_unix_ms: number | null;
  quorum: number | null;
  approver_roles: string[];
  approver_allowlist: string[];
}

export interface PromptResponse {
  choice: Decision;
  ttl: number | null;
  signature: Uint8Array | null; // HMAC bytes for webhook responses
  nonce: string | null;
  approver: string | null;
}

// A12 context inspector types  — mirrors `custos.schema` (Python).

export type InspectionVerdict = "safe" | "suspicious" | "injection";

export interface InputSource {
  source_id: string;
  source_type: string;
  content: string;
  metadata?: Record<string, unknown>;
}

export interface ContextSnapshot {
  ts_unix_ms: number;
  messages?: Record<string, unknown>[];
  sources?: InputSource[];
  system_prompt?: string | null;
}

export interface InjectionFinding {
  source: InputSource;
  confidence: number; // 0.0..1.0
  affected_indices?: number[];
  method?: string;
}

export interface InspectionResult {
  verdict: InspectionVerdict;
  findings?: InjectionFinding[];
  confidence: number; // 0.0..1.0
  masked_snapshot?: ContextSnapshot | null;
  reasoning: string;
}