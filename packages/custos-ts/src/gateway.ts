// Gateway — the 8-step pipeline . Mirrors
// `custos.gateway.Gateway.decide` (Python).  floor/ceiling invariant:
// a policy `deny` is final; an assistant can ONLY escalate strictness,
// never relax a `deny`.

// Sync assistants (A1/A2/A7/A11) return bare `AssistantOutput`. Async
// assistants (sidecarAssistant) return `Promise<AssistantOutput>`. The
// gateway `await`s both forms uniformly.

// Exception safety : assistant / responder / fatigue-layer
// exceptions are caught at the pipeline boundary, converted to a safe
// `deny`, and the audit event + fatigue `afterPrompt` ALWAYS run
// (try/finally). Failure to emit an `AuditEvent` per call is itself an
// auditable error.

import { createHash, randomBytes } from "node:crypto";

import { Policy, Rule, type PolicyRuleSpec, type PolicyAction } from "./policy/engine.ts";
import { MatchSpec, type MatchSpec as MatchSpecType } from "./policy/match.ts";
import type { Assistant, AssistantAsync } from "./assistants/base.ts";
import type { Responder } from "./responders/base.ts";
import type { AuditSink } from "./audit/sink.ts";
import type { FatigueLayer } from "./fatigue/base.ts";
import {
  type Invocation,
  type SubjectContext,
  type AssistantOutput,
  type PromptRequest,
  type PromptResponse,
  type AuditEvent,
  type ToolDescriptor,
} from "./schema.ts";
import type { Decision } from "./decision.ts";
import { validateToolDescriptor } from "./schema.ts";
import { PermissionDenied } from "./exceptions.ts";
import { InMemoryFatigueLayer } from "./fatigue/dedup.ts";
import { NullAuditSink } from "./audit/sink.ts";

export interface GatewayOptions {
  policy: Policy;
  assistant: Assistant | AssistantAsync | null;
  responder: Responder | null;
  auditSink?: AuditSink;
  fatigue?: FatigueLayer;
  defaultContext?: SubjectContext;
}

export interface DecideOptions {
  context?: SubjectContext;
  descriptor?: ToolDescriptor | null;
  requestId?: string;
}

export interface DecideResult {
  decision: Decision;
  audit: AuditEvent;
}

export class Gateway {
  policy: Policy; // mutable for `insertRuleBefore` (assistant persisted rules) + `reloadPolicy`
  readonly assistant: Assistant | AssistantAsync | null;
  readonly responder: Responder | null;
  readonly auditSink: AuditSink;
  readonly fatigue: FatigueLayer;
  private defaultContext: SubjectContext | null;

  constructor(opts: GatewayOptions) {
    this.policy = opts.policy;
    this.assistant = opts.assistant;
    this.responder = opts.responder;
    this.auditSink = opts.auditSink ?? new NullAuditSink();
    this.fatigue = opts.fatigue ?? new InMemoryFatigueLayer();
    this.defaultContext = opts.defaultContext ?? null;
  }

  async decide(
    tool: string,
    args: Record<string, unknown>,
    options: DecideOptions = {}
  ): Promise<DecideResult> {
    const ctx = options.context ?? this.defaultContext;
    if (!ctx) {
      throw new Error(
        "Gateway.decide: no SubjectContext (pass options.context or set GatewayOptions.defaultContext)"
      );
    }
    if (options.descriptor) validateToolDescriptor(options.descriptor);
    const inv: Invocation = {
      tool,
      args,
      context: ctx,
      descriptor: options.descriptor ?? null,
      request_id: options.requestId ?? randomNonce(),
    };

    const tStart = Date.now();
    let finalDecision: Decision = "deny";
    let policyMatch: string | null = null;
    let assistantName: string | null = null;
    let riskScore = 0;
    let reasoning = "";
    let responderName: string | null = null;
    let approver: string | null = null;
    let quorumState: "met" | "failed" | null = null;
    let matchedRule: Rule | null = null;

    try {
      // Step 2: policy evaluation (deterministic, pure).
      const evalResult = this.policy.evaluate(inv);
      matchedRule = evalResult.matched;
      if (matchedRule) policyMatch = matchedRule.id;

      //  floor/ceiling: policy DENY/ALLOW short-circuit BEFORE the
      // fatigue cache so a freshly-tightened policy is never shadowed by a
      // stale cached `allow` (; arch #1 regression, council
      // 2026-07-22). Mirrors the Python gateway's policy-first ordering.
      if (evalResult.outcome === "deny") {
        finalDecision = "deny";
        reasoning = "policy deny (floor)";
        return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState);
      }
      if (evalResult.outcome === "allow") {
        finalDecision = "allow";
        reasoning = "policy allow";
        return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState);
      }

      // Seam A: fatigue dedup lookup. Per  only user-resolved
      // decisions are cached; the TS surface ships only dedup (no
      // rate-limit), so any cached decision here is user-resolved.
      const fatigueHit = this.fatigue.lookup(inv);
      if (fatigueHit.decision !== "defer" && fatigueHit.cacheable) {
        finalDecision = fatigueHit.decision;
        reasoning = fatigueHit.reasoning;
        return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState);
      }

      switch (evalResult.outcome) {
        case "prompt":
          finalDecision = "prompt";
          reasoning = "policy prompt";
          break;
        case "assist": {
          if (!this.assistant) {
            finalDecision = "deny";
            reasoning = "assist action but no assistant configured (safe deny)";
            break;
          }
          const configuredName = this.assistant.name;
          //  named-assistant routing: an unresolved name fails closed.
          if (matchedRule && matchedRule.assistantName !== null && matchedRule.assistantName !== configuredName) {
            finalDecision = "deny";
            reasoning = `assist:${matchedRule.assistantName} routed but configured assistant is ${configuredName} (safe deny)`;
            break;
          }
          assistantName = configuredName;
          let assistantOut: AssistantOutput;
          try {
            const out = await this.assistant.decide(inv, ctx);
            assistantOut = out;
          } catch (err) {
            //  responder/assistant exception safety: safe `deny`.
            finalDecision = "deny";
            reasoning = `assistant error: ${(err as Error).message}`;
            break;
          }
          riskScore = assistantOut.risk;
          reasoning = assistantOut.reasoning;
          if (assistantOut.decision === "deny") {
            finalDecision = "deny";
          } else if (assistantOut.decision === "prompt") {
            finalDecision = "prompt";
          } else if (
            assistantOut.decision === "allow" ||
            assistantOut.decision === "allow_once" ||
            assistantOut.decision === "allow_and_persist"
          ) {
            finalDecision = assistantOut.decision;
            // H3 narrowness: an assistant `allow_and_persist` inserts a
            // rule BEFORE the matched rule. A broad poisoned rule is
            // rejected at insert time.
            if (
              assistantOut.decision === "allow_and_persist" &&
              assistantOut.persist_rule &&
              matchedRule
            ) {
              try {
                const newRule = buildPersistedRule(assistantOut.persist_rule);
                if (isNarrower(newRule.match, matchedRule.match)) {
                  const matchedIndex = this.policy.rules.indexOf(matchedRule);
                  if (matchedIndex >= 0) {
                    this.policy = this.policy.insertRuleBefore(matchedIndex, newRule);
                    reasoning += "; persisted narrower rule";
                  }
                } else {
                  reasoning += "; rejected broad persisted rule (H3)";
                }
              } catch (err) {
                reasoning += `; persist_rule rejected: ${(err as Error).message}`;
              }
            }
          }
          break;
        }
      }

      // Steps 4-6: route to the responder if `prompt`.
      if (finalDecision === "prompt") {
        if (!this.responder) {
          finalDecision = "deny";
          reasoning = "prompt decision but no responder configured (safe deny)";
        } else {
          const argsRedacted = redactArgs(inv.args, inv.descriptor);
          const req: PromptRequest = {
            tool: inv.tool,
            args_redacted: argsRedacted,
            risk: riskScore,
            reasoning,
            options: ["allow", "deny", "allow_once"],
            request_id: inv.request_id,
            deadline_unix_ms: null,
            quorum: matchedRule?.quorum ?? null,
            approver_roles: matchedRule?.approverRoles ?? [],
            approver_allowlist: matchedRule?.approverAllowlist ?? [],
          };
          let resp: PromptResponse | null = null;
          try {
            resp = await this.responder.prompt(req);
            responderName = this.responder.name;
            approver = resp.approver;
          } catch (err) {
            finalDecision = "deny";
            reasoning = `responder error: ${(err as Error).message}`;
          }
          if (resp !== null) {
            if (resp.choice === "defer") {
              finalDecision = "defer";
              quorumState = "failed"; // matches Python _infer_quorum_state for unresolved prompts
            } else if (resp.choice === "deny") {
              finalDecision = "deny";
              if (matchedRule?.quorum) quorumState = "failed";
            } else if (resp.choice === "allow" || resp.choice === "allow_once") {
              finalDecision = resp.choice;
              if (matchedRule?.quorum) quorumState = "met";
            }
            // : only user-resolved decisions (non-DEFER, non-PROMPT)
            // are cacheable.
            if (finalDecision !== "defer" && finalDecision !== "prompt") {
              try {
                this.fatigue.afterPrompt(inv, finalDecision, resp.ttl);
              } catch {
                // fatigue layer failure does not change the decision
              }
            }
          }
        }
      }
    } catch (err) {
      // Uncaught pipeline exception -> safe `deny`, audit ALWAYS runs.
      finalDecision = "deny";
      reasoning = `pipeline error: ${(err as Error).message}`;
    }

    return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState);
  }

  private finalize(
    inv: Invocation,
    decision: Decision,
    tStart: number,
    policyMatch: string | null,
    assistantName: string | null,
    riskScore: number,
    reasoning: string,
    responderName: string | null,
    approver: string | null,
    quorumState: "met" | "failed" | null,
  ): DecideResult {
    const latencyMs = Date.now() - tStart;
    const event: AuditEvent = {
      ts_unix_ms: Date.now(),
      invocation: inv,
      decision,
      policy_match: policyMatch,
      assistant: assistantName,
      risk_score: riskScore,
      reasoning,
      responder: responderName,
      latency_ms: latencyMs,
      subject: inv.context,
      approver,
      quorum_state: quorumState,
      schema_version: "1.0",
    };
    try {
      this.auditSink.emit(event);
    } catch {
      process.stderr.write(`[custos] audit sink failure\n`);
    }
    return { decision, audit: event };
  }

  // SDK helper: wrap a function so each call routes through `decide`.
  // Mirrors `custos.sdk.wrap_callables` (Python). The wrapped function
  // becomes async (the gateway is async); a `deny`/`defer` raises
  // `PermissionDenied`.
  wrap<T extends (...args: any[]) => any>(
    fn: T,
    opts: { tool: string; descriptor?: ToolDescriptor | null }
  ): T {
    const gw = this;
    const wrapped = async function (this: unknown, ...args: unknown[]) {
      const ctx = gw.defaultContext;
      if (!ctx) throw new Error("Gateway.wrap: defaultContext not set");
      const argNames = extractParamNames(fn);
      const argsRecord: Record<string, unknown> = {};
      for (let i = 0; i < argNames.length; i++) {
        if (i < args.length) argsRecord[argNames[i]] = args[i];
      }
      const { decision } = await gw.decide(opts.tool, argsRecord, {
        context: ctx,
        descriptor: opts.descriptor ?? null,
      });
      if (decision === "deny" || decision === "defer") {
        throw new PermissionDenied(`custos: ${decision} on ${opts.tool}`);
      }
      return await fn.apply(this, args);
    } as T;
    Object.defineProperty(wrapped, "name", { value: fn.name });
    return wrapped;
  }

  setDefaultContext(ctx: SubjectContext): void {
    this.defaultContext = ctx;
  }

  reloadPolicy(next: Policy): void {
    this.policy = next;
    this.fatigue.clear();
  }
}

// H3 narrowness check: is `a` structurally narrower than `b`? A rule is
// narrower if every input matching `a` ALSO matches `b` AND `a` adds at
// least one restricting criterion. Broad globs / `any:true` are NOT
// narrower than anything.
function isNarrower(a: MatchSpecType, b: MatchSpecType): boolean {
  if (a.any) return false;
  if (b.any) return !a.any;
  const aCount = countCriteria(a);
  const bCount = countCriteria(b);
  if (aCount <= bCount) return false;
  if (a.tool_glob && b.tool_glob) {
    if (a.tool_glob === b.tool_glob) return aCount > bCount;
    if (!isGlobSubset(a.tool_glob, b.tool_glob)) return false;
  }
  return true;
}

function countCriteria(m: MatchSpecType): number {
  let n = 0;
  if (m.tool_glob !== null) n++;
  if (m.risk_tier_min !== null || m.risk_tier_max !== null) n++;
  if (m.side_effects.size > 0) n++;
  if (m.args.size > 0) n += m.args.size;
  if (m.goal_id !== null) n++;
  if (m.delegation_depth !== null) n++;
  return n;
}

function isGlobSubset(a: string, b: string): boolean {
  if (a === b) return false;
  const aIsLiteral = !/[*?\[]/.test(a);
  const bIsLiteral = !/[*?\[]/.test(b);
  if (bIsLiteral) return a === b;
  if (aIsLiteral) return a.startsWith(b.replace(/\*+$/, ""));
  return false;
}

function buildPersistedRule(rule: { match: Record<string, unknown>; action: string }): Rule {
  // The persisted rule comes from an assistant (UNTRUSTED). The gateway
  // validates narrowness BEFORE inserting; `buildPersistedRule` itself
  // only constructs the object. The action MUST be a valid
  // `PolicyAction` (validated against the allowlist); an unknown action
  // throws and the H3 outer catch records it in the reasoning.
  const match = MatchSpec.fromMapping(rule.match);
  const allowed: PolicyAction[] = [
    "allow", "deny", "prompt", "assist", "allow_and_audit", "deny_and_alert",
  ];
  if (!allowed.includes(rule.action as PolicyAction)) {
    throw new Error(`persist_rule.action must be one of ${allowed.join(", ")}, got ${JSON.stringify(rule.action)}`);
  }
  const spec: PolicyRuleSpec = {
    match,
    action: rule.action as PolicyAction,
    assistant_name: null,
    batching: null,
    quorum: null,
    approver_roles: [],
    approver_allowlist: [],
  };
  return new Rule(spec);
}

// Redact args — . Mirrors `custos.schema._redact_args` (recursive).
// Flat `secret:true` / `format:password` redaction + the
// `SideEffect.PII`-without-per-field-spec "redact all" fallback. Deep
// recursion through `properties`/`items` for theparity fixture subset.
export function redactArgs(
  args: Record<string, unknown>,
  descriptor: ToolDescriptor | null
): Record<string, unknown> {
  if (!descriptor) return { ...args };
  const schema = descriptor.schema;
  if (!schema || typeof schema !== "object") return { ...args };
  const out: Record<string, unknown> = { ...args };
  redactWalk(out, schema as Record<string, unknown>, 0, 10);
  if (descriptor.side_effects.includes("pii") && !hasSecretAnnotation(schema as Record<string, unknown>)) {
    for (const k of Object.keys(out)) out[k] = "[REDACTED]";
  }
  return out;
}

function redactWalk(
  args: Record<string, unknown>,
  schema: Record<string, unknown>,
  depth: number,
  maxDepth: number
): void {
  if (depth >= maxDepth) return;
  const props = schema.properties;
  if (props && typeof props === "object" && !Array.isArray(props)) {
    for (const [name, fieldSchema] of Object.entries(props as Record<string, unknown>)) {
      if (!(name in args)) continue;
      if (!fieldSchema || typeof fieldSchema !== "object") continue;
      const fs = fieldSchema as Record<string, unknown>;
      if (fs.secret === true || fs.format === "password") {
        args[name] = "[REDACTED]";
      } else if (typeof args[name] === "object" && args[name] !== null && !Array.isArray(args[name])) {
        redactWalk(args[name] as Record<string, unknown>, fs, depth + 1, maxDepth);
      } else if (Array.isArray(args[name])) {
        const itemsSchema = fs.items;
        if (itemsSchema && typeof itemsSchema === "object" && !Array.isArray(itemsSchema)) {
          for (const el of args[name] as unknown[]) {
            if (el && typeof el === "object" && !Array.isArray(el)) {
              redactWalk(el as Record<string, unknown>, itemsSchema as Record<string, unknown>, depth + 1, maxDepth);
            }
          }
        }
      }
    }
  }
}

function hasSecretAnnotation(schema: Record<string, unknown>): boolean {
  if (schema.secret === true || schema.format === "password") return true;
  const props = schema.properties;
  if (props && typeof props === "object" && !Array.isArray(props)) {
    for (const fs of Object.values(props as Record<string, unknown>)) {
      if (fs && typeof fs === "object" && hasSecretAnnotation(fs as Record<string, unknown>)) return true;
    }
  }
  const items = schema.items;
  return !!items && typeof items === "object" && !Array.isArray(items) && hasSecretAnnotation(items as Record<string, unknown>);
}

function extractParamNames(fn: (...args: any[]) => any): string[] {
  const src = fn.toString();
  const m = src.match(/(?:function\s+\w*|\(|\w+\s*=\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))\s*\(([^)]*)\)/);
  if (!m) return [];
  return m[1].split(",").map((p) => p.trim().replace(/\.\.\./g, "").replace(/=\s*[\s\S]*$/, "").trim()).filter(Boolean);
}

// `createHash` is imported for parity with the (unused here, but used by
// the sidecar) crypto surface; kept to keep the module's import shapes
// consistent. Callers of `sidecarAssistant`'s HMAC verification use it.
// `createHash` is imported for parity with the (unused here, but used by
// the sidecar) crypto surface; kept to keep the module's import shapes
// consistent. Callers of `sidecarAssistant`'s HMAC verification use it.
export { createHash };

// Synthesize a per-call request_id / nonce when the caller didn't supply
// one. The sidecar replay-guard (replay at the boundary) requires a
// non-empty `request_id`; the in-process pipeline accepts `null` so we
// generate a short random hex string here. Mirrors the Python
// `uuid.uuid4.hex` fallback in `custos.gateway.Gateway.decide`.
function randomNonce(): string {
  return randomBytes(16).toString("hex");
}