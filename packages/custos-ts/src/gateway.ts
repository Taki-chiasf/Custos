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
import { MatchSpec } from "./policy/match.ts";
import type { Assistant, AssistantAsync } from "./assistants/base.ts";
import { AssistantRegistry } from "./assistants/registry.ts";
import type { ContextInspector } from "./inspectors/base.ts";
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
  type ContextSnapshot,
} from "./schema.ts";
import type { Decision } from "./decision.ts";
import { validateToolDescriptor } from "./schema.ts";
import { PermissionDenied } from "./exceptions.ts";
import { InMemoryFatigueLayer } from "./fatigue/dedup.ts";
import { NullAuditSink } from "./audit/sink.ts";

export interface GatewayOptions {
  policy: Policy;
  assistant?: Assistant | AssistantAsync | null;
  assistants?: (Assistant | AssistantAsync)[];
  responder?: Responder | null;
  auditSink?: AuditSink;
  fatigue?: FatigueLayer;
  defaultContext?: SubjectContext;
  inspector?: ContextInspector | null;
  localOnly?: boolean;
}

export interface DecideOptions {
  context?: SubjectContext;
  descriptor?: ToolDescriptor | null;
  requestId?: string;
  snapshot?: ContextSnapshot | null;
}

export interface DecideResult {
  decision: Decision;
  audit: AuditEvent;
}

export class Gateway {
  policy: Policy;
  readonly assistantRegistry: AssistantRegistry;
  readonly responder: Responder | null;
  readonly auditSink: AuditSink;
  readonly fatigue: FatigueLayer;
  readonly inspector: ContextInspector | null;
  private defaultContext: SubjectContext | null;

  constructor(opts: GatewayOptions) {
    this.policy = opts.policy;
    this.responder = opts.responder ?? null;
    this.auditSink = opts.auditSink ?? new NullAuditSink();
    this.fatigue = opts.fatigue ?? new InMemoryFatigueLayer();
    this.defaultContext = opts.defaultContext ?? null;
    this.inspector = opts.inspector ?? null;

    const registry = new AssistantRegistry(undefined, opts.localOnly ?? false);
    if (opts.assistants) {
      for (const a of opts.assistants) registry.register(a);
    }
    if (opts.assistant) {
      registry.register(opts.assistant);
    }
    this.assistantRegistry = registry;
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
    const snapshot = options.snapshot ?? null;

    const tStart = Date.now();
    let finalDecision: Decision = "deny";
    let policyMatch: string | null = null;
    let assistantName: string | null = null;
    let inspectorName: string | null = null;
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
      let effectiveOutcome = evalResult.outcome;

      //  floor/ceiling: policy DENY/ALLOW short-circuit BEFORE the
      // fatigue cache so a freshly-tightened policy is never shadowed by a
      // stale cached `allow` (; arch #1 regression, council
      // 2026-07-22). Mirrors the Python gateway's policy-first ordering.
      if (effectiveOutcome === "deny") {
        finalDecision = "deny";
        reasoning = "policy deny (floor)";
        return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState, inspectorName);
      }
      if (effectiveOutcome === "allow") {
        finalDecision = "allow";
        reasoning = "policy allow";
        return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState, inspectorName);
      }

      // Seam A: fatigue dedup lookup. Per  only user-resolved
      // decisions are cached; the TS surface ships only dedup (no
      // rate-limit), so any cached decision here is user-resolved.
      const fatigueHit = this.fatigue.lookup(inv);
      if (fatigueHit.decision !== "defer" && fatigueHit.cacheable) {
        finalDecision = fatigueHit.decision;
        reasoning = fatigueHit.reasoning;
        return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState, inspectorName);
      }

      // Step 3a: INSPECT — context inspector (A12).
      if (evalResult.outcome === "inspect") {
        const nameSuffix = matchedRule?.inspectorName ?? null;
        //  named-inspector routing: the configured inspector must match
        // the named action suffix. Unresolved -> safe deny.
        if (!this.inspector) {
          finalDecision = "deny";
          reasoning = nameSuffix
            ? `inspect:${nameSuffix} routed but no inspector configured (safe deny)`
            : "inspect action but no inspector configured (safe deny)";
        } else if (nameSuffix && this.inspector.name !== nameSuffix) {
          finalDecision = "deny";
          reasoning = `inspect:${nameSuffix} routed but configured inspector is ${this.inspector.name} (safe deny)`;
        } else if (!snapshot) {
          finalDecision = "deny";
          reasoning = "inspect requested but no ContextSnapshot provided";
        } else {
          inspectorName = this.inspector.name;
          try {
            const inspResult = await this.inspector.inspect(inv, ctx, snapshot);
            riskScore = inspResult.confidence;
            reasoning = inspResult.reasoning || "inspector: no reasoning";
            if (inspResult.verdict === "safe") {
              effectiveOutcome = "assist";
            } else if (inspResult.verdict === "suspicious") {
              finalDecision = "prompt";
            } else {
              finalDecision = "quarantine";
            }
          } catch (err) {
            finalDecision = "deny";
            reasoning = `inspector error: ${(err as Error).message}`;
          }
        }
      }

      switch (effectiveOutcome) {
        case "prompt":
          finalDecision = "prompt";
          reasoning = "policy prompt";
          break;
        case "inspect":
          // INSPECT already handled above; if verdict was SAFE,
          // effectiveOutcome was changed to "assist".
          break;
        case "assist": {
          //  named-assistant routing via registry.
          const nameSuffix = matchedRule?.assistantName ?? null;
          const resolved = nameSuffix
            ? this.assistantRegistry.get(nameSuffix)
            : this.assistantRegistry.default;

          if (!resolved) {
            finalDecision = "deny";
            reasoning = nameSuffix
              ? `assist:${nameSuffix} routed but no matching assistant (safe deny)`
              : "assist action but no assistant configured (safe deny)";
            break;
          }

          assistantName = resolved.name;
          let assistantOut: AssistantOutput;
          try {
            const out = await resolved.decide(inv, ctx);
            assistantOut = out;
          } catch (err) {
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
            if (assistantOut.decision === "allow_and_persist") {
              finalDecision = "allow_once";
            } else {
              finalDecision = assistantOut.decision;
            }
            // H3 narrowness: an assistant `allow_and_persist` inserts a
            // rule BEFORE the matched rule. A broad poisoned rule is
            // rejected at insert time.
            if (
              assistantOut.decision === "allow_and_persist" &&
              assistantOut.persist_rule &&
              matchedRule
            ) {
              try {
                const newRule = buildPersistedRule(assistantOut.persist_rule, this.policy, matchedRule);
                if (newRule) {
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
              quorumState = "failed";
            } else if (resp.choice === "deny") {
              finalDecision = "deny";
              if (matchedRule?.quorum) quorumState = "failed";
            } else if (resp.choice === "allow" || resp.choice === "allow_once") {
              finalDecision = resp.choice;
              if (matchedRule?.quorum) quorumState = "met";
            }
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
      finalDecision = "deny";
      reasoning = `pipeline error: ${(err as Error).message}`;
    }

    return this.finalize(inv, finalDecision, tStart, policyMatch, assistantName, riskScore, reasoning, responderName, approver, quorumState, inspectorName);
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
    inspectorName: string | null,
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
      inspector: inspectorName,
    };
    try {
      this.auditSink.emit(event);
    } catch {
      process.stderr.write("[custos] audit sink failure\n");
    }
    return { decision, audit: event };
  }

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
      if (decision === "deny" || decision === "defer" || decision === "quarantine") {
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

// H3 narrowness check — full validation matching Python
// `_persist_assistant_rule_impl`. Rejects: `any:true`, broad `*` tool
// globs, bare `allow`/`allow_and_audit` actions without narrowing
// criteria, `matches` (regex) arg predicates, and rules that would
// shadow a later `deny*` rule.
function isNarrowerAndSafe(
  persistMatch: Record<string, unknown>,
  persistAction: string,
  policy: Policy,
  matchedIndex: number,
): boolean {
  // Reject any:true.
  if (persistMatch.any === true || persistMatch.any === "true") return false;

  // Reject broad tool glob "*".
  const tool = persistMatch.tool;
  if (typeof tool === "string" && tool === "*") return false;

  // Reject bare allow/allow_and_audit without narrowing criteria.
  if (persistAction === "allow" || persistAction === "allow_and_audit") {
    const hasNarrowing = typeof tool === "string" && tool !== "*" && tool !== "";
    const hasArgs = persistMatch.args && typeof persistMatch.args === "object";
    const hasRiskTier = persistMatch.risk_tier !== undefined;
    const hasSideEffects = persistMatch.side_effects !== undefined;
    const hasGoalId = persistMatch.goal_id !== undefined;
    const hasDepth = persistMatch.delegation_depth !== undefined;
    if (!hasNarrowing && !hasArgs && !hasRiskTier && !hasSideEffects && !hasGoalId && !hasDepth) {
      return false;
    }
  }

  // Reject `matches` (regex) operators in arg predicates.
  const args = persistMatch.args;
  if (args && typeof args === "object") {
    for (const argVal of Object.values(args as Record<string, unknown>)) {
      if (argVal && typeof argVal === "object" && "matches" in (argVal as Record<string, unknown>)) {
        return false;
      }
    }
  }

  // Reject rules that would shadow a later deny* rule.
  const rules = policy.rules as readonly Rule[];
  if (matchedIndex >= 0 && matchedIndex < rules.length - 1) {
    for (let i = matchedIndex + 1; i < rules.length; i++) {
      const laterRule = rules[i];
      if (laterRule.action.startsWith("deny")) {
        const laterTool = laterRule.match.tool_glob;
        if (laterTool === null || laterTool === "*") return false;
        if (typeof tool === "string") {
          const { fnmatchCase } = require("./fnmatch.ts") as typeof import("./fnmatch.ts");
          if (fnmatchCase(tool, laterTool) || fnmatchCase(laterTool, tool)) return false;
        }
      }
    }
  }

  return true;
}

function buildPersistedRule(
  rule: { match: Record<string, unknown>; action: string },
  policy: Policy,
  matchedRule: Rule,
): Rule | null {
  const match = MatchSpec.fromMapping(rule.match);
  const allowed: PolicyAction[] = [
    "allow", "deny", "prompt", "assist", "inspect", "allow_and_audit", "deny_and_alert",
  ];
  if (!allowed.includes(rule.action as PolicyAction)) {
    throw new Error(`persist_rule.action must be one of ${allowed.join(", ")}, got ${JSON.stringify(rule.action)}`);
  }
  const matchedIndex = (policy.rules as readonly Rule[]).indexOf(matchedRule);
  if (!isNarrowerAndSafe(rule.match, rule.action, policy, matchedIndex)) return null;
  const spec: PolicyRuleSpec = {
    match,
    action: rule.action as PolicyAction,
    assistant_name: null,
    inspector_name: null,
    batching: null,
    quorum: null,
    approver_roles: [],
    approver_allowlist: [],
  };
  return new Rule(spec);
}

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

  // Direct properties.
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

  // patternProperties — wildcard property schemas.
  const patternProps = schema.patternProperties;
  if (patternProps && typeof patternProps === "object" && !Array.isArray(patternProps)) {
    for (const [key, val] of Object.entries(args)) {
      for (const [pat, patSchema] of Object.entries(patternProps as Record<string, unknown>)) {
        if (!patSchema || typeof patSchema !== "object") continue;
        try {
          if (new RegExp(pat).test(key) && typeof val === "object" && val !== null && !Array.isArray(val)) {
            redactWalk(val as Record<string, unknown>, patSchema as Record<string, unknown>, depth + 1, maxDepth);
          }
        } catch {
          // invalid regex — skip
        }
      }
    }
  }

  // additionalProperties — catch-all property schema.
  const addl = schema.additionalProperties;
  if (addl && typeof addl === "object" && !Array.isArray(addl)) {
    const processed = new Set(props ? Object.keys(props as Record<string, unknown>) : []);
    for (const [key, val] of Object.entries(args)) {
      if (processed.has(key)) continue;
      if (typeof val === "object" && val !== null && !Array.isArray(val)) {
        redactWalk(val as Record<string, unknown>, addl as Record<string, unknown>, depth + 1, maxDepth);
      }
    }
  }

  // Composite schemas: allOf / anyOf / oneOf.
  for (const compKey of ["allOf", "anyOf", "oneOf"] as const) {
    const comp = schema[compKey];
    if (Array.isArray(comp)) {
      for (const subSchema of comp) {
        if (subSchema && typeof subSchema === "object" && !Array.isArray(subSchema)) {
          redactWalk(args, subSchema as Record<string, unknown>, depth + 1, maxDepth);
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

export { createHash };

function randomNonce(): string {
  return randomBytes(16).toString("hex");
}
