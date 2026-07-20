// A11 — `delegation-aware`. Pure-deterministic depth-tier table; NO LLM
// (mirrors `custos.assistants.delegation_aware.DelegationAwareAssistant`,
//). The depth-tier table overrides the base-passthrough
// verdict according to `ctx.delegation_chain.length`:
//   depth 0..1      -> base passthrough (composed RulePolicy or A7)
//   depth 2        -> escalate above-base calls to PROMPT (base DENY preserved)
//   depth >= 3     -> force PROMPT on any call
//   depth >= 4     -> force DENY (deep-chain exfiltration guard)

// The depth tier table is YAML-overrideable via `DepthThreshold.fromMapping`
// (host can construct a custom `DepthThreshold[]`).

import type { Assistant } from "./base.ts";
import type { AssistantOutput, Invocation, SubjectContext } from "../schema.ts";

export interface DepthThreshold {
  min_depth: number;
  decision: "passthrough" | "prompt" | "deny";
}

export const DEFAULT_DEPTH_THRESHOLDS: DepthThreshold[] = [
  { min_depth: 0, decision: "passthrough" },
  { min_depth: 2, decision: "prompt" },
  { min_depth: 3, decision: "prompt" },
  { min_depth: 4, decision: "deny" },
];

export function depthThresholdFromMapping(m: Record<string, unknown>): DepthThreshold {
  const min = m.min_depth;
  const decision = m.decision;
  if (typeof min !== "number" || !Number.isInteger(min) || min < 0) {
    throw new Error(`DepthThreshold.min_depth must be a non-negative int, got ${JSON.stringify(min)}`);
  }
  if (typeof decision !== "string" || !["passthrough", "prompt", "deny"].includes(decision)) {
    throw new Error(
      `DepthThreshold.decision must be "passthrough"|"prompt"|"deny", got ${JSON.stringify(decision)}`
    );
  }
  return { min_depth: min, decision: decision as DepthThreshold["decision"] };
}

export class DelegationAwareAssistant implements Assistant {
  readonly name = "delegation-aware";
  readonly exfiltratesArgs = false;
  private readonly thresholds: DepthThreshold[];
  private readonly base: Assistant;

  constructor(opts: { base: Assistant; thresholds?: DepthThreshold[] }) {
    this.base = opts.base;
    this.thresholds = (opts.thresholds ?? DEFAULT_DEPTH_THRESHOLDS).slice().sort(
      (a, b) => b.min_depth - a.min_depth
    );
  }

  decide(inv: Invocation, ctx: SubjectContext): AssistantOutput | Promise<AssistantOutput> {
    const depth = ctx.delegation_chain.length;
    const tier = this.thresholds.find((t) => depth >= t.min_depth) ?? this.thresholds[this.thresholds.length - 1];
    if (!tier || tier.decision === "passthrough") {
      return this.base.decide(inv, ctx);
    }
    if (tier.decision === "deny") {
      return {
        decision: "deny",
        risk: 1.0,
        reasoning: `A11 delegation-aware: depth ${depth} >= 4 (deep-chain guard)`,
        fatigue_hint: false,
        persist_rule: null,
      };
    }
    // tier.decision === "prompt".  floor: a base DENY is preserved.
    // The base `Assistant.decide` may be async; A11 awaits it via
    // Promise.resolve to handle both sync + async base uniformly.
    return Promise.resolve(this.base.decide(inv, ctx)).then((baseOut) => {
      if (baseOut.decision === "deny") return baseOut;
      return {
        decision: "prompt",
        risk: Math.max(baseOut.risk, 0.5),
        reasoning: `A11 delegation-aware: depth ${depth} escalates to prompt`,
        fatigue_hint: false,
        persist_rule: null,
      } satisfies AssistantOutput;
    });
  }
}