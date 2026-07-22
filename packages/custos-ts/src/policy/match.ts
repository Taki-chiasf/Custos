// MatchSpec — pure match predicate for policy rules .

// Mirrors `custos.policy.match.MatchSpec` (Python). Compiles a match
// mapping  into a frozen, dependency-free predicate over
// `Invocation`. Same `invocation` + `context` + `policy_version` MUST
// yield the same result  — this module performs no I/O, no
// time-dependent reads, and no randomness.

// Match criteria (all AND-ed; an absent criterion matches everything):
//   tool              - glob matched against `inv.tool` via `fnmatchCase`.
//   risk_tier         - number (exact) or `[min, max]` (inclusive range).
//   side_effects      - array; rule matches if the tool's side_effects
//                       intersect the rule's set (any-of semantics).
//   args              - object of arg-name -> predicate. A bare scalar
//                       means `==`; a `{operator: value}` object applies
//                       one of the 11 operators .
//   goal_id           - exact match against `ctx.goal_id`.
//   delegation_depth  - exact match against `ctx.delegation_depth`.
//   any               - `true` matches everything (wildcard).

// Re-implemented (NOT copied) from the ABAC semantics documented in
// `Janus/architecture.md` and the observable behavior of
// `Janus/src/permissions/policy_engine.py`. Production Custos uses the
//  match shape, not Janus's `{attribute, operator, value}` triple.

import { fnmatchCase } from "../fnmatch.ts";
import { applyOperator, OPERATOR_KEYS } from "./operators.ts";
import { PolicyValidationError } from "../exceptions.ts";
import type { Invocation, SideEffect } from "../schema.ts";
import { SIDE_EFFECT_VALUES } from "../schema.ts";

export const ARG_OPERATORS: ReadonlySet<string> = new Set(OPERATOR_KEYS);

export interface MatchSpecInit {
  tool_glob: string | null;
  risk_tier_min: number | null;
  risk_tier_max: number | null;
  side_effects: ReadonlySet<SideEffect>;
  args: ReadonlyMap<string, ArgPred>;
  goal_id: string | null;
  delegation_depth: number | null;
  any: boolean;
}

export interface ArgPred {
  op: string;
  value: unknown;
}

export class MatchSpec {
  readonly tool_glob: string | null;
  readonly risk_tier_min: number | null;
  readonly risk_tier_max: number | null;
  readonly side_effects: ReadonlySet<SideEffect>;
  readonly args: ReadonlyMap<string, ArgPred>;
  readonly goal_id: string | null;
  readonly delegation_depth: number | null;
  readonly any: boolean;

  private constructor(init: MatchSpecInit) {
    this.tool_glob = init.tool_glob;
    this.risk_tier_min = init.risk_tier_min;
    this.risk_tier_max = init.risk_tier_max;
    this.side_effects = init.side_effects;
    this.args = init.args;
    this.goal_id = init.goal_id;
    this.delegation_depth = init.delegation_depth;
    this.any = init.any;
  }

  static fromMapping(match: Record<string, unknown>): MatchSpec {
    if ("any" in match) {
      if (match.any === true) return new MatchSpec({
        tool_glob: null, risk_tier_min: null, risk_tier_max: null,
        side_effects: new Set(), args: new Map(),
        goal_id: null, delegation_depth: null, any: true,
      });
      if (typeof match.any !== "boolean") {
        throw new PolicyValidationError(
          `match.any must be a bool, got ${typeof match.any}`
        );
      }
    }

    const toolGlob = match.tool ?? null;
    if (toolGlob !== null && typeof toolGlob !== "string") {
      throw new PolicyValidationError("match.tool must be a string glob");
    }

    let riskMin: number | null = null;
    let riskMax: number | null = null;
    if ("risk_tier" in match) {
      const rt = match.risk_tier;
      if (typeof rt === "number" && Number.isInteger(rt)) {
        riskMin = riskMax = rt;
      } else if (Array.isArray(rt) && rt.length === 2) {
        riskMin = rt[0] as number;
        riskMax = rt[1] as number;
      } else {
        throw new PolicyValidationError(
          `match.risk_tier must be int or [min, max], got ${JSON.stringify(rt)}`
        );
      }
    }

    let sideEffects = new Set<SideEffect>();
    if ("side_effects" in match) {
      const raw = match.side_effects;
      if (!Array.isArray(raw)) {
        throw new PolicyValidationError("match.side_effects must be an array");
      }
      sideEffects = new Set(
        raw.map((s) => {
          if (typeof s !== "string" || !SIDE_EFFECT_VALUES.includes(s as SideEffect)) {
            throw new PolicyValidationError(`unknown side_effect: ${JSON.stringify(s)}`);
          }
          return s as SideEffect;
        })
      );
    }

    const args = new Map<string, ArgPred>();
    if ("args" in match) {
      const rawArgs = match.args;
      if (rawArgs === null || typeof rawArgs !== "object" || Array.isArray(rawArgs)) {
        throw new PolicyValidationError("match.args must be a mapping");
      }
      for (const [name, pred] of Object.entries(rawArgs as Record<string, unknown>)) {
        args.set(name, compileArgPredicate(pred));
      }
    }

    const goalId = match.goal_id ?? null;
    if (goalId !== null && typeof goalId !== "string") {
      throw new PolicyValidationError("match.goal_id must be a string");
    }

    let delegationDepth = match.delegation_depth ?? null;
    if (delegationDepth !== null) {
      if (typeof delegationDepth !== "number" || !Number.isInteger(delegationDepth) || delegationDepth < 0) {
        throw new PolicyValidationError(
          `delegation_depth must be a non-negative int, got ${JSON.stringify(delegationDepth)}`
        );
      }
    }

    return new MatchSpec({
      tool_glob: toolGlob,
      risk_tier_min: riskMin,
      risk_tier_max: riskMax,
      side_effects: sideEffects,
      args,
      goal_id: goalId,
      delegation_depth: delegationDepth,
      any: false,
    });
  }

  matches(inv: Invocation): boolean {
    if (this.any) return true;

    if (this.tool_glob !== null && !fnmatchCase(inv.tool, this.tool_glob)) {
      return false;
    }

    if (this.risk_tier_min !== null || this.risk_tier_max !== null) {
      const tier = inv.descriptor?.risk_tier ?? 0;
      if (this.risk_tier_min !== null && tier < this.risk_tier_min) return false;
      if (this.risk_tier_max !== null && tier > this.risk_tier_max) return false;
    }

    if (this.side_effects.size > 0) {
      if (!inv.descriptor) return false;
      const invSe = new Set(inv.descriptor.side_effects);
      let intersect = false;
      for (const se of this.side_effects) {
        if (invSe.has(se)) { intersect = true; break; }
      }
      if (!intersect) return false;
    }

    if (this.args.size > 0) {
      for (const [name, pred] of this.args) {
        if (!(name in inv.args)) return false;
        if (!applyOperator(pred.op, inv.args[name], pred.value)) return false;
      }
    }

    if (this.goal_id !== null && inv.context.goal_id !== this.goal_id) {
      return false;
    }

    if (this.delegation_depth !== null) {
      const depth = inv.context.delegation_chain.length;
      if (depth !== this.delegation_depth) return false;
    }

    return true;
  }
}

function compileArgPredicate(pred: unknown): ArgPred {
  if (pred !== null && typeof pred === "object" && !Array.isArray(pred)) {
    const entries = Object.entries(pred as Record<string, unknown>);
    if (entries.length !== 1) {
      throw new PolicyValidationError(
        `arg predicate must be a single-operator dict, got ${JSON.stringify(pred)}`
      );
    }
    const [op, value] = entries[0];
    if (!ARG_OPERATORS.has(op)) {
      throw new PolicyValidationError(
        `unknown arg operator ${JSON.stringify(op)}; allowed: ${[...ARG_OPERATORS].sort()}`
      );
    }
    return { op, value };
  }
  // Bare scalar -> equality.
  return { op: "==", value: pred };
}