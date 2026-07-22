// Policy engine — IR_CONTRACT  ; ..9.7.

// Mirrors `custos.policy.engine.Policy` (Python). First-match-wins,
// deterministic, dep-free . `default` = "deny"|"allow". Hot-reload
// is delegated to the host (`Policy.fromSpec` constructs the immutable
// object; the host re-creates it from a fresh file read).

// Allow-actions: `allow`, `deny`, `prompt`, `assist:<name>`,
// `allow_and_audit`, `deny_and_alert`. `assist:<name>` collapses to
// `ASSIST` and the named assistant is routed by the gateway.
// `default_deny` semantics if no rule matches (configurable to
// `default_allow` for dev mode —).

// `allow_and_persist` rules (assistant-created) MUST be structurally
// narrower than the rule they escalate from (H3). The gateway validates
// this at insert time; the engine exposes `insertRule` for the gateway
// to call when an assistant emits `allow_and_persist`.

import { MatchSpec } from "./match.ts";
import { PolicyValidationError } from "../exceptions.ts";
import type { Invocation } from "../schema.ts";
import type { Decision } from "../decision.ts";

export type PolicyAction =
  | "allow"
  | "deny"
  | "prompt"
  | "assist"
  | "allow_and_audit"
  | "deny_and_alert";

const POLICY_DEFAULTS = ["deny", "allow"] as const;
export type PolicyDefault = (typeof POLICY_DEFAULTS)[number];

// Rule-level responder hints (— NOT MatchSpec predicates).
interface ResponderHints {
  quorum: number | null;
  approver_roles: string[];
  approver_allowlist: string[];
}

export interface PolicyRuleSpec {
  match: MatchSpec;
  action: PolicyAction;
  assistant_name: string | null; // present when action === "assist"
  batching: { window_ms: number; max_per_minute: number } | null;
  quorum: number | null;
  approver_roles: string[];
  approver_allowlist: string[];
}

export class Rule {
  readonly match: MatchSpec;
  readonly action: PolicyAction;
  readonly assistantName: string | null;
  readonly batching: { window_ms: number; max_per_minute: number } | null;
  readonly quorum: number | null;
  readonly approverRoles: string[];
  readonly approverAllowlist: string[];

  constructor(spec: PolicyRuleSpec) {
    this.match = spec.match;
    this.action = spec.action;
    this.assistantName = spec.assistant_name;
    this.batching = spec.batching;
    this.quorum = spec.quorum;
    this.approverRoles = spec.approver_roles;
    this.approverAllowlist = spec.approver_allowlist;
  }

  get id(): string {
    return this.match.tool_glob ?? "<any>";
  }
}

// Intermediate policy outcome — see decision.ts PolicyOutcome.
export interface PolicyEval {
  outcome: "allow" | "deny" | "prompt" | "assist";
  matched: Rule | null;
}

export class Policy {
  readonly rules: readonly Rule[];
  readonly default: PolicyDefault;
  readonly version: string;

  constructor(rules: Iterable<Rule>, options: { default?: PolicyDefault; version?: string } = {}) {
    this.rules = Object.freeze([...rules]);
    this.default = options.default ?? "deny";
    this.version = options.version ?? "1";
    Object.freeze(this);
  }

  evaluate(inv: Invocation): PolicyEval {
    for (const rule of this.rules) {
      if (rule.match.matches(inv)) {
        return { outcome: actionToOutcome(rule.action), matched: rule };
      }
    }
    return { outcome: this.default === "allow" ? "allow" : "deny", matched: null };
  }

  matchedRule(inv: Invocation): Rule | null {
    for (const rule of this.rules) {
      if (rule.match.matches(inv)) return rule;
    }
    return null;
  }

  // Insert a persisted (assistant-created) rule BEFORE the matched rule.
  // H3 narrowness is checked at the gateway before reaching here; this
  // method assumes the caller has validated narrowness.
  insertRuleBefore(matchedIndex: number, rule: Rule): Policy {
    const next = [...this.rules];
    next.splice(matchedIndex, 0, rule);
    return new Policy(next, { default: this.default, version: this.version });
  }

  static fromSpec(spec: PolicySpec): Policy {
    const rules = (spec.rules ?? []).map(parseRule);
    const def: PolicyDefault = spec.default === "allow" ? "allow" : (spec.default ?? "deny");
    if (spec.default !== undefined && !POLICY_DEFAULTS.includes(spec.default as PolicyDefault)) {
      throw new PolicyValidationError(
        `default must be "deny" or "allow", got ${JSON.stringify(spec.default)}`
      );
    }
    return new Policy(rules, { default: def, version: spec.version });
  }
}

export interface PolicySpec {
  version?: string;
  default?: PolicyDefault;
  rules?: RuleSpec[];
}

export interface RuleSpec {
  match: Record<string, unknown>;
  action: string;
  options?: Decision[];
  batching?: { window_ms: number; max_per_minute: number } | null;
  quorum?: number | null;
  approver_roles?: string[];
  approver_allowlist?: string[];
}

function parseRule(spec: RuleSpec): Rule {
  if (!spec.match || typeof spec.match !== "object" || Array.isArray(spec.match)) {
    throw new PolicyValidationError("rule.match must be a mapping");
  }
  const match = MatchSpec.fromMapping(spec.match as Record<string, unknown>);

  let action: PolicyAction;
  let assistantName: string | null = null;
  if (typeof spec.action !== "string") {
    throw new PolicyValidationError("rule.action must be a string");
  }
  if (spec.action.startsWith("assist:")) {
    action = "assist";
    assistantName = spec.action.slice("assist:".length);
    if (!assistantName) {
      throw new PolicyValidationError("assist action requires a name");
    }
  } else if (
    ["allow", "deny", "prompt", "allow_and_audit", "deny_and_alert"].includes(spec.action)
  ) {
    action = spec.action as PolicyAction;
  } else {
    throw new PolicyValidationError(`unknown action: ${JSON.stringify(spec.action)}`);
  }

  let batching: { window_ms: number; max_per_minute: number } | null = null;
  if (spec.batching !== undefined && spec.batching !== null) {
    const b = spec.batching;
    if (
      typeof b.window_ms !== "number" ||
      typeof b.max_per_minute !== "number" ||
      b.window_ms < 0 ||
      b.max_per_minute < 0
    ) {
      throw new PolicyValidationError("batching requires non-negative window_ms + max_per_minute");
    }
    batching = b;
  }

  let responderHints: ResponderHints = {
    quorum: null, approver_roles: [], approver_allowlist: [],
  };
  if (spec.quorum !== undefined && spec.quorum !== null) {
    if (typeof spec.quorum !== "number" || !Number.isInteger(spec.quorum) || spec.quorum < 1) {
      throw new PolicyValidationError("quorum must be a positive int");
    }
    responderHints.quorum = spec.quorum;
  }
  if (spec.approver_roles !== undefined) {
    if (!Array.isArray(spec.approver_roles) || spec.approver_roles.some((r) => typeof r !== "string")) {
      throw new PolicyValidationError("approver_roles must be a string array");
    }
    responderHints.approver_roles = spec.approver_roles;
  }
  if (spec.approver_allowlist !== undefined) {
    if (!Array.isArray(spec.approver_allowlist) || spec.approver_allowlist.some((r) => typeof r !== "string")) {
      throw new PolicyValidationError("approver_allowlist must be a string array");
    }
    responderHints.approver_allowlist = spec.approver_allowlist;
  }
  if (responderHints.quorum !== null && responderHints.quorum > 0) {
    if (responderHints.approver_roles.length < responderHints.quorum) {
      throw new PolicyValidationError("approver_roles length must be >= quorum");
    }
  }

  return new Rule({
    match, action, assistant_name: assistantName,
    batching, quorum: responderHints.quorum,
    approver_roles: responderHints.approver_roles,
    approver_allowlist: responderHints.approver_allowlist,
  });
}

function actionToOutcome(action: PolicyAction): "allow" | "deny" | "prompt" | "assist" {
  switch (action) {
    case "allow":
    case "allow_and_audit":
      return "allow";
    case "deny":
    case "deny_and_alert":
      return "deny";
    case "prompt":
      return "prompt";
    case "assist":
      return "assist";
  }
}