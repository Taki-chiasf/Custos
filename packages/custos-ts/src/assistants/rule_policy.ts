// A7 — `rule-policy`. Pure deterministic rules; no LLM. Fast path for
// low-risk read ops. Re-evaluates the invocation against an inner
// `Policy` (the "rule table") and returns the inner verdict.

// Per D17 the TS `@taqiy/custos-core` ships A7 in-process; LLM-backed
// assistants route via the sidecar.

import type { Assistant } from "./base.ts";
import type { AssistantOutput, Invocation, SubjectContext } from "../schema.ts";
import { Policy } from "../policy/engine.ts";

export class RulePolicyAssistant implements Assistant {
  readonly name = "rule-policy";
  readonly exfiltratesArgs = false;
  private readonly ruleTable: Policy;

  constructor(ruleTable: Policy) {
    this.ruleTable = ruleTable;
  }

  decide(inv: Invocation, _ctx: SubjectContext): AssistantOutput {
    const evalResult = this.ruleTable.evaluate(inv);
    switch (evalResult.outcome) {
      case "allow":
        return {
          decision: "allow_once",
          risk: 0,
          reasoning: "A7 rule-policy: inner rule-table allow",
          fatigue_hint: false,
          persist_rule: null,
        };
      case "deny":
        return {
          decision: "deny",
          risk: 1.0,
          reasoning: "A7 rule-policy: inner rule-table deny",
          fatigue_hint: false,
          persist_rule: null,
        };
      case "prompt":
        return {
          decision: "prompt",
          risk: 0.5,
          reasoning: "A7 rule-policy: inner rule-table prompt",
          fatigue_hint: false,
          persist_rule: null,
        };
      case "assist":
        // Inner rule-table `assist:<name>` would re-enter the assistant
        // pipeline; the gateway handles assistant chaining separately. A7
        // treats an inner ASSIST as a deny-then-prompt by default.
        return {
          decision: "prompt",
          risk: 0.5,
          reasoning: "A7 rule-policy: inner ASSIST reified as prompt",
          fatigue_hint: false,
          persist_rule: null,
        };
    }
  }
}