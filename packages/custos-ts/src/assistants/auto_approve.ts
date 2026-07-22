// A1 — `auto-approve`. Mirrors `custos.assistants.rule_policy`-adjacent
// baseline (Janus A1). Unconditionally approves every denied call. No
// LLM, no prompts, no policy synthesis. Baseline.

import type { Assistant } from "./base.ts";
import type { AssistantOutput, Invocation, SubjectContext } from "../schema.ts";

export class AutoApproveAssistant implements Assistant {
  readonly name = "auto-approve";
  readonly exfiltratesArgs = false;

  decide(_inv: Invocation, _ctx: SubjectContext): AssistantOutput {
    return {
      decision: "allow_once",
      risk: 0,
      reasoning: "A1 auto-approve: unconditional baseline allow",
      fatigue_hint: false,
      persist_rule: null,
    };
  }
}