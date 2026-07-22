// A2 — `user-confirmation`. Prompts the user for every denied call.
// Max security, severe fatigue. No LLM. Baseline.

// In Custos semantics this assistant emits `prompt` (a Custos-only
// extension — Janus A2 maps to it via the contract's verdict mapping
// for the "escalate" leg, but Janus's `approve_once`/`reject` doesn't
// have a deterministic "always ask" output so we synthesize `prompt`).

import type { Assistant } from "./base.ts";
import type { AssistantOutput, Invocation, SubjectContext } from "../schema.ts";

export class UserConfirmationAssistant implements Assistant {
  readonly name = "user-confirmation";
  readonly exfiltratesArgs = false;

  decide(_inv: Invocation, _ctx: SubjectContext): AssistantOutput {
    return {
      decision: "prompt",
      risk: 0.5,
      reasoning: "A2 user-confirmation: always ask the user",
      fatigue_hint: false,
      persist_rule: null,
    };
  }
}