// Context inspector Protocol — IR_CONTRACT  (A12).

// Mirrors `custos.inspectors.base.ContextInspector` (Python). An
// inspector analyses the agent's full context snapshot and returns an
// `InspectionResult`. Inspectors MAY be non-deterministic (e.g.
// LLM-backed); this is the only allowed source of non-determinism for
// the inspect step.

import type { Invocation, SubjectContext, ContextSnapshot, InspectionResult } from "../schema.ts";

export interface ContextInspector {
  readonly name: string;
  readonly exfiltratesArgs: boolean;
  inspect(
    inv: Invocation,
    ctx: SubjectContext,
    snapshot: ContextSnapshot
  ): InspectionResult | Promise<InspectionResult>;
}
