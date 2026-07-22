// Fatigue layer Protocol — IR_CONTRACT . TS equivalent of the Python
// `FatigueLayer` Protocol. Per D17 the in-process TS surface implements
// only dedup/suppression; batching routes via the sidecar.

import type { Invocation } from "../schema.ts";
import type { Decision } from "../decision.ts";

export interface FatigueDecision {
  decision: Decision | "defer";
  reasoning: string;
  cacheable: boolean;
}

export interface FatigueLayer {
  lookup(inv: Invocation): FatigueDecision;
  afterPrompt(inv: Invocation, decision: Decision, ttlS: number | null): void;
  clear(): void;
}