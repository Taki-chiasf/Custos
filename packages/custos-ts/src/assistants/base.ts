// Assistant Protocol — IR_CONTRACT  (Assistant interface).

// Mirrors `custos.assistants.base.Assistant` (Python), adapted to TS:
// the assistant is sync (the TS `Gateway.decide` is async but the
// deterministic in-process subset of assistants is sync — A1/A2/A7/A11
// perform no I/O). LLM-backed assistants (A3/A4/A5/A6/A9/A10) are
// reached via `sidecarAssistant(transport)` (gRPC) and the
// sidecar-async bridge routes them through the transport's promise.

import type { Invocation, AssistantOutput, SubjectContext } from "../schema.ts";

// The `Assistant` interface's `decide` returns `AssistantOutput | Promise<AssistantOutput>`
// so that BOTH sync in-process assistants (A1/A2/A7/A11) AND async
// sidecar-routed assistants (`sidecarAssistant(transport)`) satisfy the
// same interface. The gateway `await`s the result uniformly.
export interface Assistant {
  readonly name: string;
  readonly exfiltratesArgs: boolean;
  decide(inv: Invocation, ctx: SubjectContext): AssistantOutput | Promise<AssistantOutput>;
}

// `AssistantAsync` is a marker alias for assistants whose `decide` returns
// a Promise (e.g. `sidecarAssistant`). It is structurally identical to
// `Assistant` (which already permits Promise returns) — kept as a named
// alias for documentation and type-narrowing in the gateway.
export interface AssistantAsync extends Assistant {}