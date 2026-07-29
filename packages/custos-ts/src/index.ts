// Custos TypeScript SDK — `@taqiy/custos-core`.

// The deterministic subset of the Python `custos` package per IR_CONTRACT
// - . LLM-backed assistants + out-of-band responders route
// via the  gRPC sidecar (see `sidecarAssistant`).

export * from "./decision.ts";
export * from "./schema.ts";
export * from "./exceptions.ts";
export * from "./canonicalize.ts";
export * from "./fnmatch.ts";
export * from "./policy/operators.ts";
export * from "./policy/match.ts";
export * from "./policy/engine.ts";
export * from "./fatigue/index.ts";
export * from "./assistants/index.ts";
export * from "./responders/index.ts";
export * from "./audit/index.ts";
export * from "./inspectors/index.ts";
export * from "./gateway.ts";

// The SidecarTransport + sidecarAssistant factory live under
// `@taqiy/custos-core/assistants` (re-exported above via `assistants/index`).
export type {
  SidecarTransport,
  DecideRequestWire,
  DecideResponseWire,
} from "./assistants/sidecar.ts";