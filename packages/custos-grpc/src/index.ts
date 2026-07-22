// `@custos/grpc` — gRPC transport for the Custos sidecar .

// The real `SidecarTransport` implementation consumed by `@custos/core`'s
// `sidecarAssistant(transport)` factory. Wire-shape +  replay-guard
// + mTLS envelope pinned in `IR_CONTRACT.md` -.

export {
  GrpcSidecarTransport,
  type GrpcSidecarTransportOptions,
  type SidecarDecideRequest,
  type SidecarDecideResponse,
  type SidecarTransportLike,
} from "./grpc_sidecar_transport.ts";