"""Custos sidecar gRPC package (+  sidecar auth envelope).

The sidecar exposes the in-process ``Gateway.decide`` over gRPC, secured
by mTLS + a bearer-token caller auth envelope + per-call ``request_id``
nonce (replay guard) + per-tenant in-memory rate limit (single-tenant
guard rail for v1.0, D19). The ``custos[sidecar]`` extra pins ``grpcio``
+ ``protobuf`` (tested-minimum); the runtime dep set stays
``jsonschema``-literal .

The TS :class:`SidecarTransport` conforming to ``@taqiy/custos-core``'s
``sidecarAssistant(transport)`` factory is shipped as the sibling
``@taqiy/custos-grpc`` package ; the  floor-is-local rule
(IR_CONTRACT) is enforced by ``Gateway.decide`` on the caller
side -- sidecar output is untrusted across the boundary.
"""

from custos.sidecar.server import (  # noqa: F401
    CapturingAuditSink,
    GatewayServicer,
    ReplayCache,
    SidecarConfig,
    TenantRateLimiter,
    serve,
)

__all__ = [
    "SidecarConfig",
    "GatewayServicer",
    "ReplayCache",
    "TenantRateLimiter",
    "CapturingAuditSink",
    "serve",
]
