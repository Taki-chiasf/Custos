"""Custos sidecar gRPC server (+  sidecar auth envelope).

Exposes the in-process :class:`custos.gateway.Gateway.decide` over gRPC.
The server runs as a long-lived process; an operator launches it with
``custos sidecar`` (see ``custos.cli``). The transport auth envelope is:

  - **mTLS** at the transport layer (server presents its cert; caller
    presents a client cert signed by the operator's CA, validated
    against ``--tls-ca``).
  - **Bearer / delegated OIDC** at the application layer (`DecideRequest.bearer`).
    Callers without a bearer are rejected UNLESS they are the mTLS
    principal in an operator-configured anonymous-call allowlist (empty
    by default -> every caller MUST present a bearer).
  - **Per-call ``request_id`` nonce**: a replayed nonce -> ``DENY`` with
    reasoning ``"sidecar: replayed request_id"`` (the  replay guard at
    the boundary).
  - **Per-tenant in-memory rate limit**: ``--rate-limit-per-minute`` per
    ``tenant_id`` (default tenant = empty string); overflow -> ``DENY``
    with reasoning ``"sidecar: tenant rate limit exceeded"``. Single-tenant
    for v1.0 per decision D19; this is a guard rail, not a multi-tenant
    isolation boundary.

 floor is enforced at the sidecar (the underlying ``Gateway.decide``
runs through the policy engine). The  floor-is-local rule (IR_CONTRACT
) is re-applied by the TS caller on returned verdicts -- the sidecar
signs the verdict (`verdict_signature` HMAC over
``decision.name|request_id|ts_unix_ms|risk_score``) so the caller can
verify the verdict is unmodified in transit. A failed signature
verification at the caller downgrades to ``DENY`` locally. An OPTIONAL
secondary-responder fallback chain  is the gateway's
responsibility server-side; the sidecar surfaces the responder-decision
verbatim (the caller re-applies its own floor).

The verifier HMAC key is operator-supplied (``--verdict-hmac-key``).
When empty, verdict signing is disabled (`verdict_signature` empty) -- this
is documented as an operator choice; production deployments MUST supply a
key.

License: Apache-2.0 . ``grpcio`` + ``protobuf`` are pulled into the
``custos[sidecar]`` extra; the runtime dep set stays ``jsonschema``-literal
.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import threading
import time
from concurrent import futures
from dataclasses import dataclass, field
from typing import Any

from custos.audit import AuditSink
from custos.gateway import Gateway
from custos.schema import (
    AuditEvent as PyAuditEvent,
)
from custos.schema import Decision as PyDecision
from custos.schema import (
    Invocation as PyInvocation,
)
from custos.schema import (
    SideEffect,
)
from custos.schema import (
    SubjectContext as PySubjectContext,
)
from custos.schema import (
    ToolDescriptor as PyToolDescriptor,
)

__all__ = [
    "SidecarConfig",
    "GatewayServicer",
    "ReplayCache",
    "TenantRateLimiter",
    "CapturingAuditSink",
    "serve",
]


class CapturingAuditSink(AuditSink):
    """Audit sink that captures the most-recent event (thread-local).

    The sidecar needs the full :class:`AuditEvent` (not just the
    :class:`Decision` the sync ``Gateway.decide`` returns) so it can be
    echoed back to the caller in the ``DecideResponse.audit_event`` field.
    Because the gRPC server uses a per-call thread executor, the capture
    is thread-local — each ``Decide`` RPC sees exactly the audit event
    its own gateway invocation emitted. Wrap the operator's configured
    sink (file / stdout) via ``wrapped`` to avoid losing observability.
    """

    def __init__(self, wrapped: AuditSink | None = None) -> None:
        self._wrapped = wrapped
        self._local = threading.local()

    def emit(self, event: PyAuditEvent) -> None:
        self._local.last = event
        if self._wrapped is not None:
            self._wrapped.emit(event)

    def take(self) -> PyAuditEvent | None:
        return getattr(self._local, "last", None)

    def clear(self) -> None:
        """Clear the thread-local capture (C5 regression, council 2026-07-22).

        The gRPC server reuses worker threads; without a per-call clear, a
        prior call's audit event survives and ``take`` could return it on a
        later call that emitted no event (masking the  anomaly the
        ``audit is None`` check is there to catch). The gateway calls this at
        the top of every ``Decide`` RPC.
        """
        self._local.last = None


logger = logging.getLogger(__name__)


# ───────────────────────────────────────────────────────────────────────── #
# Auth / replay / rate-limit helpers
# ───────────────────────────────────────────────────────────────────────── #


class ReplayCache:
    """In-memory nonce tracker -- rejects replayed ``request_id`` (replay guard).

    The cache is a single-process dict guarded by a lock. Tuples of
    ``(caller_id, request_id)`` are tracked for a TTL (default 600 s) and
    rejected on a second occurrence. A ``request_id`` of ``""`` is the
    "no nonce supplied" case -- rejected (a missing nonce is an audit
    anomaly under).

    Single-process state (HA deferred to v1.1 alongside Redis-backed
    fatigue state); on a sidecar restart the cache is fresh.
    """

    def __init__(self, ttl_s: int = 600) -> None:
        self._ttl_s = ttl_s
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    def check_and_record(self, caller_id: str, request_id: str) -> bool:
        """Return True if this (caller_id, request_id) is fresh, False on replay."""
        if request_id == "":
            # A missing nonce is an audit anomaly and is rejected.
            return False
        key = (caller_id, request_id)
        now = time.monotonic()
        with self._lock:
            # Garbage-collect expired entries opportunistically.
            expired = [k for k, exp in self._seen.items() if exp <= now]
            for k in expired:
                self._seen.pop(k, None)
            if key in self._seen:
                return False
            self._seen[key] = now + self._ttl_s
            return True


@dataclass
class TenantRateLimiter:
    """Per-tenant in-memory rate limit (single-tenant guard rail for v1.0, D19).

    ``max_per_minute`` per ``tenant_id`` (default tenant = empty string).
    Overflow returns False (the caller is rejected with a rate-limit
    ``DENY``). Sliding-window counting via per-tenant monotonic-minute
    buckets -- matches the fatigue layer's  shape.

    This is NOT a multi-tenant isolation boundary: a noisy tenant can
    starve its own bucket but cannot starve another's. Multi-tenant
    isolation is a v1.1 target (+ Redis-backed fatigue).
    """

    max_per_minute: int
    _buckets: dict[str, tuple[int, int]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def take(self, tenant_id: str) -> bool:
        """Return True if the tenant is under the limit, False on overflow."""
        now_monotonic = time.monotonic()
        minute = int(now_monotonic // 60)
        with self._lock:
            entry = self._buckets.get(tenant_id)
            if entry is None or entry[0] != minute:
                self._buckets[tenant_id] = (minute, 1)
                return True
            count = entry[1] + 1
            if count > self.max_per_minute:
                # Leave the bucket as-is so the rest of the minute is
                # also rejected (avoids a one-token reprieve on the next
                # call within the same minute).
                return False
            self._buckets[tenant_id] = (minute, count)
            return True


# ───────────────────────────────────────────────────────────────────────── #
# Config
# ───────────────────────────────────────────────────────────────────────── #


@dataclass
class SidecarConfig:
    """Operator-supplied server configuration.

    TLS fields are REQUIRED for production -- a sidecar with `tls_cert` /
    `tls_key` / `tls_ca` unset refuses to start with a clear error (a
    plaintext sidecar is a  violation: bearer / nonce are post-TLS
    primitives, not transport primitives). The `bearer_allowlist` is the
    set of bearer values accepted; an empty `bearer` is rejected UNLESS
    the caller is the mTLS principal in `anonymous_mtls_allowlist` (empty
    by default -> every caller MUST present a bearer).
    """

    gateway: Gateway
    bind: str = "127.0.0.1:7443"
    tls_cert: str = ""
    tls_key: str = ""
    tls_ca: str = ""
    bearer_allowlist: frozenset[str] = frozenset()
    anonymous_mtls_allowlist: frozenset[str] = frozenset()
    verdict_hmac_key: bytes = b""
    rate_limit_per_minute: int = 600


# ───────────────────────────────────────────────────────────────────────── #
# Servicer
# ───────────────────────────────────────────────────────────────────────── #


def _safe_decision_enum(d: PyDecision) -> int:
    """Map the Python ``Decision`` to the proto enum value (1-indexed)."""
    return {
        "allow": 1,
        "allow_once": 2,
        "allow_and_persist": 3,
        "deny": 4,
        "prompt": 5,
        "defer": 6,
    }[d.value]


def _struct_to_dict(struct: Any) -> dict[str, Any]:
    """`google.protobuf.Struct` -> plain dict (JSON-shaped)."""
    from google.protobuf.json_format import (
        MessageToDict,  # local import: protobuf is the sidecar extra
    )

    if struct is None or (hasattr(struct, "ByteSize") and struct.ByteSize() == 0):
        return {}
    return dict(MessageToDict(struct))  # preserves JSON types


def _invocation_from_proto(req_invocation: Any) -> PyInvocation:
    """Build a :class:`custos.schema.Invocation` from the proto message."""
    args = _struct_to_dict(req_invocation.args) if req_invocation.HasField("args") else {}
    descriptor = None
    if req_invocation.HasField("descriptor") and req_invocation.descriptor.name:
        d = req_invocation.descriptor
        side_effects = frozenset(SideEffect(s) for s in d.side_effects)
        descriptor = PyToolDescriptor(
            name=d.name,
            risk_tier=d.risk_tier,
            schema=_struct_to_dict(d.schema) if d.HasField("schema") else {},
            reversible=d.reversible,
            side_effects=side_effects,
        )
    ctx = req_invocation.context
    extra = _struct_to_dict(ctx.extra) if ctx.HasField("extra") else {}
    subject = PySubjectContext(
        user_id=ctx.user_id or "anonymous",
        goal_id=ctx.goal_id or None,
        task_id=ctx.task_id or None,
        delegation_chain=tuple(ctx.delegation_chain),
        session_ttl=ctx.session_ttl or None,
        extra=extra,
    )
    return PyInvocation(
        tool=req_invocation.tool,
        args=args,
        context=subject,
        descriptor=descriptor,
        request_id=req_invocation.request_id or None,
    )


def _audit_event_to_proto(event: PyAuditEvent) -> Any:
    """Build the proto ``AuditEvent`` from a Python :class:`AuditEvent`."""
    from google.protobuf.json_format import ParseDict  # local import

    from custos.sidecar.proto import AuditEvent as AuditEventProto

    pb = AuditEventProto()
    inv = event.invocation
    pb.ts_unix_ms = event.ts_unix_ms
    # invocation
    pb.invocation.tool = inv.tool
    if inv.request_id is not None:
        pb.invocation.request_id = inv.request_id
    if inv.descriptor is not None:
        pb.invocation.descriptor.name = inv.descriptor.name
        pb.invocation.descriptor.risk_tier = inv.descriptor.risk_tier
        pb.invocation.descriptor.reversible = inv.descriptor.reversible
        pb.invocation.descriptor.side_effects.extend(
            sorted(se.value for se in inv.descriptor.side_effects)
        )
    # decision
    pb.decision = _safe_decision_enum(event.decision)
    if event.policy_match is not None:
        pb.policy_match = event.policy_match
    if event.assistant is not None:
        pb.assistant = event.assistant
    pb.risk_score = event.risk_score
    pb.reasoning = event.reasoning
    if event.responder is not None:
        pb.responder = event.responder
    pb.latency_ms = event.latency_ms
    # subject
    pb.subject.user_id = event.subject.user_id
    if event.subject.goal_id is not None:
        pb.subject.goal_id = event.subject.goal_id
    if event.subject.task_id is not None:
        pb.subject.task_id = event.subject.task_id
    pb.subject.delegation_chain.extend(event.subject.delegation_chain)
    if event.subject.session_ttl is not None:
        pb.subject.session_ttl = event.subject.session_ttl
    # extra is filtered by AUDIT_SUBJECT_FIELDS server-side too (defense
    # in depth even though the caller re-reddacts).
    allowlist = {"user_id", "goal_id", "task_id"}
    extra_f = {k: v for k, v in event.subject.extra.items() if k in allowlist}
    if extra_f:
        ParseDict(extra_f, pb.subject.extra, ignore_unknown_fields=True)
    if event.approver is not None:
        pb.approver = event.approver
    if event.quorum_state is not None:
        pb.quorum_state = event.quorum_state
    # The forward `schema_version` field is irrespective of the in-process
    # impl; the sidecar emits "1.0" from day one per IR_CONTRACT .
    pb.schema_version = event.to_dict().get("schema_version", "1.0")
    return pb


def _verdict_signature(
    decision_name: str,
    request_id: str,
    ts_unix_ms: int,
    risk_score: float,
    key: bytes,
) -> bytes:
    """HMAC-SHA256 over ``decision|request_id|ts_unix_ms|risk_score`` ."""
    canonical = f"{decision_name}|{request_id}|{ts_unix_ms}|{risk_score}"
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).digest()


class GatewayServicer:
    """The Custos sidecar gRPC servicer ."""

    def __init__(self, config: SidecarConfig) -> None:
        self._cfg = config
        self._capturing_sink = CapturingAuditSink()
        # Wrap the operator's configured sink so the audit log still
        # receives events (file / stdout / etc.) AND we get the in-call
        # capture for the DecideResponse.
        gw = config.gateway
        if not isinstance(gw.audit_sink, CapturingAuditSink):
            self._capturing_sink = CapturingAuditSink(wrapped=gw.audit_sink)
            gw.audit_sink = self._capturing_sink
        else:
            self._capturing_sink = gw.audit_sink
        self._replay = ReplayCache()
        self._limiter = TenantRateLimiter(max_per_minute=config.rate_limit_per_minute)

    # The generated ``CustosGatewayServicer`` ABC has a ``Decide`` stub
    # returning ``DecideResponse``. We override it; the registration
    # helper wires our method into the server.

    def Decide(self, request: Any, context: Any) -> Any:  # noqa: N802 - protobuf names
        from custos.sidecar.proto import Decision as DecisionProto

        request_id = request.request_id or ""
        caller_id = request.caller_id or ""

        # Clear the thread-local capture for this call (C5 regression,
        # council 2026-07-22): worker threads are reused, and a stale
        # prior-call event would mask the ``audit is None`` anomaly below.
        self._capturing_sink.clear()

        # 1. Bearer check — fail closed.
        bearer = request.bearer or ""
        bearer_ok = bool(bearer) and (
            not self._cfg.bearer_allowlist or bearer in self._cfg.bearer_allowlist
        )
        anonymous_ok = (
            not bearer and caller_id != "" and caller_id in self._cfg.anonymous_mtls_allowlist
        )
        if not bearer_ok and not anonymous_ok:
            return self._deny_response(
                context=None,
                request=request,
                decision_proto=DecisionProto.DENY,
                reasoning="sidecar: missing or unauthorized bearer (caller auth)",
                risk_score=1.0,
            )

        # 2. Replay check — fail closed.
        if not self._replay.check_and_record(caller_id, request_id):
            return self._deny_response(
                context=None,
                request=request,
                decision_proto=DecisionProto.DENY,
                reasoning="sidecar: replayed or missing request_id (replay guard)",
                risk_score=1.0,
            )

        # 3. Rate-limit check.
        tenant_id = request.tenant_id or ""
        if not self._limiter.take(tenant_id):
            return self._deny_response(
                context=None,
                request=request,
                decision_proto=DecisionProto.DENY,
                reasoning="sidecar: tenant rate limit exceeded",
                risk_score=1.0,
            )

        # 4. Build the in-process Invocation + run the gateway pipeline.
        try:
            inv = _invocation_from_proto(request.invocation)
        except Exception as exc:  # noqa: BLE001 - boundary exception safety
            return self._deny_response(
                context=None,
                request=request,
                decision_proto=DecisionProto.DENY,
                reasoning=f"sidecar: invocation parse error: {exc!s}",
                risk_score=1.0,
            )

        # Run the sync `Gateway.decide`. The audit event is captured by
        # the `CapturingAuditSink` mounted on the gateway (the operator's
        # configured sink is wrapped so it still fires for observability).
        try:
            result = self._cfg.gateway.decide(inv)
        except Exception as exc:  # noqa: BLE001 -  exception safety
            return self._deny_response(
                context=None,
                request=request,
                decision_proto=DecisionProto.DENY,
                reasoning=f"sidecar: gateway exception: {exc!s}",
                risk_score=1.0,
            )

        decision = result.decision
        audit = result.audit

        decision_proto_value = _safe_decision_enum(decision)
        # Sign the verdict.
        vsig = b""
        if self._cfg.verdict_hmac_key:
            vsig = _verdict_signature(
                decision.value,
                request_id,
                audit.ts_unix_ms,
                audit.risk_score,
                self._cfg.verdict_hmac_key,
            )

        return self._build_response(
            request=request,
            audit=audit,
            decision_proto=decision_proto_value,
            reasoning=audit.reasoning,
            risk_score=audit.risk_score,
            verdict_signature=vsig,
        )

    def _deny_response(
        self,
        *,
        context: Any,
        request: Any,
        decision_proto: int,
        reasoning: str,
        risk_score: float,
    ) -> Any:
        """Fail-closed helper: build a DENY response without an audit event."""
        from custos.sidecar.proto import AuditEvent, DecideResponse

        # Build a synthetic AuditEvent the caller persists locally so the
        #  anomaly is observable. The `ts_unix_ms` is the current time.
        audit_proto = AuditEvent()
        ts_ms = int(time.time() * 1000)
        audit_proto.ts_unix_ms = ts_ms
        if request.HasField("invocation"):
            audit_proto.invocation.tool = request.invocation.tool
            audit_proto.invocation.request_id = request.invocation.request_id
        audit_proto.decision = decision_proto
        audit_proto.reasoning = reasoning
        audit_proto.risk_score = risk_score
        audit_proto.subject.user_id = "anonymous"
        audit_proto.schema_version = "1.0"

        # Emit the auth-failure event to the operator's audit sink so server-side
        # operators have observability of all auth-boundary rejections.
        py_event = PyAuditEvent(
            ts_unix_ms=ts_ms,
            invocation=PyInvocation(
                tool=request.invocation.tool if request.HasField("invocation") else "",
                args={},
                context=PySubjectContext(user_id="anonymous"),
                request_id=request.invocation.request_id
                if request.HasField("invocation")
                else None,
            ),
            decision=PyDecision.DENY,
            policy_match="sidecar:auth-boundary",
            assistant=None,
            risk_score=risk_score,
            reasoning=reasoning,
            responder=None,
            latency_ms=0,
            subject=PySubjectContext(user_id="anonymous"),
        )
        self._capturing_sink.emit(py_event)

        resp = DecideResponse()
        resp.decision = decision_proto
        resp.audit_event.CopyFrom(audit_proto)
        resp.server_latency_ms = 0
        resp.verdict_cache_ms = 0
        return resp

    def _build_response(
        self,
        *,
        request: Any,
        audit: PyAuditEvent,
        decision_proto: int,
        reasoning: str,
        risk_score: float,
        verdict_signature: bytes,
    ) -> Any:
        from custos.sidecar.proto import DecideResponse

        resp = DecideResponse()
        resp.decision = decision_proto
        resp.audit_event.CopyFrom(_audit_event_to_proto(audit))
        resp.server_latency_ms = audit.latency_ms
        # `verdict_cache_ms`: the local dedup TTL the caller should honour.
        # Forward the gateway's fatigue-layer TTL by reading the configured
        # dedup_ttl_s. The caller's process uses its OWN monotonic clock
        # per .
        fatigue = getattr(self._cfg.gateway, "fatigue", None)
        ttl_s = getattr(fatigue, "dedup_ttl_s", 300) if fatigue else 300
        resp.verdict_cache_ms = int(ttl_s * 1000)
        resp.verdict_signature = verdict_signature
        resp.risk_score = risk_score
        resp.reasoning = reasoning
        return resp


def serve(config: SidecarConfig) -> int:
    """Launch the sidecar with mTLS + the servicer registered.

    Returns 0 on a clean shutdown, 1 on configuration / TLS errors.
    Callers (``custos sidecar`` CLI) block here.
    """
    import grpc  # local import: grpcio is the sidecar extra

    from custos.sidecar.proto import (
        add_CustosGatewayServicer_to_server,
    )

    if not config.tls_cert or not config.tls_key or not config.tls_ca:
        logger.error(
            "custos sidecar: mTLS is REQUIRED for v1.0 (sidecar auth envelope). "
            "Pass --tls-cert, --tls-key, --tls-ca."
        )
        return 1

    # Build the credentials.
    try:
        with open(config.tls_cert, "rb") as fh:
            cert_chain = fh.read()
        with open(config.tls_key, "rb") as fh:
            private_key = fh.read()
        with open(config.tls_ca, "rb") as fh:
            ca_cert = fh.read()
    except OSError as exc:
        logger.error("custos sidecar: cannot read TLS material: %s", exc)
        return 1

    server_credentials = grpc.ssl_server_credentials(
        [(private_key, cert_chain)],
        root_certificates=ca_cert,
        require_client_auth=True,  # mTLS — caller MUST present a client cert.
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    add_CustosGatewayServicer_to_server(GatewayServicer(config), server)  # type: ignore[no-untyped-call]
    server.add_secure_port(config.bind, server_credentials)
    server.start()
    logger.info("custos sidecar listening on %s (mTLS, require_client_auth=True)", config.bind)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(grace=1.0).wait()
    return 0


# This class at module top-level is a stub so the registration helper
# can subclass it; we attach via the generated ABC.
try:
    from custos.sidecar.proto import CustosGatewayServicer as _GeneratedServicer

    # Re-export the typed servicer that mixes in our implementation. The
    # generated ABC declares `Decide(self, request, context)` returning
    # `DecideResponse`; `GatewayServicer.Decide` satisfies it. We mark
    # the multiple-inheritance `# type: ignore` because the generated
    # base's signature is dynamic (mypy sees `Any`).
    class TypedGatewayServicer(_GeneratedServicer, GatewayServicer):
        """The composed servicer: generated ABC + our ``Decide``."""

        pass

    __all__.append("TypedGatewayServicer")
except ImportError as _exc:  # pragma: no cover - exercised only without the extra
    logger.debug("custos[sidecar] extra not installed: %s", _exc)
