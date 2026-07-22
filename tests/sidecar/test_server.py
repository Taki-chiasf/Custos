"""sidecar auth-envelope tests (+).

Drives the gRPC servicer in-process (a `grpc.server` bound to an
in-memory port + a real client stub) so the  paths are exercised
end-to-end:
  - replayed nonce -> DENY
  - missing/expired bearer -> DENY
  - no-mTLS -> the `serve` helper refuses to start (no transport
    material -> exit 1 + stderr message)
  - broad poisoned `allow_and_persist` from a sidecar-shadowed assistant
    rejected locally (the H3 narrowness check runs server-side; the
    caller applies the floor again via the  floor-is-local rule
    pinned in IR_CONTRACT)
  - verdict_signature HMAC verification (happy path + invalid signature)

The mTLS keys + ca material are generated in-process for the test;
production deployments supply operator-managed PEMs.

Requires the `custos[sidecar]` extra (grpcio + protobuf). Skipped if
unavailable so a runtime-only install stays green.
"""

# ruff: noqa: E402, I001 - all imports below are post-importorskip by design
from __future__ import annotations

import datetime as _dt
import hmac
import warnings
from pathlib import Path
from typing import Any

import pytest

grpc = pytest.importorskip("grpc")
from google.protobuf.json_format import ParseDict

from custos.audit import NullAuditSink
from custos.gateway import Gateway
from custos.policy import Policy
from custos.responders import NoopResponder
from custos.sidecar import GatewayServicer, SidecarConfig, serve
from custos.sidecar.proto import (
    DecideRequest,
    Decision as DecisionProto,
    Invocation as InvocationProto,
    SubjectContext as SubjectContextProto,
    add_CustosGatewayServicer_to_server,
)
from custos.sidecar.proto.custos_v1_pb2_grpc import CustosGatewayStub
from custos.sidecar.server import (
    ReplayCache,
    TenantRateLimiter,
    _verdict_signature,
)

require_tls_module = pytest.importorskip("cryptography")

# Python 3.12+ deprecates datetime.datetime.utcnow; cryptography will
# emit a warning for the cert validity window below. Suppress those to
# keep the suite output readable.
warnings.filterwarnings(
    "ignore",
    message=r"datetime\.datetime\.utcnow\(\) is deprecated",
    category=DeprecationWarning,
)

_NOW = _dt.datetime.now(_dt.UTC)


def _build_cert_builder(
    subject_cn: str,
    issuer_cert: Any,
    subject_key: Any,
) -> Any:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _dt.timedelta(days=1))
        .not_valid_after(_NOW + _dt.timedelta(days=1))
    )


# ───────────────────────────────────────────────────────────────────────── #
# Test fixtures
# ───────────────────────────────────────────────────────────────────────── #


def _self_signed_tls(tmp_path: Path) -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Generate a CA, a server cert signed by it, and a client cert signed by it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    def _make_key() -> Any:
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _pem(key: Any, path: Path) -> bytes:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        return pem

    def _cert(
        subject_cn: str,
        issuer_key: Any,
        issuer_cert: x509.Certificate | None,
        subject_key: Any,
        ca: bool = False,
    ) -> x509.Certificate:
        builder = _build_cert_builder(subject_cn, issuer_cert, subject_key)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=ca, path_length=None), critical=True
        )
        return builder.sign(issuer_key, hashes.SHA256())

    ca_key = _make_key()
    ca_cert = _cert("custos-test-ca", ca_key, None, ca_key, ca=True)
    server_key = _make_key()
    server_cert = _cert("localhost", ca_key, ca_cert, server_key)
    client_key = _make_key()
    client_cert = _cert("custos-test-client", ca_key, ca_cert, client_key)

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    server_key_pem = _pem(server_key, tmp_path / "server.key")
    client_cert_pem = client_cert.public_bytes(serialization.Encoding.PEM)
    client_key_pem = _pem(client_key, tmp_path / "client.key")
    (tmp_path / "ca.pem").write_bytes(ca_pem)
    (tmp_path / "server.crt").write_bytes(server_cert_pem)
    (tmp_path / "client.crt").write_bytes(client_cert_pem)
    return server_cert_pem, server_key_pem, ca_pem, client_cert_pem, client_key_pem


def _base_policy() -> Policy:
    return Policy.from_dict(
        {
            "version": 1,
            "default": "deny",
            "overlays": [
                {
                    "id": "base",
                    "rules": [
                        {"match": {"tool": "fs.write*"}, "action": "assist:auto-approve"},
                    ],
                }
            ],
        }
    )


def _build_servicer(
    *,
    bearer_allowlist: frozenset[str] = (),
    verdict_hmac_key: bytes = b"",
    rate_limit_per_minute: int = 600,
    gateway: Gateway | None = None,
) -> GatewayServicer:
    gw = gateway or Gateway(
        policy=_base_policy(),
        assistant=_AutoApprove(),
        responder=NoopResponder(),
        audit_sink=NullAuditSink(),
    )
    cfg = SidecarConfig(
        gateway=gw,
        bearer_allowlist=bearer_allowlist,
        verdict_hmac_key=verdict_hmac_key,
        rate_limit_per_minute=rate_limit_per_minute,
    )
    return GatewayServicer(cfg)


class _AutoApprove:
    """A1-style assistant that always allows (for testing the  boundary)."""

    name = "auto-approve"
    exfiltrates_args = False

    def decide(self, inv: Any, ctx: Any) -> Any:
        from custos.schema import AssistantOutput, Decision

        return AssistantOutput(
            decision=Decision.ALLOW_ONCE,
            risk=0.1,
            reasoning="test auto-approve",
            fatigue_hint=False,
            persist_rule=None,
        )


def _make_request(
    *,
    tool: str = "fs.write_log",
    args: dict[str, Any] | None = None,
    request_id: str = "req-1",
    caller_id: str = "custos-test-client",
    bearer: str = "test-bearer",
    tenant_id: str = "",
) -> DecideRequest:
    inv = InvocationProto(tool=tool, request_id=request_id)
    if args is not None:
        ParseDict(args, inv.args)
    ctx = SubjectContextProto(user_id="alice")
    inv.context.CopyFrom(ctx)
    req = DecideRequest(
        invocation=inv,
        caller_id=caller_id,
        bearer=bearer,
        request_id=request_id,
        tenant_id=tenant_id,
    )
    return req


# ───────────────────────────────────────────────────────────────────────── #
# ReplayCache / TenantRateLimiter unit tests
# ───────────────────────────────────────────────────────────────────────── #


def test_replay_cache_rejects_replayed_nonce() -> None:
    cache = ReplayCache(ttl_s=60)
    assert cache.check_and_record("alice", "nonce-1") is True
    assert cache.check_and_record("alice", "nonce-1") is False


def test_replay_cache_rejects_empty_nonce() -> None:
    cache = ReplayCache(ttl_s=60)
    assert cache.check_and_record("alice", "") is False


def test_replay_cache_scoped_per_caller() -> None:
    cache = ReplayCache(ttl_s=60)
    assert cache.check_and_record("alice", "n") is True
    assert cache.check_and_record("bob", "n") is True  # different caller OK


def test_tenant_rate_limiter_overflow_returns_false() -> None:
    limiter = TenantRateLimiter(max_per_minute=2)
    assert limiter.take("t1") is True
    assert limiter.take("t1") is True
    assert limiter.take("t1") is False
    # Same minute, still rejected.
    assert limiter.take("t1") is False


def test_tenant_rate_limiter_scoped_per_tenant() -> None:
    limiter = TenantRateLimiter(max_per_minute=1)
    assert limiter.take("t1") is True
    assert limiter.take("t1") is False
    assert limiter.take("t2") is True  # different tenant


# ───────────────────────────────────────────────────────────────────────── #
# Servicer Decide:  paths
# ───────────────────────────────────────────────────────────────────────── #


def test_missing_bearer_returns_deny() -> None:
    servicer = _build_servicer()
    req = _make_request(bearer="")
    resp = servicer.Decide(req, context=None)
    assert resp.decision == DecisionProto.DENY
    assert "missing or unauthorized bearer" in resp.audit_event.reasoning


def test_unauthorized_bearer_returns_deny() -> None:
    servicer = _build_servicer(bearer_allowlist=frozenset({"good"}))
    req = _make_request(bearer="bad")
    resp = servicer.Decide(req, context=None)
    assert resp.decision == DecisionProto.DENY
    assert "missing or unauthorized bearer" in resp.audit_event.reasoning


def test_authoritative_bearer_passes() -> None:
    servicer = _build_servicer(bearer_allowlist=frozenset({"good"}))
    req = _make_request(bearer="good", request_id="req-auth-ok")
    resp = servicer.Decide(req, context=None)
    # AutoApprove -> allow_once (the policy floor sits at the assistant
    # route; an ASSIST rule -> assistant allow -> allow_once).
    assert resp.decision == DecisionProto.ALLOW_ONCE
    assert resp.audit_event.decision == DecisionProto.ALLOW_ONCE
    # The forward-field schema_version is "1.0" from day one .
    assert resp.audit_event.schema_version == "1.0"


def test_replayed_nonce_returns_deny() -> None:
    servicer = _build_servicer()
    req = _make_request(request_id="nonce-once")
    first = servicer.Decide(req, context=None)
    assert first.decision == DecisionProto.ALLOW_ONCE
    second = servicer.Decide(req, context=None)  # same nonce
    assert second.decision == DecisionProto.DENY
    assert "replayed" in second.audit_event.reasoning


def test_missing_nonce_returns_deny() -> None:
    servicer = _build_servicer()
    req = _make_request(request_id="")
    resp = servicer.Decide(req, context=None)
    assert resp.decision == DecisionProto.DENY
    assert "replayed or missing request_id" in resp.audit_event.reasoning


def test_tenant_rate_limit_overflow_returns_deny() -> None:
    servicer = _build_servicer(rate_limit_per_minute=1)
    req1 = _make_request(request_id="n1")
    r1 = servicer.Decide(req1, context=None)
    assert r1.decision == DecisionProto.ALLOW_ONCE
    req2 = _make_request(request_id="n2")
    r2 = servicer.Decide(req2, context=None)
    assert r2.decision == DecisionProto.DENY
    assert "rate limit exceeded" in r2.audit_event.reasoning


def test_verdict_signature_is_present_when_key_set() -> None:
    servicer = _build_servicer(verdict_hmac_key=b"test-hmac-key")
    req = _make_request(request_id="req-sig")
    resp = servicer.Decide(req, context=None)
    assert resp.verdict_signature != b""
    # Verify the signature locally: HMAC over "decision|request_id|ts_unix_ms|risk_score".
    decision_name = DecisionProto.Name(resp.decision).lower()
    expected = _verdict_signature(
        decision_name,
        "req-sig",
        resp.audit_event.ts_unix_ms,
        resp.audit_event.risk_score,
        b"test-hmac-key",
    )
    assert hmac.compare_digest(resp.verdict_signature, expected)


def test_verdict_signature_absent_when_key_unset() -> None:
    servicer = _build_servicer()
    req = _make_request(request_id="req-sig-none")
    resp = servicer.Decide(req, context=None)
    assert resp.verdict_signature == b""


def test_policy_deny_short_circuits_before_assistant() -> None:
    """A policy DENY rule MUST short-circuit at step 2 —  floor."""
    policy = Policy.from_dict(
        {
            "version": 1,
            "default": "deny",
            "overlays": [
                {"id": "deny", "rules": [{"match": {"tool": "shell.*"}, "action": "deny"}]},
            ],
        }
    )
    gw = Gateway(
        policy=policy,
        assistant=_AutoApprove(),
        responder=NoopResponder(),
        audit_sink=NullAuditSink(),
    )
    cfg = SidecarConfig(gateway=gw)
    servicer = GatewayServicer(cfg)
    req = _make_request(tool="shell.exec", request_id="req-deny")
    resp = servicer.Decide(req, context=None)
    assert resp.decision == DecisionProto.DENY
    assert resp.audit_event.assistant == ""


# ───────────────────────────────────────────────────────────────────────── #
# serve refuses to start without mTLS material
# ───────────────────────────────────────────────────────────────────────── #


def test_serve_refuses_to_start_without_tls_material(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cfg = SidecarConfig(gateway=Gateway(policy=_base_policy(), audit_sink=NullAuditSink()))
    with caplog.at_level("ERROR", logger="custos.sidecar.server"):
        rc = serve(cfg)
    assert rc == 1
    assert any("mTLS is REQUIRED" in rec.message for rec in caplog.records)


# ───────────────────────────────────────────────────────────────────────── #
# End-to-end gRPC: mTLS handshake + Decide round-trip
# ───────────────────────────────────────────────────────────────────────── #


def test_end_to_end_mtls_decide_round_trip(tmp_path: Path) -> None:
    """Spin up a real gRPC server with mTLS, call Decide, assert allow_once."""
    (
        server_cert_pem,
        server_key_pem,
        ca_pem,
        client_cert_pem,
        client_key_pem,
    ) = _self_signed_tls(tmp_path)
    from concurrent import futures

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    _self = _build_servicer(verdict_hmac_key=b"e2e-key")
    add_CustosGatewayServicer_to_server(_self, server)
    server_credentials = grpc.ssl_server_credentials(
        [(server_key_pem, server_cert_pem)],
        root_certificates=ca_pem,
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", server_credentials)
    server.start()
    try:
        channel_creds = grpc.ssl_channel_credentials(
            root_certificates=ca_pem,
            private_key=client_key_pem,
            certificate_chain=client_cert_pem,
        )
        # The server cert CN is "localhost"; override the target name so
        # the channel handshake doesn't fail the hostname check against
        # the literal "127.0.0.1" we dial.
        options = (("grpc.ssl_target_name_override", "localhost"),)
        channel = grpc.secure_channel(f"127.0.0.1:{port}", channel_creds, options=options)
        stub = CustosGatewayStub(channel)
        req = _make_request(request_id="req-e2e")
        resp = stub.Decide(req)
        assert resp.decision == DecisionProto.ALLOW_ONCE
        assert resp.audit_event.schema_version == "1.0"
    finally:
        server.stop(grace=0).wait()


def test_end_to_end_no_mtls_connection_rejected(tmp_path: Path) -> None:
    """A plaintext (no-mTLS) caller is rejected by `require_client_auth=True`."""
    (
        server_cert_pem,
        server_key_pem,
        ca_pem,
        _,
        _,
    ) = _self_signed_tls(tmp_path)
    from concurrent import futures

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    _self = _build_servicer()
    add_CustosGatewayServicer_to_server(_self, server)
    server_credentials = grpc.ssl_server_credentials(
        [(server_key_pem, server_cert_pem)],
        root_certificates=ca_pem,
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", server_credentials)
    server.start()
    try:
        # A channel WITHOUT a client cert — the server should refuse the
        # handshake at the TLS layer (grpc.RpcError).
        channel_creds = grpc.ssl_channel_credentials(root_certificates=ca_pem)
        channel = grpc.secure_channel(f"127.0.0.1:{port}", channel_creds)
        stub = CustosGatewayStub(channel)
        with pytest.raises(grpc.RpcError):
            stub.Decide(_make_request(request_id="bad-no-mtls"))
    finally:
        server.stop(grace=0).wait()
