"""Start the Custos Python sidecar with self-signed mTLS material.

Writes a CA, server cert, and client cert to a temp dir, starts the
sidecar based on a fixed policy (deny email.send; allow fs.read*;
assist:auto-approve fs.write*), prints the bind address + the cert paths
on stdout as JSON, and blocks until SIGTERM.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import signal
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from custos.audit import NullAuditSink
from custos.gateway import Gateway
from custos.policy import Policy
from custos.responders import NoopResponder
from custos.sidecar import GatewayServicer, SidecarConfig, serve
from custos.sidecar.proto import add_CustosGatewayServicer_to_server

import grpc
from concurrent import futures


_NOW = _dt.datetime.now(_dt.UTC)


def _make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _cert(cn, issuer_key, issuer_cert, subject_key, ca=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    b = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_cert.subject if issuer_cert is not None else name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - _dt.timedelta(days=1))
        .not_valid_after(_NOW + _dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    return b.sign(issuer_key, hashes.SHA256())


class _DBG(GatewayServicer):
    def Decide(self, request, context):
        if os.environ.get("CUSTOS_GRPC_DEBUG"):
            print(
                f"[python-debug] request_id={request.request_id!r} caller_id={request.caller_id!r} bearer={request.bearer!r} tenant={request.tenant_id!r}",
                file=sys.stderr,
                flush=True,
            )
            print(
                f"[python-debug] invocation.tool={request.invocation.tool!r} inv.request_id={request.invocation.request_id!r}",
                file=sys.stderr,
                flush=True,
            )
        return super().Decide(request, context)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="custos-sidecar-itest-"))
    ca_key = _make_key()
    ca_cert = _cert("itest-ca", ca_key, None, ca_key, ca=True)
    server_key = _make_key()
    server_cert = _cert("localhost", ca_key, ca_cert, server_key)
    client_key = _make_key()
    client_cert = _cert("itest-client", ca_key, ca_cert, client_key)

    (tmp / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "server.crt").write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "server.key").write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (tmp / "client.crt").write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
    (tmp / "client.key").write_bytes(
        client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    policy = Policy.from_dict(
        {
            "version": 1,
            "default": "deny",
            "overlays": [
                {
                    "id": "base",
                    "rules": [
                        {"match": {"tool": "fs.read*"}, "action": "allow_and_audit"},
                        {"match": {"tool": "fs.write*"}, "action": "assist:auto-approve"},
                        {"match": {"tool": "shell.*"}, "action": "deny"},
                    ],
                }
            ],
        }
    )

    class AutoApprove:
        name = "auto-approve"
        exfiltrates_args = False

        def decide(self, inv, ctx):
            from custos.schema import AssistantOutput, Decision

            return AssistantOutput(
                decision=Decision.ALLOW_ONCE,
                risk=0.1,
                reasoning="itest auto-approve",
                fatigue_hint=False,
                persist_rule=None,
            )

    gw = Gateway(
        policy=policy,
        assistant=AutoApprove(),
        responder=NoopResponder(),
        audit_sink=NullAuditSink(),
    )
    cfg = SidecarConfig(
        gateway=gw,
        bind="127.0.0.1:0",
        tls_cert=str(tmp / "server.crt"),
        tls_key=str(tmp / "server.key"),
        tls_ca=str(tmp / "ca.pem"),
        bearer_allowlist=frozenset({"itest-bearer"}),
        verdict_hmac_key=b"itest-verdict-key",
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=2))
    good_servicer = _DBG(cfg) if os.environ.get("CUSTOS_GRPC_DEBUG") else GatewayServicer(cfg)
    add_CustosGatewayServicer_to_server(good_servicer, server)
    server_creds = grpc.ssl_server_credentials(
        [(open(tmp / "server.key", "rb").read(), open(tmp / "server.crt", "rb").read())],
        root_certificates=open(tmp / "ca.pem", "rb").read(),
        require_client_auth=True,
    )
    port = server.add_secure_port("127.0.0.1:0", server_creds)
    server.start()

    # Emit a JSON line on stdout so the TS test can pick up the address
    # + cert paths. The TS test owns the process lifecycle.
    print(
        json.dumps(
            {
                "port": port,
                "ca": str(tmp / "ca.pem"),
                "client_crt": str(tmp / "client.crt"),
                "client_key": str(tmp / "client.key"),
                "bearer": "itest-bearer",
                "verdict_hmac_key": "itest-verdict-key",
            }
        ),
        flush=True,
    )

    # Block until SIGTERM.
    stop = threading.Event()

    def _sig(_s, _f):
        stop.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    stop.wait()
    server.stop(grace=0).wait()


if __name__ == "__main__":
    main()
