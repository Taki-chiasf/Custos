"""``custos`` console entrypoint (: ``custos eval``).

Subcommands land per phase:
   - ``custos audit tail <file>``  (pretty-print last N JSONL events)
   - ``custos eval --suite <name> --policy <file>``
   - ``custos audit replay <file> --policy new.yaml``
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

__all__ = ["main"]


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        _usage()
        return 0

    parser = argparse.ArgumentParser(
        prog="custos",
        description="Custos - permission middleware for AI agents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # ---- audit --------------------------------------------------------------
    audit = sub.add_parser("audit", help="Inspect audit logs (FR-9.21).")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    tail = audit_sub.add_parser("tail", help="Print the last N JSONL audit events (FR-9.22).")
    tail.add_argument("file", help="Path to a JSONL audit log.")
    tail.add_argument(
        "-n", "--n", type=int, default=10, help="Number of events to print (default 10)."
    )

    # Audit replay . Subparser registered here so
    # `custos audit --help` surfaces it; the handler routes through the
    # eval.audit_replay module (lazy import keeps the runtime dep-free).
    replay_p = audit_sub.add_parser(
        "replay", help="Replay audit log decisions against a new policy (FR-9.23)."
    )
    replay_p.add_argument("file", help="Path to a JSONL audit log (FR-9.21 schema).")
    replay_p.add_argument(
        "--policy", "-p", required=True, help="New policy YAML to replay against."
    )

    # Audit verify . Verifies a hash-chained
    # audit log written by `HashChainedAuditSink`. v1.0 ships HMAC-SHA256
    # symmetric verification (the documented v1.0 compliance primitive);
    # `--pubkey` is reserved for the v1.1 asymmetric (Ed25519) path and
    # prints a clear "lands in v1.1" message when supplied.
    verify_p = audit_sub.add_parser(
        "verify",
        help="Verify a hash-chained audit log.",
    )
    verify_p.add_argument("file", help="Path to a hash-chained JSONL audit log (FR-9.24a).")
    verify_p.add_argument(
        "--hmac-key",
        dest="hmac_key",
        default="",
        help="HMAC-SHA256 key (UTF-8 literal) the sink was signed with. "
        "v1.0 verification primitive.",
    )
    verify_p.add_argument(
        "--pubkey",
        dest="pubkey",
        default="",
        help="Public key for asymmetric verification (v1.1 target, Ed25519). "
        "Reserved in v1.0; prints an informational message and exits 2.",
    )
    verify_p.add_argument(
        "--schema-version",
        dest="schema_version",
        default="1.0",
        help="Expected envelope `schema_version` (default '1.0').",
    )

    # ---- eval  -------------------------------------------
    eval_parser = sub.add_parser("eval", help="Run an eval suite (FR-9.25).")
    eval_parser.add_argument(
        "--suite",
        default="janus-v1",
        help="Suite name (janus-v1 | adversarial). Default janus-v1.",
    )
    eval_parser.add_argument("--policy", help="Policy file (YAML) to evaluate against.")
    eval_parser.add_argument(
        "--baseline",
        help="Baseline metrics CSV for parity check (FR-9.29; janus-v1 only).",
    )
    eval_parser.add_argument(
        "--smoke",
        action="store_true",
        help="Fast smoke subset (per-PR tier; FR-9.29).",
    )
    eval_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan + write manifest only; no LLM (FR-9.26, default for janus-v1).",
    )
    eval_parser.add_argument(
        "--execute",
        action="store_true",
        help="Run every cell live (needs an LLM backend; default unless --dry-run).",
    )
    eval_parser.add_argument(
        "--output-dir", dest="output_dir", default="runs/eval", help="Output directory."
    )
    eval_parser.add_argument(
        "--repetitions",
        type=int,
        default=5,
        help="Repetitions per cell (full matrix only; smoke is always 1).",
    )
    eval_parser.add_argument(
        "--model",
        help="Override the agent LLM (default CUSTOS_EVAL_AGENT_MODEL or ollama/llama3.1:8b).",
    )
    eval_parser.add_argument(
        "--judge-model",
        dest="judge_model",
        help="Override the judge LLM (default CUSTOS_EVAL_JUDGE_MODEL or the agent model).",
    )

    # ---- sidecar  -------------------------------
    # Exposes the in-process `Gateway.decide` over gRPC. Requires the
    # `custos[sidecar]` extra (grpcio + protobuf). mTLS is MANDATORY
    # for v1.0 (--tls-cert/--tls-key/--tls-ca); the server refuses to
    # start without them (a plaintext sidecar is a  violation: bearer
    # / nonce are post-TLS primitives, not transport primitives).
    sidecar_parser = sub.add_parser("sidecar", help="Run the Custos gateway sidecar (gRPC, mTLS).")
    sidecar_parser.add_argument(
        "--policy",
        "--policy-yaml",
        dest="policy",
        required=True,
        help="Policy YAML file to load (FR-9.7; requires custos[yaml]).",
    )
    sidecar_parser.add_argument(
        "--bind",
        default="127.0.0.1:7443",
        help="Bind address (default 127.0.0.1:7443).",
    )
    sidecar_parser.add_argument("--tls-cert", default="", help="Server TLS certificate PEM.")
    sidecar_parser.add_argument("--tls-key", default="", help="Server TLS private key PEM.")
    sidecar_parser.add_argument("--tls-ca", default="", help="Client-ca PEM for mTLS verify.")
    sidecar_parser.add_argument(
        "--bearer",
        dest="bearer_allowlist",
        action="append",
        default=[],
        help="Acceptable bearer value (repeatable; empty = accept any non-empty bearer).",
    )
    sidecar_parser.add_argument(
        "--verdict-hmac-key",
        default="",
        help="HMAC key for verdict signatures (empty = unsigned).",
    )
    sidecar_parser.add_argument(
        "--rate-limit-per-minute",
        dest="rate_limit_per_minute",
        type=int,
        default=600,
        help="Per-tenant max RPCs per minute (single-tenant guard rail, D19).",
    )
    sidecar_parser.add_argument(
        "--audit",
        default="",
        help="Audit JSONL sink path (optional; default stdout).",
    )

    parsed = parser.parse_args(args)

    if parsed.command == "audit" and parsed.audit_command == "tail":
        return _audit_tail(Path(parsed.file), parsed.n)
    if parsed.command == "audit" and parsed.audit_command == "replay":
        return _audit_replay(parsed.file, parsed.policy)
    if parsed.command == "audit" and parsed.audit_command == "verify":
        return _audit_verify(parsed)
    if parsed.command == "eval":
        return _eval(parsed)
    if parsed.command == "sidecar":
        return _sidecar(parsed)
    return 2  # unreachable; argparse enforces required subcommands.


def _audit_tail(path: Path, n: int) -> int:
    """Pretty-print the last ``n`` JSONL events from ``path`` ."""
    if not path.exists():
        print(f"custos: audit log not found: {path}", file=sys.stderr)
        return 1
    lines = path.read_text(encoding="utf-8").splitlines()
    events = [ln for ln in lines if ln.strip()]
    tail = events[-n:] if n > 0 else events
    if not tail:
        print(f"(no events in {path})", file=sys.stderr)
        return 0
    for line in tail:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            print(f"--- (unparseable line) {line[:80]}", file=sys.stderr)
            continue
        print(json.dumps(event, indent=2, sort_keys=True))
        print("---")
    return 0


def _audit_replay(audit_path: str, policy_path: str) -> int:
    """Handle ``custos audit replay <file> --policy new.yaml`` .

    Defers to :mod:`eval.audit_replay`; lazy import keeps the runtime dep-free
    (- the eval package is optional).
    """
    try:
        from custos.eval.audit_replay import main as replay_main
    except ImportError as exc:
        print(
            f"custos audit replay: needs the eval package - {exc}",
            file=sys.stderr,
        )
        return 1
    return replay_main([audit_path, "--policy", policy_path])


def _audit_verify(parsed: argparse.Namespace) -> int:
    """Handle ``custos audit verify <file> [--hmac-key ...]`` .

    Verifies a hash-chained audit log written by :class:`HashChainedAuditSink`.
    v1.0 ships HMAC-SHA256 symmetric verification (the documented v1.0
    compliance primitive). ``--pubkey`` is reserved for the v1.1 asymmetric
    (Ed25519) path - supplying it without ``--hmac-key`` prints an
    informational "lands in v1.1" message and exits ``2`` so a CI run is
    explicit about which primitive was (not) checked.
    """
    from custos.audit import verify_chain

    path = Path(parsed.file)
    if not path.exists():
        print(f"custos audit verify: audit log not found: {path}", file=sys.stderr)
        return 1

    if parsed.pubkey and not parsed.hmac_key:
        print(
            "custos audit verify: --pubkey (asymmetric verification) lands in v1.1; "
            "v1.0 supports --hmac-key only. Supply --hmac-key <key> for the v1.0 "
            "HMAC-SHA256 verification primitive.",
            file=sys.stderr,
        )
        return 2

    hmac_key = parsed.hmac_key.encode("utf-8") if parsed.hmac_key else None
    report = verify_chain(
        path,
        hmac_key=hmac_key,
        expected_schema_version=parsed.schema_version,
    )
    if report.is_ok:
        print(
            f"OK: {report.line_count} line(s) verified, chain continuous, "
            f"schema_version={parsed.schema_version!r}."
        )
        return 0
    print(
        f"FAIL: {len(report.errors)} defect(s) across {report.line_count} line(s):",
        file=sys.stderr,
    )
    for err in report.errors:
        print(f"  line {err.line_no}: {err.kind}: {err.detail}", file=sys.stderr)
    return 1


def _eval(parsed: argparse.Namespace) -> int:
    """Handle ``custos eval --suite <name> ...`` ."""
    try:
        from custos.eval.suite import SuiteArgs, run_eval
    except ImportError as exc:
        print(
            f"custos eval: needs the eval package - {exc}",
            file=sys.stderr,
        )
        return 1
    args = SuiteArgs(
        suite=parsed.suite,
        policy=parsed.policy,
        baseline=parsed.baseline,
        smoke=parsed.smoke,
        execute=parsed.execute,
        dry_run=parsed.dry_run,
        output_dir=parsed.output_dir,
        repetitions=parsed.repetitions,
        model=parsed.model,
        judge_model=parsed.judge_model,
    )
    return run_eval(args)


def _usage() -> None:
    print("custos - permission middleware for AI agents")
    print("usage: custos <command> [args]")
    print("commands: audit tail, audit replay, audit verify, eval, sidecar")


def _sidecar(parsed: argparse.Namespace) -> int:
    """Handle ``custos sidecar --policy ... --tls-cert ... ...`` .

    Requires the ``custos[sidecar]`` extra (``grpcio`` + ``protobuf``).
    mTLS is MANDATORY for v1.0 — the server refuses to start without
    ``--tls-cert`` / ``--tls-key`` / ``--tls-ca`` (a plaintext sidecar
    is a  violation: bearer / nonce are post-TLS primitives, not
    transport primitives).
    """
    try:
        from custos.sidecar import SidecarConfig, serve
    except ImportError as exc:
        print(
            f"custos sidecar: needs the [sidecar] extra - {exc}\n  pip install 'custos[sidecar]'",
            file=sys.stderr,
        )
        return 1
    try:
        from custos.policy import Policy
    except ImportError as exc:
        print(f"custos sidecar: policy module unavailable - {exc}", file=sys.stderr)
        return 1

    # Load the policy . `from_yaml` is added by the optional
    # `custos[yaml]` extra; resolve it dynamically so mypy --strict
    # doesn't error on the conditional attribute (: the runtime
    # stays dep-free beyond jsonschema; YAML is optional).
    from_yaml = getattr(Policy, "from_yaml", None)
    if from_yaml is None:
        print(
            "custos sidecar: YAML loading requires the [yaml] extra\n  pip install 'custos[yaml]'",
            file=sys.stderr,
        )
        return 1
    try:
        policy = from_yaml(parsed.policy)
    except FileNotFoundError:
        print(f"custos sidecar: policy file not found: {parsed.policy}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"custos sidecar: invalid policy: {exc}", file=sys.stderr)
        return 1

    # Build the in-process gateway. Assistants / responder default to None
    # (the  floor still runs at the sidecar — operators wire the full
    # Python stack via the Python embedding point; the sidecar is the
    # transport surface, not the configuration surface). Operators with a
    # configured assistant / responder construct the gateway in a small
    # launcher and pass it to `serve` directly.
    from custos.gateway import Gateway

    audit_sink = parsed.audit or None
    gw = Gateway(policy=policy, audit_sink=audit_sink)
    config = SidecarConfig(
        gateway=gw,
        bind=parsed.bind,
        tls_cert=parsed.tls_cert,
        tls_key=parsed.tls_key,
        tls_ca=parsed.tls_ca,
        bearer_allowlist=frozenset(parsed.bearer_allowlist),
        verdict_hmac_key=parsed.verdict_hmac_key.encode("utf-8")
        if parsed.verdict_hmac_key
        else b"",
        rate_limit_per_minute=parsed.rate_limit_per_minute,
    )
    return serve(config)


if __name__ == "__main__":
    raise SystemExit(main())
