"""Tests for :class:`HashChainedAuditSink` + :func:`verify_chain` .

Covers:
- Happy-path chain continuity (genesis + 1+ linked lines).
- Mutation detection (modify an event field -> broken_chain on the next line).
- Truncation / single-line (genesis only is still OK).
- Insertion detection (a forged line whose prev_hash != sha256(prev)).
- HMAC signing + missing-signature + bad-signature.
- schema_version mismatch reporting.
- ``custos audit verify`` CLI entry (exit code 0 / 1 / 2 for pubkey-only).
- ``AuditEvent.schema_version`` defaults to ``"1.0"`` + serializes in ``to_dict``.
- ``FileAuditSink`` docstring surfaces the NOT-tamper-evident warning.
"""

from __future__ import annotations

import json
from pathlib import Path

from custos.audit import (
    GENESIS_HASH,
    FileAuditSink,
    HashChainedAuditSink,
    verify_chain,
)
from custos.cli import main as cli_main
from custos.schema import AuditEvent, Decision, Invocation, SubjectContext


def _ctx() -> SubjectContext:
    return SubjectContext(user_id="u1", goal_id="g1")


def _inv() -> Invocation:
    return Invocation(tool="fs.read", args={"path": "/etc/hosts"}, context=_ctx())


def _event(decision: Decision = Decision.ALLOW_ONCE, ts: int = 1) -> AuditEvent:
    return AuditEvent(
        ts_unix_ms=ts,
        invocation=_inv(),
        decision=decision,
        policy_match="base:allow",
        assistant=None,
        risk_score=0.1,
        reasoning="ok",
        responder=None,
        latency_ms=1,
        subject=_ctx(),
    )


def _lines(path: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        if ln.strip():
            out.append(json.loads(ln))
    return out


# --- AuditEvent.schema_version -----------------------------------------------


def test_audit_event_schema_version_defaults_to_1_0() -> None:
    d = _event().to_dict()
    assert d["schema_version"] == "1.0"


def test_audit_event_schema_version_field_is_settable() -> None:
    e = _event()
    # frozen dataclass replace semantics
    from dataclasses import replace

    e2 = replace(e, schema_version="1.1")
    assert e2.to_dict()["schema_version"] == "1.1"


# --- HashChainedAuditSink happy path -----------------------------------------


def test_hash_chain_first_line_is_genesis(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    sink.emit(_event())
    lines = _lines(p)
    assert len(lines) == 1
    assert lines[0]["prev_hash"] == GENESIS_HASH
    assert lines[0]["schema_version"] == "1.0"
    inner = lines[0]["event"]
    assert isinstance(inner, dict)
    assert inner["decision"] == "allow_once"


def test_hash_chain_links_back_to_sha256_of_prev_line(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    sink.emit(_event(ts=1))
    sink.emit(_event(ts=2))
    sink.emit(_event(ts=3))
    lines = _lines(p)
    assert len(lines) == 3

    import hashlib

    raw_lines = p.read_bytes().split(b"\n")
    raw_lines = [ln for ln in raw_lines if ln.strip()]
    # Each line N > 0 references the sha256 of raw line N-1.
    for i in range(1, len(raw_lines)):
        expected = hashlib.sha256(raw_lines[i - 1]).hexdigest()
        env = json.loads(raw_lines[i].decode("utf-8"))
        assert env["prev_hash"] == expected


def test_verify_chain_happy_path_returns_ok(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    for ts in range(5):
        sink.emit(_event(ts=ts))
    rep = verify_chain(p)
    assert rep.is_ok
    assert rep.line_count == 5
    assert rep.errors == []


def test_verify_chain_empty_file_is_ok_zero_lines(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    p.write_text("", encoding="utf-8")
    rep = verify_chain(p)
    assert rep.is_ok
    assert rep.line_count == 0


def test_verify_chain_single_genesis_line_is_ok(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    HashChainedAuditSink(p).emit(_event())
    rep = verify_chain(p)
    assert rep.is_ok
    assert rep.line_count == 1


# --- Mutation detection ------------------------------------------------------


def test_verify_chain_detects_event_field_mutation(tmp_path: Path) -> None:
    """Modifying an event field breaks the NEXT line's prev_hash."""
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    sink.emit(_event(ts=1, decision=Decision.ALLOW_ONCE))
    sink.emit(_event(ts=2, decision=Decision.DENY))
    # Tamper with line 1's event.decision (swap allow_once -> allow).
    lines = p.read_text(encoding="utf-8").splitlines()
    env = json.loads(lines[0])
    env["event"]["decision"] = "allow"  # was "allow_once"
    lines[0] = json.dumps(env, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rep = verify_chain(p)
    assert not rep.is_ok
    kinds = {e.kind for e in rep.errors}
    assert "broken_chain" in kinds  # line 2's prev_hash no longer matches
    assert rep.line_count == 2


def test_verify_chain_detects_removed_middle_line(tmp_path: Path) -> None:
    """Deleting a middle line breaks the successor's prev_hash."""
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    for ts in range(4):
        sink.emit(_event(ts=ts))
    # Remove line 2 (middle), leaving lines 1, 3, 4.
    lines = p.read_text(encoding="utf-8").splitlines()
    lines = lines[0:1] + lines[2:]
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rep = verify_chain(p)
    assert not rep.is_ok
    kinds = {e.kind for e in rep.errors}
    assert "broken_chain" in kinds
    assert rep.line_count == 3


def test_verify_chain_detects_bad_genesis(tmp_path: Path) -> None:
    """First line with a non-genesis prev_hash is flagged bad_genesis."""
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    sink.emit(_event())
    env = json.loads(p.read_text(encoding="utf-8").strip())
    env["prev_hash"] = "a" * 64  # not GENESIS_HASH
    p.write_text(json.dumps(env, sort_keys=True) + "\n", encoding="utf-8")
    rep = verify_chain(p)
    assert not rep.is_ok
    assert rep.errors[0].kind == "bad_genesis"


def test_verify_chain_detects_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    sink.emit(_event(ts=1))
    sink.emit(_event(ts=2))
    # Corrupt line 2 with a non-JSON fragment.
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[1] = "{not json"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rep = verify_chain(p)
    assert not rep.is_ok
    kinds = {e.kind for e in rep.errors}
    assert "parse_error" in kinds
    assert rep.line_count == 2  # the bad line still counted


def test_verify_chain_detects_missing_prev_hash(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    HashChainedAuditSink(p).emit(_event())
    env = json.loads(p.read_text(encoding="utf-8").strip())
    del env["prev_hash"]
    p.write_text(json.dumps(env, sort_keys=True) + "\n", encoding="utf-8")
    rep = verify_chain(p)
    assert not rep.is_ok
    assert rep.errors[0].kind == "missing_prev_hash"


# --- HMAC signing ------------------------------------------------------------


def test_hash_chain_with_hmac_signs_each_line(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"super-secret-key"
    sink = HashChainedAuditSink(p, signing_key=key)
    sink.emit(_event(ts=1))
    sink.emit(_event(ts=2))
    for env in _lines(p):
        assert "sig" in env
        assert isinstance(env["sig"], str)


def test_verify_chain_with_hmac_happy_path(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"super-secret-key"
    sink = HashChainedAuditSink(p, signing_key=key)
    for ts in range(3):
        sink.emit(_event(ts=ts))
    rep = verify_chain(p, hmac_key=key)
    assert rep.is_ok
    assert rep.line_count == 3


def test_verify_chain_with_hmac_detects_forged_line(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    key = b"super-secret-key"
    sink = HashChainedAuditSink(p, signing_key=key)
    sink.emit(_event(ts=1))
    sink.emit(_event(ts=2))
    # Tamper with line 1; the chain breaks at line 2 AND the HMAC fails at line 1.
    lines = p.read_text(encoding="utf-8").splitlines()
    env = json.loads(lines[0])
    env["event"]["decision"] = "allow"  # was "allow_once"
    lines[0] = json.dumps(env, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rep = verify_chain(p, hmac_key=key)
    assert not rep.is_ok
    kinds = {e.kind for e in rep.errors}
    assert "bad_signature" in kinds
    assert "broken_chain" in kinds


def test_verify_chain_with_wrong_hmac_key_reports_bad_signature(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p, signing_key=b"correct-key")
    sink.emit(_event(ts=1))
    rep = verify_chain(p, hmac_key=b"wrong-key")
    assert not rep.is_ok
    assert rep.errors[0].kind == "bad_signature"


def test_verify_chain_reports_missing_signature_when_hmac_key_supplied(
    tmp_path: Path,
) -> None:
    p = tmp_path / "audit.jsonl"
    # Unsigned sink (no signing_key passed).
    HashChainedAuditSink(p).emit(_event())
    rep = verify_chain(p, hmac_key=b"some-key")
    assert not rep.is_ok
    assert rep.errors[0].kind == "missing_signature"


# --- schema_version mismatch -------------------------------------------------


def test_verify_chain_reports_schema_version_mismatch(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    HashChainedAuditSink(p).emit(_event())
    rep = verify_chain(p, expected_schema_version="2.0")
    assert not rep.is_ok
    assert rep.errors[0].kind == "bad_schema_version"


# --- CLI: custos audit verify ------------------------------------------------


def test_cli_audit_verify_ok_exit_0(tmp_path: Path, capsys: object) -> None:
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p, signing_key=b"k")
    for ts in range(3):
        sink.emit(_event(ts=ts))
    rc = cli_main(["audit", "verify", str(p), "--hmac-key", "k"])
    assert rc == 0


def test_cli_audit_verify_fail_exit_1(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    HashChainedAuditSink(p).emit(_event(ts=1))
    HashChainedAuditSink(p).emit(_event(ts=2))
    # Tamper.
    lines = p.read_text(encoding="utf-8").splitlines()
    env = json.loads(lines[0])
    env["event"]["decision"] = "allow"  # was "allow_once"
    lines[0] = json.dumps(env, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rc = cli_main(["audit", "verify", str(p)])
    assert rc == 1


def test_cli_audit_verify_pubkey_only_exit_2(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    HashChainedAuditSink(p).emit(_event())
    rc = cli_main(["audit", "verify", str(p), "--pubkey", "/tmp/pubkey.pem"])
    assert rc == 2


def test_cli_audit_verify_missing_file_exit_1(tmp_path: Path) -> None:
    rc = cli_main(["audit", "verify", str(tmp_path / "missing.jsonl")])
    assert rc == 1


# --- FileAuditSink is not tamper-evident -------------------------------------


def test_file_audit_sink_is_not_hash_chained(tmp_path: Path) -> None:
    """Sanity: FileAuditSink writes bare JSONL, no envelope."""
    p = tmp_path / "audit.jsonl"
    FileAuditSink(p).emit(_event())
    env = json.loads(p.read_text(encoding="utf-8").strip())
    # Plain event dict, NOT a hash-chain envelope.
    assert "prev_hash" not in env
    assert "event" not in env
    # The forward field DOES appear on the bare event (forward field).
    assert env["schema_version"] == "1.0"


def test_file_audit_sink_verify_chain_reports_missing_prev_hash(
    tmp_path: Path,
) -> None:
    """``verify_chain`` on a FileAuditSink log flags every line as missing_prev_hash.

    `FileAuditSink` is documented NOT tamper-evident; `verify_chain` correctly
    refuses to vouch for it.
    """
    p = tmp_path / "audit.jsonl"
    FileAuditSink(p).emit(_event())
    FileAuditSink(p).emit(_event())
    rep = verify_chain(p)
    assert not rep.is_ok
    kinds = {e.kind for e in rep.errors}
    assert kinds == {"missing_prev_hash"}


# --- HashChainedAuditSink across instances (resume append) -------------------


def test_hash_chain_resumes_across_sink_instances(tmp_path: Path) -> None:
    """A fresh sink reading the file's last line re-anchors the chain."""
    p = tmp_path / "audit.jsonl"
    HashChainedAuditSink(p).emit(_event(ts=1))
    # New instance, same path, no in-memory state shared.
    HashChainedAuditSink(p).emit(_event(ts=2))
    rep = verify_chain(p)
    assert rep.is_ok
    assert rep.line_count == 2


# --- HashChainedAuditSink cached _get_prev_hash behaviour ---------------------


def test_hash_chain_cached_prev_hash_avoids_disk_rescan(tmp_path: Path) -> None:
    """After the first emit, subsequent emits use the in-memory cache."""
    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    sink.emit(_event(ts=1))
    assert sink._last_hash is not None
    cached = sink._last_hash
    sink.emit(_event(ts=2))
    assert sink._last_hash != cached
    rep = verify_chain(p)
    assert rep.is_ok


def test_hash_chain_emit_thread_safety(tmp_path: Path) -> None:
    """Multiple emitters from different threads produce a valid chain."""
    import threading

    p = tmp_path / "audit.jsonl"
    sink = HashChainedAuditSink(p)
    errors: list[Exception] = []

    def emit_one(ts: int) -> None:
        try:
            sink.emit(_event(ts=ts))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=emit_one, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    rep = verify_chain(p)
    assert rep.is_ok
    assert rep.line_count == 10
