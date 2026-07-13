"""Tests for :mod:`custos.audit` - file + stdout sinks ."""

from __future__ import annotations

import io
import json
from pathlib import Path

from custos.audit import FileAuditSink, NullAuditSink, StdoutAuditSink
from custos.schema import AuditEvent, Decision, Invocation, SideEffect, SubjectContext


def _ctx() -> SubjectContext:
    return SubjectContext(user_id="u1", goal_id="g1")


def _inv() -> Invocation:
    return Invocation(tool="fs.read", args={"path": "/etc/passwd"}, context=_ctx())


def _event(decision: Decision = Decision.DENY) -> AuditEvent:
    return AuditEvent(
        ts_unix_ms=1700000000000,
        invocation=_inv(),
        decision=decision,
        policy_match="base:deny",
        assistant=None,
        risk_score=0.0,
        reasoning="policy: deny",
        responder=None,
        latency_ms=1,
        subject=_ctx(),
    )


def test_null_audit_sink_swallow() -> None:
    assert NullAuditSink().emit(_event()) is None


def test_file_audit_sink_writes_jsonl(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = FileAuditSink(p)
    sink.emit(_event(Decision.ALLOW))
    sink.emit(_event(Decision.DENY))
    lines = p.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["decision"] == "allow"
    assert first["policy_match"] == "base:deny"
    assert first["invocation"]["tool"] == "fs.read"
    assert first["invocation"]["args"]["path"] == "/etc/passwd"
    assert first["subject"]["user_id"] == "u1"
    second = json.loads(lines[1])
    assert second["decision"] == "deny"


def test_file_audit_sink_serializes_side_effects(tmp_path: Path) -> None:
    """Frozen dataclass + frozenset + enum serialize cleanly to JSONL."""
    from custos.schema import ToolDescriptor

    inv = Invocation(
        tool="fs.write",
        args={"x": 1},
        context=_ctx(),
        descriptor=ToolDescriptor(
            name="fs.write",
            risk_tier=3,
            side_effects=frozenset({SideEffect.WRITE, SideEffect.NETWORK}),
        ),
    )
    event = AuditEvent(
        ts_unix_ms=1,
        invocation=inv,
        decision=Decision.ALLOW,
        policy_match="base:allow",
        assistant="risk-assessment",
        risk_score=0.42,
        reasoning="ok",
        responder=None,
        latency_ms=5,
        subject=_ctx(),
    )
    p = tmp_path / "audit.jsonl"
    FileAuditSink(p).emit(event)
    record = json.loads(p.read_text(encoding="utf-8"))
    desc = record["invocation"]["descriptor"]
    assert desc is not None
    assert set(desc["side_effects"]) == {"write", "network"}  # sorted list
    assert record["assistant"] == "risk-assessment"
    assert record["risk_score"] == 0.42


def test_stdout_audit_sink_writes_one_line_per_event() -> None:
    buf = io.StringIO()
    sink = StdoutAuditSink(buf)
    sink.emit(_event(Decision.ALLOW))
    sink.emit(_event(Decision.DENY))
    out = buf.getvalue().splitlines()
    assert len(out) == 2
    assert json.loads(out[0])["decision"] == "allow"
    assert json.loads(out[1])["decision"] == "deny"


def test_audit_event_to_dict_round_trips_decision_enum() -> None:
    d = _event().to_dict()
    assert d["decision"] == "deny"  # enum serialized as .value
    assert isinstance(d["ts_unix_ms"], int)


def test_audit_event_to_dict_includes_schema_version_forward_field() -> None:
    """  : `to_dict` emits `schema_version: "1.0"`."""
    d = _event().to_dict()
    assert d["schema_version"] == "1.0"
