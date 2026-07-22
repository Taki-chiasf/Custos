"""Smoke tests confirming the scaffold wires up correctly.

These guard against accidental breakage of the public surface as
fills in the stubs. Not behavioral tests of the pipeline (those land with
each implementation milestone).
"""

from __future__ import annotations

import custos
from custos import (
    Decision,
    Gateway,
    Invocation,
    Policy,
    PolicyOutcome,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)
from custos.audit import NullAuditSink
from custos.responders import NoopResponder
from custos.schema import AuditEvent


def test_version_is_pep440ish() -> None:
    assert isinstance(custos.__version__, str)
    assert custos.__version__.count(".") >= 1


def test_decision_enum_contract() -> None:
    # : the six Custos decisions.
    assert {d.value for d in Decision} == {
        "allow",
        "allow_once",
        "allow_and_persist",
        "deny",
        "prompt",
        "defer",
    }
    assert Decision.ALLOW.is_allow
    assert not Decision.DENY.is_allow


def test_policy_outcome_contract() -> None:
    #  step 2 + : policy deny is final.
    assert {d.value for d in PolicyOutcome} == {"allow", "deny", "prompt", "assist"}


def test_side_effect_taxonomy() -> None:

    assert {s.value for s in SideEffect} == {
        "none",
        "read",
        "write",
        "network",
        "payment",
        "destructive",
        "pii",
    }


def test_tool_descriptor_risk_tier_bounds() -> None:
    import pytest

    ToolDescriptor(name="fs.read", risk_tier=1)
    ToolDescriptor(name="fs.nuke", risk_tier=5)
    with pytest.raises(ValueError):
        ToolDescriptor(name="bad", risk_tier=0)
    with pytest.raises(ValueError):
        ToolDescriptor(name="bad", risk_tier=6)


def test_gateway_default_denies_unknown_invocation() -> None:
    # Default policy (no rules) -> default-deny .
    ctx = SubjectContext(user_id="u1")
    inv = Invocation(tool="fs.read", args={}, context=ctx)
    gw = Gateway(policy=Policy(), responder=NoopResponder(), audit_sink=None)
    assert gw.decide(inv) == Decision.DENY


def test_null_audit_sink_swallow() -> None:
    # Audit infrastructure wires up without error.
    ctx = SubjectContext(user_id="u1")
    inv = Invocation(tool="fs.read", args={}, context=ctx)
    event = AuditEvent(
        ts_unix_ms=0,
        invocation=inv,
        decision=Decision.DENY,
        policy_match=None,
        assistant=None,
        risk_score=0.0,
        reasoning="scaffold smoke",
        responder=None,
        latency_ms=0,
        subject=ctx,
    )
    # Should not raise; returns None.
    assert NullAuditSink().emit(event) is None
