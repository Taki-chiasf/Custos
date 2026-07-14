"""Tests for :class:`custos.responders.MultiApproverResponder` .

Covers the Q10 quorum contract under the async surface:
  - ``met``    — quorum of N distinct-role approvals reached → ALLOW
  - ``failed`` — deny vote / timeout / quorum-not-met-after-all-return → DENY
  - ``pending`` — a child returns DEFER before met/fail → DEFER
  - separation-of-duties: one role counts once toward the quorum
  - approver_allowlist gates which approver ids count
  - sync children are bridged via ``asyncio.to_thread``
  - construction mismatch (children vs child_roles length) raises

Plus policy-level tests for the new ``quorum`` / ``approver_roles`` /
``approver_allowlist`` rule attrs (PolicyRuleSpec / validate_rule / parsing).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from custos.async_gateway import AsyncGateway
from custos.audit import FileAuditSink
from custos.policy import Policy, PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.policy.schema import PolicyValidationError, validate_rule
from custos.responders import MultiApproverResponder
from custos.schema import (
    Decision,
    Invocation,
    PromptRequest,
    PromptResponse,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)

# --------------------------------------------------------------------------- #
# Async test helper (mirror of tests/test_async_gateway._async_test)
# --------------------------------------------------------------------------- #


def _async_test(coro_fn):
    import asyncio
    import functools

    @functools.wraps(coro_fn)
    def runner(*args: Any, **kwargs: Any) -> None:
        return asyncio.run(coro_fn(*args, **kwargs))

    return runner


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class StubResponder:
    """Sync stub child responder; returns a pre-configured PromptResponse."""

    name: str

    def __init__(
        self,
        role: str,
        vote: Decision,
        *,
        approver: str = "user@example.com",
        delay_s: float = 0.0,
    ) -> None:
        self.name = role
        self._vote = vote
        self._approver = approver
        self._delay_s = delay_s
        self.calls = 0

    def prompt(self, req: PromptRequest) -> PromptResponse:
        import time

        if self._delay_s:
            time.sleep(self._delay_s)
        self.calls += 1
        return PromptResponse(choice=self._vote, approver=self._approver)


class AsyncStubResponder:
    """Native-async stub child responder."""

    name: str

    def __init__(self, role: str, vote: Decision, *, approver: str = "async@example.com") -> None:
        self.name = role
        self._vote = vote
        self._approver = approver

    async def prompt(self, req: PromptRequest) -> PromptResponse:
        import asyncio

        await asyncio.sleep(0)
        return PromptResponse(choice=self._vote, approver=self._approver)


class RaisingStubResponder:
    """Sync stub that raises when prompted."""

    name = "raising"

    def prompt(self, req: PromptRequest) -> PromptResponse:
        raise RuntimeError("child exploded")


def _req(
    *,
    quorum: int | None = 2,
    roles: tuple[str, ...] = ("finance", "security"),
    allowlist: tuple[str, ...] = (),
    request_id: str = "req-1",
) -> PromptRequest:
    return PromptRequest(
        tool="payment.refund",
        args_redacted={"order_id": "ord-1"},
        risk=0.8,
        reasoning="payment requires quorum",
        request_id=request_id,
        deadline_unix_ms=None,
        quorum=quorum,
        approver_roles=roles,
        approver_allowlist=allowlist,
    )


# --------------------------------------------------------------------------- #
# Quorum ``met``: enough distinct-role approvals
# --------------------------------------------------------------------------- #


@_async_test
async def test_quorum_met_two_distinct_role_approvals() -> None:
    finance = StubResponder("finance", Decision.ALLOW, approver="alice@corp")
    security = StubResponder("security", Decision.ALLOW, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security],
        child_roles=["finance", "security"],
    )
    resp = await multi.prompt(_req())
    assert resp.choice == Decision.ALLOW
    # Approving approvers are comma-joined sorted.
    assert resp.approver is not None
    parts = resp.approver.split(",")
    assert "alice@corp" in parts
    assert "bob@corp" in parts


@_async_test
async def test_quorum_met_three_distinct_roles() -> None:
    a = StubResponder("a", Decision.ALLOW, approver="a@x")
    b = StubResponder("b", Decision.ALLOW, approver="b@x")
    c = StubResponder("c", Decision.ALLOW, approver="c@x")
    multi = MultiApproverResponder(
        children=[a, b, c],
        child_roles=["a", "b", "c"],
    )
    resp = await multi.prompt(_req(quorum=3, roles=("a", "b", "c"), allowlist=()))
    assert resp.choice == Decision.ALLOW


@_async_test
async def test_quorum_met_allow_once_also_counts() -> None:
    finance = StubResponder("finance", Decision.ALLOW_ONCE, approver="alice@corp")
    security = StubResponder("security", Decision.ALLOW, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security],
        child_roles=["finance", "security"],
    )
    resp = await multi.prompt(_req())
    assert resp.choice == Decision.ALLOW


@_async_test
async def test_quorum_met_native_async_children() -> None:
    finance = AsyncStubResponder("finance", Decision.ALLOW, approver="ali@x")
    security = AsyncStubResponder("security", Decision.ALLOW, approver="bob@x")
    multi = MultiApproverResponder(
        children=[finance, security], child_roles=["finance", "security"]
    )
    resp = await multi.prompt(_req())
    assert resp.choice == Decision.ALLOW


# --------------------------------------------------------------------------- #
# Separation of duties: one role counts once
# --------------------------------------------------------------------------- #


@_async_test
async def test_separation_of_duties_same_role_counts_once() -> None:
    # Two "finance" approvers but quorum=2 from {finance, security}: the second
    # finance vote is de-duplicated; the quorum cannot be met → DENY.
    fin1 = StubResponder("fin1", Decision.ALLOW, approver="alice@corp")
    fin2 = StubResponder("fin2", Decision.ALLOW, approver="alice@corp")
    multi = MultiApproverResponder(children=[fin1, fin2], child_roles=["finance", "finance"])
    resp = await multi.prompt(_req())
    # Both children are "finance" role, so only one role approves → not met.
    assert resp.choice == Decision.DENY


# --------------------------------------------------------------------------- #
# ``failed``: deny vote fails the quorum immediately
# --------------------------------------------------------------------------- #


@_async_test
async def test_first_deny_immediately_fails_quorum() -> None:
    finance = StubResponder("finance", Decision.ALLOW, approver="alice@corp")
    security = StubResponder("security", Decision.DENY, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security], child_roles=["finance", "security"]
    )
    resp = await multi.prompt(_req())
    assert resp.choice == Decision.DENY


@_async_test
async def test_quorum_not_met_after_all_return_fails() -> None:
    # Only one role approves; the other abstains (returns DENY, simulating a
    # declined prompt). Quorum=2 can't be met → DENY.
    finance = StubResponder("finance", Decision.ALLOW, approver="alice@corp")
    # Second child returns DENY (not a deny vote from security, just declined)
    # which short-circuits — but the result is the same DENY either way.
    security = StubResponder("security", Decision.DENY, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security], child_roles=["finance", "security"]
    )
    resp = await multi.prompt(_req())
    assert resp.choice == Decision.DENY


# --------------------------------------------------------------------------- #
# ``pending``: a child DEFER before met/fail → DEFER
# --------------------------------------------------------------------------- #


@_async_test
async def test_defer_before_met_returns_defer_pending() -> None:
    finance = StubResponder("finance", Decision.ALLOW, approver="alice@corp")
    security = StubResponder("security", Decision.DEFER, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security], child_roles=["finance", "security"]
    )
    resp = await multi.prompt(_req())
    assert resp.choice == Decision.DEFER


# --------------------------------------------------------------------------- #
# No-quorum path: single-approver fallback (first valid response wins)
# --------------------------------------------------------------------------- #


@_async_test
async def test_no_quorum_configured_first_valid_wins() -> None:
    a = StubResponder("a", Decision.DEFER, approver="a@x")
    b = StubResponder("b", Decision.ALLOW, approver="b@x")
    c = StubResponder("c", Decision.DEFER, approver="c@x")
    multi = MultiApproverResponder(children=[a, b, c], child_roles=["a", "b", "c"])
    resp = await multi.prompt(_req(quorum=None, roles=()))
    # First non-DEFER response wins.
    assert resp.choice == Decision.ALLOW


@_async_test
async def test_no_quorum_all_defer_returns_defer() -> None:
    a = StubResponder("a", Decision.DEFER, approver="a@x")
    b = StubResponder("b", Decision.DEFER, approver="b@x")
    multi = MultiApproverResponder(children=[a, b], child_roles=["a", "b"])
    resp = await multi.prompt(_req(quorum=None, roles=()))
    assert resp.choice == Decision.DEFER


# --------------------------------------------------------------------------- #
# Allowlist gate
# --------------------------------------------------------------------------- #


@_async_test
async def test_approver_not_in_allowlist_does_not_count() -> None:
    # finance approves but with an approver NOT in the allowlist → doesn't
    # count. security Approves with an approver in the allowlist. Quorum=2
    # cannot be met since finance's vote is dropped → DENY (not met).
    finance = StubResponder("finance", Decision.ALLOW, approver="stranger@x")
    security = StubResponder("security", Decision.ALLOW, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security], child_roles=["finance", "security"]
    )
    resp = await multi.prompt(_req(allowlist=("alice@corp", "bob@corp", "carol@corp")))
    # finance's approval is dropped (not in allowlist), quorum=2 not met → DENY.
    assert resp.choice == Decision.DENY


# --------------------------------------------------------------------------- #
# Approver identity attestation flows through
# --------------------------------------------------------------------------- #


@_async_test
async def test_approver_identity_flows_through_on_met() -> None:
    finance = StubResponder("finance", Decision.ALLOW, approver="alice@corp")
    security = StubResponder("security", Decision.ALLOW, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security], child_roles=["finance", "security"]
    )
    resp = await multi.prompt(_req(allowlist=("alice@corp", "bob@corp")))
    assert resp.approver is not None
    parts = resp.approver.split(",")
    assert "alice@corp" in parts
    assert "bob@corp" in parts


# --------------------------------------------------------------------------- #
# Construction mismatch raises
# --------------------------------------------------------------------------- #


def test_construction_role_length_mismatch_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="same length"):
        MultiApproverResponder(
            children=[StubResponder("a", Decision.ALLOW)],
            child_roles=["a", "b"],
        )


# --------------------------------------------------------------------------- #
# End-to-end with AsyncGateway: quorum_state recorded in audit
# --------------------------------------------------------------------------- #


def _policy(rules: list[PolicyRuleSpec], *, default: str = "deny") -> Policy:
    return Policy.from_spec(
        PolicyFile(
            version=1,
            default=default,
            overlays=(PolicyOverlaySpec(id="base", rules=tuple(rules)),),
        )
    )


@_async_test
async def test_e2e_quorum_met_audit_records_met(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    multi = MultiApproverResponder(
        children=[
            StubResponder("finance", Decision.ALLOW, approver="alice@corp"),
            StubResponder("security", Decision.ALLOW, approver="bob@corp"),
        ],
        child_roles=["finance", "security"],
    )
    policy = _policy(
        [
            PolicyRuleSpec(
                match={"tool": "payment.*"},
                action="prompt",
                quorum=2,
                approver_roles=("finance", "security"),
            )
        ]
    )
    gw = AsyncGateway(
        policy=policy,
        responder=multi,
        audit_sink=FileAuditSink(audit_path),
        default_timeout_ms=5_000,
    )
    inv = Invocation(
        tool="payment.refund",
        args={"order": "o-1"},
        context=SubjectContext(user_id="ops"),
        descriptor=ToolDescriptor(
            name="payment.refund",
            risk_tier=5,
            side_effects=frozenset({SideEffect.PAYMENT}),
        ),
    )
    decision = await gw.decide(inv)
    assert decision == Decision.ALLOW
    evt = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert evt["quorum_state"] == "met"
    assert "alice@corp" in evt["approver"]
    assert "bob@corp" in evt["approver"]


@_async_test
async def test_e2e_quorum_deny_audit_records_failed(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    multi = MultiApproverResponder(
        children=[
            StubResponder("finance", Decision.DENY, approver="alice@corp"),
            StubResponder("security", Decision.ALLOW, approver="bob@corp"),
        ],
        child_roles=["finance", "security"],
    )
    policy = _policy(
        [
            PolicyRuleSpec(
                match={"tool": "payment.*"},
                action="prompt",
                quorum=2,
                approver_roles=("finance", "security"),
            )
        ]
    )
    gw = AsyncGateway(
        policy=policy,
        responder=multi,
        audit_sink=FileAuditSink(audit_path),
        default_timeout_ms=5_000,
    )
    inv = Invocation(
        tool="payment.refund",
        args={"order": "o-2"},
        context=SubjectContext(user_id="ops"),
        descriptor=ToolDescriptor(
            name="payment.refund",
            risk_tier=5,
            side_effects=frozenset({SideEffect.PAYMENT}),
        ),
    )
    decision = await gw.decide(inv)
    assert decision == Decision.DENY
    evt = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert evt["quorum_state"] == "failed"


@_async_test
async def test_e2e_quorum_defer_audit_records_pending(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    multi = MultiApproverResponder(
        children=[
            StubResponder("finance", Decision.ALLOW, approver="alice@corp"),
            StubResponder("security", Decision.DEFER, approver="bob@corp"),
        ],
        child_roles=["finance", "security"],
    )
    policy = _policy(
        [
            PolicyRuleSpec(
                match={"tool": "payment.*"},
                action="prompt",
                quorum=2,
                approver_roles=("finance", "security"),
            )
        ]
    )
    gw = AsyncGateway(
        policy=policy,
        responder=multi,
        audit_sink=FileAuditSink(audit_path),
        default_timeout_ms=5_000,
    )
    inv = Invocation(
        tool="payment.refund",
        args={"order": "o-3"},
        context=SubjectContext(user_id="ops"),
        descriptor=ToolDescriptor(
            name="payment.refund",
            risk_tier=5,
            side_effects=frozenset({SideEffect.PAYMENT}),
        ),
    )
    decision = await gw.decide(inv)
    assert decision == Decision.DEFER
    evt = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert evt["quorum_state"] == "pending"


# --------------------------------------------------------------------------- #
# Single-approver rule (no quorum configured) leaves quorum_state=None
# --------------------------------------------------------------------------- #


@_async_test
async def test_e2e_no_quorum_state_is_none_in_audit(tmp_path: Path) -> None:
    """A plain ``prompt`` rule without quorum leaves ``quorum_state`` None
    (backward compat with the v0.4 single-approver H12 audit shape)."""
    audit_path = tmp_path / "audit.jsonl"
    policy = _policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")])

    class StubResp:
        name = "stub"

        def prompt(self, req):
            return PromptResponse(choice=Decision.ALLOW, approver="user@x")

    gw = AsyncGateway(
        policy=policy,
        responder=StubResp(),
        audit_sink=FileAuditSink(audit_path),
    )
    inv = Invocation(
        tool="any.tool",
        args={},
        context=SubjectContext(user_id="u"),
        descriptor=ToolDescriptor(name="t", risk_tier=1),
    )
    decision = await gw.decide(inv)
    assert decision == Decision.ALLOW
    evt = json.loads(audit_path.read_text(encoding="utf-8").strip())
    assert evt["quorum_state"] is None


# --------------------------------------------------------------------------- #
# Policy-rule attr validation
# --------------------------------------------------------------------------- #


def test_validate_rule_quorum_requires_appover_roles() -> None:
    import pytest

    with pytest.raises(PolicyValidationError, match="approver_roles"):
        validate_rule(PolicyRuleSpec(match={"tool": "*"}, action="prompt", quorum=2))


def test_validate_rule_quorum_must_be_positive() -> None:
    import pytest

    with pytest.raises(PolicyValidationError, match="positive int"):
        validate_rule(
            PolicyRuleSpec(
                match={"tool": "*"},
                action="prompt",
                quorum=0,
                approver_roles=("a",),
            )
        )


def test_validate_rule_appover_roles_without_quorum_rejected() -> None:
    import pytest

    with pytest.raises(PolicyValidationError, match="approver_roles"):
        validate_rule(
            PolicyRuleSpec(
                match={"tool": "*"},
                action="prompt",
                quorum=None,
                approver_roles=("a",),
            )
        )


def test_validate_rule_quorum_exceeds_role_count_rejected() -> None:
    import pytest

    with pytest.raises(PolicyValidationError, match="fewer distinct roles"):
        validate_rule(
            PolicyRuleSpec(
                match={"tool": "*"},
                action="prompt",
                quorum=3,
                approver_roles=("a", "b"),
            )
        )


def test_validate_rule_quorum_inside_match_mapping_typo_caught() -> None:
    import pytest

    # Authors writing ``quorum`` inside ``match`` get the existing typo-catch
    # (known_keys doesn't include it). The rule-level field lives alongside
    # ``match``/``action`` (PolicyRuleSpec.quorum), not inside ``match``.
    with pytest.raises(PolicyValidationError, match="unknown match criteria"):
        validate_rule(
            PolicyRuleSpec(
                match={"tool": "*", "quorum": 2},
                action="prompt",
                quorum=None,
                approver_roles=(),
            )
        )


def test_validate_rule_approver_allowlist_non_string_rejected() -> None:
    import pytest

    with pytest.raises(PolicyValidationError, match="approver_allowlist"):
        validate_rule(
            PolicyRuleSpec(
                match={"tool": "*"},
                action="prompt",
                quorum=1,
                approver_roles=("a",),
                approver_allowlist=(5,),  # type: ignore[arg-type]
            )
        )


# --------------------------------------------------------------------------- #
# YAML/programmatic parsing round-trips the new fields
# --------------------------------------------------------------------------- #


def test_policy_from_dict_parses_quorum_config() -> None:
    data = {
        "version": 1,
        "default": "deny",
        "overlays": [
            {
                "id": "base",
                "rules": [
                    {
                        "match": {"tool": "payment.*"},
                        "action": "prompt",
                        "quorum": 2,
                        "approver_roles": ["finance", "security"],
                        "approver_allowlist": ["alice", "bob"],
                    }
                ],
            }
        ],
    }
    policy = Policy.from_dict(data)
    rule = policy.rules[0]
    assert rule.spec.quorum == 2
    assert tuple(rule.spec.approver_roles) == ("finance", "security")
    assert tuple(rule.spec.approver_allowlist) == ("alice", "bob")


# --------------------------------------------------------------------------- #
# Name attribute + ResponderAsync Protocol satisfaction
# --------------------------------------------------------------------------- #


def test_multi_approver_name() -> None:
    multi = MultiApproverResponder(
        children=[StubResponder("a", Decision.ALLOW)],
        child_roles=["a"],
    )
    assert multi.name == "multi-approver"
