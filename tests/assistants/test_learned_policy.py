"""Tests for :class:`custos.assistants.LearnedPolicyAssistant` (A10).

Covers:
  - cold-start falls back to A7 RulePolicy (no learned entries)
  - after a recorded user decision, ``decide`` auto-resolves to the learned choice
  - disagreement-aware: conflicting observations fall back to A7
  - ``read_only`` opt-out blocks learning (A10-poisoning mitigation)
  - args-hash key isolation (different args → different learned entry)
  - per-user isolation (different user → different learned entry)
  - ``exfiltrates_args=False`` (air-gapped-safe, Q11)
  - Protocol satisfaction + name
  - ``allow_and_persist`` poisoning handled at the gateway layer (not here),
    demonstrated via a Gateway integration test
"""

from __future__ import annotations

from typing import Any

from custos.assistants import LearnedPolicyAssistant, LearnedPolicyStore, RulePolicy
from custos.audit import NullAuditSink
from custos.gateway import Gateway
from custos.policy import Policy, PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.schema import (
    AssistantOutput,
    Decision,
    Invocation,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ctx(user_id: str = "u1") -> SubjectContext:
    return SubjectContext(user_id=user_id)


def _inv(
    tool: str = "fs.read",
    *,
    args: dict[str, Any] | None = None,
    descriptor: ToolDescriptor | None = None,
    user_id: str = "u1",
) -> Invocation:
    return Invocation(tool=tool, args=args or {}, context=_ctx(user_id), descriptor=descriptor)


def _desc(risk_tier: int = 1, side: frozenset[SideEffect] = frozenset()) -> ToolDescriptor:
    return ToolDescriptor(name="t", risk_tier=risk_tier, side_effects=side)


def _policy(rules: list[PolicyRuleSpec], *, default: str = "deny") -> Policy:
    return Policy.from_spec(
        PolicyFile(
            version=1,
            default=default,
            overlays=(PolicyOverlaySpec(id="base", rules=tuple(rules)),),
        )
    )


# --------------------------------------------------------------------------- #
# Cold-start: A10 with no observations falls back to A7 RulePolicy
# --------------------------------------------------------------------------- #


def test_cold_start_falls_back_to_rule_policy_default_deny() -> None:
    asst = LearnedPolicyAssistant()
    out = asst.decide(_inv(descriptor=_desc(risk_tier=2)), _ctx())
    assert out.decision == Decision.DENY
    assert "no rule matched" in out.reasoning


def test_cold_start_uses_composed_rule_table() -> None:
    rules = [
        (
            {"tool": "fs.*"},
            AssistantOutput(decision=Decision.ALLOW_ONCE, reasoning="read ok"),
        )
    ]
    asst = LearnedPolicyAssistant(rules=rules)
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx())
    assert out.decision == Decision.ALLOW_ONCE
    assert out.reasoning == "read ok"


def test_cold_start_falls_back_when_explicit_fallback_passed() -> None:
    fallback = RulePolicy(
        [({"tool": "*"}, AssistantOutput(decision=Decision.PROMPT, reasoning="fb"))]
    )
    asst = LearnedPolicyAssistant(fallback=fallback)
    out = asst.decide(_inv(descriptor=_desc(1)), _ctx())
    assert out.decision == Decision.PROMPT
    assert out.reasoning == "fb"


# --------------------------------------------------------------------------- #
# Learning: a recorded user decision makes ``decide`` auto-resolve
# --------------------------------------------------------------------------- #


def test_recorded_allow_auto_resolves_on_next_decide() -> None:
    asst = LearnedPolicyAssistant()
    inv = _inv(tool="email.send", args={"to": "alice@x.com"}, descriptor=_desc(3))
    # First decide: cold-start fallback (deny).
    out1 = asst.decide(inv, inv.context)
    assert out1.decision == Decision.DENY
    # Host records the user's actual choice (allow).
    asst.record_decision(inv, Decision.ALLOW)
    # Second decide: auto-resolves to the learned choice.
    out2 = asst.decide(inv, inv.context)
    assert out2.decision == Decision.ALLOW
    assert "learned-policy" in out2.reasoning


def test_recorded_deny_auto_resolves_on_next_decide() -> None:
    asst = LearnedPolicyAssistant()
    inv = _inv(descriptor=_desc(1))
    asst.record_decision(inv, Decision.DENY)
    out = asst.decide(inv, inv.context)
    assert out.decision == Decision.DENY
    assert "learned-policy" in out.reasoning


def test_recorded_allow_once_auto_resolves() -> None:
    asst = LearnedPolicyAssistant()
    inv = _inv(descriptor=_desc(1))
    asst.record_decision(inv, Decision.ALLOW_ONCE)
    out = asst.decide(inv, inv.context)
    assert out.decision == Decision.ALLOW_ONCE


# --------------------------------------------------------------------------- #
# Args-hash isolation (different args → different learned entry)
# --------------------------------------------------------------------------- #


def test_args_isolation_different_args_do_not_share() -> None:
    asst = LearnedPolicyAssistant()
    inv_a = _inv(args={"path": "/tmp/a"}, descriptor=_desc(1))
    inv_b = _inv(args={"path": "/tmp/b"}, descriptor=_desc(1))
    asst.record_decision(inv_a, Decision.ALLOW)
    # inv_b has not been observed - falls back to A7.
    out = asst.decide(inv_b, inv_b.context)
    assert out.decision == Decision.DENY
    assert "no rule matched" in out.reasoning


def test_args_isolation_same_args_different_order_hashes_equal() -> None:
    """H13 canonicalization: dict keys are sorted, so order doesn't matter."""
    asst = LearnedPolicyAssistant()
    inv1 = _inv(args={"a": "1", "b": "2"}, descriptor=_desc(1))
    inv2 = _inv(args={"b": "2", "a": "1"}, descriptor=_desc(1))
    asst.record_decision(inv1, Decision.ALLOW)
    out = asst.decide(inv2, inv2.context)
    assert out.decision == Decision.ALLOW


# --------------------------------------------------------------------------- #
# Per-user isolation
# --------------------------------------------------------------------------- #


def test_per_user_isolation() -> None:
    asst = LearnedPolicyAssistant()
    inv_alice = _inv(args={"x": "1"}, user_id="alice")
    inv_bob = _inv(args={"x": "1"}, user_id="bob")
    asst.record_decision(inv_alice, Decision.ALLOW)
    # Bob has not observed - falls back to A7.
    out = asst.decide(inv_bob, inv_bob.context)
    assert out.decision == Decision.DENY


# --------------------------------------------------------------------------- #
# Disagreement-aware: conflicting user observations fall back to A7
# --------------------------------------------------------------------------- #


def test_disagreement_falls_back_to_rule_policy() -> None:
    asst = LearnedPolicyAssistant()
    inv = _inv(args={"x": "1"}, descriptor=_desc(1))
    asst.record_decision(inv, Decision.ALLOW)
    asst.record_decision(inv, Decision.DENY)  # conflicting
    out = asst.decide(inv, inv.context)
    # Disagreement -> NOT confident -> fall back to A7 default deny.
    assert out.decision == Decision.DENY
    assert "no rule matched" in out.reasoning


def test_repeated_agreement_stays_confident() -> None:
    asst = LearnedPolicyAssistant()
    inv = _inv(args={"x": "1"}, descriptor=_desc(1))
    asst.record_decision(inv, Decision.ALLOW)
    asst.record_decision(inv, Decision.ALLOW)
    asst.record_decision(inv, Decision.ALLOW)
    out = asst.decide(inv, inv.context)
    assert out.decision == Decision.ALLOW
    assert "learned-policy" in out.reasoning


def test_higher_confidence_threshold_demands_more_observations() -> None:
    asst = LearnedPolicyAssistant(confidence_threshold=3)
    inv = _inv(args={"x": "1"}, descriptor=_desc(1))
    asst.record_decision(inv, Decision.ALLOW)  # agree=1 < 3 -> not confident
    out1 = asst.decide(inv, inv.context)
    assert out1.decision == Decision.DENY  # fallback
    asst.record_decision(inv, Decision.ALLOW)  # agree=2 < 3
    asst.record_decision(inv, Decision.ALLOW)  # agree=3 == 3 -> confident
    out2 = asst.decide(inv, inv.context)
    assert out2.decision == Decision.ALLOW


# --------------------------------------------------------------------------- #
# read_only opt-out (A10-poisoning mitigation)
# --------------------------------------------------------------------------- #


def test_read_only_blocks_record_decision() -> None:
    asst = LearnedPolicyAssistant(read_only=True)
    inv = _inv(args={"x": "1"}, descriptor=_desc(1))
    asst.record_decision(inv, Decision.ALLOW)  # no-op
    out = asst.decide(inv, inv.context)
    # Still cold-start fallback; nothing was learned.
    assert out.decision == Decision.DENY
    assert "no rule matched" in out.reasoning


def test_read_only_store_directly() -> None:
    store = LearnedPolicyStore(read_only=True)
    store.record("u1", "fs.read", "hash", Decision.ALLOW)
    assert store.lookup("u1", "fs.read", "hash") is None


def test_read_only_store_clear_is_allowed() -> None:
    # clear is maintenance, not learning; allowed even in read-only mode.
    store = LearnedPolicyStore(read_only=True)
    store.clear()  # no error


# --------------------------------------------------------------------------- #
# Shared LearnedPolicyStore across assistants
# --------------------------------------------------------------------------- #


def test_shared_store_persists_across_assistant_instances() -> None:
    store = LearnedPolicyStore()
    a1 = LearnedPolicyAssistant(store=store)
    a2 = LearnedPolicyAssistant(store=store)
    inv = _inv(args={"x": "1"}, descriptor=_desc(1))
    a1.record_decision(inv, Decision.ALLOW)
    out = a2.decide(inv, inv.context)
    assert out.decision == Decision.ALLOW


# --------------------------------------------------------------------------- #
# Security: exfiltrates_args + name + Protocol
# --------------------------------------------------------------------------- #


def test_exfiltrates_args_false_air_gapped_safe() -> None:
    assert LearnedPolicyAssistant().exfiltrates_args is False


def test_name_attribute() -> None:
    assert LearnedPolicyAssistant().name == "learned-policy"


def test_satisfies_assistant_protocol() -> None:
    from custos.assistants.base import Assistant

    asst = LearnedPolicyAssistant()
    assert isinstance(asst, Assistant)


# --------------------------------------------------------------------------- #
# allow_and_persist: poisoning handled at the gateway (H3 narrowness), not here
# --------------------------------------------------------------------------- #


def test_gateway_rejects_broad_persisted_rule_from_learned_policy() -> None:
    """A10's ALLOW_AND_PERSIST with ``any:true`` is rejected by the gateway (H3)."""
    # Force the assistant to emit a poisoned broad allow - mimicking a
    # confused-approver attack vector (A10-poisoning risk).
    asst_with_poison = LearnedPolicyAssistant()
    asst_with_poison.decide = lambda inv, ctx: AssistantOutput(  # type: ignore[assignment]
        decision=Decision.ALLOW_AND_PERSIST,
        risk=0.0,
        persist_rule={"match": {"any": True}, "action": "allow"},
    )
    policy = _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:learned-policy")])
    gw = Gateway(
        policy=policy,
        assistant=asst_with_poison,
        audit_sink=NullAuditSink(),
    )
    decision = gw.decide(_inv(descriptor=_desc(1))).decision
    # The one-time allow is returned (ALLOW_AND_PERSIST → ALLOW_ONCE per)...
    assert decision == Decision.ALLOW_ONCE
    # ...BUT the broad ``any:true`` rule was rejected by H3 + NOT inserted.
    # The next identical call hits the matched ``assist:learned-policy`` rule
    # again, NOT a broad allow - proving the poisoning was structurally blocked.
    rules = policy.rules
    # Policy still has exactly 1 rule (the original assist rule), no poison rule inserted.
    assist_rules = [r for r in rules if r.action.startswith("assist")]
    assert len(assist_rules) == 1
    broad_allows = [r for r in rules if r.action == "allow" and r.spec.match.get("any") is True]
    assert len(broad_allows) == 0


def test_record_decision_after_gateway_user_resolved_prompt() -> None:
    """End-to-end: host records the user's ALLOW choice → next call auto-allows."""
    asst = LearnedPolicyAssistant()
    policy = _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:learned-policy")])

    class StubResponder:
        name = "stub"

        def prompt(self, req):
            from custos.schema import PromptResponse

            return PromptResponse(choice=Decision.ALLOW)

    gw = Gateway(
        policy=policy,
        assistant=asst,
        responder=StubResponder(),
        audit_sink=NullAuditSink(),
    )
    inv = _inv(tool="fs.read", args={"path": "/tmp/x"}, descriptor=_desc(1))
    # First call: cold-start fallback deny → assistant returns DENY → gateway
    # sees DENY (no responder path; A10 doesn't PROMPT). Record nothing.
    first = gw.decide(inv).decision
    assert first == Decision.DENY
    # Host now observes a user-choice for the SAME call via an external prompt
    # (simulating the host wiring record_decision to its own approval surface).
    asst.record_decision(inv, Decision.ALLOW)
    # Second call: learned-policy auto-resolves to ALLOW.
    second = gw.decide(inv).decision
    assert second == Decision.ALLOW
