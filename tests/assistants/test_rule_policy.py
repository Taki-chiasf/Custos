"""Tests for :class:`custos.assistants.RulePolicy` (A7).

Pure deterministic rules; no LLM. Verifies first-match-wins via the rule
table and the tier-scaled default-deny fallback.
"""

from __future__ import annotations

from custos.assistants import RulePolicy
from custos.schema import (
    AssistantOutput,
    Decision,
    Invocation,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)


def _ctx() -> SubjectContext:
    return SubjectContext(user_id="u1")


def _inv(tool: str = "fs.read", *, descriptor: ToolDescriptor | None = None) -> Invocation:
    return Invocation(tool=tool, args={}, context=_ctx(), descriptor=descriptor)


def _desc(risk_tier: int = 1, side: frozenset[SideEffect] = frozenset()) -> ToolDescriptor:
    return ToolDescriptor(name="t", risk_tier=risk_tier, side_effects=side)


def test_rule_policy_no_rules_returns_default_deny() -> None:
    asst = RulePolicy()
    out = asst.decide(_inv(descriptor=_desc(2)), _ctx())
    assert out.decision == Decision.DENY
    assert 0.0 <= out.risk <= 1.0
    assert "no rule matched" in out.reasoning


def test_rule_policy_first_matching_rule_wins() -> None:
    rules = [
        ({"tool": "fs.*"}, AssistantOutput(decision=Decision.ALLOW_ONCE, reasoning="read ok")),
        ({"tool": "*"}, AssistantOutput(decision=Decision.DENY, reasoning="catchall")),
    ]
    asst = RulePolicy(rules)
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx())
    assert out.decision == Decision.ALLOW_ONCE
    assert out.reasoning == "read ok"


def test_rule_policy_falls_through_to_second_rule_when_first_misses() -> None:
    rules = [
        ({"tool": "shell.*"}, AssistantOutput(decision=Decision.DENY, reasoning="shell denied")),
        (
            {"tool": "*"},
            AssistantOutput(decision=Decision.ALLOW, reasoning="everything else allowed"),
        ),
    ]
    asst = RulePolicy(rules)
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx())
    assert out.decision == Decision.ALLOW
    assert out.reasoning == "everything else allowed"


def test_rule_policy_risk_scaled_from_tier_on_no_match() -> None:
    asst = RulePolicy()
    # tier 1 -> 0.2, tier 5 -> 1.0
    out1 = asst.decide(_inv(descriptor=_desc(1)), _ctx())
    assert out1.risk == 0.2
    out5 = asst.decide(_inv(descriptor=_desc(5)), _ctx())
    assert out5.risk == 1.0


def test_rule_policy_default_decision_configurable() -> None:
    asst = RulePolicy(default_decision=Decision.PROMPT)
    out = asst.decide(_inv(descriptor=_desc(1)), _ctx())
    assert out.decision == Decision.PROMPT


def test_rule_policy_no_descriptor_uses_tier_3_default() -> None:
    asst = RulePolicy()
    out = asst.decide(_inv(descriptor=None), _ctx())
    assert out.decision == Decision.DENY
    assert round(out.risk, 3) == 0.6  # 3 * 0.2


def test_rule_policy_name_attribute() -> None:
    assert RulePolicy().name == "rule-policy"
