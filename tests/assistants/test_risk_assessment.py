"""Tests for A5 ``RiskAssessment`` and A6 ``RiskAssessmentAutonomous`` .

Uses :class:`~custos.llm.FunctionLLMClient` with canned responses so no real
LLM/API key is needed. Verifies the 2-LLM-call shape (goal extraction + risk
judging), the tolerance threshold split (≤ → allow_once, > → prompt [A5] /
deny [A6]), and robustness to malformed LLM output.
"""

from __future__ import annotations

from typing import Any

from custos.assistants import RiskAssessment, RiskAssessmentAutonomous
from custos.assistants.base import AssistantBase
from custos.llm import FunctionLLMClient
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext, ToolDescriptor


def _ctx() -> SubjectContext:
    return SubjectContext(user_id="u1")


def _inv(tool: str = "fs.write", *, args: dict[str, Any] | None = None) -> Invocation:
    return Invocation(
        tool=tool,
        args=args or {},
        context=_ctx(),
        descriptor=ToolDescriptor(name=tool, risk_tier=3),
    )


def _llm(risk_json: str = '{"risk": 0.4, "reason": "mid"}') -> FunctionLLMClient:
    """Fake LLM that returns ``risk_json`` on every call (no goal extraction)."""
    return FunctionLLMClient(lambda _m, _t: risk_json)


def _llm_with_goals(
    goals_json: str, risk_json: str = '{"risk": 0.4, "reason": "mid"}'
) -> FunctionLLMClient:
    """Fake LLM that returns ``goals_json`` on the 1st call, ``risk_json``
    thereafter. Use for tests that call ``observe_user_message`` then ``decide``."""
    responses = [goals_json, risk_json]

    def fn(_msgs: Any, _t: float) -> str:
        return responses.pop(0) if responses else '{"risk": 1.0, "reason": "exhausted"}'

    return FunctionLLMClient(fn)


# --------------------------------------------------------------------------- #
# AssistantBase (D4)
# --------------------------------------------------------------------------- #


def test_assistant_base_observe_user_message_is_noop_by_default() -> None:
    class NoOpAsst(AssistantBase):
        name = "noop"

        def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
            return AssistantOutput(decision=Decision.DENY)

    asst = NoOpAsst()
    assert asst.observe_user_message("hello") is None


def test_assistant_base_decide_is_abstract() -> None:
    import pytest

    with pytest.raises(TypeError):
        AssistantBase()  # type: ignore[abstract]


# --------------------------------------------------------------------------- #
# A5 RiskAssessment - tolerance split
# --------------------------------------------------------------------------- #


def test_a5_risk_below_tolerance_returns_allow_once() -> None:
    llm = _llm(risk_json='{"risk": 0.2, "reason": "low"}')
    asst = RiskAssessment(tolerance=0.35, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.ALLOW_ONCE
    assert out.risk == 0.2
    assert "0.200 <= tolerance 0.350" in out.reasoning


def test_a5_risk_equal_to_tolerance_returns_allow_once() -> None:
    llm = _llm(risk_json='{"risk": 0.35, "reason": "edge"}')
    asst = RiskAssessment(tolerance=0.35, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.ALLOW_ONCE


def test_a5_risk_above_tolerance_returns_prompt() -> None:
    llm = _llm(risk_json='{"risk": 0.8, "reason": "high"}')
    asst = RiskAssessment(tolerance=0.35, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.PROMPT
    assert out.risk == 0.8
    assert "0.800 > tolerance 0.350" in out.reasoning


# --------------------------------------------------------------------------- #
# A6 RiskAssessmentAutonomous - never escalates
# --------------------------------------------------------------------------- #


def test_a6_risk_above_tolerance_returns_deny_not_prompt() -> None:
    llm = _llm(risk_json='{"risk": 0.9, "reason": "dangerous"}')
    asst = RiskAssessmentAutonomous(tolerance=0.35, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.DENY
    assert "autonomous: no escalation" in out.reasoning


def test_a6_risk_below_tolerance_still_returns_allow_once() -> None:
    llm = _llm(risk_json='{"risk": 0.1, "reason": "safe"}')
    asst = RiskAssessmentAutonomous(tolerance=0.35, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.ALLOW_ONCE


def test_a6_name_attribute() -> None:
    assert RiskAssessmentAutonomous(tolerance=0.5, llm=_llm()).name == "risk-assessment-autonomous"


# --------------------------------------------------------------------------- #
# Goal extraction (observe_user_message)
# --------------------------------------------------------------------------- #


def test_a5_observe_user_message_extracts_goals_list() -> None:
    llm = _llm_with_goals(goals_json='["read the docs", "summarize findings"]')
    asst = RiskAssessment(tolerance=0.5, llm=llm)
    asst.observe_user_message("read the docs and summarize findings")
    assert asst.goals == ["read the docs", "summarize findings"]


def test_a5_observe_user_message_extracts_goals_dict() -> None:
    llm = _llm_with_goals(goals_json='{"goals": ["goal a", "goal b"]}')
    asst = RiskAssessment(tolerance=0.5, llm=llm)
    asst.observe_user_message("do goal a and goal b")
    assert asst.goals == ["goal a", "goal b"]


def test_a5_observe_user_message_handles_malformed_output() -> None:
    llm = _llm_with_goals(goals_json="not json at all")
    asst = RiskAssessment(tolerance=0.5, llm=llm)
    asst.observe_user_message("hello")
    assert asst.goals == []


def test_a5_observe_user_message_filters_non_scalar_goals() -> None:
    llm = _llm_with_goals(goals_json='["real", 42, {"nested": "skip"}, null]')
    asst = RiskAssessment(tolerance=0.5, llm=llm)
    asst.observe_user_message("x")
    # Only str/int/float survive; dict and None are filtered.
    assert "real" in asst.goals
    assert "42" in asst.goals
    assert all(not isinstance(g, dict) for g in asst.goals)
