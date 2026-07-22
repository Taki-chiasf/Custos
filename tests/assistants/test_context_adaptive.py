"""Tests for A9 ``context-adaptive`` assistant .

Uses :class:`~custos.llm.FunctionLLMClient` with canned responses so no real
LLM/API key is needed. Verifies: goal extraction (reuses A5 shape),
sensitivity threshold split (low -> ALLOW, high -> PROMPT), safe DENY when
no LLM is configured, robustness to malformed LLM output.
"""

from __future__ import annotations

from typing import Any

from custos.assistants.base import Assistant
from custos.assistants.context_adaptive import ContextAdaptiveAssistant
from custos.llm import FunctionLLMClient
from custos.schema import Decision, Invocation, SubjectContext, ToolDescriptor


def _ctx() -> SubjectContext:
    return SubjectContext(user_id="u1")


def _inv(tool: str = "fs.write", *, args: dict[str, Any] | None = None) -> Invocation:
    return Invocation(
        tool=tool,
        args=args or {},
        context=_ctx(),
        descriptor=ToolDescriptor(name=tool, risk_tier=3),
    )


def _llm(
    sensitivity_json: str = '{"sensitivity": 0.4, "reason": "moderate"}',
) -> FunctionLLMClient:
    """Fake LLM that returns ``sensitivity_json`` on every call."""
    return FunctionLLMClient(lambda _m, _t: sensitivity_json)


def _llm_with_goals(
    goals_json: str,
    sensitivity_json: str = '{"sensitivity": 0.4, "reason": "moderate"}',
) -> FunctionLLMClient:
    """Fake LLM that returns ``goals_json`` on 1st call, ``sensitivity_json``
    thereafter (for observe_user_message -> decide flow)."""
    responses = [goals_json, sensitivity_json]

    def fn(_msgs: Any, _t: float) -> str:
        return responses.pop(0) if responses else '{"sensitivity": 1.0, "reason": "exhausted"}'

    return FunctionLLMClient(fn)


# --------------------------------------------------------------------------- #
# Sensitivity threshold split
# --------------------------------------------------------------------------- #


def test_a9_sensitivity_below_threshold_returns_allow() -> None:
    llm = _llm(sensitivity_json='{"sensitivity": 0.2, "reason": "read-only"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.ALLOW
    assert out.risk == 0.2
    assert "0.200 <= threshold 0.500" in out.reasoning
    assert "read-only" in out.reasoning


def test_a9_sensitivity_equal_to_threshold_returns_allow() -> None:
    llm = _llm(sensitivity_json='{"sensitivity": 0.5, "reason": "edge"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.ALLOW


def test_a9_sensitivity_above_threshold_returns_prompt() -> None:
    llm = _llm(sensitivity_json='{"sensitivity": 0.8, "reason": "PII access"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.PROMPT
    assert out.risk == 0.8
    assert "0.800 > threshold 0.500" in out.reasoning
    assert "PII access" in out.reasoning


def test_a9_custom_threshold() -> None:
    llm = _llm(sensitivity_json='{"sensitivity": 0.3, "reason": "low"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.25, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.PROMPT  # 0.3 > 0.25


# --------------------------------------------------------------------------- #
# Goal extraction (observe_user_message — same shape as A5)
# --------------------------------------------------------------------------- #


def test_a9_observe_user_message_extracts_goals_list() -> None:
    llm = _llm_with_goals(
        goals_json='["read docs", "send email"]',
        sensitivity_json='{"sensitivity": 0.2, "reason": "ok"}',
    )
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    asst.observe_user_message("read the docs and send an email")
    assert asst.goals == ["read docs", "send email"]


def test_a9_observe_user_message_extracts_goals_dict() -> None:
    llm = _llm_with_goals(goals_json='{"goals": ["goal a", "goal b"]}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    asst.observe_user_message("do goal a and goal b")
    assert asst.goals == ["goal a", "goal b"]


def test_a9_observe_user_message_handles_malformed_output() -> None:
    llm = _llm_with_goals(goals_json="not json at all")
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    asst.observe_user_message("hello")
    assert asst.goals == []


def test_a9_observe_user_message_filters_non_scalar_goals() -> None:
    llm = _llm_with_goals(goals_json='["real", 42, {"nested": "skip"}, null]')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    asst.observe_user_message("x")
    assert "real" in asst.goals
    assert "42" in asst.goals
    assert all(not isinstance(g, dict) for g in asst.goals)


# --------------------------------------------------------------------------- #
# Malformed sensitivity output
# --------------------------------------------------------------------------- #


def test_a9_malformed_sensitivity_falls_back_to_max() -> None:
    """Unparseable LLM output -> sensitivity=1.0 (default) -> PROMPT (safe)."""
    llm = _llm(sensitivity_json="not json at all")
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.PROMPT
    assert out.risk == 1.0


def test_a9_missing_sensitivity_key_defaults_to_max() -> None:
    llm = _llm(sensitivity_json='{"reason": "no score"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.PROMPT
    assert out.risk == 1.0


def test_a9_non_numeric_sensitivity_defaults_to_max() -> None:
    llm = _llm(sensitivity_json='{"sensitivity": "high", "reason": "bad"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.PROMPT
    assert out.risk == 1.0


def test_a9_sensitivity_clamped_to_range() -> None:
    llm = _llm(sensitivity_json='{"sensitivity": 5.0, "reason": "overflow"}')
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=llm)
    out = asst.decide(_inv(), _ctx())
    assert out.risk == 1.0  # clamped from 5.0


# --------------------------------------------------------------------------- #
# No LLM configured -> safe DENY
# --------------------------------------------------------------------------- #


def test_a9_no_llm_configured_returns_safe_deny() -> None:
    """MissingLLMClient raises NoLLMClientError -> A9 catches and returns DENY."""
    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5)  # no llm=
    out = asst.decide(_inv(), _ctx())
    assert out.decision == Decision.DENY
    assert out.risk == 1.0
    assert "no LLM configured" in out.reasoning


def test_a9_no_llm_observe_user_message_raises() -> None:
    """observe_user_message without an LLM raises (caller should configure one)."""
    import pytest

    from custos.llm import NoLLMClientError

    asst = ContextAdaptiveAssistant(sensitivity_threshold=0.5)
    with pytest.raises(NoLLMClientError):
        asst.observe_user_message("hello")


# --------------------------------------------------------------------------- #
# Attributes + Protocol
# --------------------------------------------------------------------------- #


def test_a9_name_attribute() -> None:
    assert (
        ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=_llm()).name == "context-adaptive"
    )


def test_a9_satisfies_assistant_protocol() -> None:
    assert isinstance(ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=_llm()), Assistant)


def test_a9_no_persist_rule() -> None:
    out = ContextAdaptiveAssistant(sensitivity_threshold=0.5, llm=_llm()).decide(_inv(), _ctx())
    assert out.persist_rule is None
