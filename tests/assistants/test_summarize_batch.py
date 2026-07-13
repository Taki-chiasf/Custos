"""Tests for A8 ``summarize-batch`` assistant ."""

from __future__ import annotations

from custos.assistants.summarize_batch import SummarizeBatchAssistant
from custos.schema import Decision, Invocation, SubjectContext


def _inv() -> Invocation:
    return Invocation(
        tool="email.send", args={"to": "a@x.com"}, context=SubjectContext(user_id="u1")
    )


def test_returns_prompt_with_fatigue_hint() -> None:
    asst = SummarizeBatchAssistant()
    out = asst.decide(_inv(), SubjectContext(user_id="u1"))
    assert out.decision == Decision.PROMPT
    assert out.fatigue_hint is True


def test_name_attribute() -> None:
    assert SummarizeBatchAssistant().name == "summarize-batch"


def test_risk_in_range() -> None:
    out = SummarizeBatchAssistant().decide(_inv(), SubjectContext(user_id="u1"))
    assert 0.0 <= out.risk <= 1.0


def test_reasoning_non_empty() -> None:
    out = SummarizeBatchAssistant().decide(_inv(), SubjectContext(user_id="u1"))
    assert out.reasoning


def test_no_persist_rule() -> None:
    out = SummarizeBatchAssistant().decide(_inv(), SubjectContext(user_id="u1"))
    assert out.persist_rule is None


def test_observe_user_message_is_noop() -> None:
    """A8 inherits AssistantBase's no-op observe_user_message."""
    asst = SummarizeBatchAssistant()
    asst.observe_user_message("hello")  # should not raise


def test_satisfies_assistant_protocol() -> None:
    from custos.assistants.base import Assistant

    assert isinstance(SummarizeBatchAssistant(), Assistant)
