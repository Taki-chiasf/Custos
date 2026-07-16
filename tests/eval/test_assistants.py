"""A1/A2 reproducing expected decisions without an LLM."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from custos.eval.harness.assistants import get_permission_assistant
from custos.eval.harness.schema import JanusAssistantVerdict

_CONSTITUTION = (
    Path(__file__).resolve().parent.parent.parent
    / "eval"
    / "suites"
    / "janus_v1"
    / "fixtures"
    / "constitutions"
    / "default.md"
)


def _run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_a1_auto_approve_is_unconditional_approve_once() -> None:
    asst = get_permission_assistant("auto_approve")
    out = _run(
        asst.handle_permission_denial(
            subject={"user_id": "u1"},
            tool_name="email",
            action="send",
            args={"to": "mark.black-2134@gmail.com"},
            failed_policies=[],
        )
    )
    assert out.decision is JanusAssistantVerdict.APPROVE_ONCE
    assert out.policy is None  # auto_approve never persists


def test_a2_user_confirmation_approves_on_yes() -> None:
    yes = {"value": False}

    async def confirm_hook(prompt: str, **_: object) -> bool:
        yes["value"] = True
        return True

    asst = get_permission_assistant("user_confirmation")
    asst.set_prompt_hooks(confirm_hook=confirm_hook)
    out = _run(
        asst.handle_permission_denial(
            subject={"user_id": "u1"},
            tool_name="email",
            action="delete",
            args={"id": 1},
            failed_policies=[],
        )
    )
    assert out.decision is JanusAssistantVerdict.APPROVE_ONCE
    assert yes["value"] is True


def test_a2_user_confirmation_rejects_on_no() -> None:
    async def confirm_hook(prompt: str, **_: object) -> bool:
        return False

    asst = get_permission_assistant("user_confirmation")
    asst.set_prompt_hooks(confirm_hook=confirm_hook)
    out = _run(
        asst.handle_permission_denial(
            subject={"user_id": "u1"},
            tool_name="email",
            action="send",
            args={"to": "x@y.z"},
            failed_policies=[],
        )
    )
    assert out.decision is JanusAssistantVerdict.REJECT


def test_a3_constitution_without_key_raises_clearly() -> None:
    from custos.eval.harness.llm import MissingLLMClient, NoApiKeyError

    asst = get_permission_assistant(
        "constitution",
        constitution_file=str(_CONSTITUTION),
        llm=MissingLLMClient(),
    )
    # Set a user message so the LLM intent-check branch fires (otherwise the
    # assistant would fall through to the manual `_confirm` path, which reads
    # from stdin and blocks pytest's capture on Python 3.13). Under
    # `MissingLLMClient` the LLM intent check raises `NoApiKeyError` clearly
    # rather than silently falling through to interactive confirmation.
    _run(asst.handle_user_message("send an email to x@y.z"))
    with pytest.raises(NoApiKeyError):
        _run(
            asst.handle_permission_denial(
                subject={"user_id": "u1"},
                tool_name="email",
                action="send",
                args={"to": "x@y.z"},
                failed_policies=[],
            )
        )


def test_a5_without_key_raises_clearly() -> None:
    from custos.eval.harness.llm import MissingLLMClient, NoApiKeyError

    asst = get_permission_assistant("risk_assessment", risk_tolerance=0.2, llm=MissingLLMClient())
    with pytest.raises(NoApiKeyError):
        _run(
            asst.handle_permission_denial(
                subject={"user_id": "u1"},
                tool_name="email",
                action="send",
                args={"to": "x@y.z"},
                failed_policies=[],
            )
        )


def test_a6_subclass_of_a5_uses_a5_logic() -> None:
    from custos.eval.harness.assistants.risk_assessment import RiskAssessmentAssistant
    from custos.eval.harness.assistants.risk_assessment_autonomous import (
        RiskAssessmentAutonomousAssistant,
    )

    assert issubclass(RiskAssessmentAutonomousAssistant, RiskAssessmentAssistant)
    asst = get_permission_assistant("risk_assessment_autonomous", risk_tolerance=0.2)
    from custos.eval.harness.llm import NoApiKeyError

    with pytest.raises(NoApiKeyError):
        _run(
            asst.handle_permission_denial(
                subject={"user_id": "u1"},
                tool_name="email",
                action="send",
                args={},
                failed_policies=[],
            )
        )
