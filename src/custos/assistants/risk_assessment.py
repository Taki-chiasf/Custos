"""A5 ``risk-assessment`` - goal-aware risk scoring .

Clean-room re-implementation (NOT copied) of the documented behaviour of
``Janus/src/permissions/assistants/risk_assessment.py``:

  - ``observe_user_message`` extracts task goals via LLM (before any tool call).
  - On ``decide``, ``_judge_tool_call`` returns a risk score in [0.0, 1.0]
    via a second LLM call.
  - If risk <= ``tolerance`` -> ``allow_once``.
  - If risk >  ``tolerance`` -> :meth:`_escalate` returns ``prompt`` (the
    Custos extension that hands to a responder). The autonomous subclass (A6)
    overrides :meth:`_escalate` to return ``deny`` instead.

Persists nothing. Two LLM calls per risky invocation.

The production interface is sync ; the LiteLLM adapter wraps the
sync provider ``completion`` to satisfy :class:`~custos.llm.LLMClient`.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from custos.assistants.base import AssistantBase
from custos.llm import LLMClient, MissingLLMClient
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

__all__ = ["RiskAssessment"]


_EXTRACT_GOALS_PROMPT = (
    "Extract the user's task goals from the message. Output ONLY a JSON list "
    "of short goal strings; no prose."
)
_JUDGE_RISK_PROMPT = (
    "You are a risk evaluator. Given the user's goals and a planned tool call, "
    "return a risk score in [0.0, 1.0] and a one-sentence reason. Output ONLY "
    'JSON like {"risk": 0.42, "reason": "..."}.'
)


class RiskAssessment(AssistantBase):
    """A5: goal-aware risk scoring . Two LLM calls."""

    name = "risk-assessment"
    exfiltrates_args = True

    def __init__(
        self,
        *,
        tolerance: float,
        llm: LLMClient | None = None,
    ) -> None:
        self.tolerance = tolerance
        self.llm: LLMClient = llm if llm is not None else MissingLLMClient()
        self.goals: list[str] = []

    def observe_user_message(self, message: str) -> None:
        """Pre-tool hook: extract goals via LLM before any tool call (A5)."""
        response = self.llm.complete(
            [
                {"role": "system", "content": _EXTRACT_GOALS_PROMPT},
                {"role": "user", "content": message},
            ]
        )
        parsed = _parse_json_loose(response)
        if isinstance(parsed, list):
            self.goals = [str(g) for g in parsed if _is_scalar(g)]
        elif isinstance(parsed, dict) and "goals" in parsed:
            self.goals = [str(g) for g in parsed["goals"] if _is_scalar(g)]

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        risk, reason = self._judge_tool_call(inv.tool, inv.args)
        if risk <= self.tolerance:
            return AssistantOutput(
                decision=Decision.ALLOW_ONCE,
                risk=risk,
                reasoning=f"risk {risk:.3f} <= tolerance {self.tolerance:.3f}: {reason}",
            )
        return self._escalate(inv, risk, reason)

    def _escalate(self, inv: Invocation, risk: float, reason: str) -> AssistantOutput:
        """Above tolerance: hand to the responder (Custos ``prompt``)."""
        return AssistantOutput(
            decision=Decision.PROMPT,
            risk=risk,
            reasoning=f"risk {risk:.3f} > tolerance {self.tolerance:.3f}: {reason}",
        )

    def _judge_tool_call(
        self, tool: str, args: Mapping[str, Any] | dict[str, Any]
    ) -> tuple[float, str]:
        payload = json.dumps(
            {
                "goals": self.goals,
                "tool": tool,
                "arguments": dict(args) if args else {},
            }
        )
        response = self.llm.complete(
            [
                {"role": "system", "content": _JUDGE_RISK_PROMPT},
                {"role": "user", "content": payload},
            ]
        )
        parsed = _parse_json_loose(response)
        if isinstance(parsed, dict):
            try:
                risk = float(parsed.get("risk", 1.0))
            except (TypeError, ValueError):
                risk = 1.0
            reason = str(parsed.get("reason", ""))
            return max(0.0, min(1.0, risk)), reason
        return 1.0, "risk judge returned unparseable output"


def _parse_json_loose(text: str) -> Any:
    """Extract the first JSON object/array from ``text`` (tolerant of prose)."""
    match = re.search(r"\{.*\}|\[.*\]", text, re.DOTALL)
    if not match:
        return {}
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}


def _is_scalar(value: object) -> bool:
    return isinstance(value, (str, int, float))
