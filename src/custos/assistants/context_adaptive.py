"""A9 ``context-adaptive`` assistant - prompt granularity by task sensitivity .

Reuses A5's goal-extraction shape (``observe_user_message`` -> LLM -> goals
list). On ``decide``, one LLM call scores ``(call, goals) -> sensitivity`` in
[0.0, 1.0]. Sensitivity at or below ``sensitivity_threshold`` -> ``ALLOW``
(low-sensitivity task, no prompt needed). Above -> ``PROMPT`` (escalate to
user with full context). Falls back to safe ``DENY`` when no LLM is configured.

One LLM call per ``decide`` (vs A5's two: goal extraction + risk judging).
Goal extraction happens once per user message via ``observe_user_message``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from custos.assistants.base import AssistantBase
from custos.assistants.risk_assessment import (
    _EXTRACT_GOALS_PROMPT,
    _is_scalar,
    _parse_json_loose,
)
from custos.llm import LLMClient, MissingLLMClient, NoLLMClientError
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

__all__ = ["ContextAdaptiveAssistant"]


_SCORE_SENSITIVITY_PROMPT = (
    "You are a task-sensitivity evaluator. Given the user's active goals and a "
    "planned tool call, return a sensitivity score in [0.0, 1.0] where 0.0 = "
    "benign/read-only and 1.0 = highly sensitive (PII, payments, destructive). "
    'Output ONLY JSON like {"sensitivity": 0.42, "reason": "..."}.'
)


class ContextAdaptiveAssistant(AssistantBase):
    """A9: context-adaptive prompt granularity . One LLM call per decide."""

    name = "context-adaptive"
    exfiltrates_args = True

    def __init__(
        self,
        *,
        sensitivity_threshold: float = 0.5,
        llm: LLMClient | None = None,
    ) -> None:
        self.sensitivity_threshold = sensitivity_threshold
        self.llm: LLMClient = llm if llm is not None else MissingLLMClient()
        self.goals: list[str] = []

    def observe_user_message(self, message: str) -> None:
        """Pre-tool hook: extract goals via LLM (same shape as A5)."""
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
        try:
            sensitivity, reason = self._score_sensitivity(inv.tool, inv.args)
        except NoLLMClientError:
            return AssistantOutput(
                decision=Decision.DENY,
                risk=1.0,
                reasoning="context-adaptive: no LLM configured; safe deny",
            )
        if sensitivity <= self.sensitivity_threshold:
            return AssistantOutput(
                decision=Decision.ALLOW,
                risk=sensitivity,
                reasoning=(
                    f"sensitivity {sensitivity:.3f} <= threshold "
                    f"{self.sensitivity_threshold:.3f}: {reason}"
                ),
            )
        return AssistantOutput(
            decision=Decision.PROMPT,
            risk=sensitivity,
            reasoning=(
                f"sensitivity {sensitivity:.3f} > threshold "
                f"{self.sensitivity_threshold:.3f}: {reason}"
            ),
        )

    def _score_sensitivity(
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
                {"role": "system", "content": _SCORE_SENSITIVITY_PROMPT},
                {"role": "user", "content": payload},
            ]
        )
        parsed = _parse_json_loose(response)
        if isinstance(parsed, dict):
            try:
                sensitivity = float(parsed.get("sensitivity", 1.0))
            except (TypeError, ValueError):
                sensitivity = 1.0
            reason = str(parsed.get("reason", ""))
            return max(0.0, min(1.0, sensitivity)), reason
        return 1.0, "sensitivity judge returned unparseable output"
