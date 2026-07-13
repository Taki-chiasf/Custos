"""A7 ``rule-policy`` assistant - pure deterministic rules, no LLM .

Fast path for low-risk read ops. Takes a rule table at construction (a list
of ``(match, AssistantOutput)`` pairs); ``decide`` evaluates first-match-wins
using :class:`~custos.policy.match.MatchSpec` and returns the matching rule's
output. If no rule matches, returns a ``deny`` with risk scaled from the
tool's risk_tier.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from custos.assistants.base import AssistantBase
from custos.policy.match import MatchSpec
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

__all__ = ["RulePolicy"]


# Static risk score for an unmatched call: tool_tier / 5.0, clamped to [0,1).
_TIER_RISK_FACTOR = 0.2


class RulePolicy(AssistantBase):
    """Pure deterministic rules; no LLM (A7)."""

    name = "rule-policy"

    def __init__(
        self,
        rules: Sequence[tuple[Mapping[str, object], AssistantOutput]] | None = None,
        *,
        default_decision: Decision = Decision.DENY,
    ) -> None:
        self._compiled: list[tuple[MatchSpec, AssistantOutput]] = [
            (MatchSpec.from_mapping(m), out) for m, out in (rules or [])
        ]
        self._default_decision = default_decision

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        for match, out in self._compiled:
            if match.matches(inv):
                return out
        # No rule matched: deny with risk scaled from the tool's tier.
        tier = inv.descriptor.risk_tier if inv.descriptor else 3
        risk = min(1.0, max(0.0, tier * _TIER_RISK_FACTOR))
        return AssistantOutput(
            decision=self._default_decision,
            risk=risk,
            reasoning=f"rule-policy: no rule matched; tier={tier}",
        )
