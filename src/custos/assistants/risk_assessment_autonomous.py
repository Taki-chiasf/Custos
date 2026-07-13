"""A6 ``risk-assessment-autonomous`` - same as A5 but never prompts .

Clean-room re-implementation of the documented behaviour of
``Janus/src/permissions/assistants/risk_assessment_autonomous.py`` (a tiny
subclass overriding the escalation flag). Above-tolerance calls are silently
denied; the user is never prompted. Differs from A5 only in
:meth:`_escalate`.
"""

from __future__ import annotations

from custos.assistants.risk_assessment import RiskAssessment
from custos.schema import AssistantOutput, Decision, Invocation

__all__ = ["RiskAssessmentAutonomous"]


class RiskAssessmentAutonomous(RiskAssessment):
    """A6: goal-aware risk scoring that never escalates to a user ."""

    name = "risk-assessment-autonomous"
    exfiltrates_args = True

    def _escalate(self, inv: Invocation, risk: float, reason: str) -> AssistantOutput:
        """Above tolerance: silently deny (no user prompt)."""
        return AssistantOutput(
            decision=Decision.DENY,
            risk=risk,
            reasoning=(
                f"risk {risk:.3f} > tolerance {self.tolerance:.3f}: {reason} "
                f"(autonomous: no escalation)"
            ),
        )
