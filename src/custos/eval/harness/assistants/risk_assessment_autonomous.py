"""A6 ``risk_assessment_autonomous`` — same as A5 but never escalates.

Clean-room re-implementation of the documented behaviour of
``Janus/src/permissions/assistants/risk_assessment_autonomous.py`` (a tiny
subclass overriding only the escalation flag). Above-tolerance calls are
silently ``reject``-ed; the user is never prompted.
"""

from __future__ import annotations

from custos.eval.harness.assistants.risk_assessment import RiskAssessmentAssistant

__all__ = ["RiskAssessmentAutonomousAssistant"]


class RiskAssessmentAutonomousAssistant(RiskAssessmentAssistant):
    name = "risk_assessment_autonomous"

    def _should_escalate_on_reject(self) -> bool:
        return False
