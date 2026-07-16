"""The 6 Janus reference assistants, clean-room re-implemented for  parity.

A1-A6 all implement the async :class:`eval.harness.assistants.base.BasePermissionAssistant`
contract. A1 and A2 require no LLM and are fully runnable without an API key;
A3-A6 require a configured :class:`eval.harness.llm.LLMClient`.
"""

from custos.eval.harness.assistants.auto_approve import AutoApproveAssistant
from custos.eval.harness.assistants.base import BasePermissionAssistant
from custos.eval.harness.assistants.constitution import ConstitutionAssistant
from custos.eval.harness.assistants.policy_suggestion import PolicySuggestionAssistant
from custos.eval.harness.assistants.registry import (
    ASSISTANT_REGISTRY,
    AVAILABLE_PERMISSION_ASSISTANTS,
    expand_runs,
    get_permission_assistant,
    resolve_risk_tolerance,
)
from custos.eval.harness.assistants.risk_assessment import RiskAssessmentAssistant
from custos.eval.harness.assistants.risk_assessment_autonomous import (
    RiskAssessmentAutonomousAssistant,
)
from custos.eval.harness.assistants.user_confirmation import UserConfirmationAssistant

__all__ = [
    "BasePermissionAssistant",
    "ASSISTANT_REGISTRY",
    "AVAILABLE_PERMISSION_ASSISTANTS",
    "get_permission_assistant",
    "resolve_risk_tolerance",
    "expand_runs",
    "AutoApproveAssistant",
    "UserConfirmationAssistant",
    "ConstitutionAssistant",
    "PolicySuggestionAssistant",
    "RiskAssessmentAssistant",
    "RiskAssessmentAutonomousAssistant",
]
