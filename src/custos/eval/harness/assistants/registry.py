"""Assistant registry + risk-tolerance resolution (mirrors Janus dispatch)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from custos.eval.harness.assistants.auto_approve import AutoApproveAssistant
from custos.eval.harness.assistants.base import BasePermissionAssistant
from custos.eval.harness.assistants.constitution import ConstitutionAssistant
from custos.eval.harness.assistants.policy_suggestion import PolicySuggestionAssistant
from custos.eval.harness.assistants.risk_assessment import RiskAssessmentAssistant
from custos.eval.harness.assistants.risk_assessment_autonomous import (
    RiskAssessmentAutonomousAssistant,
)
from custos.eval.harness.assistants.user_confirmation import UserConfirmationAssistant

__all__ = [
    "ASSISTANT_REGISTRY",
    "AVAILABLE_PERMISSION_ASSISTANTS",
    "get_permission_assistant",
    "resolve_risk_tolerance",
]

ASSISTANT_REGISTRY: dict[str, type[BasePermissionAssistant]] = {
    "auto_approve": AutoApproveAssistant,
    "user_confirmation": UserConfirmationAssistant,
    "constitution": ConstitutionAssistant,
    "policy_suggestion": PolicySuggestionAssistant,
    "risk_assessment": RiskAssessmentAssistant,
    "risk_assessment_autonomous": RiskAssessmentAutonomousAssistant,
}

AVAILABLE_PERMISSION_ASSISTANTS: tuple[str, ...] = tuple(ASSISTANT_REGISTRY.keys())


def get_permission_assistant(name: str, **kwargs: Any) -> BasePermissionAssistant:
    """Instantiate the named assistant; pass kwargs to the constructor."""
    if name not in ASSISTANT_REGISTRY:
        raise ValueError(
            f"unknown assistant {name!r}; available: {AVAILABLE_PERMISSION_ASSISTANTS}"
        )
    return ASSISTANT_REGISTRY[name](**kwargs)


def resolve_risk_tolerance(name: str, risk_tolerances: Sequence[float]) -> float | None:
    """Re-implements ``Janus/src/scripts/runner_common.py:resolve_risk_tolerance``.

    Per-assistant effective tolerance:
      - ``auto_approve``             -> 1.0 (always approves)
      - ``user_confirmation``        -> 0.0 (always defers to user)
      - ``constitution`` /
        ``policy_suggestion``        -> None (tolerance unused)
      - ``risk_assessment`` /
        ``risk_assessment_autonomous`` -> raw CLI value (expanded by the harness)
    """
    if not risk_tolerances:
        if name in {"risk_assessment", "risk_assessment_autonomous"}:
            return 0.0
        return None
    primary = risk_tolerances[0]
    if name == "auto_approve":
        return 1.0
    if name == "user_confirmation":
        return 0.0
    if name in {"constitution", "policy_suggestion"}:
        return None
    if name in {"risk_assessment", "risk_assessment_autonomous"}:
        return float(primary)
    return None


def expand_runs(
    assistant_names: Sequence[str],
    risk_tolerances: Sequence[float],
) -> list[tuple[str, float | None]]:
    """Re-implements ``Janus/src/scripts/run_harness.py:_expand_runs``.

    The 2 tolerances expand only for the risk_assessment variants; the other 4
    assistants use only ``risk_tolerances[0]`` (or None when the value is unused).
    This is what collapses the 6x3x4x3x2x5 grid to the observed 1440 rows.
    """
    out: list[tuple[str, float | None]] = []
    for name in assistant_names:
        if name in {"risk_assessment", "risk_assessment_autonomous"} and len(risk_tolerances) > 1:
            for t in risk_tolerances:
                out.append((name, float(t)))
        else:
            out.append((name, resolve_risk_tolerance(name, risk_tolerances)))
    return out
