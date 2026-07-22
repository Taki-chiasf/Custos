"""Janus-aligned schema for  parity reproduction.

These types deliberately use Janus's labels (`approve_once`, `create_policy`,
`reject`) — NOT Custos's production `Decision` enum — so parity run output is
directly comparable to `Janus/metrics/submission_metrics.csv`. See
`docs/DECISION_SEMANTICS.md` for the locked mapping to `custos.schema.Decision`.

 (dual-type-drift mitigation): all types prefixed with
``Janus`` so they cannot be confused with the production
:class:`custos.schema.AssistantOutput` when both are in scope. The mapping
between Janus verdicts and Custos decisions is locked in
:func:`custos.policy.operators.to_custos_decision` and machine-checked in
``tests/eval/test_janus_decision_mapping.py``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = ["JanusAssistantVerdict", "JanusAssistantOutput", "JanusPermissionContext"]


class JanusAssistantVerdict(str, Enum):
    """The three labels a Janus assistant may return (mapping source)."""

    APPROVE_ONCE = "approve_once"
    CREATE_POLICY = "create_policy"
    REJECT = "reject"


@dataclass(frozen=True)
class JanusAssistantOutput:
    """Mirrors the dict Janus assistants return from ``handle_permission_denial``.

    Janus does not enforce this shape; we reify it so the reimplementation is
    typed and the gateway can consume a stable contract. Renamed from
    ``AssistantOutput`` → ``JanusAssistantOutput`` (dual-type-drift fix)
    so this never collides with :class:`custos.schema.AssistantOutput`.
    """

    decision: JanusAssistantVerdict
    reason: str = ""
    policy: Mapping[str, Any] | None = None
    risk_score: float | None = None
    fatigue_hint: bool = False
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_janus_dict(self) -> dict[str, Any]:
        """Emit a dict shaped like Janus's bare return (for traced parity)."""
        out: dict[str, Any] = {"decision": self.decision.value, "reason": self.reason}
        if self.policy is not None:
            out["policy"] = dict(self.policy)
        return out


@dataclass
class JanusPermissionContext:
    """The context dict the policy engine evaluates against (Janus shape).

    Keys mirror ``Janus/src/permissions/permission_manager.py`` lines 278-288:
    ``subject``, ``tool_name``, ``action``, ``parameters`` (with
    ``{tool, action, arguments}`` nested). Renamed from ``PermissionContext``
    → ``JanusPermissionContext`` (dual-type-drift fix).
    """

    subject: dict[str, Any]
    tool_name: str
    action: str
    args: dict[str, Any]

    def as_engine_context(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "tool_name": self.tool_name,
            "action": self.action,
            "parameters": {"tool": self.tool_name, "action": self.action, "arguments": self.args},
        }
