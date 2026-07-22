"""Permission manager — orchestrates PolicySet + a permission assistant.

Clean-room re-implementation of the observable behaviour of
``Janus/src/permissions/permission_manager.py`` (``check_permission`` only —
the interactive_policy_management console loop is not needed for the harness):

  1. Build the engine context from (subject, tool_name, action, args).
  2. Evaluate the PolicySet (default-deny-with-permit-precedence; see
     ``docs/DECISION_SEMANTICS.md``  — we deliberately do NOT enforce the
     Custos  deny-floor here so parity numbers match Janus).
  3. If policy PERMITs -> allow (no assistant).
  4. If policy DENIES -> call the assistant's ``handle_permission_denial``.
  5. Approve_once -> allow one-time. Create_policy -> persist a new PERMIT rule
     to the in-memory PolicySet (and to disk iff a policy file was supplied);
     allow one-time. Reject -> deny.

Returns a typed :class:`PermissionDecision` so the cell runner can drive the
tool call (allow) or block it (deny) and record metrics.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from custos.eval.harness.assistants.base import BasePermissionAssistant
from custos.eval.harness.policy.engine import Effect, Policy, PolicySet, new_policy_id
from custos.eval.harness.schema import JanusAssistantOutput, JanusAssistantVerdict

__all__ = ["PermissionDecision", "PermissionManager"]


@dataclass(frozen=True)
class PermissionDecision:
    allowed: bool
    assistant_used: bool
    assistant_output: JanusAssistantOutput | None
    reason: str

    @property
    def verdict(self) -> JanusAssistantVerdict | None:
        return self.assistant_output.decision if self.assistant_output else None


class PermissionManager:
    """Owns the policy set + the assistant; centralizes ``check_permission``."""

    def __init__(
        self,
        assistant: BasePermissionAssistant,
        *,
        policy_set: PolicySet | None = None,
        policy_file: str | None = None,
    ) -> None:
        self.assistant = assistant
        self.policy_set = policy_set or PolicySet()
        self.policy_file = policy_file  # if set, created policies are persisted

    async def check_permission(
        self,
        subject: dict[str, Any],
        tool_name: str,
        action: str,
        args: dict[str, Any],
    ) -> PermissionDecision:
        context = {
            "subject": subject,
            "tool_name": tool_name,
            "action": action,
            "parameters": {"tool": tool_name, "action": action, "arguments": args},
        }
        effect = self.policy_set.evaluate(context)
        if effect == Effect.PERMIT:
            return PermissionDecision(
                allowed=True,
                assistant_used=False,
                assistant_output=None,
                reason="policy permits",
            )
        # Policy denied -> escalate to the assistant (Janus  default-deny gating).
        failed = [
            p.to_dict()
            for p in self.policy_set.list_policies()
            if p.tool_name == tool_name and p.action == action
        ]
        out = await self.assistant.handle_permission_denial(
            subject=subject, tool_name=tool_name, action=action, args=args, failed_policies=failed
        )
        if out.decision is JanusAssistantVerdict.APPROVE_ONCE:
            return PermissionDecision(
                allowed=True,
                assistant_used=True,
                assistant_output=out,
                reason=out.reason or "assistant: approve_once",
            )
        if out.decision is JanusAssistantVerdict.CREATE_POLICY:
            policy = out.policy
            if policy:
                self._persist_policy(dict(policy), tool_name, action)
            return PermissionDecision(
                allowed=True,
                assistant_used=True,
                assistant_output=out,
                reason=out.reason or "assistant: create_policy",
            )
        # REJECT (and any unknown) -> deny.
        return PermissionDecision(
            allowed=False,
            assistant_used=True,
            assistant_output=out,
            reason=out.reason or "assistant: reject",
        )

    def _persist_policy(self, policy: dict[str, Any], tool_name: str, action: str) -> None:
        """Add the assistant-suggested policy to the in-memory set (+ file if set)."""
        self.policy_set.add_policy(
            Policy(
                id=new_policy_id(),
                name=str(policy.get("name", "assistant_suggested")),
                description=str(policy.get("description", "")),
                tool_name=str(policy.get("tool_name", tool_name)),
                action=str(policy.get("action", action)),
                conditions=_coerce_conditions(policy.get("conditions", [])),
                effect=Effect.PERMIT,  # Janus create_policy always PERMITs
            )
        )
        if self.policy_file:
            self.policy_set.save_to_file(self.policy_file)


def _coerce_conditions(conditions: Sequence[Any]) -> list[Any]:
    from custos.eval.harness.policy.engine import Condition, JanusOperator

    out: list[Condition] = []
    for c in conditions:
        if not isinstance(c, dict):
            continue
        try:
            out.append(
                Condition(
                    attribute=str(c["attribute"]),
                    operator=JanusOperator.from_value(str(c["operator"])),
                    value=c["value"],
                )
            )
        except (KeyError, ValueError):
            continue
    return out
