"""A2 ``user_confirmation`` — prompts the user for every denied call.

No LLM. Max security / severe fatigue. Clean-room re-implementation of the
documented behaviour of ``Janus/src/permissions/assistants/user_confirmation.py``:
log the call, ask yes/no, return ``approve_once`` on yes else ``reject``.
Does NOT persist rules.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from custos.eval.harness.assistants.base import BasePermissionAssistant
from custos.eval.harness.schema import JanusAssistantOutput, JanusAssistantVerdict

__all__ = ["UserConfirmationAssistant"]


class UserConfirmationAssistant(BasePermissionAssistant):
    name = "user_confirmation"

    async def handle_permission_denial(
        self,
        subject: dict[str, Any],
        tool_name: str,
        action: str,
        args: dict[str, Any],
        failed_policies: Sequence[Mapping[str, Any]],
    ) -> JanusAssistantOutput:
        prompt = f"Allow tool call {tool_name}.{action}?\n  args: {args}"
        approved = await self._confirm(prompt)
        if approved:
            return JanusAssistantOutput(
                decision=JanusAssistantVerdict.APPROVE_ONCE,
                reason="user approved one-time tool call",
            )
        return JanusAssistantOutput(
            decision=JanusAssistantVerdict.REJECT,
            reason="user rejected tool call",
        )
