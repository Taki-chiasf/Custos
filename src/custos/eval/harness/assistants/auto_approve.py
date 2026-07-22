"""A1 ``auto_approve`` — unconditionally approves every denied call.

No LLM, no prompts, no policy synthesis.  baseline. Clean-room
re-implementation of the documented behaviour of
``Janus/src/permissions/assistants/auto_approve.py`` (the assistant whose
entire body is "return approve_once").

Does NOT persist a rule — Janus's ``auto_approve`` never emits ``create_policy``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from custos.eval.harness.assistants.base import BasePermissionAssistant
from custos.eval.harness.schema import JanusAssistantOutput, JanusAssistantVerdict

__all__ = ["AutoApproveAssistant"]


class AutoApproveAssistant(BasePermissionAssistant):
    name = "auto_approve"

    async def handle_permission_denial(
        self,
        subject: dict[str, Any],
        tool_name: str,
        action: str,
        args: dict[str, Any],
        failed_policies: Sequence[Mapping[str, Any]],
    ) -> JanusAssistantOutput:
        return JanusAssistantOutput(
            decision=JanusAssistantVerdict.APPROVE_ONCE,
            reason="auto-approve: unconditional one-time approval",
        )
