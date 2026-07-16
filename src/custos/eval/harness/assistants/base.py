"""Base class for the 6  permission assistants.

Clean-room re-implementation of the observable contract documented at
``Janus/src/permissions/assistants/base.py``: an async ``handle_permission_denial``
plus an optional async ``handle_user_message`` pre-tool hook. Prompt hooks
(``_ask`` / ``_confirm``) are overridable externally so the harness can swap a
rich CLI prompt for a synthetic responder.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from custos.eval.harness.schema import JanusAssistantOutput, JanusPermissionContext

__all__ = [
    "BasePermissionAssistant",
    "AskHook",
    "ConfirmHook",
    "MetricsRecorder",
]


AskHook = Callable[..., Awaitable[str]]
ConfirmHook = Callable[..., Awaitable[bool]]
MetricsRecorder = Callable[[str, Mapping[str, Any]], None]  # (event, payload)


class BasePermissionAssistant(ABC):
    """The async assistant contract (mirrors Janus shape, reimpl semantics)."""

    name: str = "base"

    def __init__(
        self,
        *,
        verbose: bool = False,
        metrics: MetricsRecorder | None = None,
        risk_tolerance: float | None = None,
        llm: Any | None = None,
        constitution_file: str | Path | None = None,
        constitution_use_auto_approve: bool = True,
        run_log_dir: str | Path | None = None,
        **_unused: Any,
    ) -> None:
        self.verbose = verbose
        self.metrics = metrics
        self.risk_tolerance = risk_tolerance
        self.llm = llm
        self.constitution_file = constitution_file
        self.constitution_use_auto_approve = constitution_use_auto_approve
        self.run_log_dir = Path(run_log_dir) if run_log_dir else None
        self._ask_hook: AskHook | None = None
        self._confirm_hook: ConfirmHook | None = None

    # ---- hooks the harness patches ---------------------------------------

    def set_prompt_hooks(
        self,
        ask_hook: AskHook | None = None,
        confirm_hook: ConfirmHook | None = None,
    ) -> None:
        self._ask_hook = ask_hook
        self._confirm_hook = confirm_hook

    # ---- pre-tool hook (default no-op) ----------------------------------

    async def handle_user_message(self, message: str) -> None:
        """Hook called for each user message; subclasses may override."""
        return None

    # ---- the contract ----------------------------------------------------

    @abstractmethod
    async def handle_permission_denial(
        self,
        subject: dict[str, Any],
        tool_name: str,
        action: str,
        args: dict[str, Any],
        failed_policies: Sequence[Mapping[str, Any]],
    ) -> JanusAssistantOutput:
        """Decide how to handle a policy denial; return an JanusAssistantOutput."""
        raise NotImplementedError

    # ---- shared helpers --------------------------------------------------

    async def _ask(self, prompt: str, **kwargs: Any) -> str:
        if self._ask_hook is not None:
            response = await self._ask_hook(prompt, **kwargs)
        else:
            response = await asyncio_default_input(prompt)
        self._record_user_response()
        return response

    async def _confirm(self, prompt: str, **kwargs: Any) -> bool:
        if self._confirm_hook is not None:
            result = await self._confirm_hook(prompt, **kwargs)
        else:
            result = await asyncio_default_confirm(prompt)
        self._record_user_response()
        return result

    def _record_user_response(self) -> None:
        # The harness's metrics recorder tracks user-input count via this event.
        if self.metrics is not None:
            self.metrics("user_response", {"assistant": self.name})

    def _log_event(self, event: str, **details: Any) -> None:
        if self.run_log_dir is None:
            return
        payload = {"assistant": self.name, **details}
        try:
            serialized = json.dumps(payload, default=str, ensure_ascii=True, sort_keys=True)
        except TypeError:
            serialized = json.dumps(
                {k: str(v) for k, v in payload.items()}, ensure_ascii=True, sort_keys=True
            )
        # Append-only event log per-run; the harness owns the file lifecycle.
        (self.run_log_dir / "assistant_events.log").write_text(
            f"PERMISSION_ASSISTANT: {event} {serialized}\n"
        )

    def _ctx(self, tool_name: str, action: str, args: dict[str, Any]) -> JanusPermissionContext:
        # Convenience for subclasses; subject is filled by the gateway, not here.
        return JanusPermissionContext(subject={}, tool_name=tool_name, action=action, args=args)


async def asyncio_default_input(prompt: str) -> str:  # pragma: no cover - interactive only
    """Default ``_ask`` fallback (no hook installed): blocking stdin read.

     harness always installs an ask_hook, so this only matters for ad-hoc
    interactive debugging. Kept simple/synchronous deliberately.
    """
    import asyncio

    await asyncio.to_thread(input, prompt + " ")
    return ""


async def asyncio_default_confirm(prompt: str) -> bool:  # pragma: no cover - interactive
    """Default ``_confirm`` fallback (no hook installed)."""
    import asyncio

    response = await asyncio.to_thread(input, prompt + " [y/N] ")
    return response.strip().lower() in {"y", "yes"}
