"""The pluggable ``Responder`` interface ."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from custos.schema import PromptRequest, PromptResponse

__all__ = ["Responder", "ResponderAsync", "PromptRequest", "PromptResponse"]


@runtime_checkable
class Responder(Protocol):
    """Called by the gateway when the pipeline reaches ``PROMPT`` (step 4)."""

    name: str

    def prompt(self, req: PromptRequest) -> PromptResponse:
        """Deliver ``req`` to a user and await a signed response ."""
        ...


@runtime_checkable
class ResponderAsync(Protocol):
    """Async twin of :class:`Responder` (, resolves  sync-gateway risk).

    Native-async responders (web widget SSE, async webhook client, multi-approver
    quorum collector) await their transport without blocking the event loop.
    The :class:`~custos.async_gateway.AsyncGateway` also accepts a sync
    :class:`Responder` and wraps it via :func:`asyncio.to_thread`, so the
    existing CLI/Slack/Web/Webhook/threaded-Event responders keep working.
    """

    name: str

    async def prompt(self, req: PromptRequest) -> PromptResponse:
        """Async variant of :meth:`Responder.prompt`."""
        ...
