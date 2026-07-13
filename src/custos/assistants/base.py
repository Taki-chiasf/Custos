"""The pluggable ``Assistant`` interface .

Security note : an assistant's output is UNTRUSTED. The gateway never
lets an assistant relax a policy ``deny``; it may only escalate strictness.

Two shapes are provided:
  - :class:`Assistant` - the runtime-checkable ``@runtime_checkable Protocol``
    (the minimal contract: ``name`` + ``decide``). External implementers can
    satisfy this with any duck-typed object.
  - :class:`AssistantBase` - an ABC implementing :class:`Assistant` with a
    default no-op ``observe_user_message`` hook (for assistants that need a
    pre-tool signal, e.g. A5's goal extraction). Subclass this for the
    built-in assistants.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from custos.schema import AssistantOutput, Invocation, SubjectContext

__all__ = [
    "Assistant",
    "AssistantAsync",
    "AssistantBase",
    "AssistantBaseAsync",
    "AssistantRegistry",
]


@runtime_checkable
class Assistant(Protocol):
    """Called by the gateway when policy returns ``ASSIST`` (step 3)."""

    name: str

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Return a proposed decision + risk + reasoning.

        Implementations MAY be non-deterministic (e.g. LLM-backed); this is the
        ONLY allowed source of non-determinism in the pipeline .
        """
        ...


@runtime_checkable
class AssistantAsync(Protocol):
    """Async twin of :class:`Assistant` (, resolves  sync-gateway risk).

    Native-async assistants await I/O (LLM provider, network) without blocking
    the event loop. The :class:`~custos.async_gateway.AsyncGateway` also accepts
    a sync :class:`Assistant` and wraps it via :func:`asyncio.to_thread`, so
    existing sync implementations continue to work unchanged.
    """

    name: str

    async def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Async variant of :meth:`Assistant.decide` (still holds)."""
        ...


class AssistantBase(ABC):
    """Convenience ABC for built-in assistants implementing :class:`Assistant`.

    Provides a default no-op :meth:`observe_user_message` so subclasses that
    don't need a pre-tool hook don't have to override it. LLM-backed
    assistants (e.g. A5) override it to extract goals from user messages.

    Not exported as a Protocol - concrete subclasses are duck-typed to
    :class:`Assistant` via the ``name`` attribute + ``decide`` method.
    """

    name: str = "assistant-base"
    exfiltrates_args: bool = False
    """Whether this assistant sends raw invocation args to a remote LLM (H4).

    Remote-LLM-backed assistants (A5/A6/A9/A3/A4) set ``exfiltrates_args=True``.
    In-process deterministic assistants (A7/A8) set ``False``. The gateway uses
    this flag to route invocations bearing ``secret:true``/``format:password``/
    ``SideEffect.PII`` args away from exfiltrating assistants (FR-9.24, NFR-5)."""

    def observe_user_message(self, message: str) -> None:
        """Pre-tool hook: observe a user message before any tool call.

        Default no-op. Assistants that need goal context (A5) override this to
        extract goals via LLM. Called by the gateway's host integration (the
        Python SDK / LangChain adapter) when a user message arrives.
        """
        return None

    @abstractmethod
    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Return a proposed decision + risk + reasoning. Subclasses implement."""
        ...


class AssistantBaseAsync(ABC):
    """Async convenience ABC for built-in assistants implementing
    :class:`AssistantAsync` .

    Subclasses override :meth:`observe_user_message` (sync, pre-tool hook) and
    implement :meth:`decide` as a coroutine. Mirrors :class:`AssistantBase`
    so the same migration path exists for native-async LLM-backed assistants
    (e.g. a future async A5 wrapping ``litellm.acompletion`` directly).

    Not exported as a Protocol - concrete subclasses are duck-typed to
    :class:`AssistantAsync` via the ``name`` attribute + ``async decide``.
    """

    name: str = "assistant-base-async"
    exfiltrates_args: bool = False

    def observe_user_message(self, message: str) -> None:
        """Pre-tool hook: observe a user message before any tool call.

        Default no-op. Stays sync so it can be called from either a sync or
        async gateway host (goal extraction is pre-pipeline, blocking is OK).
        """
        return None

    @abstractmethod
    async def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Async variant of :meth:`AssistantBase.decide`. Subclasses implement."""
        ...


class AssistantRegistry:
    """A name-keyed registry of :class:`Assistant` instances (H11).

    Resolves ``assist:<name>`` policy actions to the correct assistant.
    An unresolved name fails closed — the gateway returns a safe ``DENY``
    and logs the missing assistant in the audit trail.
    """

    def __init__(
        self,
        assistants: list[Assistant] | None = None,
        *,
        local_only: bool = False,
    ) -> None:
        self._by_name: dict[str, Assistant] = {}
        self._local_only = local_only
        if assistants:
            for a in assistants:
                self.register(a)

    def register(self, assistant: Assistant) -> None:
        """Register an assistant by name (H11).

        In the air-gapped profile (``local_only=True``) an assistant with
        ``exfiltrates_args=True`` (routes args to a remote LLM) is refused —
        upfront, not merely at call time. (C4 regression, council 2026-07-22.)
        """
        if self._local_only and getattr(assistant, "exfiltrates_args", False):
            raise ValueError(
                f"air-gapped profile (local_only=True) refuses to register "
                f"exfiltrating assistant {assistant.name!r} "
                f"(exfiltrates_args=True); assign an in-process assistant "
                f"or construct Gateway(local_only=False)"
            )
        self._by_name[assistant.name] = assistant

    def get(self, name: str) -> Assistant | None:
        return self._by_name.get(name)

    @property
    def default(self) -> Assistant | None:
        """Return the first registered assistant, if any. Used as the default
        when the policy action is bare ``assist`` (no ``:<name>`` suffix)."""
        for a in self._by_name.values():
            return a
        return None
