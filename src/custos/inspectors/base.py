"""The pluggable ``ContextInspector`` interface (A12).

Security note: an inspector's output is UNTRUSTED. The gateway never lets
an inspector relax a policy ``deny`` or ``quarantine``; it may only escalate
strictness (SAFE -> SUSPICIOUS -> INJECTION -> QUARANTINE).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from custos.schema import (
    ContextSnapshot,
    InspectionResult,
    Invocation,
    SubjectContext,
)

__all__ = [
    "ContextInspector",
    "ContextInspectorAsync",
    "ContextInspectorBase",
    "InspectorRegistry",
]


@runtime_checkable
class ContextInspector(Protocol):
    """Called by the gateway when policy returns ``INSPECT`` (step 2.5).

    Unlike an :class:`~custos.assistants.base.Assistant`, a context inspector
    receives the agent's full conversation context via :class:`ContextSnapshot`
    in addition to the current :class:`Invocation`. This enables leave-one-out
    causal attribution and retroactive CoT masking against IPI.
    """

    name: str

    def inspect(
        self, inv: Invocation, ctx: SubjectContext, snapshot: ContextSnapshot
    ) -> InspectionResult:
        """Inspect the agent context for injection; return SAFE/SUSPICIOUS/INJECTION."""
        ...


@runtime_checkable
class ContextInspectorAsync(Protocol):
    """Async twin of :class:`ContextInspector`."""

    name: str

    async def inspect(
        self, inv: Invocation, ctx: SubjectContext, snapshot: ContextSnapshot
    ) -> InspectionResult:
        """Async variant of :meth:`ContextInspector.inspect`."""
        ...


class ContextInspectorBase(ABC):
    """Convenience ABC for built-in inspectors implementing :class:`ContextInspector`.

    Provides the ``exfiltrates_args`` gate and the ``name`` attribute.
    Subclasses implement :meth:`inspect`.
    """

    name: str = "inspector-base"
    exfiltrates_args: bool = False
    """Whether this inspector sends raw invocation args to a remote LLM.

    Set ``True`` on LLM-backed inspectors (A12 with deep attribution).
    The gateway uses this flag to route restricted-arg invocations away.
    """

    @abstractmethod
    def inspect(
        self, inv: Invocation, ctx: SubjectContext, snapshot: ContextSnapshot
    ) -> InspectionResult:
        """Inspect the agent context for injection. Subclasses implement."""
        ...


class InspectorRegistry:
    """A name-keyed registry of :class:`ContextInspector` instances.

    Resolves ``inspect:<name>`` policy actions to the correct inspector.
    An unresolved name fails closed — the gateway returns a safe ``DENY``
    and logs the missing inspector in the audit trail.
    """

    def __init__(
        self,
        inspectors: list[ContextInspector] | None = None,
        *,
        local_only: bool = False,
    ) -> None:
        self._by_name: dict[str, ContextInspector] = {}
        self._local_only = local_only
        if inspectors:
            for i in inspectors:
                self.register(i)

    def register(self, inspector: ContextInspector) -> None:
        """Register an inspector by name.

        In the air-gapped profile (``local_only=True``) an inspector with
        ``exfiltrates_args=True`` (sends args to a remote LLM) is refused.
        """
        if self._local_only and getattr(inspector, "exfiltrates_args", False):
            raise ValueError(
                f"air-gapped profile (local_only=True) refuses to register "
                f"exfiltrating inspector {inspector.name!r} "
                f"(exfiltrates_args=True)"
            )
        self._by_name[inspector.name] = inspector

    def get(self, name: str) -> ContextInspector | None:
        return self._by_name.get(name)

    @property
    def default(self) -> ContextInspector | None:
        """Return the first registered inspector, if any."""
        for i in self._by_name.values():
            return i
        return None
