"""Python SDK: wrap plain callables with Custos gating (US-1).

``wrap_callables`` returns proxies with identical signatures that call
``Gateway.decide`` before invoking the underlying tool. On ``deny``/``defer``
the proxy raises :class:`PermissionDenied` and never invokes the tool.
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from custos.exceptions import PermissionDenied
from custos.gateway import Gateway
from custos.schema import (
    ContextSnapshot,
    Decision,
    InputSource,
    Invocation,
    SubjectContext,
    ToolDescriptor,
    WipeStrategy,
)

__all__ = [
    "wrap_callables",
    "set_default_context",
    "get_default_context",
    "MemoryWipe",
    "ContextProvider",
    "MemoryWipeResult",
]


# Module-level default subject context (used when a wrapped tool is called
# without an explicit ``custos_context`` kwarg). Tests can override it.
_default_context: SubjectContext = SubjectContext(user_id="default")


def set_default_context(ctx: SubjectContext) -> None:
    """Set the default :class:`SubjectContext` used by ``wrap_callables`` proxies."""
    global _default_context
    _default_context = ctx


def get_default_context() -> SubjectContext:
    """Return the current default :class:`SubjectContext`."""
    return _default_context


@runtime_checkable
class MemoryWipe(Protocol):
    """Protocol for SDK-level context sanitisation after IPI detection (A12).

    Each framework adapter implements this to clear/sanitise agent context
    when the gateway returns :attr:`Decision.QUARANTINE`.
    """

    def sanitize(
        self,
        context: Any,
        sources: tuple[InputSource, ...],
        strategy: WipeStrategy,
    ) -> Any:
        """Return sanitised context after removing injection sources."""
        ...


@runtime_checkable
class ContextProvider(Protocol):
    """Protocol for providing a :class:`ContextSnapshot` to the gateway (A12).

    Framework adapters implement this to snapshot the agent's full conversation
    context (messages, input sources, system prompt) before each tool call.
    """

    def get_snapshot(self) -> ContextSnapshot:
        """Return the current agent context snapshot."""
        ...


class MemoryWipeResult:
    """Result of a memory-wipe operation (A12).

    Attributes:
        sanitized_context: the sanitised context (framework-specific).
        sources_removed: count of injection sources removed.
        strategy: the strategy that was applied.
    """

    __slots__ = ("sanitized_context", "sources_removed", "strategy")

    def __init__(
        self, sanitized_context: Any, sources_removed: int, strategy: WipeStrategy
    ) -> None:
        self.sanitized_context = sanitized_context
        self.sources_removed = sources_removed
        self.strategy = strategy


def wrap_callables(
    gateway: Gateway,
    tools: list[Callable[..., Any]] | tuple[Callable[..., Any], ...],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> list[Callable[..., Any]]:
    """Wrap a list of plain callables so every call is gated by the gateway (US-1).

    Each returned proxy has the same signature as the original (via
    :func:`functools.wraps`). At call time the proxy:

      1. Builds an :class:`Invocation` from the tool's name + bound args +
         a :class:`SubjectContext`.
      2. Calls ``gateway.decide(inv, snapshot=...)`` when ``context_provider``
         is set.
      3. On ``deny``/``defer`` raises :class:`PermissionDenied` and never
         invokes the tool.
      4. On ``allow`` / ``allow_once`` / ``allow_and_persist`` forwards to the
         underlying callable and returns its result.
      5. On ``quarantine`` calls ``memory_wipe.sanitize(...)`` when
         ``memory_wipe`` is set.

    The tool name used in the :class:`Invocation` is the descriptor's ``name``
    when ``descriptors`` maps the callable's ``__name__`` to a descriptor
    (this lets policy tool globs like ``fs.read*`` match Python functions
    named ``fs_read``); otherwise the callable's ``__name__`` is used.

    The context is resolved from, in order: an explicit ``custos_context``
    kwarg passed at call time, else the module default (see
    :func:`set_default_context`).
    """
    descriptors = descriptors or {}
    wrapped: list[Callable[..., Any]] = []
    for tool in tools:
        py_name = getattr(tool, "__name__", None) or repr(tool)
        descriptor = descriptors.get(py_name) or _minimal_descriptor(py_name)
        tool_name = descriptor.name or py_name
        wrapped.append(
            _wrap_one(
                gateway,
                tool,
                tool_name,
                descriptor,
                context_provider=context_provider,
                memory_wipe=memory_wipe,
            )
        )
    return wrapped


def _minimal_descriptor(name: str) -> ToolDescriptor:
    """Build a minimal risk_tier=3 descriptor for tools without one."""
    return ToolDescriptor(name=name, risk_tier=3)


def _minimal_signature_args(
    tool: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind ``args``/``kwargs`` to ``tool``'s signature (US-1, shared with
    :class:`~custos.async_gateway.AsyncGateway`).

    Mirrors the binding logic in :func:`_wrap_one`'s sync ``proxy``: full
    :func:`inspect.signature.bind` with defaults applied; fallen back to a
    positional+kwargs union if the tool's signature is not introspectable.
    """
    sig = inspect.signature(tool)
    try:
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        merged = dict(kwargs)
        merged.update(dict(zip(sig.parameters, args, strict=False)))
        return merged


def _wrap_one(
    gateway: Gateway,
    tool: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
    *,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> Callable[..., Any]:
    @functools.wraps(tool)
    def proxy(*args: Any, **kwargs: Any) -> Any:
        ctx = kwargs.pop("custos_context", None) or _default_context
        sig = inspect.signature(tool)
        try:
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            call_args = dict(bound.arguments)
        except TypeError:
            call_args = dict(kwargs)
            call_args.update(dict(zip(sig.parameters, args, strict=False)))
        inv = Invocation(
            tool=name,
            args=call_args,
            context=ctx,
            descriptor=descriptor,
        )
        snapshot = context_provider.get_snapshot() if context_provider else None
        result = gateway.decide(inv, snapshot=snapshot)
        if result.decision == Decision.QUARANTINE and memory_wipe is not None:
            if context_provider is not None:
                current_ctx = context_provider.get_snapshot()
                memory_wipe.sanitize(
                    current_ctx,
                    (),
                    WipeStrategy.FULL,
                )
            raise PermissionDenied(
                name,
                result.decision.value,
                reasoning=result.audit.reasoning,
                risk=result.audit.risk_score,
                policy_match=result.audit.policy_match,
                assistant=result.audit.assistant,
            )
        if result.decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(
                name,
                result.decision.value,
                reasoning=result.audit.reasoning,
                risk=result.audit.risk_score,
                policy_match=result.audit.policy_match,
                assistant=result.audit.assistant,
            )
        return tool(*args, **kwargs)

    return proxy
