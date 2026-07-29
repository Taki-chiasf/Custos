"""LangChain adapter .

Lives in the ``custos[langchain]`` extra (``langchain-core`` is not a runtime
dependency -). Wraps a list of LangChain ``BaseTool`` objects with
Custos gating so the agent sees identical tool signatures and the gateway's
``decide`` runs before each tool invocation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from custos.exceptions import PermissionDenied
from custos.gateway import Gateway
from custos.schema import Decision, Invocation, ToolDescriptor, WipeStrategy
from custos.sdk import ContextProvider, MemoryWipe, get_default_context

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["wrap_langchain_tools"]


def wrap_langchain_tools(
    gateway: Gateway,
    tools: Sequence[Any],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> list[Any]:
    """Wrap LangChain ``BaseTool`` objects with Custos gating (US-1).

    Each returned tool has the same name + args + description as the original;
    its invocation first runs ``gateway.decide``, raising
    :class:`PermissionDenied` on ``deny``/``defer`` and otherwise forwarding to
    the original tool. Requires ``langchain-core`` (``custos[langchain]`` extra).
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as exc:  # pragma: no cover - depends on env
        raise ImportError(
            "langchain-core is not installed. Install with: pip install 'custos[langchain]'"
        ) from exc

    descriptors = descriptors or {}
    wrapped: list[Any] = []
    for tool in tools:
        name = getattr(tool, "name", None) or repr(tool)
        descriptor = descriptors.get(name) or _minimal_descriptor(name)
        description = getattr(tool, "description", "") or f"Wrapped by Custos: {name}"
        args_schema = getattr(tool, "args_schema", None)
        _gated = _make_gated_fn(
            gateway, tool, name, descriptor,
            context_provider=context_provider,
            memory_wipe=memory_wipe,
        )
        wrapped.append(
            StructuredTool.from_function(
                _gated,
                name=name,
                description=description,
                args_schema=args_schema,
            )
        )
    return wrapped


def _make_gated_fn(
    gateway: Gateway,
    original: Any,
    name: str,
    descriptor: ToolDescriptor,
    *,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> Any:
    """Build a gated callable that closes over its arguments (avoids loop binding)."""

    def _gated(**kwargs: Any) -> Any:
        ctx = kwargs.pop("custos_context", None) or get_default_context()
        inv = Invocation(
            tool=name,
            args=dict(kwargs),
            context=ctx,
            descriptor=descriptor,
        )
        snapshot = context_provider.get_snapshot() if context_provider else None
        result = gateway.decide(inv, snapshot=snapshot)
        if result.decision == Decision.QUARANTINE and memory_wipe is not None and context_provider is not None:
            current_ctx = context_provider.get_snapshot()
            memory_wipe.sanitize(current_ctx, (), WipeStrategy.FULL)
            raise PermissionDenied(name, result.decision.value)
        if result.decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, result.decision.value)
        return original.invoke(kwargs)

    return _gated


def _minimal_descriptor(name: str) -> ToolDescriptor:
    return ToolDescriptor(name=name, risk_tier=3)


wrap_langchain_tools._custos_alias = True  # type: ignore[attr-defined]
wrap_tools = wrap_langchain_tools
