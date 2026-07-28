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
from custos.schema import Decision, Invocation, ToolDescriptor
from custos.sdk import get_default_context

if TYPE_CHECKING:
    from collections.abc import Sequence

__all__ = ["wrap_langchain_tools"]


def wrap_langchain_tools(
    gateway: Gateway,
    tools: Sequence[Any],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
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
        _gated = _make_gated_fn(gateway, tool, name, descriptor)
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
        decision = gateway.decide(inv)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        return original.invoke(kwargs)

    return _gated


def _minimal_descriptor(name: str) -> ToolDescriptor:
    return ToolDescriptor(name=name, risk_tier=3)


wrap_langchain_tools._custos_alias = True  # type: ignore[attr-defined]
wrap_tools = wrap_langchain_tools
