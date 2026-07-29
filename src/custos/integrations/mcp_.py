"""MCP (Model Context Protocol) in-process adapter .

Wraps tools registered on an MCP server (``mcp.server.fastmcp.FastMCP``; v1.x
stable, the line Janus pins and the v1.0 RC targets) so each
:rpc:msg:`tools/call` invocation first runs through
:class:`~custos.async_gateway.AsyncGateway.decide`. On ``deny``/``defer`` the
gated tool raises :class:`~custos.exceptions.PermissionDenied` (MCP surfaces
this as a protocol error to the client; the host agent handles it). On allow
the underlying tool runs unchanged.

Two APIs:

  - :func:`gated_tool` — decorator factory. Primary, recommended path; the
    tool function is registered on the server AND wrapped in one step. The
    wrapper preserves the function's signature (via :func:`functools.wraps`)
    so MCP's JSON-schema introspection still sees the typed parameters.

  - :func:`wrap_mcp_tools` — post-hoc re-wrap of an existing server's
    registered tools. Best-effort; reaches into ``FastMCP._tool_manager._tools``
    (private but stable on the 1.x line) and replaces each ``tool.fn`` with a
    Custos-gated variant. Useful when integrating Custos into an existing
    MCP server code base without rewriting the tool decorators.

Native-async-first (MCP's ``call_tool`` path is async; the v1.0 RC pairs this
adapter with :class:`~custos.async_gateway.AsyncGateway`).

 : the ``mcp`` package is an optional extra (``custos[mcp]``).
Vendor imports happen strictly inside the adapter functions, never at module
top-level — ``import custos`` with no extras installed never attempts to
import ``mcp``. Asserted by ``tests/integrations/test_mcp.py``'s
leakage regression test (per the  "vendor-SDK churn /  runtime-dep
leakage" risk row).

Filename convention: trailing ``_`` matches the  Anthropic-shadowing
rule (NEVER name the adapter ``mcp.py`` — it would shadow the upstream ``mcp``
package for any ``from custos.integrations import mcp`` re-export path; locked
in ``CONTRIBUTING.md`` in).
"""

from __future__ import annotations

import functools
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from custos.exceptions import PermissionDenied
from custos.schema import Decision, Invocation, SideEffect, ToolDescriptor
from custos.sdk import get_default_context

if TYPE_CHECKING:
    from custos.async_gateway import AsyncGateway

__all__ = ["gated_tool", "wrap_mcp_tools"]


def gated_tool(
    mcp_server: Any,
    gateway: AsyncGateway,
    *,
    risk_tier: int = 1,
    side_effects: frozenset[SideEffect] = frozenset(),
    schema: dict[str, Any] | None = None,
    reversible: bool = False,
    tool_name: str | None = None,
    description: str | None = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory: register a Custos-gated tool on an MCP server .

    The decorated function is registered on ``mcp_server`` (via its ``tool``
    decorator) so MCP's standard ``tools/list`` discovery surfaces it, and its
    invocations go through ``await gateway.decide(inv)`` first. On
    ``Decision.DENY`` / ``Decision.DEFER`` the gated wrapper raises
    :class:`PermissionDenied` (MCP propagates it as a protocol-level error to
    the client). On allow the underlying function runs unchanged (sync or
    async; the wrapper awaits awaitables).

    The Custos subject context is resolved from, in order: an explicit
    ``custos_context`` kwarg in the MCP call args, else the module default
    (:func:`custos.sdk.get_default_context`). The ``custos_context`` key is
    popped before the underlying function is called (so the original tool
    never sees it).

    Args:
        mcp_server: a ``FastMCP`` server instance (v1.x).
        gateway: an :class:`AsyncGateway` (sync ``Gateway`` is async-bridged
            by ``AsyncGateway`` but the MCP runtime is natively async, so
            ``AsyncGateway`` is the recommended pairing).
        risk_tier: 1 (trivial)..5 (catastrophic) for the tool descriptor.
        side_effects: :class:`SideEffect` set for the tool descriptor.
        schema: optional JSON-schema for the tool's input params (MCP's own
            ``inspect.signature``-derived schema is preserved on the server;
            this Custos-side schema is for redaction/exfiltration gating).
        reversible: whether the call can be undone.
        tool_name: MCP-side tool name (defaults to the function's ``__name__``,
            exactly like ``@mcp.tool``).
        description: human-readable description (defaults to the function's
            docstring, matching MCP).

    Returns:
        A decorator that registers + wraps the function and returns the
        gated wrapper (preserving the original signature via
        :func:`functools.wraps`).

    Example::

        from mcp.server.fastmcp import FastMCP
        from custos import AsyncGateway, Policy
        from custos.integrations.mcp_ import gated_tool

        mcp = FastMCP("my-server")
        gw = AsyncGateway(policy=Policy.from_dict({...}))

        @gated_tool(mcp, gw, risk_tier=2,
                    side_effects=frozenset({SideEffect.WRITE}))
        def fs_write(path: str, content: str) -> str:
            "...write a file..."
            return f"wrote {len(content)} bytes to {path}"
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        policy_tool_name = tool_name or fn.__name__
        descriptor = ToolDescriptor(
            name=policy_tool_name,
            risk_tier=risk_tier,
            side_effects=frozenset(side_effects),
            schema=schema or {},
            reversible=reversible,
        )

        @functools.wraps(fn)
        async def gated(*args: Any, **kwargs: Any) -> Any:
            ctx = kwargs.pop("custos_context", None) or get_default_context()
            # Bind bound args for the Invocation (so policy args predicates
            # can match by parameter name, not just kwarg name).
            call_args = _bind_args(fn, args, kwargs)
            inv = Invocation(
                tool=policy_tool_name,
                args=call_args,
                context=ctx,
                descriptor=descriptor,
            )
            result = await gateway.decide(inv)
            decision = result.decision
            if decision in (Decision.DENY, Decision.DEFER):
                raise PermissionDenied(policy_tool_name, decision.value)
            res = fn(*args, **kwargs)
            if inspect.isawaitable(res):
                return await res
            return res

        gated.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
        # Register on the MCP server via its standard decorator. The MCP
        # server's introspection follows ``__wrapped__`` (functools.wraps)
        # so it sees the original typed signature for JSON-schema building.
        mcp_server.tool(name=tool_name, description=description)(gated)
        return gated

    return decorator


def wrap_mcp_tools(
    gateway: AsyncGateway,
    mcp_server: Any,
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
) -> list[str]:
    """Re-wrap an existing MCP server's registered tools with Custos gating.

    Post-hoc integration path for servers built before Custos was added. Walks
    the server's currently-registered tools, builds an async gated wrapper for
    each (functools.wraps the original so MCP's JSON-schema introspection
    follows ``__wrapped__``), and re-registers via the manager's ``add_tool``
    (which re-runs ``Tool.from_function(gated)`` — so the gated variant's
    ``is_async=True`` is honored by ``call_tool`` regardless of the original's
    asyncness). Returns the list of tool names that were re-wrapped.

    Best-effort: if the server's tool-manager layout changes between MCP
    releases (private attribute path drift), this raises ``RuntimeError`` with
    a pointer to the :func:`gated_tool` decorator as the primary stable API.

    Args:
        gateway: an :class:`AsyncGateway`.
        mcp_server: a ``FastMCP`` server with at least one registered tool.
        descriptors: optional per-tool :class:`ToolDescriptor` overrides
            (keyed by tool name); absent tools get a minimal ``risk_tier=3``
            descriptor.
    """
    descriptors = descriptors or {}
    try:
        manager = mcp_server._tool_manager
        tools = dict(manager._tools)
    except AttributeError as exc:
        raise RuntimeError(
            "wrap_mcp_tools: expected a FastMCP server (mcp.server.fastmcp.FastMCP) "
            "with a ``_tool_manager._tools`` registry. The MCP SDK layout may have "
            "changed; use the gated_tool decorator factory as the stable API "
            "(custos.integrations.mcp_.gated_tool). Original error: " + str(exc)
        ) from exc

    # De-duplicate on descriptor identity per tool name (one closure per iter).
    wrapped_names: list[str] = []
    for name, tool in tools.items():
        original_fn = tool.fn
        descriptor = descriptors.get(name) or ToolDescriptor(name=name, risk_tier=3)
        gated = _make_gated_async(original_fn, name, descriptor, gateway)

        # Re-register via the manager's add_tool so Tool.from_function re-runs
        # on the async gated wrapper (sets is_async=True); replace in place by
        # dropping the existing entry first so add_tool doesn't no-op on the
        # duplicate-name short-circuit.
        with _suppress_keyerror():
            del manager._tools[name]
        manager.add_tool(
            gated,
            name=name,
            description=tool.description,
        )
        wrapped_names.append(name)
    return wrapped_names


def _make_gated_async(
    original_fn: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
) -> Callable[..., Any]:
    """Build an async gated wrapper around ``original_fn`` (sync or async).

    ``functools.wraps`` preserves the original signature so MCP's JSON-schema
    introspection follows ``__wrapped__`` and sees the typed parameters.
    """

    @functools.wraps(original_fn)
    async def gated(*args: Any, **kwargs: Any) -> Any:
        ctx = kwargs.pop("custos_context", None) or get_default_context()
        call_args = _bind_args(original_fn, args, kwargs)
        inv = Invocation(
            tool=name,
            args=call_args,
            context=ctx,
            descriptor=descriptor,
        )
        result = await gateway.decide(inv)
        decision = result.decision
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        res = original_fn(*args, **kwargs)
        if inspect.isawaitable(res):
            return await res
        return res

    gated.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
    return gated


class _suppress_keyerror:
    """Context manager that swallows ``KeyError`` (for ``del`` on a missing key)."""

    def __enter__(self) -> _suppress_keyerror:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool:
        return exc_type is KeyError


def _bind_args(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind ``args`` + ``kwargs`` to ``fn``'s signature (parameter-name keyed).

    Mirrors :func:`custos.sdk._minimal_signature_args` (kept local here to
    avoid a cross-module import that would pull the SDK into the adapter's
    top-level graph — keeps the MCP adapter self-contained for the
    leakage regression test).
    """
    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        return dict(bound.arguments)
    except TypeError:
        merged = dict(kwargs)
        merged.update(dict(zip(inspect.signature(fn).parameters, args, strict=False)))
        return merged


# Consistent alias — the canonical ``gated_tool`` is already the primary name.
wrap_tools = wrap_mcp_tools
