"""LlamaIndex in-process adapter (carry-forward).

LlamaIndex exposes tools via ``llama_index.core.tools.FunctionTool``
(``FunctionTool.from_defaults(fn=...)`` builds the LLM-schema + a
``callync``/``acall`` dispatcher). The host passes the tool to an agent
(``ReActAgent(tools=[...])``, ``FunctionAgent``, etc.) and LlamaIndex's
dispatch loop invokes the tool's ``acall`` on the model's tool calls.

This adapter gates the *handler* side: each call to the underlying Python
function runs through :class:`~custos.async_gateway.AsyncGateway.decide`
first. Two APIs (mirroring the AutoGen  + Anthropic
handler-side-gating convention):

  - :func:`gated_llamaindex_tool` — authoring helper. Returns the
    ``llama_index.core.tools.FunctionTool`` (built via
    ``FunctionTool.from_defaults`` with the gated proxy) so the host registers
    it on an agent exactly as usual.

  - :func:`wrap_llamaindex_tools` — post-hoc re-wrap of an existing list of
    ``FunctionTool`` objects. Rebuilds from the gated proxy preserving the
    tool's name / description.

Native-async-first (LlamaIndex's ``acall`` path is async; the v1.0 RC pairs
this adapter with :class:`~custos.async_gateway.AsyncGateway`).

 : the ``llama-index-core`` package is an optional extra
(``custos[llamaindex]``). Vendor imports happen strictly inside the adapter
function bodies, never at module top — ``import custos`` with no extras
installed never attempts to import ``llama_index``. Asserted by
``tests/integrations/test_llamaindex.py``'s  leakage regression test
(per the  "vendor-SDK churn /  runtime-dep leakage" risk row).
Echoes the  MCP +  OpenAI Agents +  Anthropic +
AutoGen/Google ADK adapter convention.

Filename convention: trailing ``_`` follows the  import-shadowing rule
(NEVER name the adapter ``llama_index.py`` or ``llamaindex.py``; the
trailing-underscore is the LlamaIndex-moniker-specific lock here). Locked
in CONTRIBUTING.md.
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

__all__ = ["gated_llamaindex_tool", "wrap_llamaindex_tools"]


def gated_llamaindex_tool(
    gateway: AsyncGateway,
    fn: Callable[..., Any],
    *,
    name: str | None = None,
    description: str | None = None,
    risk_tier: int = 1,
    side_effects: frozenset[SideEffect] = frozenset(),
    schema: dict[str, Any] | None = None,
    reversible: bool = False,
    **from_defaults_kwargs: Any,
) -> Any:
    """Build a Custos-gated LlamaIndex ``FunctionTool`` .

    Wraps ``fn`` with an async gated proxy (preserving its signature via
    :func:`functools.wraps` so ``FunctionTool.from_defaults``'s
    introspection follows ``__wrapped__``), then constructs a
    ``llama_index.core.tools.FunctionTool`` via
    ``FunctionTool.from_defaults(gated, ...)`` with the caller's kwargs
    (``name``, ``description``, ``fn_schema``, etc.).

    The returned ``FunctionTool`` is registered on a LlamaIndex agent
    exactly as usual (``ReActAgent(tools=[my_tool])``); invocations go
    through ``await gateway.decide(inv)`` first.

    On ``Decision.DENY`` / ``Decision.DEFER`` the gated proxy raises
    :class:`PermissionDenied`. On allow the underlying function runs
    unchanged (sync or async; the wrapper awaits awaitables).

    Args:
        gateway: an :class:`AsyncGateway`.
        fn: the underlying Python callable.
        name: tool name (defaults to ``fn.__name__``; LlamaIndex uses
            this as the tool-calling identity reported to the LLM).
        description: tool description (defaults to ``fn.__doc__``).
        risk_tier: 1..5 for the Custos-side descriptor.
        side_effects: :class:`SideEffect` set for the Custos descriptor.
        schema: optional Custos-side JSON-schema (for redaction/exfiltration).
        reversible: whether the call can be undone.
        **from_defaults_kwargs: passthrough to
            ``FunctionTool.from_defaults``.
    """
    policy_tool_name = name or fn.__name__
    descriptor = ToolDescriptor(
        name=policy_tool_name,
        risk_tier=risk_tier,
        side_effects=frozenset(side_effects),
        schema=schema or {},
        reversible=reversible,
    )
    gated = _make_gated_async_fn(fn, policy_tool_name, descriptor, gateway)
    # Late import — keeps the module importable without the SDK installed.
    from llama_index.core.tools import FunctionTool

    return FunctionTool.from_defaults(
        gated,
        name=name,
        description=description,
        **from_defaults_kwargs,
    )


def wrap_llamaindex_tools(
    gateway: AsyncGateway,
    tools: list[Any],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
) -> list[Any]:
    """Re-wrap an existing list of LlamaIndex ``FunctionTool`` objects with
    Custos gating.

    Post-hoc integration path for agents built before Custos was added. For
    each ``FunctionTool`` in the input list, the original wrapped
    callable (the ``FN_TOOLS`` field on a ``FunctionTool`` is
    ``{"sync": fn, "async": afn}``; the host's underlying Python function
    is the ``sync`` entry — the canonical attribute path on
    ``FunctionTool.metadata`` in the 0.12 line) is wrapped in an async
    gated proxy and a new ``FunctionTool`` is built via
    ``FunctionTool.from_defaults`` carrying the gated proxy. Other list
    entries (non-``FunctionTool`` LlamaIndex tool types — `QueryEngineTool`,
    `ToolMetadata` constructs) are returned unchanged.

    Args:
        gateway: an :class:`AsyncGateway`.
        tools: list of LlamaIndex tools; only ``FunctionTool`` instances are
            gated, others are passed through.
        descriptors: optional per-tool :class:`ToolDescriptor` overrides
            keyed by tool name; absent tools get a minimal ``risk_tier=3``
            descriptor.
    """
    descriptors = descriptors or {}
    out: list[Any] = []
    from llama_index.core.tools import FunctionTool

    for tool in tools:
        if not isinstance(tool, FunctionTool):
            out.append(tool)
            continue
        # The canonical underlying-fn accessor on a FunctionTool built
        # via `from_defaults` varies slightly across the 0.x line.
        # `tool.fn` and `tool._async_call` are the two common anchors;
        # fall back to the metadata-hosted callable if neither exists.
        original_fn = (
            getattr(tool, "fn", None)
            or getattr(tool, "_fn", None)
            or getattr(tool.metadata, "fn", None)
        )
        if original_fn is None:
            out.append(tool)
            continue
        name = getattr(tool.metadata, "name", None) or original_fn.__name__
        descriptor = descriptors.get(name) or ToolDescriptor(name=name, risk_tier=3)
        gated = _make_gated_async_fn(original_fn, name, descriptor, gateway)
        out.append(
            FunctionTool.from_defaults(
                gated,
                name=name,
                description=getattr(tool.metadata, "description", None),
            )
        )
    return out


def _make_gated_async_fn(
    original_fn: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
) -> Callable[..., Any]:
    """Build an async gated wrapper around a raw Python function for
    :func:`gated_llamaindex_tool`. Awaits the result if it's awaitable."""

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
        decision = await gateway.decide(inv)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        res = original_fn(*args, **kwargs)
        if inspect.isawaitable(res):
            return await res
        return res

    gated.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
    return gated


def _bind_args(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind ``args`` + ``kwargs`` to ``fn``'s signature (parameter-name keyed).

    Mirrors :func:`custos.sdk._minimal_signature_args`. Kept local here so
    the adapter stays self-contained for the  leakage regression
    test.
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


gated_tool = gated_llamaindex_tool
wrap_tools = wrap_llamaindex_tools
