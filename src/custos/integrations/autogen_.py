"""AutoGen 0.4+ in-process adapter (carry-forward).

AutoGen 0.4 (``autogen-agentchat`` / ``autogen-core``) exposes tools via the
``ConversableAgent`` dispatch loop. The host registers tools on a
``ConversableAgent`` and the framework dispatches the LLM's tool calls to
the registered Python callables. This adapter gates the *handler* side:
each call to a handler runs through
:class:`~custos.async_gateway.AsyncGateway.decide` first.

Two APIs:

  - :func:`gated_autogen_tool` — decorator-style authoring helper. Returns a
    ``(definition, gated_callable)`` pair the host registers on its
    ``ConversableAgent`` (the definition list goes into ``llm_config``; the
    call goes into ``register_for_execution`` / ``register_for_llm``).

  - :func:`wrap_autogen_tools` — post-hoc re-wrap of an existing
    ``name -> handler`` dispatch map (the common shape AutoGen integrations
    keep). Returns a new dict where each value is an async gated callable.

Native-async-first (AutoGen's ``on_json_call`` path is async in 0.4; the
v1.0 RC pairs this adapter with :class:`~custos.async_gateway.AsyncGateway`).

 : the ``autogen-agentchat`` package is an optional extra
(``custos[autogen]``). Vendor imports happen strictly inside the adapter
function bodies, never at module top — ``import custos`` with no extras
installed never attempts to import ``autogen`` or ``autogen_core``. Asserted
by ``tests/integrations/test_autogen.py``'s  leakage regression test
(per the  "vendor-SDK churn /  runtime-dep leakage" risk row).
Echoes the  MCP +  OpenAI Agents +  Anthropic adapter
convention.

Filename convention: trailing ``_`` follows the  import-shadowing rule
(NEVER name the adapter ``autogen.py`` — it would shadow the upstream
``autogen`` package for any ``from custos.integrations import autogen``
re-export path; locked in ``CONTRIBUTING.md``).
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

__all__ = ["gated_autogen_tool", "wrap_autogen_tools"]


def gated_autogen_tool(
    gateway: AsyncGateway,
    name: str,
    description: str,
    input_schema: dict[str, Any],
    handler: Callable[..., Any],
    *,
    risk_tier: int = 1,
    side_effects: frozenset[SideEffect] = frozenset(),
    schema: dict[str, Any] | None = None,
    reversible: bool = False,
) -> tuple[dict[str, Any], Callable[..., Any]]:
    """Build a Custos-gated AutoGen tool definition + handler .

    Returns a ``(definition, gated_callable)`` pair. ``definition`` is the
    plain dict an AutoGen ``ConversableAgent`` consumes from its
    ``llm_config`` (shape:
    ``{"type": "function", "function": {"name": ..., "description": ...,
    "parameters": <input_schema>}}`` — the OpenAI tool-call shape AutoGen
    forwards to the LLM). ``gated_callable`` is what the host registers
    for execution: receives the LLM's args dict as a single positional
    argument (AutoGen invokes registered tools with the parsed JSON), runs
    through ``await gateway.decide(inv)`` first, and on
    ``Decision.DENY`` / ``Decision.DEFER`` raises
    :class:`PermissionDenied`.

    Args:
        gateway: an :class:`AsyncGateway` (sync ``Gateway`` is async-bridged
            by ``AsyncGateway``; AutoGen 0.4 is natively async, so
            ``AsyncGateway`` is the recommended pairing).
        name: tool name (passed to the LLM in the definition).
        description: human-readable tool description (passed to the LLM).
        input_schema: JSON schema for the tool's parameters (passed to the
            LLM as ``parameters``).
        handler: the underlying Python callable invoked when the LLM
            returns a tool call for this tool. Receives the parsed args
            dict as a single positional argument (the AutoGen 0.4
            ``register_for_execution`` invocation shape).
        risk_tier: 1..5 for the Custos-side descriptor.
        side_effects: :class:`SideEffect` set for the Custos descriptor.
        schema: optional Custos-side schema (defaults to ``input_schema``;
            the AutoGen-side schema is the LLM's source of truth — this is
            for Custos redaction/exfiltration).
        reversible: whether the call can be undone.
    """
    descriptor = ToolDescriptor(
        name=name,
        risk_tier=risk_tier,
        side_effects=frozenset(side_effects),
        schema=schema if schema is not None else input_schema,
        reversible=reversible,
    )
    definition = make_autogen_tool_definition(name, description, input_schema)
    gated = _make_gated_autogen_callable(name, descriptor, gateway, handler)
    return definition, gated


def wrap_autogen_tools(
    gateway: AsyncGateway,
    handlers: dict[str, Callable[..., Any]],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
) -> dict[str, Callable[..., Any]]:
    """Re-wrap an existing AutoGen ``name -> handler`` dispatch map.

    Post-hoc integration path: the host already built tool definitions and
    registered handlers on its ``ConversableAgent``. Returns a new dict
    where each handler is an async gated callable. Tool definitions are
    unrelated to this adapter — they flow straight to the LLM via
    ``llm_config``; only the dispatch side is gated.

    Args:
        gateway: an :class:`AsyncGateway`.
        handlers: ``{tool_name: handler}`` map the host dispatches on
            AutoGen tool calls.
        descriptors: optional per-tool :class:`ToolDescriptor` overrides;
            absent tools get a minimal ``risk_tier=3`` descriptor.
    """
    descriptors = descriptors or {}
    out: dict[str, Callable[..., Any]] = {}
    for name, handler in handlers.items():
        descriptor = descriptors.get(name) or ToolDescriptor(name=name, risk_tier=3)
        out[name] = _make_gated_autogen_callable(name, descriptor, gateway, handler)
    return out


def make_autogen_tool_definition(
    name: str, description: str, input_schema: dict[str, Any]
) -> dict[str, Any]:
    """Build the AutoGen 0.4 ``llm_config`` tool definition dict.

    Shape:
    ``{"type": "function", "function": {"name": ..., "description": ...,
    "parameters": <input_schema>}}`` — the OpenAI tool-call shape AutoGen
    forwards to the LLM.

    Convention: never import ``autogen`` at module import time. The dict
    shape is plain JSON-Schema-compatible; an AutoGen integration passes
    it into ``ConversableAgent(llm_config={"tools": [...]})``.
    """
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": input_schema,
        },
    }


def _make_gated_autogen_callable(
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
    handler: Callable[..., Any],
) -> Callable[..., Any]:
    """Build an async gated callable for an AutoGen tool dispatch.

    The callable receives the parsed args dict as a single positional
    argument (the AutoGen 0.4 invocation shape). It pops a ``custos_context``
    key (escape hatch for programmatic calls), builds an
    :class:`Invocation`, runs ``await gateway.decide(inv)``, and on
    ``Decision.DENY`` / ``Decision.DEFER`` raises
    :class:`PermissionDenied`. On allow it forwards to ``handler`` (sync
    or async; the wrapper awaits awaitables).
    """

    @functools.wraps(handler)
    async def gated(args_dict: Any, *rest: Any, **kw: Any) -> Any:
        if isinstance(args_dict, dict):
            args_map = dict(args_dict)
            ctx = args_map.pop("custos_context", None)
        else:
            args_map = {"input": args_dict}
            ctx = kw.pop("custos_context", None)
        if ctx is None:
            ctx = get_default_context()
        inv = Invocation(
            tool=name,
            args=args_map,
            context=ctx,
            descriptor=descriptor,
        )
        decision = await gateway.decide(inv)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        # AutoGen 0.4 invokes registered tools with the parsed JSON dict
        # as a single positional argument. Mirror that shape when
        # forwarding to the underlying handler (most AutoGen tool
        # functions take a single dict / kwargs). Fall back to kwargs
        # dispatch if the handler's signature doesn't accept a single
        # positional arg.
        try:
            sig = inspect.signature(handler)
            params = list(sig.parameters)
            if len(params) == 1 and params[0] not in ("self", "input"):
                res = handler(**{params[0]: args_dict} if isinstance(args_dict, dict) else {})
            else:
                res = handler(args_dict, *rest, **kw)
        except TypeError:
            res = handler(args_dict, *rest, **kw)
        if inspect.isawaitable(res):
            return await res
        return res

    gated.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
    return gated


gated_tool = gated_autogen_tool
wrap_tools = wrap_autogen_tools
