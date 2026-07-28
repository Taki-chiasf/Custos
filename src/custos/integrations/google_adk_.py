"""Google ADK (Agent Development Kit, Gemini) in-process adapter
(carry-forward).

Google's ADK exposes tools via ``google.adk.tools.FunctionTool`` (and the
``@tool`` decorator). The host passes a Python callable to
``FunctionTool(func)`` and the ADK runtime introspects the signature for
the LLM schema and dispatches the model's tool calls via
``await tool.run_async(args_dict)``.

Two APIs:

  - :func:`gated_adk_tool` — primary authoring path. Builds an async
    gated proxy around the user's function (preserving its signature via
    :func:`functools.wraps` so ADK's JSON-schema introspection still sees
    the typed parameters), then constructs a ``FunctionTool`` from the
    gated proxy. Returns the resulting ``FunctionTool`` (registered on an
    agent exactly as usual — ``LlmAgent(tools=[my_tool])``).

  - :func:`wrap_adk_tools` — post-hoc re-wrap of an existing list of
    ``FunctionTool`` objects. Builds a gated inner-function replacement
    per tool, preserving the tool's name / description / schema by
    reconstructing the ``FunctionTool`` from the gated proxy.

Native-async-first (ADK's ``run_async`` path is async; the v1.0 RC pairs
this adapter with :class:`~custos.async_gateway.AsyncGateway`).

 : the ``google-adk`` package is an optional extra
(``custos[google-adk]``). Vendor imports happen strictly inside the
adapter function bodies, never at module top — ``import custos`` with no
extras installed never attempts to import ``google.adk``. Asserted by
``tests/integrations/test_google_adk.py``'s  leakage regression
test (per the  "vendor-SDK churn /  runtime-dep leakage" risk
row). Echoes the  MCP +  OpenAI Agents +  Anthropic adapter
convention.

Filename convention: trailing ``_`` follows the  import-shadowing rule
for hyphen-bearing extras (``google-adk`` → ``google_adk`` at the Python
identifier level; the module is named ``google_adk_`` so a future
``from custos.integrations import google_adk`` re-export path can never
shadow the upstream ``google.adk`` namespace). Locked in CONTRIBUTING.md.
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

__all__ = ["gated_adk_tool", "wrap_adk_tools"]


def gated_adk_tool(
    gateway: AsyncGateway,
    *,
    risk_tier: int = 1,
    side_effects: frozenset[SideEffect] = frozenset(),
    schema: dict[str, Any] | None = None,
    reversible: bool = False,
    tool_name: str | None = None,
    description: str | None = None,
) -> Callable[[Callable[..., Any]], Any]:
    """Decorator factory: build a Custos-gated Google ADK ``FunctionTool``.

    Wraps the user's function with an async gated proxy, then constructs a
    ``google.adk.tools.FunctionTool`` from the gated proxy. The returned
    ``FunctionTool`` is registered on an ``LlmAgent`` exactly as usual;
    invocations go through ``await gateway.decide(inv)`` first.

    On ``Decision.DENY`` / ``Decision.DEFER`` the gated proxy raises
    :class:`PermissionDenied`. On allow the underlying function runs
    unchanged (sync or async; the wrapper awaits awaitables).

    Args:
        gateway: an :class:`AsyncGateway` (sync ``Gateway`` is
            async-bridged by ``AsyncGateway``; ADK is natively async, so
            ``AsyncGateway`` is the recommended pairing).
        risk_tier: 1..5 for the Custos-side tool descriptor.
        side_effects: :class:`SideEffect` set for the Custos-side descriptor.
        schema: optional Custos-side JSON-schema (for redaction/exfiltration
            gating). ADK's own schema is built independently from the
            function signature by ``FunctionTool`` and is the source of
            truth for the LLM.
        reversible: whether the call can be undone.
        tool_name: override forwarded to the ADK ``FunctionTool`` (defaults
            to the function's ``__name__``).
        description: override forwarded to ``FunctionTool`` (defaults to the
            function's docstring).
    """

    def decorator(fn: Callable[..., Any]) -> Any:
        policy_tool_name = tool_name or fn.__name__
        descriptor = ToolDescriptor(
            name=policy_tool_name,
            risk_tier=risk_tier,
            side_effects=frozenset(side_effects),
            schema=schema or {},
            reversible=reversible,
        )
        gated = _make_gated_async_fn(fn, policy_tool_name, descriptor, gateway)
        # Late import — keeps the module importable without the SDK
        # installed .
        from google.adk.tools import FunctionTool

        if tool_name is not None or description is not None:
            return FunctionTool(
                gated,
                name=tool_name,
                description=description,
            )
        return FunctionTool(gated)

    return decorator


def wrap_adk_tools(
    gateway: AsyncGateway,
    tools: list[Any],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
) -> list[Any]:
    """Re-wrap an existing list of Google ADK ``FunctionTool`` objects with
    Custos gating.

    Post-hoc integration path for agents built before Custos was added.
    For each ``FunctionTool`` in the input list, the original wrapped
    function (``tool.func`` — the canonical attribute on ADK's
    ``FunctionTool``) is wrapped in an async gated proxy and a new
    ``FunctionTool`` is constructed from the gated proxy, preserving the
    tool's name / description / introspected schema (``FunctionTool``
    re-runs its signature introspection on the gated proxy via
    :func:`functools.wraps` so the schema is unchanged). Other list
    entries (non-``FunctionTool`` tools — ADK's hosted tool types) are
    returned unchanged.

    Args:
        gateway: an :class:`AsyncGateway`.
        tools: list of ADK tools; only ``FunctionTool`` instances are
            gated, others are passed through.
        descriptors: optional per-tool :class:`ToolDescriptor` overrides
            keyed by tool name; absent tools get a minimal ``risk_tier=3``
            descriptor.
    """
    descriptors = descriptors or {}
    out: list[Any] = []
    from google.adk.tools import FunctionTool

    for tool in tools:
        if not isinstance(tool, FunctionTool):
            out.append(tool)
            continue
        # The canonical ADK FunctionTool wraps the user's function under
        # ``func`` (the attribute name in 1.x). Fall back gracefully if a
        # future SDK layout drifts; the gated_adk_tool decorator is the
        # primary, stable API.
        original_fn = getattr(tool, "func", None) or getattr(tool, "_func", None)
        if original_fn is None:
            out.append(tool)
            continue
        name = getattr(tool, "name", None) or original_fn.__name__
        descriptor = descriptors.get(name) or ToolDescriptor(name=name, risk_tier=3)
        gated = _make_gated_async_fn(original_fn, name, descriptor, gateway)
        gated_tool = FunctionTool(
            gated,
            name=name,
            description=getattr(tool, "description", None),
        )
        out.append(gated_tool)
    return out


def _make_gated_async_fn(
    original_fn: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
) -> Callable[..., Any]:
    """Build an async gated wrapper around a raw Python function for
    :func:`gated_adk_tool`. Awaits the result if it's awaitable."""

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


gated_tool = gated_adk_tool
wrap_tools = wrap_adk_tools
