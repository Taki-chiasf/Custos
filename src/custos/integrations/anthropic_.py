"""Anthropic messages-API tool adapter .

The Anthropic Python SDK (``anthropic``) exposes tools via the messages API:
the host passes a tool *definition* (name + description + ``input_schema``)
to ``client.messages.create(tools=[...])`` and dispatches the model's
``tool_use`` blocks to a handler it owns. There is no Anthropic "agent
framework" wrapping the host's dispatch loop, so this adapter gates the
*handler* side: each call to a handler runs through
:class:`~custos.async_gateway.AsyncGateway.decide` first.

Two APIs:

  - :func:`gated_anthropic_tool` — single-shot authoring helper. Returns a
    ``(definition_dict, gated_handler)`` pair the host registers: the
    definition goes into ``tools=[...]``; the handler goes into the host's
    ``name -> handler`` dispatch map.

  - :func:`wrap_anthropic_tool_handlers` — post-hoc re-wrap of an existing
    ``name -> handler`` dispatch map. Returns a new dict where each value
    is an async gated proxy. Tool definitions the host already built are
    unrelated to this — they flow straight to ``client.messages.create``;
    only the dispatch side is gated.

Native-async-first (handlers may be sync or async; the wrapper awaits
awaitables). The subject context comes from :func:`custos.sdk.get_default_context`
(the LLM owns the tool args; no host injection point inside them — same
decision as the OpenAI Agents adapter).

 : ``anthropic`` is an optional extra (``custos[anthropic]``).
Vendor imports happen strictly inside the adapter function bodies, never at
module top — no Shadowing of the upstream ``import anthropic`` either.
Filename ``anthropic_.py`` follows the  import-shadowing rule: a module
named ``anthropic.py`` would shadow the upstream package for any
``from custos.integrations import anthropic`` re-export path. The convention
is locked in CONTRIBUTING.md in . Note: this adapter never imports
``anthropic`` at all in practice (handler-side gating doesn't need the SDK
types), but the function-body-only convention is still enforced for the
``make_tool_definition`` schema helper which uses ``anthropic.types`` for
typed validation when available.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from custos.exceptions import PermissionDenied
from custos.schema import Decision, Invocation, SideEffect, ToolDescriptor, WipeStrategy
from custos.sdk import ContextProvider, MemoryWipe, get_default_context

if TYPE_CHECKING:
    from custos.async_gateway import AsyncGateway

__all__ = [
    "gated_anthropic_tool",
    "wrap_anthropic_tool_handlers",
    "make_tool_definition",
]


def gated_anthropic_tool(
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
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> tuple[dict[str, Any], Callable[..., Any]]:
    """Build a Custos-gated Anthropic tool + handler pair .

    Returns a ``(definition, gated_handler)`` tuple. ``definition`` is the
    plain dict to pass to ``client.messages.create(tools=[...])`` (shape:
    ``{"name": ..., "description": ..., "input_schema": ...}``);
    ``gated_handler`` is an async callable the host registers in its
    ``tool_name -> handler`` dispatch map for the model's ``tool_use``
    blocks. The handler accepts a single ``input`` dict argument (the
    ``tool_use.input`` shape) — mirroring the common Anthropic dispatch
    pattern — and returns the underlying handler's result. On deny/defer
    it raises :class:`PermissionDenied` (the host typically catches that
    and returns a ``tool_result`` block with ``is_error=True``).

    Args:
        gateway: an :class:`AsyncGateway`.
        name: tool name (passed to the model).
        description: human-readable tool description (passed to the model).
        input_schema: JSON schema for the tool's parameters (passed to the
            model as ``input_schema``).
        handler: the underlying Python callable invoked when the model
            returns a ``tool_use`` block for this tool. Receives the
            ``tool_use.input`` dict as a single positional argument.
        risk_tier: 1..5 for the Custos-side descriptor (governs redaction
            + exfiltration gating).
        side_effects: :class:`SideEffect` set for the Custos descriptor.
        schema: optional Custos-side schema (defaults to ``input_schema``;
            the SDK's input_schema is the model's source of truth — this is
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
    definition = make_tool_definition(name, description, input_schema)
    gated_handler = _make_gated_anthropic_handler(
        name, descriptor, gateway, handler,
        context_provider=context_provider,
        memory_wipe=memory_wipe,
    )
    return definition, gated_handler


def wrap_anthropic_tool_handlers(
    gateway: AsyncGateway,
    handlers: dict[str, Callable[..., Any]],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> dict[str, Callable[..., Any]]:
    """Re-wrap an existing Anthropic ``name -> handler`` dispatch map.

    Post-hoc integration path: the host already built tool definitions and
    registered handlers. Returns a new dict where each handler is an async
    gated callable. Tool definitions are unrelated to this — they flow
    straight to the API call.

    Args:
        gateway: an :class:`AsyncGateway`.
        handlers: ``{tool_name: handler}`` map the host dispatches on
            ``tool_use`` blocks.
        descriptors: optional per-tool :class:`ToolDescriptor` overrides;
            absent tools get a minimal ``risk_tier=3`` descriptor.
    """
    descriptors = descriptors or {}
    out: dict[str, Callable[..., Any]] = {}
    for name, handler in handlers.items():
        descriptor = descriptors.get(name) or ToolDescriptor(name=name, risk_tier=3)
        out[name] = _make_gated_anthropic_handler(
            name, descriptor, gateway, handler,
            context_provider=context_provider,
            memory_wipe=memory_wipe,
        )
    return out


# Cache the validated-toolparam-availability bit so the best-effort
# validation runs at most once per process: a single ``import anthropic.types``
# attempt inside the try-block is enough. After that the cached flag is read
# without touching the import system again — preserving the  invariant
# (``import custos`` with no extras installed never even ATTEMPTS to import
# ``anthropic`` post-cache-miss).
_UNSET: object = object()
_anthropic_toolparam: Any | None | object = _UNSET


def _validated_definition(definition: dict[str, Any]) -> dict[str, Any]:
    """Run the SDK's ``ToolParam`` validation if the SDK is installed. Cached
    so the import only happens once per process. Best-effort: any validation
    failure is swallowed (the caller's plain-dict shape stands).
    """
    global _anthropic_toolparam
    if _anthropic_toolparam is _UNSET:
        try:
            from anthropic.types import ToolParam

            _anthropic_toolparam = ToolParam
        except ImportError:
            _anthropic_toolparam = None
        except Exception:  # noqa: BLE001 - defensive: SDK layout drift.
            _anthropic_toolparam = None
    tool_param_cls = _anthropic_toolparam
    if tool_param_cls is not None and tool_param_cls is not _UNSET:
        # The SDK's pydantic model validates the dict shape; we don't
        # care about failures here (best-effort, the caller's dict stands).
        with contextlib.suppress(Exception):
            tool_param_cls.model_validate(definition)  # type: ignore[union-attr]
    return definition


def make_tool_definition(
    name: str, description: str, input_schema: dict[str, Any]
) -> dict[str, Any]:
    """Build a plain Anthropic tool-definition dict.

    Shape: ``{"name": str, "description": str, "input_schema": dict}``.
    Suitable for ``client.messages.create(tools=[def, ...])``.

    The convention here is to NOT require the ``anthropic`` package at
    import time — the dict shape is plain JSON-Schema-compatible. A
    type-check against ``anthropic.types.ToolParam`` is performed if the
    package is installed (best-effort validation; falls back silently).
    The import attempt happens exactly once per process and is cached.
    """
    return _validated_definition(
        {
            "name": name,
            "description": description,
            "input_schema": input_schema,
        }
    )


def _make_gated_anthropic_handler(
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
    handler: Callable[..., Any],
    *,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> Callable[..., Any]:
    """Build an async gated handler for an Anthropic ``tool_use`` block.

    The handler is invoked with the ``tool_use.input`` dict as its single
    positional argument. The wrapper pops a ``custos_context`` key (if the
    host chained it through) — escape hatch for programmatic calls.
    """

    @functools.wraps(handler)
    async def gated_handler(input_dict: Any, *args: Any, **kwargs: Any) -> Any:
        # Accept either the raw input dict or a kwargs-style call.
        if isinstance(input_dict, dict):
            args_map = dict(input_dict)
            ctx = args_map.pop("custos_context", None)
        else:
            args_map = {"input": input_dict}
            ctx = kwargs.pop("custos_context", None)
        if ctx is None:
            ctx = get_default_context()
        inv = Invocation(
            tool=name,
            args=args_map,
            context=ctx,
            descriptor=descriptor,
        )
        snapshot = context_provider.get_snapshot() if context_provider else None
        result = await gateway.decide(inv, snapshot=snapshot)
        decision = result.decision
        if decision == Decision.QUARANTINE and memory_wipe is not None and context_provider is not None:
            current_ctx = context_provider.get_snapshot()
            memory_wipe.sanitize(current_ctx, (), WipeStrategy.FULL)
            raise PermissionDenied(name, decision.value)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        # The underlying handler may accept either (input_dict) or (**kwargs).
        # Try kwargs first (most common Anthropic dispatch pattern); fall back
        # to positional.
        try:
            sig = inspect.signature(handler)
            params = list(sig.parameters)
            if len(params) == 1 and params[0] not in ("self", "input"):
                # Single named parameter; pass as kwarg.
                res = handler(**{params[0]: input_dict} if isinstance(input_dict, dict) else {})
            else:
                res = handler(input_dict, *args, **kwargs)
        except TypeError:
            res = handler(input_dict, *args, **kwargs)
        if inspect.isawaitable(res):
            return await res
        return res

    gated_handler.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
    return gated_handler


gated_tool = gated_anthropic_tool
wrap_tools = wrap_anthropic_tool_handlers
