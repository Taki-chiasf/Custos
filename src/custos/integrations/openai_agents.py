"""OpenAI Agents SDK in-process adapter .

Wraps :class:`agents.FunctionTool` instances so each tool invocation first
runs through :class:`~custos.async_gateway.AsyncGateway.decide`. On
``deny``/``defer`` the gated wrapper raises
:class:`~custos.exceptions.PermissionDenied` (the SDK surfaces this to the
LLM as a tool error or run-failure depending on the agent's
``failure_error_function``; host integrations can map it to a graceful
refusal). On allow the underlying tool runs unchanged.

Two APIs:

  - :func:`gated_function_tool` — decorator factory mirroring the SDK's
    ``@function_tool`` decorator: register a Custos-gated tool in one step.
    Internally wraps the user's function, then passes the gated wrapper to
    ``@function_tool`` so the SDK's introspection follows
    ``functools.wraps`` and builds the JSON-schema from the original typed
    parameters. Returns the resulting :class:`FunctionTool`.

  - :func:`wrap_openai_agent_tools` — post-hoc re-wrap of an existing list
    of :class:`FunctionTool` objects. Builds a gated
    ``on_invoke_tool`` for each, preserving the tool's name / description /
    ``params_json_schema`` / approval / timeout / guardrails / strict-schema
    settings by replacing only the ``on_invoke_tool`` field on a
    :func:`dataclasses.replace` copy. Useful when integrating Custos into an
    existing agent's ``tools=[...]`` list without rewriting the tool functions.

The subject context is resolved from, in order: an explicit
``custos_context`` key in the tool's JSON arguments (popped before the
gated body runs so the underlying tool never sees it), else the module
default (:func:`custos.sdk.get_default_context`).

Native-async-first. The SDK's :class:`FunctionTool.on_invoke_tool` is async;
the gated wrapper awaits :meth:`AsyncGateway.decide` and then awaits the
underlying invoker.

 : the ``openai-agents`` package is an optional extra
(``custos[openai-agents]``). Vendor imports happen strictly inside the
adapter function bodies, never at module top — ``import custos`` with no
extras installed never attempts to import ``agents``. Asserted by
``tests/integrations/test_openai_agents.py``'s  leakage regression
test (per the  "vendor-SDK churn /  runtime-dep leakage" risk row).
Echoes the  MCP adapter convention.
"""

from __future__ import annotations

import functools
import inspect
import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from custos.exceptions import PermissionDenied
from custos.schema import Decision, Invocation, SideEffect, ToolDescriptor, WipeStrategy
from custos.sdk import ContextProvider, MemoryWipe, get_default_context

if TYPE_CHECKING:
    from custos.async_gateway import AsyncGateway

__all__ = ["gated_function_tool", "wrap_openai_agent_tools"]


def gated_function_tool(
    gateway: AsyncGateway,
    *,
    risk_tier: int = 1,
    side_effects: frozenset[SideEffect] = frozenset(),
    schema: dict[str, Any] | None = None,
    reversible: bool = False,
    tool_name: str | None = None,
    description: str | None = None,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
    **function_tool_kwargs: Any,
) -> Callable[[Callable[..., Any]], Any]:
    """Decorator factory: build a Custos-gated OpenAI Agents ``FunctionTool``.

    Wraps the user's function with an async gated proxy (preserving the typed
    signature via :func:`functools.wraps` so the SDK's JSON-schema
    introspection follows ``__wrapped__``), then passes the gated proxy to
    the SDK's ``@function_tool`` decorator with the caller's kwargs. The
    returned :class:`agents.FunctionTool` is registered on an agent exactly
    as usual (``Agent(tools=[my_tool])``); invocations go through
    ``await gateway.decide(inv)`` first.

    On ``Decision.DENY`` / ``Decision.DEFER`` the gated proxy raises
    :class:`PermissionDenied`. On allow the underlying function runs
    unchanged (sync or async; the wrapper awaits awaitables).

    Args:
        gateway: an :class:`AsyncGateway` (sync ``Gateway`` is async-bridged
            by ``AsyncGateway`` but the OpenAI Agents runtime is natively
            async, so ``AsyncGateway`` is the recommended pairing).
        risk_tier: 1..5 for the Custos-side tool descriptor (runs redaction
            + exfiltration gating; the SDK's own strict JSON-schema is
            orthogonal and unchanged).
        side_effects: :class:`SideEffect` set for the Custos-side descriptor.
        schema: optional Custos-side JSON-schema (for redaction/exfiltration
            gating). The SDK's own schema is built independently from the
            function signature by ``@function_tool`` and is the source of
            truth for the LLM.
        reversible: whether the call can be undone.
        tool_name: override forwarded to ``@function_tool`` as
            ``name_override`` (defaults to the function's ``__name__``).
        description: override forwarded as ``description_override``.
        **function_tool_kwargs: passthrough to ``@function_tool``
            (``needs_approval``, ``strict_mode``, ``timeout``, etc.).
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
        gated = _make_gated_async_fn(
            fn,
            policy_tool_name,
            descriptor,
            gateway,
            context_provider=context_provider,
            memory_wipe=memory_wipe,
        )

        # Late import — keeps the module importable without the SDK installed.
        from agents import function_tool as _function_tool

        return _function_tool(
            gated,
            name_override=tool_name,
            description_override=description,
            **function_tool_kwargs,
        )

    return decorator


def wrap_openai_agent_tools(
    gateway: AsyncGateway,
    tools: list[Any],
    *,
    descriptors: dict[str, ToolDescriptor] | None = None,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> list[Any]:
    """Re-wrap an existing list of OpenAI Agents ``FunctionTool`` objects with
    Custos gating.

    Post-hoc integration path for agents built before Custos was added. For
    each :class:`FunctionTool`, wraps the *inner* ``_invoke_tool_impl`` of
    its ``on_invoke_tool`` (the SDK's ``_FailureHandlingFunctionToolInvoker``)
    rather than replacing ``on_invoke_tool`` wholesale. This preserves the
    SDK's failure-error wrapping: a Custos deny still surfaces to the LLM
    as a model-visible tool-error string (the same path as
    :func:`gated_function_tool`), rather than as a raw ``PermissionDenied``
    exception breaking the agent run.

    Every other field (``name``, ``description``, ``params_json_schema``,
    ``needs_approval``, ``timeout_seconds``, ``strict_json_schema``,
    ``tool_input_guardrails``, ``tool_output_guardrails``, ``is_enabled``,
    etc.) is preserved unchanged.

    Returns a new list of gated tools; the input list is not mutated. Tools
    in the input list that are not :class:`FunctionTool` instances are
    returned unchanged (the SDK has several hosted tool types — file
    search, web search, computer use, etc. — that don't take a Python
    callable; Custos can't gate those from inside the adapter, but the host
    can route them via policy ``deny`` rules if needed).

    Args:
        gateway: an :class:`AsyncGateway`.
        tools: list of OpenAI Agents tools; only :class:`FunctionTool`
            instances are gated, others are passed through.
        descriptors: optional per-tool :class:`ToolDescriptor` overrides
            keyed by tool name; absent tools get a minimal ``risk_tier=3``
            descriptor.
    """
    descriptors = descriptors or {}
    import copy as _copy

    out: list[Any] = []
    for tool in tools:
        # Late import — keeps the module importable without the SDK installed.
        from agents import FunctionTool

        if not isinstance(tool, FunctionTool):
            out.append(tool)
            continue
        descriptor = descriptors.get(tool.name) or ToolDescriptor(name=tool.name, risk_tier=3)
        # The SDK's on_invoke_tool is a _FailureHandlingFunctionToolInvoker
        # carrying ``_invoke_tool_impl`` (the raw invoker) + the failure
        # wrapper. Wrap the inner impl so the failure wrapper still catches
        # the deny and turns it into a model-visible error string (matches
        # the gated_function_tool decorator path).
        original_invoker = tool.on_invoke_tool
        inner_impl = getattr(original_invoker, "_invoke_tool_impl", None)
        if inner_impl is None:
            # Layout drift: no _invoke_tool_impl attribute. Fall back to
            # gating the whole invoker — preserves  at the cost of letting
            # PermissionDenied surface as an exception rather than a
            # model-visible error string. Best-effort + flagged; the
            # gated_function_tool decorator is the primary, stable API.
            gated_invoker = _make_gated_invoker(original_invoker, tool.name, descriptor, gateway)
            new_tool = _copy.copy(tool)
            new_tool.on_invoke_tool = gated_invoker
            out.append(new_tool)
            continue

        gated_inner = _make_gated_invoker(
            inner_impl,
            tool.name,
            descriptor,
            gateway,
            context_provider=context_provider,
            memory_wipe=memory_wipe,
        )
        new_tool = _copy.copy(tool)
        # The on_invoke_tool wrapper is reused (shallow-shared via the copy's
        # reference); only its inner impl is rebound. The shallow copy keeps
        # every other field intact (pointer-shared with the original, which
        # is fine since FunctionTool fields are immutable dataclass
        # attributes). The rebind mutates the *copy's* invoker wrapper, not
        # the original's.
        new_invoker = _copy.copy(original_invoker)
        new_invoker._invoke_tool_impl = gated_inner
        new_tool.on_invoke_tool = new_invoker
        out.append(new_tool)
    return out


def _make_gated_async_fn(
    original_fn: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
    *,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> Callable[..., Any]:
    """Build an async gated wrapper around a raw Python function for
    :func:`gated_function_tool`. Awaits the result if it's awaitable."""

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
        snapshot = context_provider.get_snapshot() if context_provider else None
        result = await gateway.decide(inv, snapshot=snapshot)
        decision = result.decision
        if (
            decision == Decision.QUARANTINE
            and memory_wipe is not None
            and context_provider is not None
        ):
            current_ctx = context_provider.get_snapshot()
            memory_wipe.sanitize(current_ctx, (), WipeStrategy.FULL)
            raise PermissionDenied(name, decision.value)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        res = original_fn(*args, **kwargs)
        if inspect.isawaitable(res):
            return await res
        return res

    gated.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
    return gated


def _make_gated_invoker(
    original_invoker: Callable[..., Any],
    name: str,
    descriptor: ToolDescriptor,
    gateway: AsyncGateway,
    *,
    context_provider: ContextProvider | None = None,
    memory_wipe: MemoryWipe | None = None,
) -> Callable[[Any, str], Any]:
    """Build an async gated ``on_invoke_tool(ctx, json_str)`` wrapper around
    an existing SDK :class:`FunctionTool.on_invoke_tool`.

    The SDK's invoker receives the tool's arguments as a JSON string (the LLM
    serializes the tool call that way); we parse, extract + pop the
    ``custos_context`` escape hatch, build an :class:`Invocation`, run
    ``await gateway.decide(inv)``, then re-serialize and forward to the
    original invoker.
    """

    @functools.wraps(original_invoker)
    async def gated(ctx_obj: Any, args_json: str) -> Any:
        try:
            parsed = json.loads(args_json) if args_json else {}
            if not isinstance(parsed, dict):
                parsed = {}
        except json.JSONDecodeError:
            parsed = {}
        ctx = parsed.pop("custos_context", None)
        if ctx is None:
            ctx = get_default_context()
        forwarded_json = json.dumps(parsed) if parsed else args_json
        inv = Invocation(
            tool=name,
            args=parsed,
            context=ctx,
            descriptor=descriptor,
        )
        snapshot = context_provider.get_snapshot() if context_provider else None
        result = await gateway.decide(inv, snapshot=snapshot)
        decision = result.decision
        if (
            decision == Decision.QUARANTINE
            and memory_wipe is not None
            and context_provider is not None
        ):
            current_ctx = context_provider.get_snapshot()
            memory_wipe.sanitize(current_ctx, (), WipeStrategy.FULL)
            raise PermissionDenied(name, decision.value)
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDenied(name, decision.value)
        return await original_invoker(ctx_obj, forwarded_json)

    gated.__custos_descriptor__ = descriptor  # type: ignore[attr-defined]
    return gated


def _bind_args(
    fn: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]
) -> dict[str, Any]:
    """Bind ``args`` + ``kwargs`` to ``fn``'s signature (parameter-name keyed).

    Mirrors :func:`custos.sdk._minimal_signature_args`. Kept local here so
    the adapter stays self-contained for the  leakage regression test.
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


gated_tool = gated_function_tool
wrap_tools = wrap_openai_agent_tools
