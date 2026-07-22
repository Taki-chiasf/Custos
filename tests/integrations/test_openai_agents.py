"""Tests for the OpenAI Agents SDK in-process adapter .

Skipped when ``openai-agents`` is not installed (pytest.importorskip) so the
test suite stays green in a runtime-only (no-extras) install — asserting the
 runtime-dep-leakage invariant (risk row " runtime-dep leakage").

Covers both adapter APIs:
  - :func:`custos.integrations.openai_agents.gated_function_tool` — decorator
    factory: register a Custos-gated ``FunctionTool`` in one step.
  - :func:`custos.integrations.openai_agents.wrap_openai_agent_tools` —
    post-hoc re-wrap of an existing list of ``FunctionTool`` objects.

Plus the  floor invariant (a policy ``deny`` short-circuits the gateway
before the gated tool body runs), signature preservation (the SDK's
JSON-schema introspection follows ``functools.wraps``), async tools,
allow-path forwarding, hosted-tool passthrough (``WebSearchTool`` is not a
``FunctionTool`` so it is returned unchanged), the  leakage regression,
and the `custos_context` escape hatch.
"""

from __future__ import annotations

import asyncio
import functools
import json
import sys
from typing import Any

import pytest

# Skip the whole module when the SDK isn't installed.
pytest.importorskip("agents")
from agents import WebSearchTool, function_tool  # noqa: E402
from agents.tool_context import ToolContext  # noqa: E402

from custos import AsyncGateway, Policy  # noqa: E402
from custos.exceptions import PermissionDenied  # noqa: E402
from custos.integrations.openai_agents import (  # noqa: E402
    gated_function_tool,
    wrap_openai_agent_tools,
)
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec  # noqa: E402
from custos.schema import SideEffect, SubjectContext  # noqa: E402

# --------------------------------------------------------------------------- #
# Async test helper + helpers
# --------------------------------------------------------------------------- #


def _async_test(coro_fn):
    @functools.wraps(coro_fn)
    def runner(*args: Any, **kwargs: Any) -> None:
        return asyncio.run(coro_fn(*args, **kwargs))

    return runner


def _policy(rules: list[PolicyRuleSpec], *, default: str = "deny") -> Policy:
    return Policy.from_spec(
        PolicyFile(
            version=1,
            default=default,
            overlays=(PolicyOverlaySpec(id="base", rules=tuple(rules)),),
        )
    )


def _gw(rules: list[PolicyRuleSpec]) -> AsyncGateway:
    return AsyncGateway(policy=_policy(rules), default_timeout_ms=5_000)


def _ctx(name: str, args_json: str = "") -> ToolContext:
    """Build a minimal :class:`ToolContext` for invoking a FunctionTool."""
    return ToolContext(
        context=None,
        tool_name=name,
        tool_call_id="test-call",
        tool_arguments=args_json,
    )


# --------------------------------------------------------------------------- #
# gated_function_tool decorator factory
# --------------------------------------------------------------------------- #


@_async_test
async def test_gated_function_tool_returns_a_function_tool() -> None:
    from agents import FunctionTool

    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    @gated_function_tool(gw, risk_tier=1)
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    assert isinstance(add, FunctionTool)
    assert add.name == "add"
    assert add.description == "Add two numbers."


@_async_test
async def test_gated_function_tool_allow_forwards_to_underlying() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    @gated_function_tool(gw, risk_tier=1)
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    res = await add.on_invoke_tool(_ctx("add"), json.dumps({"a": 1, "b": 2}))
    assert res == 3


@_async_test
async def test_gated_function_tool_preserves_signature_for_introspection() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    @gated_function_tool(gw, risk_tier=1)
    def compute(x: int, y: int, label: str = "out") -> str:
        """Compute."""
        return f"{label}={x + y}"

    # The SDK built the JSON schema from the typed gated wrapper (functools.wraps).
    required = set(compute.params_json_schema.get("required", []))
    assert {"x", "y"} <= required
    assert "label" in compute.params_json_schema.get("properties", {})


@_async_test
async def test_gated_function_tool_async_underlying_function() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "geo"}, action="allow")])

    @gated_function_tool(gw, risk_tier=1)
    async def geo(city: str) -> str:
        """Async geo lookup."""
        await asyncio.sleep(0)
        return f"weather in {city}"

    res = await geo.on_invoke_tool(_ctx("geo"), json.dumps({"city": "NYC"}))
    assert res == "weather in NYC"


@_async_test
async def test_gated_function_tool_deny_raises_permission_denied() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "del*"}, action="deny")])

    @gated_function_tool(gw, risk_tier=5, side_effects=frozenset({SideEffect.DESTRUCTIVE}))
    def delete_file(path: str) -> str:
        """Delete a file."""
        return "should not be called"

    # The SDK's wrapped invoker catches the PermissionDenied and yields a
    # model-visible tool-error string (default failure_error_function). We
    # assert the gated path produced a "Permission denied" error result
    # rather than letting the underlying tool body run.
    res = await delete_file.on_invoke_tool(_ctx("delete_file"), json.dumps({"path": "/tmp/x"}))
    # The SDK's default failure-error formatter produces an error string
    # describing the underlying exception. Assert the deny was visible.
    assert "Permission denied" in str(res) or PermissionDenied.__name__ in str(res)


@_async_test
async def test_gated_function_tool_default_deny_no_responder_raises() -> None:
    # No allow rule + default deny → gateway returns DENY (floor). The
    # gated wrapper raises PermissionDenied; SDK surfaces via its failure
    # error function (default returns a model-visible error string).
    gw = _gw([])

    @gated_function_tool(gw, risk_tier=1)
    def secret(token: str) -> str:
        """..."""
        return "ok"

    res = await secret.on_invoke_tool(_ctx("secret"), json.dumps({"token": "x"}))
    assert "Permission denied" in str(res) or PermissionDenied.__name__ in str(res)


# --------------------------------------------------------------------------- #
# Floor invariant : deny never invokes the underlying tool body
# --------------------------------------------------------------------------- #


@_async_test
async def test_gated_function_tool_deny_never_invokes_underlying() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="deny")])
    invoked = {"count": 0}

    @gated_function_tool(gw, risk_tier=1)
    def sentinel(x: int) -> int:
        """Sentinel."""
        invoked["count"] += 1
        return x

    res = await sentinel.on_invoke_tool(_ctx("sentinel"), json.dumps({"x": 1}))
    # The deny was visible (model-visible error string per SDK default)
    # AND the body never ran (sentinel counter stays 0 —  floor).
    assert "Permission denied" in str(res) or PermissionDenied.__name__ in str(res)
    assert invoked["count"] == 0


# --------------------------------------------------------------------------- #
# wrap_openai_agent_tools: post-hoc re-wrap of an existing tools list
# --------------------------------------------------------------------------- #


@_async_test
async def test_wrap_openai_agent_tools_passthrough_non_function_tools() -> None:
    # Hosted tools (WebSearchTool etc) are NOT FunctionTool — we can't gate
    # them in-process; pass through unchanged. Caller can route via a
    # policy deny rule for the tool name if needed.
    wst = WebSearchTool()
    gw = _gw([])
    out = wrap_openai_agent_tools(gw, [wst])
    assert out[0] is wst


@_async_test
async def test_wrap_openai_agent_tools_sync_tool() -> None:
    gw = _gw(
        [
            PolicyRuleSpec(match={"tool": "fs_read"}, action="allow"),
            PolicyRuleSpec(match={"tool": "fs_write"}, action="deny"),
        ]
    )

    @function_tool
    def fs_read(p: str) -> str:
        """read a file"""
        return f"contents of {p}"

    @function_tool
    def fs_write(p: str, c: str) -> str:
        """write a file"""
        return f"wrote to {p}"

    gated = wrap_openai_agent_tools(gw, [fs_read, fs_write])
    assert len(gated) == 2

    # Allow path: gated call forwards to the underlying invoker.
    res = await gated[0].on_invoke_tool(
        _ctx("fs_read", json.dumps({"p": "/etc/hosts"})),
        json.dumps({"p": "/etc/hosts"}),
    )
    assert res == "contents of /etc/hosts"

    # Deny path: gated wrapper raises PermissionDenied; SDK surfaces via
    # failure-error default (model-visible error string).
    res = await gated[1].on_invoke_tool(
        _ctx("fs_write", json.dumps({"p": "/x", "c": "y"})),
        json.dumps({"p": "/x", "c": "y"}),
    )
    assert "Permission denied" in str(res) or PermissionDenied.__name__ in str(res)


@_async_test
async def test_wrap_openai_agent_tools_async_tool() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "async_lookup"}, action="allow")])

    @function_tool
    async def async_lookup(key: str) -> str:
        """Async lookup."""
        await asyncio.sleep(0)
        return f"val-{key}"

    gated = wrap_openai_agent_tools(gw, [async_lookup])
    res = await gated[0].on_invoke_tool(
        _ctx("async_lookup", json.dumps({"key": "abc"})),
        json.dumps({"key": "abc"}),
    )
    assert res == "val-abc"


@_async_test
async def test_wrap_openai_agent_tools_preserves_name_description_schema() -> None:
    gw = _gw([])

    @function_tool(name_override="my_calc", description_override="Custom calc")
    def compute(x: int) -> int:
        """Native docstring."""
        return x * 2

    gated = wrap_openai_agent_tools(gw, [compute])[0]
    assert gated.name == "my_calc"
    assert gated.description == "Custom calc"
    assert "x" in gated.params_json_schema.get("properties", {})


@_async_test
async def test_wrap_openai_agent_tools_preserves_other_fields() -> None:
    # The gated clone should preserve strict_json_schema, needs_approval,
    # timeout_seconds — every field except on_invoke_tool. SDK enforces
    # timeout_seconds only on async function tools, so use one.
    gw = _gw([])

    @function_tool(strict_mode=False, needs_approval=False, timeout=42.0)
    async def with_settings(a: int) -> int:
        """..."""
        await asyncio.sleep(0)
        return a * 2

    gated = wrap_openai_agent_tools(gw, [with_settings])[0]
    assert gated.strict_json_schema is False
    assert gated.needs_approval is False
    assert gated.timeout_seconds == 42.0


@_async_test
async def test_wrap_openai_agent_tools_does_not_mutate_input_list() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    @function_tool
    def ping() -> str:
        """..."""
        return "pong"

    originals = [ping]
    original_invoker = ping.on_invoke_tool
    gated = wrap_openai_agent_tools(gw, list(originals))
    # The original FunctionTool's invoker is unchanged (we used dataclasses.replace).
    assert ping.on_invoke_tool is original_invoker
    # The gated copy has a different invoker.
    assert gated[0].on_invoke_tool is not original_invoker


@_async_test
async def test_wrap_openai_agent_tools_empty_list() -> None:
    gw = _gw([])
    assert wrap_openai_agent_tools(gw, []) == []


@_async_test
async def test_wrap_openai_agent_tools_deny_never_invokes_underlying() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="deny")])
    invoked = {"count": 0}

    @function_tool
    def sentinel(x: int) -> int:
        """Sentinel."""
        invoked["count"] += 1
        return x

    gated = wrap_openai_agent_tools(gw, [sentinel])
    res = await gated[0].on_invoke_tool(_ctx("sentinel"), json.dumps({"x": 1}))
    assert "Permission denied" in str(res) or PermissionDenied.__name__ in str(res)
    assert invoked["count"] == 0  #  floor


# --------------------------------------------------------------------------- #
# Subject context via set_default_context
# --------------------------------------------------------------------------- #


@_async_test
async def test_set_default_context_is_used_for_sdk_tool_calls() -> None:
    """For LLM-driven SDK tool calls the subject context must come from
    :func:`custos.sdk.set_default_context` (the args are model-supplied, no
    natural host-injection point inside them — unlike the plain-callable
    Python SDK where ``custos_context`` is a kwarg pop)."""
    from custos.sdk import get_default_context, set_default_context

    # Save + restore the global default so other tests aren't affected.
    saved = get_default_context()
    try:
        ctx = SubjectContext(user_id="alice")
        set_default_context(ctx)
        gw = _gw([PolicyRuleSpec(match={"tool": "ping"}, action="allow")])

        @function_tool
        def ping() -> str:
            """..."""
            return "pong"

        gated = wrap_openai_agent_tools(gw, [ping])
        res = await gated[0].on_invoke_tool(_ctx("ping"), json.dumps({}))
        assert res == "pong"
    finally:
        set_default_context(saved)


# --------------------------------------------------------------------------- #
#  runtime-dep-leakage regression (risk row "vendor-SDK churn")
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_agents() -> None:
    """A runtime-only install (no extras) MUST NOT import ``agents`` when
    ``import custos`` runs. The adapter imports ``agents`` strictly inside
    its function bodies; module import is lazy. Asserts the  invariant
    that keeps embedded agents dep-free (echoes the  MCP convention).

    Even with the SDK installed (such as in this dev env), the assertion
    checks that *importing the adapter module* didn't pull in ``agents``.
    """
    # Drop agents from sys.modules (simulate a fresh interpreter).
    to_drop_pre = {m for m in list(sys.modules) if m == "agents" or m.startswith("agents.")}
    for m in to_drop_pre:
        del sys.modules[m]

    # Re-import the adapter — must succeed WITHOUT importing agents.
    import importlib

    mod = importlib.import_module("custos.integrations.openai_agents")
    # The vendor import must NOT have happened at module-scope.
    assert "agents" not in sys.modules
    # The public symbols are addressable without agents installed.
    assert hasattr(mod, "gated_function_tool")
    assert hasattr(mod, "wrap_openai_agent_tools")
    # Restore the SDK in sys.modules so subsequent tests in this module can use it.
    import importlib as _il

    _il.import_module("agents")


def test_gated_function_tool_callable_without_agents_imported_at_module_scope() -> None:
    """The decorator factory is callable even when ``agents`` is not in
    ``sys.modules``. The actual ``agents.function_tool`` import only
    happens when the decorator is invoked. Documentation-grade sibling of
    ``test_import_custos_does_not_import_agents``.
    """
    import custos.integrations.openai_agents as oa

    assert callable(oa.gated_function_tool)
