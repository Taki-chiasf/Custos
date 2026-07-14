"""Tests for the Anthropic messages-API tool adapter .

Unlike the MCP / OpenAI Agents adapters, the Anthropic adapter does NOT need
the SDK at runtime (it builds plain tool-definition dicts and gates host-side
handlers; the SDK is only used for an optional best-effort validation in
``make_tool_definition``). The tests therefore do NOT importorskip the
SDK — they exercise the adapter's plain-Python surface.

Asserts the  import-shadowing invariant (adapter module never hosts the
upstream `anthropic` import path) and the  leakage invariant.
"""

from __future__ import annotations

import asyncio
import functools
import sys
from typing import Any

from custos import AsyncGateway, Policy
from custos.exceptions import PermissionDenied
from custos.integrations.anthropic_ import (
    gated_anthropic_tool,
    make_tool_definition,
    wrap_anthropic_tool_handlers,
)
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.schema import SideEffect


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


_ADD_SCHEMA = {
    "type": "object",
    "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
    "required": ["a", "b"],
}


# --------------------------------------------------------------------------- #
# make_tool_definition
# --------------------------------------------------------------------------- #


def test_make_tool_definition_returns_plain_dict_shape() -> None:
    d = make_tool_definition("add", "Add two numbers", _ADD_SCHEMA)
    assert d["name"] == "add"
    assert d["description"] == "Add two numbers"
    assert d["input_schema"] is _ADD_SCHEMA


def test_make_tool_definition_does_not_require_anthropic_installed() -> None:
    """The helper returns the plain-dict shape even when ``anthropic`` is not
    importable. Best-effort validation is wrapped in try/except so an
    ImportError is swallowed. (The deeper ``import custos`` → no-leak
    invariant is asserted by ``test_import_custos_does_not_import_anthropic``;
    this test focuses ONLY on the helper's defensive shape.)
    """
    # Force the adapter's cached ToolParam lookup to a stub that raises
    # ImportError to simulate "SDK not installed".
    import custos.integrations.anthropic_ as adapter

    # Save the cached bit so subsequent tests get the real SDK validation back.
    saved_cache = adapter._anthropic_toolparam
    try:
        adapter._anthropic_toolparam = adapter._UNSET  # force re-import path
        # Simulate "anthropic doesn't import" by temporarily shadowing the
        # builtins import inside the helper — we just delete anthropic from
        # sys.modules and the helper's try/except handles the rest. The helper
        # is *allowed* to call ``import anthropic.types`` (prohibits only
        # module-top vendor imports, not helper-body imports).
        pre = {m for m in list(sys.modules) if m == "anthropic" or m.startswith("anthropic.")}
        for m in pre:
            del sys.modules[m]
        d = make_tool_definition("x", "y", {"type": "object"})
        # The helper returns the dict shape regardless of SDK availability.
        assert d == {"name": "x", "description": "y", "input_schema": {"type": "object"}}
    finally:
        adapter._anthropic_toolparam = saved_cache


# --------------------------------------------------------------------------- #
# gated_anthropic_tool
# --------------------------------------------------------------------------- #


def test_gated_anthropic_tool_returns_definition_and_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    def add_handler(input: dict) -> int:
        return input["a"] + input["b"]

    definition, gated = gated_anthropic_tool(
        gw,
        "add",
        "Add two numbers",
        _ADD_SCHEMA,
        add_handler,
        risk_tier=1,
    )
    assert definition["name"] == "add"
    assert definition["input_schema"] == _ADD_SCHEMA
    assert callable(gated)


@_async_test
async def test_gated_anthropic_tool_allow_forwards_to_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    def add_handler(input: dict) -> int:
        return input["a"] + input["b"]

    _, gated = gated_anthropic_tool(
        gw,
        "add",
        "Add two numbers",
        _ADD_SCHEMA,
        add_handler,
        risk_tier=1,
    )
    res = await gated({"a": 1, "b": 2})
    assert res == 3


@_async_test
async def test_gated_anthropic_tool_deny_raises_permission_denied() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "del*"}, action="deny")])

    def del_handler(input: dict) -> str:
        return "should not be called"

    _, gated = gated_anthropic_tool(
        gw,
        "delete_file",
        "Delete a file",
        {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
        del_handler,
        risk_tier=5,
        side_effects=frozenset({SideEffect.DESTRUCTIVE}),
    )

    import pytest

    with pytest.raises(PermissionDenied):
        await gated({"path": "/tmp/x"})


@_async_test
async def test_gated_anthropic_tool_async_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    async def async_handler(input: dict) -> str:
        await asyncio.sleep(0)
        return f"async-{input['x']}"

    _, gated = gated_anthropic_tool(
        gw,
        "asynctool",
        "async tool",
        {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]},
        async_handler,
        risk_tier=1,
    )
    res = await gated({"x": "abc"})
    assert res == "async-abc"


@_async_test
async def test_gated_anthropic_tool_deny_never_invokes_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="deny")])
    invoked = {"count": 0}

    def sentinel(input: dict) -> int:
        invoked["count"] += 1
        return input["x"]

    import pytest

    _, gated = gated_anthropic_tool(
        gw,
        "sentinel",
        "sentinel",
        {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]},
        sentinel,
        risk_tier=1,
    )
    with pytest.raises(PermissionDenied):
        await gated({"x": 1})
    assert invoked["count"] == 0  #  floor


# --------------------------------------------------------------------------- #
# wrap_anthropic_tool_handlers
# --------------------------------------------------------------------------- #


@_async_test
async def test_wrap_anthropic_tool_handlers_allow_forward() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "fs_read"}, action="allow")])
    handlers = {"fs_read": lambda input: f"contents of {input['p']}"}
    gated = wrap_anthropic_tool_handlers(gw, handlers)
    res = await gated["fs_read"]({"p": "/etc/hosts"})
    assert res == "contents of /etc/hosts"


@_async_test
async def test_wrap_anthropic_tool_handlers_deny_raises() -> None:
    gw = _gw(
        [
            PolicyRuleSpec(match={"tool": "fs_read"}, action="allow"),
            PolicyRuleSpec(match={"tool": "fs_write"}, action="deny"),
        ]
    )
    handlers = {
        "fs_read": lambda input: f"contents of {input['p']}",
        "fs_write": lambda input: f"wrote to {input['p']}",
    }
    gated = wrap_anthropic_tool_handlers(gw, handlers)

    import pytest

    res = await gated["fs_read"]({"p": "/etc/hosts"})
    assert res == "contents of /etc/hosts"
    with pytest.raises(PermissionDenied):
        await gated["fs_write"]({"p": "/x", "c": "y"})


@_async_test
async def test_wrap_anthropic_tool_handlers_does_not_mutate_input_map() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    def h(input: dict) -> str:
        return "ok"

    handlers = {"x": h}
    gated = wrap_anthropic_tool_handlers(gw, handlers)
    # Input map untouched.
    assert handlers["x"] is h
    assert gated["x"] is not h


@_async_test
async def test_wrap_anthropic_tool_handlers_empty() -> None:
    gw = _gw([])
    assert wrap_anthropic_tool_handlers(gw, {}) == {}


# --------------------------------------------------------------------------- #
#  + import-shadowing invariants
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_anthropic() -> None:
    """``import custos`` with no extras must NOT import ``anthropic``."""
    to_drop = {m for m in list(sys.modules) if m == "anthropic" or m.startswith("anthropic.")}
    for m in to_drop:
        del sys.modules[m]
    import importlib

    mod = importlib.import_module("custos.integrations.anthropic_")
    assert "anthropic" not in sys.modules
    assert hasattr(mod, "gated_anthropic_tool")
    assert hasattr(mod, "wrap_anthropic_tool_handlers")
    assert hasattr(mod, "make_tool_definition")


def test_adapter_module_does_not_shadow_upstream_anthropic() -> None:
    """The adapter module name ends in ``_`` so it can never be re-exported
    as ``custos.integrations.anthropic`` (which would shadow the upstream
    SDK for any ``from custos.integrations import anthropic`` re-export
    path).  Anthropic import-shadowing risk row mitigation.
    """
    import custos.integrations.anthropic_ as adapter

    assert adapter.__name__.endswith("_")
    # The adapter cannot host the upstream anthropic import (we never imported
    # it in this test's process via the adapter).
    assert "anthropic" not in adapter.__dict__
