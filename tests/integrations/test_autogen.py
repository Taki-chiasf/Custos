"""Tests for the AutoGen 0.4 in-process adapter .

Exercises the plain-Python surface (the adapter does NOT import
``autogen`` at module top; the tests do NOT importorskip the SDK). Asserts
the  import-shadowing invariant (adapter module name ends in ``_``)
and the  leakage invariant (``import custos`` with no extras
installed never imports ``autogen`` or ``autogen_core``).
"""

from __future__ import annotations

import asyncio
import functools
import sys
from typing import Any

from custos import AsyncGateway, Policy
from custos.exceptions import PermissionDenied
from custos.integrations.autogen_ import (
    gated_autogen_tool,
    make_autogen_tool_definition,
    wrap_autogen_tools,
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
# make_autogen_tool_definition
# --------------------------------------------------------------------------- #


def test_make_autogen_tool_definition_returns_openai_function_shape() -> None:
    d = make_autogen_tool_definition("add", "Add two numbers", _ADD_SCHEMA)
    assert d["type"] == "function"
    assert d["function"]["name"] == "add"
    assert d["function"]["description"] == "Add two numbers"
    assert d["function"]["parameters"] is _ADD_SCHEMA


# --------------------------------------------------------------------------- #
# gated_autogen_tool
# --------------------------------------------------------------------------- #


def test_gated_autogen_tool_returns_definition_and_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    def add_handler(input: dict) -> int:
        return input["a"] + input["b"]

    definition, gated = gated_autogen_tool(
        gw,
        "add",
        "Add two numbers",
        _ADD_SCHEMA,
        add_handler,
        risk_tier=1,
    )
    assert definition["function"]["name"] == "add"
    assert callable(gated)


@_async_test
async def test_gated_autogen_tool_allow_forwards_to_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    def add_handler(input: dict) -> int:
        return input["a"] + input["b"]

    _, gated = gated_autogen_tool(
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
async def test_gated_autogen_tool_deny_raises_permission_denied() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "del*"}, action="deny")])

    def del_handler(input: dict) -> str:
        return "should not be called"

    _, gated = gated_autogen_tool(
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
async def test_gated_autogen_tool_async_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    async def async_handler(input: dict) -> str:
        await asyncio.sleep(0)
        return f"async-{input['x']}"

    _, gated = gated_autogen_tool(
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
async def test_gated_autogen_tool_deny_never_invokes_handler() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="deny")])
    invoked = {"count": 0}

    def sentinel(input: dict) -> int:
        invoked["count"] += 1
        return input["x"]

    _, gated = gated_autogen_tool(
        gw,
        "sentinel",
        "sentinel",
        {"type": "object", "properties": {"x": {"type": "integer"}}, "required": ["x"]},
        sentinel,
        risk_tier=1,
    )
    import pytest

    with pytest.raises(PermissionDenied):
        await gated({"x": 1})
    assert invoked["count"] == 0  #  floor


# --------------------------------------------------------------------------- #
# wrap_autogen_tools
# --------------------------------------------------------------------------- #


@_async_test
async def test_wrap_autogen_tools_allow_forward() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "fs_read"}, action="allow")])
    handlers = {"fs_read": lambda input: f"contents of {input['p']}"}
    gated = wrap_autogen_tools(gw, handlers)
    res = await gated["fs_read"]({"p": "/etc/hosts"})
    assert res == "contents of /etc/hosts"


@_async_test
async def test_wrap_autogen_tools_deny_raises() -> None:
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
    gated = wrap_autogen_tools(gw, handlers)
    import pytest

    res = await gated["fs_read"]({"p": "/etc/hosts"})
    assert res == "contents of /etc/hosts"
    with pytest.raises(PermissionDenied):
        await gated["fs_write"]({"p": "/x", "c": "y"})


@_async_test
async def test_wrap_autogen_tools_does_not_mutate_input_map() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    def h(input: dict) -> str:
        return "ok"

    handlers = {"x": h}
    gated = wrap_autogen_tools(gw, handlers)
    assert handlers["x"] is h
    assert gated["x"] is not h


@_async_test
async def test_wrap_autogen_tools_empty() -> None:
    gw = _gw([])
    assert wrap_autogen_tools(gw, {}) == {}


# --------------------------------------------------------------------------- #
#  + import-shadowing invariants
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_autogen() -> None:
    """``import custos`` with no extras must NOT import ``autogen``."""
    to_drop = {
        m
        for m in list(sys.modules)
        if m == "autogen" or m.startswith("autogen.") or m.startswith("autogen_")
    }
    for m in to_drop:
        del sys.modules[m]
    import importlib

    mod = importlib.import_module("custos.integrations.autogen_")
    assert "autogen" not in sys.modules
    assert "autogen_core" not in sys.modules
    assert hasattr(mod, "gated_autogen_tool")
    assert hasattr(mod, "wrap_autogen_tools")
    assert hasattr(mod, "make_autogen_tool_definition")


def test_adapter_module_does_not_shadow_upstream_autogen() -> None:
    """The adapter module name ends in ``_`` so it can never be re-exported
    as ``custos.integrations.autogen`` (which would shadow the upstream
    SDK for any ``from custos.integrations import autogen`` re-export
    path).  Anthropic import-shadowing risk row mitigation (extended
    to AutoGen under the same rule).
    """
    import custos.integrations.autogen_ as adapter

    assert adapter.__name__.endswith("_")
    assert "autogen" not in adapter.__dict__
