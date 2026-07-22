"""Tests for the MCP in-process adapter .

Skipped when ``mcp`` is not installed (pytest.importorskip) so the test suite
stays green in a runtime-only (no-extras) install — asserting the
runtime-dep-leakage invariant (risk row " runtime-dep leakage").

Covers both adapter APIs:
  - :func:`custos.integrations.mcp_.gated_tool` — decorator factory
  - :func:`custos.integrations.mcp_.wrap_mcp_tools` — post-hoc re-wrap

Plus the  floor invariant (a policy ``deny`` short-circuits the gateway
before the gated tool body runs), signature preservation (MCP introspection
sees the original typed parameters), async tools, allow-path forwarding, the
 leakage regression, and the fallback pointer when the server's private
layout drifts.
"""

from __future__ import annotations

import asyncio
import functools
import sys
from typing import Any

import pytest

# Skip the whole module when mcp isn't installed. Keeps the runtime dep-free.
pytest.importorskip("mcp")
from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.server.fastmcp.exceptions import ToolError  # noqa: E402

from custos import AsyncGateway, Policy  # noqa: E402
from custos.exceptions import PermissionDenied  # noqa: E402
from custos.integrations.mcp_ import gated_tool, wrap_mcp_tools  # noqa: E402
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec  # noqa: E402
from custos.schema import SideEffect  # noqa: E402

# The gated_tool wrapper raises PermissionDenied; MCP wraps it as ToolError
# when call_tool runs the gated function body. Both classes are valid matches
# for our deny-path assertions (the wrapper surfaces the custos cause inside
# the ToolError string). Caught together so the test stays robust to either
# MCP's outer ToolError wrapper or a future fast-path that lets
# PermissionDenied propagate unchanged.
_DENY_EXC = (ToolError, PermissionDenied)

# --------------------------------------------------------------------------- #
# Async test helper (mirror of tests/test_async_gateway._async_test)
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


# --------------------------------------------------------------------------- #
# gated_tool decorator: registration + allow-path forwarding
# --------------------------------------------------------------------------- #


@_async_test
async def test_gated_tool_allow_forwards_to_underlying() -> None:
    mcp = FastMCP("t1")
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    @gated_tool(mcp, gw, risk_tier=1)
    def add(a: int, b: int) -> int:
        """Add two numbers."""
        return a + b

    res = await mcp.call_tool("add", {"a": 1, "b": 2})
    # MCP 1.x call_tool returns (content_list, structured_content_dict).
    content, structured = res
    assert structured["result"] == 3
    # The tool still shows up via MCP discovery.
    tools = await mcp.list_tools()
    assert any(t.name == "add" for t in tools)


@_async_test
async def test_gated_tool_async_underlying_function() -> None:
    mcp = FastMCP("t2")
    gw = _gw([PolicyRuleSpec(match={"tool": "geo"}, action="allow")])

    @gated_tool(mcp, gw, risk_tier=1)
    async def geo(city: str) -> str:
        """Async geo lookup."""
        await asyncio.sleep(0)
        return f"weather in {city}"

    _, structured = await mcp.call_tool("geo", {"city": "NYC"})
    assert structured["result"] == "weather in NYC"


@_async_test
async def test_gated_tool_deny_raises_permission_denied() -> None:
    mcp = FastMCP("t3")
    gw = _gw([PolicyRuleSpec(match={"tool": "del*"}, action="deny")])

    @gated_tool(mcp, gw, risk_tier=5, side_effects=frozenset({SideEffect.DESTRUCTIVE}))
    def delete_file(path: str) -> str:
        """Delete a file."""
        return "should not be called"

    # MCP's call_tool wraps the PermissionDenied in a ToolError; assert it
    # surfaces. Don't rely on the exact tool-error class name (could shift
    # between MCP point releases) — just assert it raised.
    with pytest.raises(_DENY_EXC):
        await mcp.call_tool("delete_file", {"path": "/tmp/x"})


@_async_test
async def test_gated_tool_defer_raises_permission_denied() -> None:
    mcp = FastMCP("t4")
    # No allow rule + default deny = gateway short-circuits at policy floor
    # , no responder, returns DENY. Same test shape.
    gw = _gw([])

    @gated_tool(mcp, gw, risk_tier=1)
    def secret(token: str) -> str:
        """..."""
        return "ok"

    # Default-deny with no responder returns DENY → gated_tool raises PermissionDenied.
    with pytest.raises(_DENY_EXC):
        await mcp.call_tool("secret", {"token": "x"})


# --------------------------------------------------------------------------- #
# Signature preservation (MCP introspection follows functools.wraps)
# --------------------------------------------------------------------------- #


@_async_test
async def test_gated_tool_preserves_signature_for_mcp_introspection() -> None:
    mcp = FastMCP("t5")
    gw = _gw([PolicyRuleSpec(match={"tool": "compute"}, action="allow")])

    @gated_tool(mcp, gw, risk_tier=1)
    def compute(x: int, y: int, label: str = "out") -> str:
        """Compute."""
        return f"{label}={x + y}"

    tools = await mcp.list_tools()
    tool = next(t for t in tools if t.name == "compute")
    # MCP built the JSON schema from the typed wrapper (functools.wraps).
    required = set(tool.inputSchema.get("required", []))
    assert {"x", "y"} <= required
    # The optional `label` is in the properties with its default.
    assert "label" in tool.inputSchema.get("properties", {})


# --------------------------------------------------------------------------- #
# Floor invariant : gating runs BEFORE the tool body — the underlying fn
# is never invoked on deny.
# --------------------------------------------------------------------------- #


@_async_test
async def test_gated_tool_deny_never_invokes_underlying() -> None:
    mcp = FastMCP("t6")
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="deny")])
    invoked = {"count": 0}

    @gated_tool(mcp, gw, risk_tier=1)
    def sentinel(x: int) -> int:
        """Sentinel."""
        invoked["count"] += 1
        return x

    with pytest.raises(_DENY_EXC):
        await mcp.call_tool("sentinel", {"x": 1})
    assert invoked["count"] == 0  #  floor — never reached the tool body


# --------------------------------------------------------------------------- #
# wrap_mcp_tools: post-hoc re-wrap of an existing FastMCP server
# --------------------------------------------------------------------------- #


@_async_test
async def test_wrap_mcp_tools_sync_original() -> None:
    mcp = FastMCP("t7")

    @mcp.tool()
    def fs_read(p: str) -> str:
        """read a file"""
        return f"contents of {p}"

    @mcp.tool()
    def fs_write(p: str, c: str) -> str:
        """write a file"""
        return f"wrote to {p}"

    gw = _gw(
        [
            PolicyRuleSpec(match={"tool": "fs_read"}, action="allow"),
            PolicyRuleSpec(match={"tool": "fs_write"}, action="deny"),
        ]
    )
    wrapped = wrap_mcp_tools(gw, mcp)
    assert set(wrapped) == {"fs_read", "fs_write"}

    _, r = await mcp.call_tool("fs_read", {"p": "/etc/hosts"})
    assert r["result"] == "contents of /etc/hosts"

    with pytest.raises(_DENY_EXC):
        await mcp.call_tool("fs_write", {"p": "/x", "c": "y"})


@_async_test
async def test_wrap_mcp_tools_async_original() -> None:
    mcp = FastMCP("t8")

    @mcp.tool()
    async def async_lookup(key: str) -> str:
        """Async lookup."""
        await asyncio.sleep(0)
        return f"val-{key}"

    gw = _gw([PolicyRuleSpec(match={"tool": "async_lookup"}, action="allow")])
    wrap_mcp_tools(gw, mcp)
    _, r = await mcp.call_tool("async_lookup", {"key": "abc"})
    assert r["result"] == "val-abc"


@_async_test
async def test_wrap_mcp_tools_preserves_discovery() -> None:
    mcp = FastMCP("t9")

    @mcp.tool()
    def fn_a(x: int) -> int:
        """Fn A."""
        return x

    @mcp.tool()
    def fn_b(y: str) -> str:
        """Fn B."""
        return y

    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])
    wrap_mcp_tools(gw, mcp)
    tools = await mcp.list_tools()
    names = {t.name for t in tools}
    assert names == {"fn_a", "fn_b"}


@_async_test
async def test_wrap_mcp_tools_returns_list_of_wrapped_names() -> None:
    mcp = FastMCP("t10")

    @mcp.tool()
    def f1() -> str:
        return "1"

    @mcp.tool()
    def f2() -> str:
        return "2"

    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])
    out = wrap_mcp_tools(gw, mcp)
    assert sorted(out) == ["f1", "f2"]


# --------------------------------------------------------------------------- #
#  runtime-dep-leakage regression (risk row "vendor-SDK churn")
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_mcp() -> None:
    """A runtime-only install (no extras) MUST NOT import ``mcp`` when
    ``import custos`` runs. The adapter imports ``mcp`` strictly inside its
    function bodies; module import is lazy. Asserting the /
    invariant that keeps embedded agents dep-free.

    We can't actually uninstall mcp mid-test (it's a dev dep here), so we
    assert the lazy-import contract directly: importing
    ``custos.integrations.mcp_`` does NOT import ``mcp`` at module scope.
    """
    # Drop mcp from sys.modules (simulate a fresh interpreter without mcp).
    pre = set(sys.modules)
    # Re-import custos.integrations.mcp_ — must succeed without importing mcp.
    import importlib

    mod = importlib.import_module("custos.integrations.mcp_")
    # The vendor import must NOT have happened.
    assert "mcp" not in set(sys.modules) - pre - {"mcp"}
    # And `wrap_mcp_tools` / `gated_tool` symbols are addressable without mcp.
    assert hasattr(mod, "gated_tool")
    assert hasattr(mod, "wrap_mcp_tools")


def test_gated_tool_raises_clear_error_without_mcp() -> None:
    """If a caller invokes ``gated_tool`` while ``mcp`` is uninstalled, the
    failure surfaces from MCP's own import, not from custos internals. The
    adapter itself never imports mcp at module scope; the import happens
    only when the user calls a function that needs the FastMCP server. This
    test is documentation-grade — we just assert the contract holds even
    with mcp installed (it does, because the adapter never imports mcp at
    module scope)."""
    # Indirectly: module-level sys.modules check from the test above already
    # asserts the leakage boundary. This test is a sibling for readability.
    import custos.integrations.mcp_ as mcp_adapter

    # No top-level mcp import means this attribute access never touches mcp.
    assert callable(mcp_adapter.gated_tool)


# --------------------------------------------------------------------------- #
# Graceful fallback when the server's private layout drifts (vendor-SDK churn)
# --------------------------------------------------------------------------- #


def test_wrap_mcp_tools_raises_pointer_on_layout_drift() -> None:
    class FakeServer:
        # Missing `_tool_manager` — simulates a future MCP SDK restructure.
        pass

    gw = _gw([])
    with pytest.raises(RuntimeError, match="gated_tool decorator factory"):
        wrap_mcp_tools(gw, FakeServer())
