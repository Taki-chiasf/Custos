"""Tests for the Google ADK in-process adapter .

The SDK (``google-adk``) is NOT installed in the runtime-only install; the
tests do NOT importorskip the SDK. They exercise the adapter's plain-Python
surface (the `_make_gated_async_fn` inner builder + the schema helpers)
and assert the  import-shadowing +  leakage invariants.
"""

from __future__ import annotations

import asyncio
import functools
import sys
from typing import Any

from custos import AsyncGateway, Policy
from custos.exceptions import PermissionDenied
from custos.integrations.google_adk_ import _make_gated_async_fn, gated_adk_tool
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.schema import SideEffect, ToolDescriptor


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


def _make_gated(handler, name, gw, **kw):
    descriptor = ToolDescriptor(
        name=name,
        risk_tier=kw.get("risk_tier", 1),
        side_effects=kw.get("side_effects", frozenset()),
        schema={},
        reversible=False,
    )
    return _make_gated_async_fn(handler, name, descriptor, gw)


# --------------------------------------------------------------------------- #
# gated callable behavior (the inner helper that real FunctionTool would
# wrap — exercised here without constructing a real FunctionTool which
# needs the SDK + signature introspection).
# --------------------------------------------------------------------------- #


@_async_test
async def test_gated_callable_allow_forwards() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    def add(a: int, b: int) -> int:
        return a + b

    gated = _make_gated(add, "add", gw)
    assert await gated(1, 2) == 3


@_async_test
async def test_gated_callable_allow_kwargs() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "add"}, action="allow")])

    def add(a: int, b: int) -> int:
        return a + b

    gated = _make_gated(add, "add", gw)
    assert await gated(a=5, b=7) == 12


@_async_test
async def test_gated_callable_deny_raises() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "del*"}, action="deny")])

    def delete(path: str) -> str:
        return "should not be called"

    gated = _make_gated(
        delete, "delete_file", gw, risk_tier=5, side_effects=frozenset({SideEffect.DESTRUCTIVE})
    )
    import pytest

    with pytest.raises(PermissionDenied):
        await gated("/tmp/x")


@_async_test
async def test_gated_callable_async_underlying() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    async def asynctool(x: str) -> str:
        await asyncio.sleep(0)
        return f"async-{x}"

    gated = _make_gated(asynctool, "asynctool", gw)
    res = await gated("abc")
    assert res == "async-abc"


@_async_test
async def test_gated_callable_deny_never_invokes_underlying() -> None:
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="deny")])
    invoked = {"n": 0}

    def sentinel(x: int) -> int:
        invoked["n"] += 1
        return x

    gated = _make_gated(sentinel, "sentinel", gw)
    import pytest

    with pytest.raises(PermissionDenied):
        await gated(1)
    assert invoked["n"] == 0  #  floor


@_async_test
async def test_gated_callable_custos_context_escape_hatch() -> None:
    """The `custos_context` kwarg is popped before the underlying tool is
    invoked; it's the escape hatch for programmatic programmable-context
    calls (mirrors the – adapter convention).
    """
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    def f(x: int) -> int:
        return x

    from custos.schema import SubjectContext

    gated = _make_gated(f, "f", gw)
    ctx = SubjectContext(user_id="alice")
    assert await gated(5, custos_context=ctx) == 5


# --------------------------------------------------------------------------- #
# decorator factory surface
# --------------------------------------------------------------------------- #


def test_gated_adk_tool_decorator_factory_is_callable() -> None:
    """The decorator factory returns a callable decorator without
    importing the SDK — the SDK is only touched when the decorator itself
    runs (which we don't exercise here, since the SDK is absent in the
    runtime-only install).
    """
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])
    factory = gated_adk_tool(gw, risk_tier=2)
    assert callable(factory)


# --------------------------------------------------------------------------- #
#  + import-shadowing invariants
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_google_adk() -> None:
    """``import custos`` with no extras must NOT import ``google.adk``."""
    to_drop = {
        m
        for m in list(sys.modules)
        if m == "google.adk" or m.startswith("google.adk.") or m == "google"
    }
    for m in to_drop:
        del sys.modules[m]
    # Also drop the parent ``google`` namespace package only if it has no
    # remaining children (callers in this process may have legitimate use).
    import importlib

    mod = importlib.import_module("custos.integrations.google_adk_")
    assert "google.adk" not in sys.modules
    assert hasattr(mod, "gated_adk_tool")
    assert hasattr(mod, "wrap_adk_tools")


def test_adapter_module_does_not_shadow_upstream_google_adk() -> None:
    """The adapter module name ends in ``_`` so it can never be re-exported
    as ``custos.integrations.google_adk`` (which would shadow the upstream
    ``google.adk`` namespace for any re-export path).  Anthropic
    import-shadowing risk row mitigation (extended to Google ADK under
    the same rule).
    """
    import custos.integrations.google_adk_ as adapter

    assert adapter.__name__.endswith("_")
