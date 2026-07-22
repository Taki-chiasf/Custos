"""Tests for the LlamaIndex in-process adapter .

The SDK (``llama-index-core``) is NOT installed in the runtime-only install;
the tests do NOT importorskip the SDK. They exercise the adapter's
plain-Python surface (the `_make_gated_async_fn` inner builder) and assert
the  import-shadowing +  leakage invariants.
"""

from __future__ import annotations

import asyncio
import functools
import sys
from typing import Any

from custos import AsyncGateway, Policy
from custos.exceptions import PermissionDenied
from custos.integrations.llamaindex_ import _make_gated_async_fn, gated_llamaindex_tool
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.schema import SideEffect, SubjectContext, ToolDescriptor


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
# wrap — exercised here without the SDK).
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

    gated = _make_gated(f, "f", gw)
    ctx = SubjectContext(user_id="alice")
    assert await gated(5, custos_context=ctx) == 5


# --------------------------------------------------------------------------- #
# decorator / factory surface
# --------------------------------------------------------------------------- #


def test_gated_llamaindex_tool_factory_callable_without_sdk() -> None:
    """The factory returns without importing the SDK — the SDK is only
    touched when the factory itself runs (which we don't exercise here,
    since the SDK is absent in the runtime-only install).
    """
    gw = _gw([PolicyRuleSpec(match={"tool": "*"}, action="allow")])

    def f(x: int) -> int:
        return x

    # Should raise ImportError (not AttributeError or ModuleNotFoundError
    # surfacing as something else) when the SDK is absent — this is the
    #  import hygiene proof: the late import happens inside the
    # factory function body, not at module import time. We accept any
    # ImportError variant (`ImportError` or `ModuleNotFoundError`).
    import pytest

    with pytest.raises((ImportError, ModuleNotFoundError)):
        gated_llamaindex_tool(gw, f)


# --------------------------------------------------------------------------- #
#  + import-shadowing invariants
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_llama_index() -> None:
    """``import custos`` with no extras must NOT import ``llama_index``."""
    to_drop = {m for m in list(sys.modules) if m == "llama_index" or m.startswith("llama_index.")}
    for m in to_drop:
        del sys.modules[m]
    import importlib

    mod = importlib.import_module("custos.integrations.llamaindex_")
    assert "llama_index" not in sys.modules
    assert hasattr(mod, "gated_llamaindex_tool")
    assert hasattr(mod, "wrap_llamaindex_tools")


def test_adapter_module_does_not_shadow_upstream_llama_index() -> None:
    """The adapter module name ends in ``_`` so it can never be re-exported
    as ``custos.integrations.llamaindex`` (which would shadow the upstream
    ``llama_index`` namespace for any re-export path).  Anthropic
    import-shadowing risk row mitigation (extended to LlamaIndex under
    the same rule).
    """
    import custos.integrations.llamaindex_ as adapter

    assert adapter.__name__.endswith("_")
