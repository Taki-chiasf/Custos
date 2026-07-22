"""Tests for the LangChain adapter (custos[langchain] extra)."""

from __future__ import annotations

import pytest

pytest.importorskip("langchain_core")
from langchain_core.tools import StructuredTool

from custos import Gateway, Policy
from custos.exceptions import PermissionDenied
from custos.integrations.langchain import wrap_langchain_tools
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.responders.noop import NoopResponder


def _policy(action: str, *, pattern: str = "*", default: str = "deny") -> Policy:
    spec = PolicyFile(
        version=1,
        default=default,
        overlays=(
            PolicyOverlaySpec(
                id="base",
                rules=(PolicyRuleSpec(match={"tool": pattern}, action=action),),
            ),
        ),
    )
    return Policy.from_spec(spec)


def _gateway(action: str, *, pattern: str = "*") -> Gateway:
    return Gateway(policy=_policy(action, pattern=pattern), responder=NoopResponder())


def _make_tool(name: str, desc: str = "a tool") -> StructuredTool:
    def fn(x: int) -> int:
        return x * 2

    return StructuredTool.from_function(fn, name=name, description=desc)


def test_wrap_langchain_tools_preserves_name_and_description() -> None:
    gw = _gateway("allow")
    original = _make_tool("multiply", desc="doubles a number")
    wrapped = wrap_langchain_tools(gw, [original])
    assert len(wrapped) == 1
    assert wrapped[0].name == "multiply"
    assert wrapped[0].description == "doubles a number"


def test_wrap_langchain_tools_allow_forwards() -> None:
    gw = _gateway("allow", pattern="multiply")
    original = _make_tool("multiply")
    wrapped = wrap_langchain_tools(gw, [original])
    assert wrapped[0].invoke({"x": 21}) == 42


def test_wrap_langchain_tools_deny_raises_permission_denied() -> None:
    gw = _gateway("deny", pattern="*")
    original = _make_tool("dangerous")
    wrapped = wrap_langchain_tools(gw, [original])
    with pytest.raises(PermissionDenied) as exc:
        wrapped[0].invoke({"x": 1})
    assert exc.value.tool == "dangerous"
    assert exc.value.decision == "deny"


def test_wrap_langchain_tools_multiple_tools_independent() -> None:
    """Closures bind per-tool (no loop-variable leak)."""
    gw = _gateway("allow", pattern="good_tool")
    good = _make_tool("good_tool")
    bad = _make_tool("bad_tool")  # not matched -> deny via default
    wrapped = wrap_langchain_tools(gw, [good, bad])
    assert wrapped[0].invoke({"x": 5}) == 10
    with pytest.raises(PermissionDenied):
        wrapped[1].invoke({"x": 1})


def test_gateway_wrap_dispatches_to_langchain() -> None:
    gw = _gateway("allow")
    original = _make_tool("multiply")
    wrapped = gw.wrap([original])
    assert isinstance(wrapped, list)
    assert wrapped[0].invoke({"x": 4}) == 8
