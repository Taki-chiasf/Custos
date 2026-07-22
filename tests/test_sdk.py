"""Tests for ``custos.sdk.wrap_callables`` + ``Gateway.wrap`` dispatcher ."""

from __future__ import annotations

import pytest

from custos import Gateway, Policy
from custos.exceptions import PermissionDenied
from custos.policy import PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.responders.noop import NoopResponder
from custos.schema import SubjectContext
from custos.sdk import get_default_context, set_default_context, wrap_callables


def _policy(action: str, *, pattern: str = "*", default: str = "deny") -> Policy:
    spec = PolicyFile(
        version=1,
        default=default,
        overlays=(
            PolicyOverlaySpec(
                id="base", rules=(PolicyRuleSpec(match={"tool": pattern}, action=action),)
            ),
        ),
    )
    return Policy.from_spec(spec)


def _gateway(action: str, *, pattern: str = "*") -> Gateway:
    return Gateway(policy=_policy(action, pattern=pattern), responder=NoopResponder())


def test_wrap_callables_preserves_signature() -> None:
    gw = _gateway("allow")

    def read(path: str, *, mode: str = "r") -> str:
        """read a file."""
        return f"{mode}:{path}"

    wrapped = wrap_callables(gw, [read])
    assert len(wrapped) == 1
    proxy = wrapped[0]
    assert proxy.__name__ == "read"
    assert proxy.__doc__ == "read a file."


def test_wrap_callables_allow_forwards() -> None:
    gw = _gateway("allow")

    def add(x: int, y: int) -> int:
        return x + y

    wrapped = wrap_callables(gw, [add])
    assert wrapped[0](2, 3) == 5


def test_wrap_callables_deny_raises_permission_denied() -> None:
    gw = _gateway("deny")

    def boom() -> str:
        return "should not run"

    wrapped = wrap_callables(gw, [boom])
    with pytest.raises(PermissionDenied) as exc:
        wrapped[0]()
    assert exc.value.tool == "boom"
    assert exc.value.decision == "deny"


def test_wrap_callables_defer_raises_permission_denied() -> None:
    # No responder -> policy prompt routes to responder -> noop denies.
    # Use assist with no assistant -> safe deny to trigger deny path.
    gw = _gateway("deny", pattern="*")

    def f() -> str:
        return "x"

    wrapped = wrap_callables(gw, [f])
    with pytest.raises(PermissionDenied):
        wrapped[0]()


def test_wrap_callables_uses_default_context(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The module-default SubjectContext is attached to the Invocation."""
    import json

    from custos.audit import FileAuditSink

    audit = tmp_path / "audit.jsonl"
    ctx = SubjectContext(user_id="alice", goal_id="g1")
    set_default_context(ctx)
    try:
        gw = Gateway(
            policy=_policy("allow"),
            responder=NoopResponder(),
            audit_sink=FileAuditSink(audit),
        )

        def f() -> str:
            return "ok"

        wrapped = wrap_callables(gw, [f])
        wrapped[0]()
        record = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
        assert record["subject"]["user_id"] == "alice"
        assert record["subject"]["goal_id"] == "g1"
    finally:
        set_default_context(SubjectContext(user_id="default"))


def test_wrap_callables_accepts_explicit_context_kwarg() -> None:
    gw = _gateway("allow")

    def f(x: int) -> int:
        return x

    wrapped = wrap_callables(gw, [f])
    ctx = SubjectContext(user_id="bob")
    # The kwarg is consumed by the proxy, not passed to the underlying tool.
    assert wrapped[0](42, custos_context=ctx) == 42


def test_wrap_callables_kwargs_forwarded_to_tool() -> None:
    gw = _gateway("allow")

    def f(x: int, *, y: int) -> int:
        return x + y

    wrapped = wrap_callables(gw, [f])
    assert wrapped[0](1, y=2) == 3


def test_gateway_wrap_dispatches_plain_callables() -> None:
    gw = _gateway("allow")

    def f(x: int) -> int:
        return x

    wrapped = gw.wrap([f])
    assert isinstance(wrapped, list)
    assert wrapped[0](10) == 10


def test_gateway_wrap_empty_returns_empty() -> None:
    gw = _gateway("allow")
    assert gw.wrap([]) == []


def test_wrap_callables_default_context_gettable() -> None:
    ctx = get_default_context()
    assert isinstance(ctx, SubjectContext)
    set_default_context(SubjectContext(user_id="test-user"))
    assert get_default_context().user_id == "test-user"
    # Reset for other tests.
    set_default_context(SubjectContext(user_id="default"))
