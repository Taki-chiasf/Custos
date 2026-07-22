"""Tests for :class:`custos.async_gateway.AsyncGateway` .

Mirrors the sync ``test_gateway`` branch coverage under the async surface:
  - policy ALLOW / DENY short-circuit before async seams (floor)
  - ASSIST -> native-async assistant allow_once / allow / prompt / deny /
    ``allow_and_persist`` (in-memory rule persistence via shared impl)
  - PROMPT -> async responder allow / deny; no responder -> safe deny
  - sync assistant / responder / fatigue impls are bridged via ``to_thread``
  - H8 exception-safety: a raising responder -> safe DENY + audit + seam C
  - redaction before responder + audit
  - audit event emitted on every path
  - ``wrap`` returns async gated proxies that ``await decide``
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import json
from pathlib import Path
from typing import Any

import pytest

from custos.async_gateway import AsyncGateway
from custos.audit import FileAuditSink, NullAuditSink
from custos.fatigue import InMemoryFatigueLayer
from custos.policy import Policy, PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.schema import (
    AssistantOutput,
    Decision,
    Invocation,
    PromptRequest,
    PromptResponse,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)


def _async_test(coro_fn):
    """Run an ``async def test_*`` via :func:`asyncio.run` (no pytest-asyncio dep).

    Keeps the test files dep-free beyond the existing ``pytest`` dev install
    (hygiene) while letting us write natural ``async def test_X``
    coroutines that ``await`` the gateway. :func:`functools.wraps` preserves
    the signature so pytest fixture injection (e.g. ``tmp_path``) still works.
    """

    @functools.wraps(coro_fn)
    def runner(*args: Any, **kwargs: Any) -> None:
        return asyncio.run(coro_fn(*args, **kwargs))

    return runner


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeAsyncAssistant:
    """Native-async assistant duck-typing ``AssistantAsync``."""

    name = "fake-async"

    def __init__(self, output: AssistantOutput) -> None:
        self.output = output
        self.calls = 0

    async def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        self.calls += 1
        # Yield the event loop to prove we don't block it.
        await asyncio.sleep(0)
        return self.output


class FakeSyncAssistant:
    """Sync assistant duck-typing ``Assistant`` - must be bridged via to_thread."""

    name = "fake-sync"

    def __init__(self, output: AssistantOutput) -> None:
        self.output = output
        self.calls = 0

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        self.calls += 1
        return self.output


class FakeAsyncResponder:
    name = "fake-async"

    def __init__(self, choice: Decision = Decision.ALLOW, *, ttl: int | None = None) -> None:
        self.choice = choice
        self.ttl = ttl
        self.calls = 0
        self.last_req: PromptRequest | None = None

    async def prompt(self, req: PromptRequest) -> PromptResponse:
        self.calls += 1
        self.last_req = req
        await asyncio.sleep(0)
        return PromptResponse(choice=self.choice, ttl=self.ttl, approver="async-approver")


class FakeSyncResponder:
    name = "fake-sync"

    def __init__(self, choice: Decision = Decision.ALLOW) -> None:
        self.choice = choice
        self.calls = 0

    def prompt(self, req: PromptRequest) -> PromptResponse:
        self.calls += 1
        return PromptResponse(choice=self.choice)


class RaisingAsyncResponder:
    name = "raising-async"

    async def prompt(self, req: PromptRequest) -> PromptResponse:
        raise RuntimeError("responder exploded")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ctx(**kw: Any) -> SubjectContext:
    return SubjectContext(user_id="u1", **kw)  # type: ignore[arg-type]


def _inv(
    tool: str = "fs.read",
    *,
    args: dict[str, Any] | None = None,
    descriptor: ToolDescriptor | None = None,
    context: SubjectContext | None = None,
) -> Invocation:
    return Invocation(tool=tool, args=args or {}, context=context or _ctx(), descriptor=descriptor)


def _desc(
    risk_tier: int = 1,
    side: frozenset[SideEffect] = frozenset(),
    schema: dict[str, Any] | None = None,
) -> ToolDescriptor:
    return ToolDescriptor(name="t", risk_tier=risk_tier, side_effects=side, schema=schema or {})


def _policy(rules: list[PolicyRuleSpec], *, default: str = "deny") -> Policy:
    spec = PolicyFile(
        version=1,
        default=default,
        overlays=(PolicyOverlaySpec(id="base", rules=tuple(rules)),),
    )
    return Policy.from_spec(spec)


class AsyncGatewayTiny:
    """Thin wrapper to avoid repeating ``AsyncGateway(audit_sink=None)`` boilerplate."""

    def __init__(
        self,
        policy: Policy,
        assistant: Any | None = None,
        responder: Any | None = None,
        fatigue: Any | None = None,
    ) -> None:
        self._gw = AsyncGateway(
            policy=policy,
            assistant=assistant,
            responder=responder,
            audit_sink=NullAuditSink(),
            fatigue=fatigue,
        )

    async def decide(self, inv: Invocation) -> Decision:
        return await self._gw.decide(inv)

    @property
    def gw(self) -> AsyncGateway:
        return self._gw


# --------------------------------------------------------------------------- #
# policy ALLOW / DENY short-circuit (no async seams)
# --------------------------------------------------------------------------- #


@_async_test
async def test_policy_allow_returns_allow() -> None:
    gw = AsyncGatewayTiny(_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="allow")]))
    assert await gw.decide(_inv()) == Decision.ALLOW


@_async_test
async def test_policy_deny_returns_deny() -> None:
    gw = AsyncGatewayTiny(_policy([PolicyRuleSpec(match={"tool": "*"}, action="deny")]))
    assert await gw.decide(_inv()) == Decision.DENY


@_async_test
async def test_default_deny_when_no_rule_matches() -> None:
    gw = AsyncGatewayTiny(_policy([]))
    assert await gw.decide(_inv()) == Decision.DENY


# --------------------------------------------------------------------------- #
# floor invariant : policy DENY never reaches the async assistant
# --------------------------------------------------------------------------- #


@_async_test
async def test_policy_deny_never_invokes_async_assistant() -> None:
    asst = FakeAsyncAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE))
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="deny")]),
        assistant=asst,
    )
    assert await gw.decide(_inv()) == Decision.DENY
    assert asst.calls == 0


# --------------------------------------------------------------------------- #
# ASSIST -> async assistant outputs
# --------------------------------------------------------------------------- #


@_async_test
async def test_assist_async_allow_once() -> None:
    asst = FakeAsyncAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.1))
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:fake-async")]),
        assistant=asst,
    )
    assert await gw.decide(_inv()) == Decision.ALLOW_ONCE
    assert asst.calls == 1


@_async_test
async def test_assist_async_deny() -> None:
    asst = FakeAsyncAssistant(AssistantOutput(decision=Decision.DENY, risk=0.9))
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:fake-async")]),
        assistant=asst,
    )
    assert await gw.decide(_inv()) == Decision.DENY


@_async_test
async def test_assist_async_prompt_routes_to_async_responder() -> None:
    asst = FakeAsyncAssistant(AssistantOutput(decision=Decision.PROMPT, risk=0.5))
    responder = FakeAsyncResponder(choice=Decision.ALLOW)
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:fake-async")]),
        assistant=asst,
        responder=responder,
    )
    assert await gw.decide(_inv()) == Decision.ALLOW
    assert responder.calls == 1


@_async_test
async def test_assist_async_allow_and_persist_inserts_rule() -> None:
    asst = FakeAsyncAssistant(
        AssistantOutput(
            decision=Decision.ALLOW_AND_PERSIST,
            risk=0.2,
            persist_rule={
                "match": {"tool": "fs.read", "args": {"path": "/tmp/x"}},
                "action": "allow",
            },
        )
    )
    policy = _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:fake-async")])
    gw = AsyncGatewayTiny(policy, assistant=asst)
    # First call resolves via the assistant + returns ALLOW_ONCE (the persist
    # happens under the hood so the next identical call short-circuits).
    assert await gw.decide(_inv(args={"path": "/tmp/x"})) == Decision.ALLOW_ONCE
    # The persisted rule is inserted before the matched rule; an identical call
    # now hits policy ALLOW without re-invoking the assistant.
    assert asst.calls == 1
    assert await gw.decide(_inv(args={"path": "/tmp/x"})) == Decision.ALLOW
    assert asst.calls == 1


# --------------------------------------------------------------------------- #
# Bridge: sync assistant / responder impls are wrapped via to_thread
# --------------------------------------------------------------------------- #


@_async_test
async def test_sync_assistant_is_bridged_via_to_thread() -> None:
    asst = FakeSyncAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE))
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:fake-sync")]),
        assistant=asst,
    )
    assert await gw.decide(_inv()) == Decision.ALLOW_ONCE
    assert asst.calls == 1


@_async_test
async def test_sync_responder_is_bridged_via_to_thread() -> None:
    responder = FakeSyncResponder(choice=Decision.DENY)
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        responder=responder,
    )
    assert await gw.decide(_inv()) == Decision.DENY
    assert responder.calls == 1


# --------------------------------------------------------------------------- #
# PROMPT without responder -> safe deny
# --------------------------------------------------------------------------- #


@_async_test
async def test_prompt_without_responder_returns_safe_deny() -> None:
    gw = AsyncGatewayTiny(_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]))
    assert await gw.decide(_inv()) == Decision.DENY


# --------------------------------------------------------------------------- #
# ASSIST with no assistant registered -> safe deny
# --------------------------------------------------------------------------- #


@_async_test
async def test_assist_without_assistant_returns_safe_deny() -> None:
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:missing")])
    )
    assert await gw.decide(_inv()) == Decision.DENY


# --------------------------------------------------------------------------- #
# H8 exception-safety : raising async responder -> safe DENY + audit + seam C
# --------------------------------------------------------------------------- #


@_async_test
async def test_raising_responder_returns_safe_deny_and_runs_audit(tmp_path: Path) -> None:
    sink = FileAuditSink(tmp_path / "audit.jsonl")
    gw = AsyncGateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        responder=RaisingAsyncResponder(),
        audit_sink=sink,
    )
    decision = await gw.decide(_inv())
    assert decision == Decision.DENY
    # Audit was still emitted (H8 finally-block invariant).
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    evt = json.loads(lines[0])
    assert evt["decision"] == "deny"
    assert "gateway error" in evt["reasoning"]


# --------------------------------------------------------------------------- #
# Fatigue: async seams (sync InMemoryFatigueLayer bridged via to_thread)
# --------------------------------------------------------------------------- #


@_async_test
async def test_fatigue_dedup_caches_second_call() -> None:
    responder = FakeAsyncResponder(choice=Decision.ALLOW, ttl=60)
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=60)
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        responder=responder,
        fatigue=fatigue,
    )
    inv = _inv(args={"path": "/tmp/a"})
    first = await gw.decide(inv)
    second = await gw.decide(inv)
    assert first == Decision.ALLOW
    assert second == Decision.ALLOW  # cache hit
    assert responder.calls == 1  # second call short-circuited at the fatigue seam


@_async_test
async def test_fatigue_clear_via_async_reload_policy() -> None:
    responder = FakeAsyncResponder(choice=Decision.ALLOW, ttl=300)
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=300)
    gw = AsyncGateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        responder=responder,
        fatigue=fatigue,
        audit_sink=NullAuditSink(),
    )
    inv = _inv(args={"path": "/tmp/a"})
    await gw.decide(inv)
    # No source path on this policy -> reload returns False, cache stays.
    reloaded = await gw.reload_policy()
    assert reloaded is False
    assert responder.calls == 1


# --------------------------------------------------------------------------- #
# Redaction before the async responder + audit
# --------------------------------------------------------------------------- #


@_async_test
async def test_secret_args_redacted_before_async_responder() -> None:
    responder = FakeAsyncResponder(choice=Decision.ALLOW)
    schema = {
        "type": "object",
        "properties": {"token": {"type": "string", "secret": True}},
    }
    gw = AsyncGatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        responder=responder,
    )
    inv = _inv(args={"token": "supersecret"}, descriptor=_desc(schema=schema))
    await gw.decide(inv)
    assert responder.last_req is not None
    assert responder.last_req.args_redacted["token"] == "[REDACTED]"


@_async_test
async def test_secret_args_redacted_in_audit_event(tmp_path: Path) -> None:
    sink = FileAuditSink(tmp_path / "audit.jsonl")
    schema = {"type": "object", "properties": {"pw": {"format": "password"}}}
    gw = AsyncGateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        audit_sink=sink,
    )
    await gw.decide(_inv(args={"pw": "hunter2"}, descriptor=_desc(schema=schema)))
    line = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip()
    evt = json.loads(line)
    assert evt["invocation"]["args"]["pw"] == "[REDACTED]"


# --------------------------------------------------------------------------- #
# Approver flows through to audit on the async path (H12)
# --------------------------------------------------------------------------- #


@_async_test
async def test_approver_recorded_in_audit(tmp_path: Path) -> None:
    sink = FileAuditSink(tmp_path / "audit.jsonl")
    gw = AsyncGateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt")]),
        responder=FakeAsyncResponder(choice=Decision.ALLOW),
        audit_sink=sink,
    )
    await gw.decide(_inv())
    evt = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip())
    assert evt["approver"] == "async-approver"


# --------------------------------------------------------------------------- #
# wrap: plain callables become async gated proxies
# --------------------------------------------------------------------------- #


@_async_test
async def test_wrap_plain_callable_allow_forwards() -> None:
    gw = AsyncGatewayTiny(_policy([PolicyRuleSpec(match={"tool": "fs*"}, action="allow")]))

    def fs_read(path: str) -> str:
        return f"contents of {path}"

    wrapped = gw.gw.wrap([fs_read])
    assert len(wrapped) == 1
    proxy = wrapped[0]
    assert inspect.iscoroutinefunction(proxy)
    result = await proxy("hello")
    assert result == "contents of hello"


@_async_test
async def test_wrap_plain_callable_deny_raises_permission_denied() -> None:
    from custos.exceptions import PermissionDenied

    gw = AsyncGatewayTiny(_policy([PolicyRuleSpec(match={"tool": "*"}, action="deny")]))

    def fs_read(path: str) -> str:
        return "should not be called"

    proxy = gw.gw.wrap([fs_read])[0]
    with pytest.raises(PermissionDenied):
        await proxy("anything")


@_async_test
async def test_wrap_plain_async_callable_forwards_awaitable() -> None:
    gw = AsyncGatewayTiny(_policy([PolicyRuleSpec(match={"tool": "fs*"}, action="allow")]))

    async def fs_read_async(path: str) -> str:
        await asyncio.sleep(0)
        return f"async contents of {path}"

    proxy = gw.gw.wrap([fs_read_async])[0]
    result = await proxy("a")
    assert result == "async contents of a"


@_async_test
async def test_wrap_empty_returns_empty() -> None:
    gw = AsyncGatewayTiny(_policy([]))
    assert gw.gw.wrap([]) == []


@_async_test
async def test_wrap_langchain_shape_raises_with_pointer() -> None:
    class FakeLangChainTool:
        _run = staticmethod(lambda **kw: None)
        args_schema = None
        name = "lc-tool"

    gw = AsyncGatewayTiny(_policy([]))
    with pytest.raises(NotImplementedError, match="sync custos.Gateway"):
        gw.gw.wrap([FakeLangChainTool()])
