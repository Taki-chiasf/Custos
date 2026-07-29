"""Tests for :mod:`custos.fatigue` + the 3-seam gateway integration .

Covers:
   dedup: identical (tool, args) auto-resolves to the prior decision
    for a TTL.
   suppression: user "allow for N minutes" (PromptResponse.ttl)
    caches the decision for the granted window.
   rate limit: max M prompts per session-minute; excess auto-denies
    with an audit-recorded alert.
   ask-me-later: a responder returning DEFER is not cached, so the
    next identical call re-prompts.
  Gateway wiring: seam A short-circuits (skips assistant + responder); seam
    B rate-limits before the responder; seam C writes the cache after the
    responder. fatigue=None disables all seams (behavior preserved).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from custos.audit import FileAuditSink, NullAuditSink
from custos.fatigue import InMemoryFatigueLayer
from custos.gateway import Gateway
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

# --------------------------------------------------------------------------- #
# Fakes (local — reuse pattern from test_gateway.py but keep self-contained)
# --------------------------------------------------------------------------- #


class CountingAssistant:
    name = "fake"

    def __init__(self, output: AssistantOutput) -> None:
        self.output = output
        self.calls = 0

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        self.calls += 1
        return self.output


class ScriptedResponder:
    """Returns a scripted sequence of responses, recording how many times it
    was actually invoked (vs. being skipped by a cache hit)."""

    name = "fake"

    def __init__(self, responses: list[PromptResponse]) -> None:
        self._responses = list(responses)
        self.calls = 0
        self.last_req: PromptRequest | None = None

    def prompt(self, req: PromptRequest) -> PromptResponse:
        self.calls += 1
        self.last_req = req
        if self._responses:
            return self._responses.pop(0)
        return PromptResponse(choice=Decision.DENY)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ctx(**kw: Any) -> SubjectContext:
    return SubjectContext(user_id="u1", **kw)  # type: ignore[arg-type]


def _inv(
    tool: str = "email.send",
    *,
    args: dict[str, Any] | None = None,
) -> Invocation:
    return Invocation(tool=tool, args=args or {"to": "bob@x.com"}, context=_ctx())


def _desc(risk_tier: int = 3) -> ToolDescriptor:
    return ToolDescriptor(
        name="t", risk_tier=risk_tier, side_effects=frozenset({SideEffect.NETWORK})
    )


def _policy_assist() -> Policy:
    """A policy that routes everything through ``assist:fake``."""
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="base",
                rules=(PolicyRuleSpec(match={"tool": "*"}, action="assist:fake"),),
            ),
        ),
    )
    return Policy.from_spec(spec)


def _policy_prompt() -> Policy:
    """A policy that routes everything through ``prompt`` (no assistant)."""
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="base",
                rules=(PolicyRuleSpec(match={"tool": "*"}, action="prompt"),),
            ),
        ),
    )
    return Policy.from_spec(spec)


def _gw(
    policy: Policy,
    *,
    assistant: Any | None = None,
    responder: Any | None = None,
    fatigue: InMemoryFatigueLayer | None = None,
    audit_sink: Any | None = None,
) -> Gateway:
    return Gateway(
        policy=policy,
        assistant=assistant,
        responder=responder,
        fatigue=fatigue,
        audit_sink=audit_sink or NullAuditSink(),
    )


# --------------------------------------------------------------------------- #
#  dedup — identical (tool, args) auto-resolves for a TTL
# --------------------------------------------------------------------------- #


def test_dedup_caches_resolved_decision_and_skips_assistant() -> None:
    """Second identical call: assistant NOT invoked, responds with the cached
    decision ."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=300)
    asst = CountingAssistant(
        AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.3, reasoning="ok")
    )
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    first = gw.decide(_inv()).decision
    assert first == Decision.ALLOW_ONCE
    assert asst.calls == 1

    second = gw.decide(_inv()).decision  # same tool + args
    assert second == Decision.ALLOW_ONCE
    assert asst.calls == 1  # assistant skipped (cache hit)


def test_dedup_miss_on_different_args() -> None:
    """Different args -> cache miss -> assistant invoked again ."""
    fatigue = InMemoryFatigueLayer()
    asst = CountingAssistant(
        AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2, reasoning="ok")
    )
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    gw.decide(_inv(args={"to": "a@x.com"}))
    assert asst.calls == 1
    gw.decide(_inv(args={"to": "b@x.com"}))  # different args
    assert asst.calls == 2


def test_dedup_miss_on_different_tool() -> None:
    fatigue = InMemoryFatigueLayer()
    asst = CountingAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    gw.decide(_inv(tool="email.send"))
    assert asst.calls == 1
    gw.decide(_inv(tool="email.write"))
    assert asst.calls == 2


def test_dedup_miss_on_different_user() -> None:
    fatigue = InMemoryFatigueLayer()
    asst = CountingAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    gw.decide(Invocation(tool="t", args={}, context=SubjectContext(user_id="alice")))
    assert asst.calls == 1
    gw.decide(Invocation(tool="t", args={}, context=SubjectContext(user_id="bob")))
    assert asst.calls == 2


def test_dedup_expires_after_ttl() -> None:
    """A zero TTL cache entry expires immediately -> second call re-invokes."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=0.01)
    asst = CountingAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    gw.decide(_inv())
    assert asst.calls == 1
    time.sleep(0.05)
    gw.decide(_inv())
    assert asst.calls == 2  # expired -> cache miss -> assistant invoked


def test_dedup_cache_hit_emits_audit_with_fatigue_reasoning(tmp_path: Path) -> None:
    """A cache-hit audit event records the fatigue layer name in reasoning."""
    p = tmp_path / "a.jsonl"
    sink = FileAuditSink(p)
    fatigue = InMemoryFatigueLayer()
    asst = CountingAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue, audit_sink=sink)

    gw.decide(_inv())
    gw.decide(_inv())  # cache hit
    records = [json.loads(line) for line in p.read_text().splitlines()]
    assert len(records) == 2
    assert records[0]["reasoning"] != "fatigue: cache hit (in-memory)"
    assert records[1]["reasoning"] == "fatigue: cache hit (in-memory)"
    assert records[1]["assistant"] is None  # assistant skipped


# --------------------------------------------------------------------------- #
#  suppression — PromptResponse.ttl drives the cache window
# --------------------------------------------------------------------------- #


def test_suppression_uses_response_ttl_not_default_dedup_ttl() -> None:
    """The user's "allow for N minutes" ttl overrides the short dedup TTL."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=0.05)  # very short default
    responder = ScriptedResponder(
        [PromptResponse(choice=Decision.ALLOW, ttl=3600)]  # 1 hour suppression
    )
    asst = CountingAssistant(
        AssistantOutput(decision=Decision.PROMPT, risk=0.5, reasoning="ask user")
    )
    gw = _gw(_policy_assist(), assistant=asst, responder=responder, fatigue=fatigue)

    first = gw.decide(_inv()).decision
    assert first == Decision.ALLOW
    assert responder.calls == 1
    time.sleep(0.1)  # past the default dedup TTL but within suppression
    second = gw.decide(_inv()).decision
    assert second == Decision.ALLOW
    assert responder.calls == 1  # suppression cache hit; no re-prompt


def test_suppression_caches_deny_from_responder() -> None:
    """A DENY from the responder is also cached for dedup (/9.13)."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=300)
    responder = ScriptedResponder([PromptResponse(choice=Decision.DENY)])
    gw = _gw(_policy_prompt(), responder=responder, fatigue=fatigue)

    first = gw.decide(_inv()).decision
    assert first == Decision.DENY
    assert responder.calls == 1
    second = gw.decide(_inv()).decision  # cached DENY
    assert second == Decision.DENY
    assert responder.calls == 1


def test_suppression_A_choice_from_cli_sets_ttl() -> None:
    """Integration: CLIResponder's 'A' choice sets ttl -> suppression cache."""
    from custos.responders.cli import CLIResponder

    fatigue = InMemoryFatigueLayer(dedup_ttl_s=0.01)
    inputs = iter(["A"])  # "Allow 10 min"
    responder = CLIResponder(input_fn=lambda _: next(inputs), ttl_minutes=10)
    asst = CountingAssistant(AssistantOutput(decision=Decision.PROMPT, risk=0.5, reasoning="ask"))
    gw = _gw(_policy_assist(), assistant=asst, responder=responder, fatigue=fatigue)

    first = gw.decide(_inv()).decision
    assert first == Decision.ALLOW
    time.sleep(0.05)  # past default dedup but within 10-min suppression
    second = gw.decide(_inv()).decision
    assert second == Decision.ALLOW
    assert asst.calls == 1  # assistant not re-invoked (suppression hit)


# --------------------------------------------------------------------------- #
#  ask-me-later — DEFER is not cached
# --------------------------------------------------------------------------- #


def test_defer_is_not_cached_re_prompts_next_call() -> None:
    """A DEFER from the responder is never cached -> next call re-prompts
    ."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=300)
    responder = ScriptedResponder(
        [PromptResponse(choice=Decision.DEFER), PromptResponse(choice=Decision.ALLOW)]
    )
    gw = _gw(_policy_prompt(), responder=responder, fatigue=fatigue)

    first = gw.decide(_inv()).decision
    assert first == Decision.DEFER
    assert responder.calls == 1
    second = gw.decide(_inv()).decision  # not cached -> re-prompts
    assert second == Decision.ALLOW
    assert responder.calls == 2


def test_defer_through_assistant_not_cached() -> None:
    """An assistant returning DEFER directly is also not cached."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=300)
    asst = CountingAssistant(AssistantOutput(decision=Decision.DEFER, risk=0.5, reasoning="later"))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    first = gw.decide(_inv()).decision
    assert first == Decision.DEFER
    second = gw.decide(_inv()).decision
    assert second == Decision.DEFER
    assert asst.calls == 2  # not cached -> invoked again


def test_cli_l_choice_returns_defer() -> None:
    """CLIResponder 'l' (ask later) -> DEFER ."""
    from custos.responders.cli import CLIResponder

    inputs = iter(["l"])
    responder = CLIResponder(input_fn=lambda _: next(inputs))
    asst = CountingAssistant(AssistantOutput(decision=Decision.PROMPT, risk=0.5, reasoning="ask"))
    gw = _gw(_policy_assist(), assistant=asst, responder=responder)

    result = gw.decide(_inv()).decision
    assert result == Decision.DEFER


# --------------------------------------------------------------------------- #
#  rate limit — max M prompts per session-minute
# --------------------------------------------------------------------------- #


def test_rate_limit_allows_up_to_max_then_denies() -> None:
    """max_per_minute=2: first two calls prompt; third auto-denies ."""
    fatigue = InMemoryFatigueLayer(max_per_minute=2)
    responder = ScriptedResponder(
        [PromptResponse(choice=Decision.ALLOW)] * 10  # never should exceed 2 prompts
    )
    gw = _gw(_policy_prompt(), responder=responder, fatigue=fatigue)

    # First two: RESPONDER is invoked (different args each time -> no dedup).
    r1 = gw.decide(_inv(args={"to": "a@x.com"})).decision
    r2 = gw.decide(_inv(args={"to": "b@x.com"})).decision
    assert r1 == Decision.ALLOW
    assert r2 == Decision.ALLOW
    assert responder.calls == 2

    # Third: rate-limit overflow -> DENY, responder NOT called.
    r3 = gw.decide(_inv(args={"to": "c@x.com"})).decision
    assert r3 == Decision.DENY
    assert responder.calls == 2  # responder skipped


def test_rate_limit_denial_records_alert_in_audit(tmp_path: Path) -> None:
    p = tmp_path / "a.jsonl"
    sink = FileAuditSink(p)
    fatigue = InMemoryFatigueLayer(max_per_minute=1)
    responder = ScriptedResponder([PromptResponse(choice=Decision.ALLOW)] * 5)
    gw = _gw(_policy_prompt(), responder=responder, fatigue=fatigue, audit_sink=sink)

    gw.decide(_inv(args={"to": "a@x.com"}))
    gw.decide(_inv(args={"to": "b@x.com"}))  # rate-limited
    records = [json.loads(line) for line in p.read_text().splitlines()]
    rate_record = records[-1]
    assert rate_record["decision"] == "deny"
    assert "rate limit exceeded" in rate_record["reasoning"]


def test_rate_limit_zero_disables() -> None:
    """max_per_minute=0 -> no rate limiting."""
    fatigue = InMemoryFatigueLayer(max_per_minute=0)
    responder = ScriptedResponder([PromptResponse(choice=Decision.ALLOW)] * 10)
    gw = _gw(_policy_prompt(), responder=responder, fatigue=fatigue)

    for i in range(5):
        assert gw.decide(_inv(args={"to": f"u{i}@x.com"})).decision == Decision.ALLOW
    assert responder.calls == 5


def test_rate_limit_counted_per_user() -> None:
    """Rate limit is per-user: two users each get their own bucket."""
    fatigue = InMemoryFatigueLayer(max_per_minute=1)
    responder = ScriptedResponder([PromptResponse(choice=Decision.ALLOW)] * 10)
    gw = _gw(_policy_prompt(), responder=responder, fatigue=fatigue)

    r_alice = gw.decide(
        Invocation(tool="t", args={"a": 1}, context=SubjectContext(user_id="alice"))
    ).decision
    r_bob = gw.decide(Invocation(tool="t", args={"a": 2}, context=SubjectContext(user_id="bob"))).decision
    r_alice2 = gw.decide(
        Invocation(tool="t", args={"a": 3}, context=SubjectContext(user_id="alice"))
    ).decision
    assert r_alice == Decision.ALLOW
    assert r_bob == Decision.ALLOW
    assert r_alice2 == Decision.DENY  # alice's 2nd call -> rate-limited
    assert responder.calls == 2


# --------------------------------------------------------------------------- #
# Seam integration — fatigue=None preserves  behavior
# --------------------------------------------------------------------------- #


def test_fatigue_none_preserves_phase1_behavior() -> None:
    """With no fatigue layer, repeated identical calls re-invoke the assistant
    (no dedup) — matching  semantics."""
    asst = CountingAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=None)

    gw.decide(_inv())
    gw.decide(_inv())
    assert asst.calls == 2  # no dedup -> invoked twice


def test_clear_invalidates_cache() -> None:
    """After clear, the next call re-invokes the assistant (safety)."""
    fatigue = InMemoryFatigueLayer(dedup_ttl_s=300)
    asst = CountingAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.2))
    gw = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)

    gw.decide(_inv())
    assert asst.calls == 1
    fatigue.clear()
    gw.decide(_inv())
    assert asst.calls == 2  # cache cleared -> re-invoked


def test_policy_allow_short_circuits_before_fatigue_lookup() -> None:
    """A policy ALLOW short-circuits at step 2 — the fatigue cache is never
    consulted, so the cache can never shadow a new policy rule (floor)."""
    fatigue = InMemoryFatigueLayer()
    # Pre-seed the cache with a stale DENY.
    asst = CountingAssistant(AssistantOutput(decision=Decision.DENY, risk=0.2))
    gw_seed = _gw(_policy_assist(), assistant=asst, fatigue=fatigue)
    gw_seed.decide(_inv())  # caches DENY

    # New policy that ALLOWs the same tool.
    allow_policy = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="base", rules=(PolicyRuleSpec(match={"tool": "*"}, action="allow"),)
            ),
        ),
    )
    gw = _gw(Policy.from_spec(allow_policy), fatigue=fatigue)
    assert gw.decide(_inv()).decision == Decision.ALLOW  # policy floor wins, not cache


# --------------------------------------------------------------------------- #
# Protocol satisfaction
# --------------------------------------------------------------------------- #


def test_in_memory_fatigue_satisfies_protocol() -> None:
    from custos.fatigue.base import FatigueLayer

    assert isinstance(InMemoryFatigueLayer(), FatigueLayer)
