"""Tests for :class:`custos.gateway.Gateway` - the full decision pipeline .

Covers every branch of ``Gateway.decide``:
  - policy ALLOW  -> Decision.ALLOW (no assistant, no responder)
  - policy DENY   -> Decision.DENY  (floor invariant: assistant never invoked)
  - policy ASSIST -> assistant allow_once / allow / prompt / deny /
    allow_and_persist (+ in-memory rule persistence)
  - policy PROMPT -> responder allow / deny (no assistant)
  - no assistant configured on ASSIST -> safe deny
  - no responder configured on PROMPT -> safe deny
  - redaction strips ``secret: true`` / ``format: password`` fields before
    responder and audit
  - audit event emitted on every path
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from custos.audit import FileAuditSink, NullAuditSink
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
# Fakes
# --------------------------------------------------------------------------- #


class FakeAssistant:
    """A controllable assistant for pipeline tests (implements Assistant)."""

    name = "fake"

    def __init__(self, output: AssistantOutput) -> None:
        self.output = output
        self.calls = 0

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        self.calls += 1
        return self.output


class FakeResponder:
    """A controllable responder (implements Responder)."""

    name = "fake"

    def __init__(self, choice: Decision = Decision.ALLOW, *, ttl: int | None = None) -> None:
        self.choice = choice
        self.ttl = ttl
        self.calls = 0
        self.last_req: PromptRequest | None = None

    def prompt(self, req: PromptRequest) -> PromptResponse:
        self.calls += 1
        self.last_req = req
        return PromptResponse(choice=self.choice, ttl=self.ttl)


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


# --------------------------------------------------------------------------- #
# policy ALLOW / DENY (no assistant, no responder)
# --------------------------------------------------------------------------- #


def test_policy_allow_returns_allow() -> None:
    gw = GatewayTiny(_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="allow")]))
    assert gw.decide(_inv()) == Decision.ALLOW


def test_policy_deny_returns_deny() -> None:
    gw = GatewayTiny(_policy([PolicyRuleSpec(match={"tool": "*"}, action="deny")]))
    assert gw.decide(_inv()) == Decision.DENY


def test_default_deny_when_no_rule_matches() -> None:
    gw = GatewayTiny(_policy([]))
    assert gw.decide(_inv()) == Decision.DENY


# --------------------------------------------------------------------------- #
# floor invariant : policy DENY never reaches the assistant
# --------------------------------------------------------------------------- #


def test_policy_deny_never_invokes_assistant() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE))
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="deny")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.DENY
    assert asst.calls == 0


# --------------------------------------------------------------------------- #
# policy ASSIST -> assistant dispatch
# --------------------------------------------------------------------------- #


def test_assist_no_assistant_configured_is_safe_deny() -> None:
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")])
    )
    assert gw.decide(_inv()) == Decision.DENY


def test_assistant_allow_once_passes_through() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.3, reasoning="ok"))
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.ALLOW_ONCE
    assert asst.calls == 1


def test_assistant_allow_passes_through() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.ALLOW))
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.ALLOW


def test_assistant_deny_passes_through() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.DENY, reasoning="too risky"))
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.DENY


def test_assistant_prompt_routes_to_responder() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.PROMPT, risk=0.6, reasoning="ask user"))
    responder = FakeResponder(choice=Decision.ALLOW)
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
        responder=responder,
    )
    assert gw.decide(_inv()) == Decision.ALLOW
    assert responder.calls == 1
    assert responder.last_req is not None
    assert responder.last_req.reasoning == "ask user"


def test_assistant_prompt_no_responder_is_safe_deny() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.PROMPT))
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.DENY


# --------------------------------------------------------------------------- #
# allow_and_persist (step 3, Janus create_policy)
# --------------------------------------------------------------------------- #


def test_allow_and_persist_adds_rule_and_short_circuits_next_call() -> None:
    persist = {"match": {"tool": "fs.*"}, "action": "allow"}
    asst = FakeAssistant(
        AssistantOutput(
            decision=Decision.ALLOW_AND_PERSIST,
            risk=0.2,
            reasoning="low risk",
            persist_rule=persist,
        )
    )
    # The policy says assist; first call -> assistant persists a rule + allow_once.
    # Second call -> the new rule matches fs.* -> ALLOW (no assistant).
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    first = gw.decide(_inv(tool="fs.read"))
    assert first == Decision.ALLOW_ONCE
    assert asst.calls == 1
    # Second identical call should short-circuit at policy -> ALLOW.
    second = gw.decide(_inv(tool="fs.read"))
    assert second == Decision.ALLOW
    assert asst.calls == 1  # assistant NOT invoked again


def test_allow_and_persist_malformed_rule_drops_persist_keeps_allow_once() -> None:
    asst = FakeAssistant(
        AssistantOutput(
            decision=Decision.ALLOW_AND_PERSIST,
            persist_rule={"match": {"tool": "fs.*"}, "action": "bogus_action"},
        )
    )
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.ALLOW_ONCE
    # The malformed rule was dropped; next call still hits assist.
    assert gw.decide(_inv()) == Decision.ALLOW_ONCE  # again via assistant
    assert asst.calls == 2


def test_allow_and_persist_none_rule_drops_silently() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.ALLOW_AND_PERSIST, persist_rule=None))
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
    )
    assert gw.decide(_inv()) == Decision.ALLOW_ONCE


# --------------------------------------------------------------------------- #
# policy PROMPT -> responder (assistant bypassed)
# --------------------------------------------------------------------------- #


def test_policy_prompt_routes_to_responder() -> None:
    responder = FakeResponder(choice=Decision.DENY)
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")]),
        responder=responder,
    )
    assert gw.decide(_inv()) == Decision.DENY
    assert responder.calls == 1


def test_policy_prompt_no_responder_is_safe_deny() -> None:
    gw = GatewayTiny(_policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")]))
    assert gw.decide(_inv()) == Decision.DENY


def test_policy_prompt_does_not_invoke_assistant() -> None:
    asst = FakeAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE))
    responder = FakeResponder(choice=Decision.ALLOW)
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")]),
        assistant=asst,
        responder=responder,
    )
    assert gw.decide(_inv()) == Decision.ALLOW
    assert asst.calls == 0  # assistant bypassed on PROMPT


# --------------------------------------------------------------------------- #
# redaction
# --------------------------------------------------------------------------- #


def test_redaction_strips_secret_true_fields_from_responder() -> None:
    responder = FakeResponder(choice=Decision.ALLOW)
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")]),
        responder=responder,
    )
    desc = _desc(
        schema={
            "type": "object",
            "properties": {
                "token": {"secret": True},
                "path": {"type": "string"},
            },
        }
    )
    inv = _inv(args={"token": "sk-secret", "path": "/tmp"}, descriptor=desc)
    assert gw.decide(inv) == Decision.ALLOW
    assert responder.last_req is not None
    assert responder.last_req.args_redacted["token"] == "[REDACTED]"
    assert responder.last_req.args_redacted["path"] == "/tmp"


def test_redaction_strips_format_password_fields() -> None:
    responder = FakeResponder(choice=Decision.ALLOW)
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")]),
        responder=responder,
    )
    desc = _desc(
        schema={
            "properties": {"pw": {"format": "password"}},
        }
    )
    inv = _inv(args={"pw": "hunter2"}, descriptor=desc)
    gw.decide(inv)
    assert responder.last_req is not None
    assert responder.last_req.args_redacted["pw"] == "[REDACTED]"


def test_redaction_applies_to_audit_log(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = FileAuditSink(p)
    from custos.gateway import Gateway

    spec = PolicyFile(
        version=1,
        overlays=(
            PolicyOverlaySpec(
                id="base", rules=(PolicyRuleSpec(match={"tool": "*"}, action="prompt"),)
            ),
        ),
    )
    gw = Gateway(
        policy=Policy.from_spec(spec),
        responder=FakeResponder(choice=Decision.DENY),
        audit_sink=sink,
    )
    desc = _desc(schema={"properties": {"secret": {"secret": True}}})
    inv = _inv(args={"secret": "leak", "public": "ok"}, descriptor=desc)
    gw.decide(inv)
    record = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    assert record["invocation"]["args"]["secret"] == "[REDACTED]"
    assert record["invocation"]["args"]["public"] == "ok"


def test_redaction_preserves_original_invocation_args() -> None:
    """The caller's Invocation is frozen; redaction produces a copy."""
    desc = _desc(schema={"properties": {"token": {"secret": True}}})
    inv = _inv(args={"token": "sk-orig"}, descriptor=desc)
    responder = FakeResponder(choice=Decision.ALLOW)
    gw = GatewayTiny(
        _policy([PolicyRuleSpec(match={"tool": "*"}, action="prompt")]),
        responder=responder,
    )
    gw.decide(inv)
    # Original invocation untouched.
    assert inv.args["token"] == "sk-orig"


# --------------------------------------------------------------------------- #
# audit emission
# --------------------------------------------------------------------------- #


def test_audit_event_emitted_on_allow(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = FileAuditSink(p)
    from custos.gateway import Gateway

    gw = Gateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="allow")]),
        audit_sink=sink,
    )
    gw.decide(_inv(tool="fs.read"))
    records = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    assert records[0]["decision"] == "allow"
    assert records[0]["policy_match"] == "base:allow"


def test_audit_event_records_assistant_and_risk(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    sink = FileAuditSink(p)
    from custos.gateway import Gateway

    asst = FakeAssistant(AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.37, reasoning="meh"))
    gw = Gateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:risk-assessment")]),
        assistant=asst,
        audit_sink=sink,
    )
    gw.decide(_inv())
    record = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
    assert record["assistant"] == "fake"
    assert record["risk_score"] == 0.37
    assert record["reasoning"] == "meh"


def test_null_audit_sink_default_does_not_raise() -> None:
    from custos.gateway import Gateway

    gw = Gateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "fs.*"}, action="allow")]),
        audit_sink=None,
    )
    assert gw.decide(_inv(tool="fs.read")) == Decision.ALLOW


# --------------------------------------------------------------------------- #
# Conveniences
# --------------------------------------------------------------------------- #


class GatewayTiny:
    """Thin wrapper so tests don't repeat the Gateway(audit_sink=None) boilerplate.

    Builds a Gateway with a NullAuditSink + the given assistant/responder.
    """

    def __init__(
        self,
        policy: Policy,
        assistant: Any | None = None,
        responder: Any | None = None,
    ) -> None:
        from custos.gateway import Gateway

        self._gw = Gateway(
            policy=policy,
            assistant=assistant,
            responder=responder,
            audit_sink=NullAuditSink(),
        )

    def decide(self, inv: Invocation) -> Decision:
        return self._gw.decide(inv)


# --------------------------------------------------------------------------- #
# Air-gapped profile + allow_external_data (C4 regression, council 2026-07-22)
# --------------------------------------------------------------------------- #


class _ExfilAssistant:
    """A remote-LLM-shaped assistant: exfiltrates_args=True (A5/A6-style)."""

    name = "remote"
    exfiltrates_args = True

    def __init__(self, output: AssistantOutput) -> None:
        self.output = output
        self.calls = 0

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        self.calls += 1
        return self.output


def test_local_only_refuses_to_register_exfiltrating_assistant() -> None:
    """air-gapped profile: local_only=True refuses exfiltrates_args=True."""
    import pytest

    from custos.gateway import Gateway

    out = AssistantOutput(decision=Decision.ALLOW)
    with pytest.raises(ValueError, match="air-gapped"):
        Gateway(
            policy=_policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:remote")]),
            assistant=_ExfilAssistant(out),
            audit_sink=NullAuditSink(),
            local_only=True,
        )


def test_local_only_accepts_in_process_assistant() -> None:
    """local_only=True still accepts exfiltrates_args=False assistants (A10/A11)."""
    from custos.gateway import Gateway

    gw = Gateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:fake")]),
        assistant=FakeAssistant(AssistantOutput(decision=Decision.ALLOW)),
        audit_sink=NullAuditSink(),
        local_only=True,
    )
    assert gw.local_only is True
    assert gw._assistant_registry.get("fake") is not None


def test_local_only_refuses_via_assistants_list() -> None:
    import pytest

    from custos.gateway import Gateway

    out = AssistantOutput(decision=Decision.ALLOW)
    with pytest.raises(ValueError, match="air-gapped"):
        Gateway(
            policy=_policy([]),
            audit_sink=NullAuditSink(),
            local_only=True,
            assistants=[_ExfilAssistant(out)],
        )


def test_allow_external_data_true_relaxes_gate() -> None:
    """A rule with allow_external_data=True permits the exfiltrating assistant
    to run on restricted args (operator-vetted opt-out). Default False."""
    from custos.gateway import Gateway

    out = AssistantOutput(decision=Decision.ALLOW)
    asst = _ExfilAssistant(out)
    gw = Gateway(
        policy=_policy(
            [
                PolicyRuleSpec(
                    match={"tool": "*"},
                    action="assist:remote",
                    allow_external_data=True,
                )
            ]
        ),
        assistant=asst,
        responder=FakeResponder(choice=Decision.DENY),
        audit_sink=NullAuditSink(),
    )
    desc = _desc(schema={"properties": {"token": {"secret": True}}})
    inv = _inv(args={"token": "sk"}, descriptor=desc)
    assert gw.decide(inv) == Decision.ALLOW
    assert asst.calls == 1  # assistant WAS invoked (gate relaxed)


def test_allow_external_data_default_false_routes_to_prompt() -> None:
    """Default allow_external_data=False: restricted args + remote assistant
    -> prompt (NOT assistant invocation). The  floor."""
    from custos.gateway import Gateway

    out = AssistantOutput(decision=Decision.ALLOW)
    asst = _ExfilAssistant(out)
    responder = FakeResponder(choice=Decision.ALLOW)
    gw = Gateway(
        policy=_policy([PolicyRuleSpec(match={"tool": "*"}, action="assist:remote")]),
        assistant=asst,
        responder=responder,
        audit_sink=NullAuditSink(),
    )
    desc = _desc(schema={"properties": {"token": {"secret": True}}})
    inv = _inv(args={"token": "sk"}, descriptor=desc)
    assert gw.decide(inv) == Decision.ALLOW  # responder allowed
    assert asst.calls == 0  # assistant NOT invoked (gate fired -> prompt)
    assert responder.calls == 1


def test_allow_external_data_yaml_roundtrip(tmp_path: Path) -> None:
    import pytest

    pytest.importorskip("yaml")
    from custos.policy import Policy

    yml = tmp_path / "p.yaml"
    yml.write_text(
        "version: 1\ndefault: deny\noverlays:\n"
        "  - id: base\n    rules:\n"
        "      - match: {tool: 'fs.*'}\n"
        "        action: 'assist:remote'\n"
        "        allow_external_data: true\n",
        encoding="utf-8",
    )
    pol = Policy.from_yaml(str(yml))
    rule = pol.matched_rule(_inv(tool="fs.write"))
    assert rule is not None and rule.allow_external_data is True


def test_allow_external_data_non_bool_rejected(tmp_path: Path) -> None:
    import pytest

    pytest.importorskip("yaml")
    from custos.policy import Policy
    from custos.policy.schema import PolicyValidationError

    yml = tmp_path / "p.yaml"
    yml.write_text(
        "version: 1\ndefault: deny\noverlays:\n"
        "  - id: base\n    rules:\n"
        "      - match: {tool: 'fs.*'}\n"
        "        action: 'assist:remote'\n"
        "        allow_external_data: 'yes'\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyValidationError):
        Policy.from_yaml(str(yml))


# --------------------------------------------------------------------------- #
# helper functions from gateway module (unit tests for new/refactored code)
# --------------------------------------------------------------------------- #


def test_evaluate_with_match_no_rule_matches_default_deny() -> None:
    from custos.gateway import _evaluate_with_match
    from custos.policy.engine import _action_to_outcome

    pol = _policy([])
    outcome, label, matched = _evaluate_with_match(pol, _inv())
    assert outcome == _action_to_outcome("deny")
    assert label == "default:deny"
    assert matched is None


def test_evaluate_with_match_no_rule_matches_default_allow() -> None:
    from custos.gateway import _evaluate_with_match
    from custos.policy.engine import _action_to_outcome

    pol = _policy([], default="allow")
    outcome, label, matched = _evaluate_with_match(pol, _inv())
    assert outcome == _action_to_outcome("allow")
    assert label == "default:allow"
    assert matched is None


def test_evaluate_with_match_first_rule_matches() -> None:
    from custos.gateway import _evaluate_with_match

    pol = _policy([PolicyRuleSpec(match={"tool": "fs.read"}, action="allow")])
    outcome, label, matched = _evaluate_with_match(pol, _inv(tool="fs.read"))
    assert outcome is not None
    assert label == "base:allow"
    assert matched is not None


def test_resolve_policy_match_no_rule_matches() -> None:
    from custos.gateway import _resolve_policy_match

    pol = _policy([])
    assert _resolve_policy_match(pol, _inv()) == "default:deny"


def test_resolve_batching_fallback_when_matched_none() -> None:
    from custos.gateway import _resolve_batching

    pol = _policy(
        [PolicyRuleSpec(match={"tool": "fs.read"}, action="prompt", batching={"max_delay_s": 10})]
    )
    result = _resolve_batching(pol, _inv(tool="fs.read"), matched=None)
    assert result is not None
    assert result["max_delay_s"] == 10


def test_resolve_quorum_fallback_when_matched_none() -> None:
    from custos.gateway import _resolve_quorum

    pol = _policy(
        [
            PolicyRuleSpec(
                match={"tool": "fs.read"},
                action="prompt",
                quorum=2,
                approver_roles=["admin", "manager"],
                approver_allowlist=["alice"],
            )
        ]
    )
    result = _resolve_quorum(pol, _inv(tool="fs.read"), matched=None)
    assert result is not None
    assert result["quorum"] == 2
    assert "admin" in result["approver_roles"]
    assert "alice" in result["approver_allowlist"]


def test_infer_quorum_state_fallback_when_matched_none() -> None:
    from custos.gateway import _infer_quorum_state

    pol = _policy(
        [
            PolicyRuleSpec(
                match={"tool": "fs.read"},
                action="prompt",
                quorum=2,
                approver_roles=["admin", "manager"],
            )
        ]
    )
    state = _infer_quorum_state(pol, _inv(tool="fs.read"), Decision.ALLOW, matched=None)
    assert state == "met"


def test_infer_quorum_state_from_decision_defer_pending() -> None:
    from custos.gateway import _infer_quorum_state_from_decision

    assert _infer_quorum_state_from_decision(Decision.DEFER) == "pending"


def test_infer_quorum_state_from_decision_deny_failed() -> None:
    from custos.gateway import _infer_quorum_state_from_decision

    assert _infer_quorum_state_from_decision(Decision.DENY) == "failed"


def test_infer_quorum_state_from_decision_allow_met() -> None:
    from custos.gateway import _infer_quorum_state_from_decision

    assert _infer_quorum_state_from_decision(Decision.ALLOW) == "met"


def test_has_secret_args_descriptor_none() -> None:
    from custos.gateway import _has_secret_args

    assert _has_secret_args(None) is False


def test_has_secret_args_pii_side_effect() -> None:
    from custos.gateway import _has_secret_args

    desc = _desc(side=frozenset([SideEffect.PII]))
    assert _has_secret_args(desc) is True


def test_has_secret_args_schema_secret() -> None:
    from custos.gateway import _has_secret_args

    desc = _desc(schema={"properties": {"token": {"secret": True}}})
    assert _has_secret_args(desc) is True


def test_has_secret_args_schema_format_password() -> None:
    from custos.gateway import _has_secret_args

    desc = _desc(schema={"properties": {"pw": {"format": "password"}}})
    assert _has_secret_args(desc) is True


def test_has_secret_args_no_secrets() -> None:
    from custos.gateway import _has_secret_args

    desc = _desc(schema={"properties": {"name": {"type": "string"}}})
    assert _has_secret_args(desc) is False


def test_persist_assistant_rule_deny_shadow_with_fn_match() -> None:
    """A later deny rule whose tool pattern fnmatches the persisted tool blocks persistence."""
    from custos.gateway import _persist_assistant_rule_impl

    pol = _policy(
        [
            PolicyRuleSpec(match={"tool": "fs.*"}, action="assist:fake"),
            PolicyRuleSpec(match={"tool": "fs.read"}, action="deny"),
        ]
    )
    persist = {"action": "allow", "match": {"tool": "fs.read"}}
    _persist_assistant_rule_impl(pol, persist, _inv(tool="fs.write"))
    rules = list(pol.rules)
    assert len(rules) == 2  # no rule added because shadowed


def test_persist_assistant_rule_deny_any_tool_blocks() -> None:
    """A later deny rule with no tool constraint blocks any tool persistence."""
    from custos.gateway import _persist_assistant_rule_impl

    pol = _policy(
        [
            PolicyRuleSpec(match={"tool": "admin.*"}, action="assist:fake"),
            PolicyRuleSpec(match={}, action="deny"),
        ]
    )
    persist = {"action": "allow", "match": {"tool": "admin.drop"}}
    _persist_assistant_rule_impl(pol, persist, _inv(tool="admin.drop"))
    rules = list(pol.rules)
    assert len(rules) == 2  # no rule added because shadowed by tool-less deny


def test_reload_policy_clears_fatigue_cache(tmp_path: Path) -> None:
    import time

    import pytest

    pytest.importorskip("yaml")
    from custos.fatigue import InMemoryFatigueLayer
    from custos.gateway import Gateway

    yml = tmp_path / "p.yaml"
    yml.write_text(
        "version: 1\ndefault: deny\noverlays:\n  - id: base\n    rules: []\n", encoding="utf-8"
    )
    pol = Policy.from_yaml(str(yml))
    fatigue = InMemoryFatigueLayer()
    gw = Gateway(policy=pol, fatigue=fatigue, audit_sink=NullAuditSink())
    # Touch the file with a newer mtime so reload actually reads it.
    time.sleep(0.01)
    yml.write_text(
        "version: 1\ndefault: allow\noverlays:\n  - id: base\n    rules: []\n", encoding="utf-8"
    )
    result = gw.reload_policy()
    assert result is True
