"""Tests for :class:`custos.assistants.DelegationAwareAssistant` (A11).

Pure-deterministic, no LLM. Verifies the default depth-tier table:

  depth 0-1 -> base (composed RulePolicy) passthrough
  depth 2   -> escalate above-base calls to PROMPT; DENY preserved (floor)
  depth 3   -> force PROMPT on any call
  depth >=4 -> DENY (exfiltration guard; matches the delegation_depth_abuse cell)

Plus: custom overrides, air-gapped-safe, name, Protocol, DepthThreshold mapping.
"""

from __future__ import annotations

from typing import Any

from custos.assistants import DelegationAwareAssistant, DepthThreshold, RulePolicy
from custos.schema import (
    AssistantOutput,
    Decision,
    Invocation,
    SubjectContext,
    ToolDescriptor,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ctx(depth: int = 0) -> SubjectContext:
    chain = tuple(f"agent-{i}" for i in range(depth))
    return SubjectContext(user_id="u1", delegation_chain=chain)


def _inv(
    tool: str = "fs.read",
    *,
    descriptor: ToolDescriptor | None = None,
    depth: int = 0,
) -> Invocation:
    return Invocation(tool=tool, args={}, context=_ctx(depth), descriptor=descriptor)


def _desc(risk_tier: int = 1) -> ToolDescriptor:
    return ToolDescriptor(name="t", risk_tier=risk_tier)


def _allow_rules() -> list[tuple[dict[str, Any], AssistantOutput]]:
    return [
        (
            {"tool": "fs.*"},
            AssistantOutput(decision=Decision.ALLOW_ONCE, reasoning="read ok"),
        )
    ]


# --------------------------------------------------------------------------- #
# Depth 0-1: passthrough to the composed RulePolicy
# --------------------------------------------------------------------------- #


def test_depth_0_passthrough_allow() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(0))
    assert out.decision == Decision.ALLOW_ONCE
    assert out.reasoning == "read ok"


def test_depth_1_passthrough_allow() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(1))
    assert out.decision == Decision.ALLOW_ONCE


def test_depth_0_passthrough_deny_when_no_rule_matches() -> None:
    asst = DelegationAwareAssistant()
    out = asst.decide(_inv(tool="shell.rm", descriptor=_desc(4)), _ctx(0))
    assert out.decision == Decision.DENY
    assert "no rule matched" in out.reasoning


# --------------------------------------------------------------------------- #
# Depth 2: escalate above-base to PROMPT; base DENY preserved (floor)
# --------------------------------------------------------------------------- #


def test_depth_2_escalates_above_base_allow_to_prompt() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(2))
    assert out.decision == Decision.PROMPT
    assert "depth=2" in out.reasoning


def test_depth_2_preserves_base_deny_floor() -> None:
    # No rule matches -> base returns DENY. Floor invariant: depth tier never relaxes a deny.
    asst = DelegationAwareAssistant()
    out = asst.decide(_inv(tool="shell.rm", descriptor=_desc(5)), _ctx(2))
    assert out.decision == Decision.DENY
    assert "no rule matched" in out.reasoning


def test_depth_2_deny_rule_preserved_not_escalated_to_prompt() -> None:
    rules = [
        (
            {"tool": "shell.*"},
            AssistantOutput(decision=Decision.DENY, reasoning="shell denied"),
        )
    ]
    asst = DelegationAwareAssistant(rules=rules)
    out = asst.decide(_inv(tool="shell.rm", descriptor=_desc(4)), _ctx(2))
    assert out.decision == Decision.DENY
    assert out.reasoning == "shell denied"


# --------------------------------------------------------------------------- #
# Depth 3: force PROMPT on ANY call (even a base allow)
# --------------------------------------------------------------------------- #


def test_depth_3_forces_prompt_on_base_allow() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(3))
    assert out.decision == Decision.PROMPT
    assert "forced prompt" in out.reasoning


def test_depth_3_forces_prompt_even_on_base_deny_match() -> None:
    # Base returns DENY (no rule matches). The depth>=3 tier overrides to PROMPT.
    # This is an escalation, not a relaxation: DENY→PROMPT asks the user, never
    # auto-approves. (The  floor is about never relaxing a POLICY deny to an
    # assistant allow; A11 escalating a base-DENY assistant output to PROMPT
    # does not contradict  - the policy floor is upstream of the assistant.)
    asst = DelegationAwareAssistant()
    out = asst.decide(_inv(tool="shell.rm", descriptor=_desc(4)), _ctx(3))
    assert out.decision == Decision.PROMPT


# --------------------------------------------------------------------------- #
# Depth >=4: DENY (exfiltration guard)
# --------------------------------------------------------------------------- #


def test_depth_4_forces_deny_even_on_base_allow() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(4))
    assert out.decision == Decision.DENY
    assert "exfiltration guard" in out.reasoning


def test_depth_5_forces_deny() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(5))
    assert out.decision == Decision.DENY


def test_depth_4_deny_matches_adversarial_cell_semantics() -> None:
    """The delegation_depth_abuse adversarial cell uses a POLICY deny at depth=4.
    A11 reaches the same DENY via the assistant tier, so deployments that route
    through ``assist:delegation-aware`` instead of a hard policy deny get the
    same protection."""
    asst = DelegationAwareAssistant(rules=_allow_rules())
    inv = _inv(tool="fs.read", descriptor=_desc(1), depth=4)
    assert asst.decide(inv, inv.context).decision == Decision.DENY


# --------------------------------------------------------------------------- #
# Custom depth_thresholds override
# --------------------------------------------------------------------------- #


def test_custom_depth_thresholds_override_defaults() -> None:
    # A stricter deployment: deny at depth>=2 (no prompt window).
    def _deny_at_2(_depth: int, _base: AssistantOutput) -> AssistantOutput:
        return AssistantOutput(
            decision=Decision.DENY,
            risk=1.0,
            reasoning="custom: depth>=2 -> deny",
        )

    def _base_passthrough(_depth: int, base: AssistantOutput) -> AssistantOutput:
        return base

    asst = DelegationAwareAssistant(
        rules=_allow_rules(),
        depth_thresholds=((2, _deny_at_2), (0, _base_passthrough)),
    )
    out_shallow = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(1))
    assert out_shallow.decision == Decision.ALLOW_ONCE
    out_deep = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(2))
    assert out_deep.decision == Decision.DENY
    assert "custom" in out_deep.reasoning


def test_custom_depth_thresholds_empty_falls_through_to_base() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules(), depth_thresholds=())
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(10))
    assert out.decision == Decision.ALLOW_ONCE  # base passed through


# --------------------------------------------------------------------------- #
# Explicit fallback (RulePolicy instance) works the same as `rules=`
# --------------------------------------------------------------------------- #


def test_explicit_fallback_composed() -> None:
    fb = RulePolicy(_allow_rules())
    asst = DelegationAwareAssistant(fallback=fb)
    out = asst.decide(_inv(tool="fs.read", descriptor=_desc(1)), _ctx(0))
    assert out.decision == Decision.ALLOW_ONCE


# --------------------------------------------------------------------------- #
# Determinism : same inputs -> same output
# --------------------------------------------------------------------------- #


def test_deterministic_same_inputs_yield_same_output() -> None:
    asst = DelegationAwareAssistant(rules=_allow_rules())
    inv = _inv(tool="fs.read", descriptor=_desc(1), depth=3)
    out1 = asst.decide(inv, inv.context)
    out2 = asst.decide(inv, inv.context)
    assert out1 == out2


# --------------------------------------------------------------------------- #
# Security: exfiltrates_args + air-gapped + name + Protocol
# --------------------------------------------------------------------------- #


def test_exfiltrates_args_false_air_gapped_safe() -> None:
    assert DelegationAwareAssistant().exfiltrates_args is False


def test_name_attribute() -> None:
    assert DelegationAwareAssistant().name == "delegation-aware"


def test_satisfies_assistant_protocol() -> None:
    from custos.assistants.base import Assistant

    asst = DelegationAwareAssistant()
    assert isinstance(asst, Assistant)


# --------------------------------------------------------------------------- #
# DepthThreshold: typed wrapper + mapping authoring shape
# --------------------------------------------------------------------------- #


def test_depth_threshold_from_mapping_valid() -> None:
    dt = DepthThreshold.from_mapping({"min_depth": 5, "decision": "deny"})
    assert dt.min_depth == 5
    assert dt.decision == Decision.DENY


def test_depth_threshold_from_mapping_invalid_min_depth() -> None:
    import pytest

    with pytest.raises(ValueError, match="min_depth"):
        DepthThreshold.from_mapping({"min_depth": -1, "decision": "deny"})


def test_depth_threshold_from_mapping_non_string_decision() -> None:
    import pytest

    with pytest.raises(ValueError, match="decision"):
        DepthThreshold.from_mapping({"min_depth": 0, "decision": 5})
