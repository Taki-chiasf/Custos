"""Tests for :mod:`custos.policy.match` - the pure match predicate .

Every criterion is exercised individually and in combination. All tests are
deterministic  - no I/O, no time, no randomness.
"""

from __future__ import annotations

import pytest

from custos.policy.match import MatchSpec
from custos.policy.schema import PolicyValidationError
from custos.schema import Invocation, SideEffect, SubjectContext, ToolDescriptor


def _ctx(**kwargs: object) -> SubjectContext:
    return SubjectContext(user_id="u1", **kwargs)  # type: ignore[arg-type]


def _inv(
    tool: str = "fs.read",
    *,
    args: dict[str, object] | None = None,
    descriptor: ToolDescriptor | None = None,
    context: SubjectContext | None = None,
) -> Invocation:
    return Invocation(
        tool=tool,
        args=args or {},
        context=context or _ctx(),
        descriptor=descriptor,
    )


# --------------------------------------------------------------------------- #
# tool glob
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("glob", "tool", "expect"),
    [
        ("fs.read*", "fs.read", True),
        ("fs.read*", "fs.read_file", True),
        ("fs.read*", "fs.write", False),
        ("shell.*", "shell.exec", True),
        ("shell.*", "shell", False),  # '*' requires at least the dot
        ("email.send", "email.send", True),
        ("email.send", "email.sendBulk", False),
    ],
)
def test_tool_glob(glob: str, tool: str, expect: bool) -> None:
    m = MatchSpec.from_mapping({"tool": glob})
    assert m.matches(_inv(tool=tool)) is expect


def test_tool_glob_is_case_sensitive() -> None:
    m = MatchSpec.from_mapping({"tool": "FS.Read"})
    assert m.matches(_inv(tool="fs.read")) is False


# --------------------------------------------------------------------------- #
# risk_tier
# --------------------------------------------------------------------------- #


def _desc(risk_tier: int, side: frozenset[SideEffect] = frozenset()) -> ToolDescriptor:
    return ToolDescriptor(name="t", risk_tier=risk_tier, side_effects=side)


def test_risk_tier_exact() -> None:
    m = MatchSpec.from_mapping({"risk_tier": 3})
    assert m.matches(_inv(descriptor=_desc(3))) is True
    assert m.matches(_inv(descriptor=_desc(4))) is False


def test_risk_tier_range() -> None:
    m = MatchSpec.from_mapping({"risk_tier": [4, 5]})
    assert m.matches(_inv(descriptor=_desc(4))) is True
    assert m.matches(_inv(descriptor=_desc(5))) is True
    assert m.matches(_inv(descriptor=_desc(3))) is False
    assert m.matches(_inv(descriptor=_desc(1))) is False


def test_risk_tier_missing_descriptor_matches_zero_tier() -> None:
    # No descriptor -> tier 0; a rule requiring tier >=1 should not match.
    m = MatchSpec.from_mapping({"risk_tier": 1})
    assert m.matches(_inv(descriptor=None)) is False


def test_risk_tier_range_min_max_swapped_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        from custos.policy.schema import PolicyRuleSpec, validate_rule

        validate_rule(PolicyRuleSpec(match={"risk_tier": [5, 4]}, action="allow"))


# --------------------------------------------------------------------------- #
# side_effects (intersect / any-of - D6)
# --------------------------------------------------------------------------- #


def test_side_effects_intersect_any_of() -> None:
    m = MatchSpec.from_mapping({"side_effects": ["read"]})
    assert m.matches(_inv(descriptor=_desc(1, frozenset({SideEffect.READ})))) is True
    assert (
        m.matches(_inv(descriptor=_desc(1, frozenset({SideEffect.READ, SideEffect.NETWORK}))))
        is True
    )
    assert m.matches(_inv(descriptor=_desc(1, frozenset({SideEffect.WRITE})))) is False


def test_side_effects_multiple_any_match() -> None:
    # Rule {read, network} matches iff tool's side_effects intersect it.
    m = MatchSpec.from_mapping({"side_effects": ["read", "network"]})
    assert m.matches(_inv(descriptor=_desc(1, frozenset({SideEffect.WRITE})))) is False
    assert m.matches(_inv(descriptor=_desc(1, frozenset({SideEffect.READ})))) is True
    assert m.matches(_inv(descriptor=_desc(1, frozenset({SideEffect.NETWORK})))) is True


def test_side_effects_unknown_value_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        MatchSpec.from_mapping({"side_effects": ["bogus"]})


def test_side_effects_no_descriptor_no_match() -> None:
    m = MatchSpec.from_mapping({"side_effects": ["read"]})
    assert m.matches(_inv(descriptor=None)) is False


# --------------------------------------------------------------------------- #
# args predicates
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("pred", "value", "expect"),
    [
        ("trusted.org", "trusted.org", True),
        ("trusted.org", "other.org", False),
        ({"==": 42}, 42, True),
        ({"==": 42}, 43, False),
        ({"!=": 42}, 43, True),
        ({"!=": 42}, 42, False),
        ({">": 10}, 11, True),
        ({"<": 10}, 9, True),
        ({">=": 10}, 10, True),
        ({"<=": 10}, 10, True),
        ({"in": ["trusted.org", "safe.org"]}, "trusted.org", True),
        ({"in": ["trusted.org"]}, "evil.org", False),
        ({"not_in": ["evil.org"]}, "trusted.org", True),
        ({"contains": "user"}, "user_id", True),
        ({"contains": "missing"}, "user_id", False),
        ({"not_contains": "pw"}, "user_id", True),
        ({"matches": r"^fs\."}, "fs.read", True),
        ({"matches": r"^fs\."}, "shell.exec", False),
    ],
)
def test_arg_operators(pred: object, value: object, expect: bool) -> None:
    m = MatchSpec.from_mapping({"args": {"x": pred}})
    assert m.matches(_inv(args={"x": value})) is expect


def test_arg_missing_key_does_not_match() -> None:
    m = MatchSpec.from_mapping({"args": {"x": 1}})
    assert m.matches(_inv(args={})) is False


def test_arg_operator_type_mismatch_is_false_not_error() -> None:
    # Comparing incompatible types returns False (no TypeError leakage).
    m = MatchSpec.from_mapping({"args": {"x": {">": 10}}})
    assert m.matches(_inv(args={"x": "not-a-number"})) is False


def test_arg_unknown_operator_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        MatchSpec.from_mapping({"args": {"x": {"bogus": 1}}})


def test_arg_multi_key_predicate_dict_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        MatchSpec.from_mapping({"args": {"x": {"==": 1, "!=": 2}}})


def test_matches_regex_on_non_string_is_false() -> None:
    m = MatchSpec.from_mapping({"args": {"x": {"matches": r"\d+"}}})
    assert m.matches(_inv(args={"x": 123})) is False  # non-string arg


# --------------------------------------------------------------------------- #
# goal_id + delegation_depth
# --------------------------------------------------------------------------- #


def test_goal_id_exact() -> None:
    m = MatchSpec.from_mapping({"goal_id": "g1"})
    assert m.matches(_inv(context=_ctx(goal_id="g1"))) is True
    assert m.matches(_inv(context=_ctx(goal_id="g2"))) is False
    assert m.matches(_inv(context=_ctx(goal_id=None))) is False


def test_delegation_depth_exact() -> None:
    m = MatchSpec.from_mapping({"delegation_depth": 2})
    assert m.matches(_inv(context=_ctx(delegation_chain=("a", "b")))) is True
    assert m.matches(_inv(context=_ctx(delegation_chain=("a",)))) is False


def test_delegation_depth_negative_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        MatchSpec.from_mapping({"delegation_depth": -1})


# --------------------------------------------------------------------------- #
# any: true wildcard
# --------------------------------------------------------------------------- #


def test_any_true_matches_everything() -> None:
    m = MatchSpec.from_mapping({"any": True})
    assert m.matches(_inv(tool="anything", descriptor=_desc(5))) is True


def test_any_true_ignores_other_keys() -> None:
    # When any: true, other keys are ignored (the wildcard short-circuits).
    m = MatchSpec.from_mapping({"any": True, "tool": "never.*"})
    assert m.matches(_inv(tool="matches-nothing")) is True


def test_any_false_is_not_wildcard() -> None:
    m = MatchSpec.from_mapping({"any": False})
    # No criteria -> matches everything (empty predicate = True).
    assert m.matches(_inv()) is True


def test_any_non_bool_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        MatchSpec.from_mapping({"any": "yes"})


# --------------------------------------------------------------------------- #
# AND semantics + absent criteria
# --------------------------------------------------------------------------- #


def test_all_criteria_are_anded() -> None:
    m = MatchSpec.from_mapping(
        {
            "tool": "fs.*",
            "side_effects": ["write"],
            "args": {"force": True},
            "goal_id": "g1",
        }
    )
    # All match.
    assert (
        m.matches(
            _inv(
                tool="fs.write",
                args={"force": True},
                descriptor=_desc(2, frozenset({SideEffect.WRITE})),
                context=_ctx(goal_id="g1"),
            )
        )
        is True
    )
    # One fails (tool).
    assert (
        m.matches(
            _inv(
                tool="shell.exec",
                args={"force": True},
                descriptor=_desc(2, frozenset({SideEffect.WRITE})),
                context=_ctx(goal_id="g1"),
            )
        )
        is False
    )
    # One fails (args).
    assert (
        m.matches(
            _inv(
                tool="fs.write",
                args={"force": False},
                descriptor=_desc(2, frozenset({SideEffect.WRITE})),
                context=_ctx(goal_id="g1"),
            )
        )
        is False
    )


def test_empty_match_matches_everything() -> None:
    m = MatchSpec.from_mapping({})
    assert m.matches(_inv()) is True
    assert m.matches(_inv(tool="anything", descriptor=_desc(5))) is True


def test_unknown_match_key_rejected_by_validate_rule() -> None:
    from custos.policy.schema import PolicyRuleSpec, validate_rule

    with pytest.raises(PolicyValidationError):
        validate_rule(PolicyRuleSpec(match={"bogus": 1}, action="allow"))


# --------------------------------------------------------------------------- #
#  determinism
# --------------------------------------------------------------------------- #


def test_repeated_evaluation_is_deterministic() -> None:
    m = MatchSpec.from_mapping({"tool": "fs.*", "side_effects": ["read"]})
    inv = _inv(tool="fs.read", descriptor=_desc(1, frozenset({SideEffect.READ})))
    results = [m.matches(inv) for _ in range(100)]
    assert all(r is True for r in results)
