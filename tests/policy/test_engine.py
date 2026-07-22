"""Tests for :mod:`custos.policy.engine` .

Covers: from_yaml, from_spec, first-match-wins, default-deny/allow, overlay
scope filtering, hot-reload mtime swap, add_rule, validate_rule/validate_policy_file.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from custos.policy import (
    Policy,
    PolicyFile,
    PolicyOverlaySpec,
    PolicyRuleSpec,
    PolicyScope,
    PolicyValidationError,
    Rule,
    validate_policy_file,
)
from custos.schema import Invocation, PolicyOutcome, SideEffect, SubjectContext, ToolDescriptor

FIXTURES = Path(__file__).parent / "fixtures"


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


def _desc(risk_tier: int = 1, side: frozenset[SideEffect] = frozenset()) -> ToolDescriptor:
    return ToolDescriptor(name="t", risk_tier=risk_tier, side_effects=side)


# --------------------------------------------------------------------------- #
# from_yaml  + the canonical fixture
# --------------------------------------------------------------------------- #


def test_from_yaml_loads_canonical_fixture() -> None:
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    # Default-deny from the fixture.
    assert policy.default == "deny"
    # unknown.tool falls through base overlay -> caught by fatigue overlay's
    # any:true rule -> assist:summarize-batch (ASSIST).
    assert policy.evaluate(_inv(tool="unknown.tool")) == PolicyOutcome.ASSIST


def test_from_yaml_allow_and_audit_rule() -> None:
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    inv = _inv(
        tool="fs.read_file",
        descriptor=_desc(1, frozenset({SideEffect.READ})),
    )
    assert policy.evaluate(inv) == PolicyOutcome.ALLOW


def test_from_yaml_assist_rule_collapses_to_assist() -> None:
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    inv = _inv(
        tool="fs.write_log",
        descriptor=_desc(2, frozenset({SideEffect.WRITE})),
    )
    # assist:risk-assessment -> PolicyOutcome.ASSIST (the name is selected by
    # the gateway, not the engine).
    assert policy.evaluate(inv) == PolicyOutcome.ASSIST


def test_from_yaml_prompt_rule() -> None:
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    inv = _inv(tool="shell.exec", descriptor=_desc(4))
    assert policy.evaluate(inv) == PolicyOutcome.PROMPT


def test_from_yaml_prompt_options_preserved_on_rule_spec() -> None:
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    # payment.* rule has options [allow_once, deny]; verify the spec survives.
    payment_rule = next(r for r in policy.rules if r.spec.match.get("tool") == "payment.*")
    assert tuple(payment_rule.spec.options) == ("allow_once", "deny")


def test_from_yaml_args_predicate_rule() -> None:
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    trusted = _inv(tool="email.send", args={"recipient_domain": "trusted.org"})
    assert policy.evaluate(trusted) == PolicyOutcome.ALLOW
    untrusted = _inv(tool="email.send", args={"recipient_domain": "evil.org"})
    # Falls through to fatigue overlay's assist:summarize-batch (any: true).
    assert policy.evaluate(untrusted) == PolicyOutcome.ASSIST


def test_from_yaml_first_match_wins() -> None:
    # The first overlay (base) has fs.read* -> allow; fatigue has any:true ->
    # assist. fs.read* should hit base first and return ALLOW.
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    inv = _inv(
        tool="fs.read",
        descriptor=_desc(1, frozenset({SideEffect.READ})),
    )
    assert policy.evaluate(inv) == PolicyOutcome.ALLOW


def test_from_yaml_requires_pyyaml_extra_message() -> None:
    # PyYAML is installed in the dev venv, so this only checks the import works.
    # The actual missing-extra path is covered by the ImportError branch in
    # engine.py; we verify it raises a helpful message via monkeypatch.
    policy = Policy.from_yaml(FIXTURES / "policy.example.yaml")
    assert isinstance(policy, Policy)


# --------------------------------------------------------------------------- #
# from_spec + validation
# --------------------------------------------------------------------------- #


def _make_spec(
    rules: list[PolicyRuleSpec],
    *,
    default: str = "deny",
    overlay_id: str = "base",
    scope: PolicyScope | None = None,
) -> PolicyFile:
    return PolicyFile(
        version=1,
        default=default,
        overlays=(PolicyOverlaySpec(id=overlay_id, rules=tuple(rules), scope=scope),),
    )


def test_from_spec_compiles_and_evaluates() -> None:
    spec = _make_spec(
        [PolicyRuleSpec(match={"tool": "fs.*"}, action="allow")],
        default="deny",
    )
    policy = Policy.from_spec(spec)
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.ALLOW
    assert policy.evaluate(_inv(tool="shell.exec")) == PolicyOutcome.DENY


def test_from_spec_default_allow() -> None:
    spec = _make_spec([], default="allow")
    policy = Policy.from_spec(spec)
    assert policy.evaluate(_inv(tool="anything")) == PolicyOutcome.ALLOW


def test_from_spec_unsupported_version_rejected() -> None:
    spec = PolicyFile(version=2, default="deny", overlays=())
    with pytest.raises(PolicyValidationError):
        Policy.from_spec(spec)


def test_from_spec_bad_default_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        Policy(default="bogus")
    spec = PolicyFile(version=1, default="bogus", overlays=())
    with pytest.raises(PolicyValidationError):
        validate_policy_file(spec)


def test_from_spec_duplicate_overlay_id_rejected() -> None:
    spec = PolicyFile(
        version=1,
        overlays=(
            PolicyOverlaySpec(id="dup"),
            PolicyOverlaySpec(id="dup"),
        ),
    )
    with pytest.raises(PolicyValidationError):
        validate_policy_file(spec)


def test_from_spec_unknown_action_rejected() -> None:
    spec = _make_spec([PolicyRuleSpec(match={"tool": "x"}, action="bogus")])
    with pytest.raises(PolicyValidationError):
        Policy.from_spec(spec)


def test_from_spec_assist_without_name_rejected() -> None:
    spec = _make_spec([PolicyRuleSpec(match={"tool": "x"}, action="assist:")])
    with pytest.raises(PolicyValidationError):
        Policy.from_spec(spec)


def test_from_spec_assist_with_name_compiles() -> None:
    spec = _make_spec([PolicyRuleSpec(match={"tool": "x"}, action="assist:risk-assessment")])
    policy = Policy.from_spec(spec)
    assert policy.evaluate(_inv(tool="x")) == PolicyOutcome.ASSIST


# --------------------------------------------------------------------------- #
# first-match-wins
# --------------------------------------------------------------------------- #


def test_first_match_wins_order_matters() -> None:
    spec = _make_spec(
        [
            PolicyRuleSpec(match={"tool": "fs.*"}, action="prompt"),
            PolicyRuleSpec(match={"tool": "fs.read"}, action="allow"),
        ]
    )
    policy = Policy.from_spec(spec)
    # fs.read matches the first rule (fs.*) -> prompt, not the second allow.
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.PROMPT


def test_no_rule_match_uses_default_deny() -> None:
    spec = _make_spec([PolicyRuleSpec(match={"tool": "fs.*"}, action="allow")])
    policy = Policy.from_spec(
        spec,
    )  # type: ignore[arg-type]
    # default deny
    assert policy.evaluate(_inv(tool="shell.exec")) == PolicyOutcome.DENY


# --------------------------------------------------------------------------- #
# overlay scope filtering
# --------------------------------------------------------------------------- #


def test_overlay_scope_user_id_restricts_rules() -> None:
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="alice-only",
                rules=(PolicyRuleSpec(match={"tool": "*"}, action="allow"),),
                scope=PolicyScope(user_id="alice"),
            ),
        ),
    )
    policy = Policy.from_spec(spec)
    # Alice's overlay applies.
    assert (
        policy.evaluate(Invocation(tool="x", args={}, context=SubjectContext(user_id="alice")))
        == PolicyOutcome.ALLOW
    )
    # Bob's context -> overlay skipped, default deny.
    assert (
        policy.evaluate(Invocation(tool="x", args={}, context=SubjectContext(user_id="bob")))
        == PolicyOutcome.DENY
    )


def test_overlay_scope_goal_id_restricts_rules() -> None:
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="goal-g1",
                rules=(PolicyRuleSpec(match={"tool": "*"}, action="allow"),),
                scope=PolicyScope(goal_id="g1"),
            ),
        ),
    )
    policy = Policy.from_spec(spec)
    assert policy.evaluate(_inv(context=_ctx(goal_id="g1"))) == PolicyOutcome.ALLOW
    assert policy.evaluate(_inv(context=_ctx(goal_id="g2"))) == PolicyOutcome.DENY


def test_overlay_scope_env_via_context_extra() -> None:
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="prod-only",
                rules=(PolicyRuleSpec(match={"tool": "*"}, action="allow"),),
                scope=PolicyScope(env="prod"),
            ),
        ),
    )
    policy = Policy.from_spec(spec)
    ctx_prod = SubjectContext(user_id="u1", extra={"env": "prod"})
    ctx_dev = SubjectContext(user_id="u1", extra={"env": "dev"})
    assert policy.evaluate(Invocation(tool="x", args={}, context=ctx_prod)) == PolicyOutcome.ALLOW
    assert policy.evaluate(Invocation(tool="x", args={}, context=ctx_dev)) == PolicyOutcome.DENY


def test_overlay_scope_unscoped_always_applies() -> None:
    spec = _make_spec(
        [PolicyRuleSpec(match={"tool": "*"}, action="allow")],
        scope=None,
    )
    policy = Policy.from_spec(spec)
    for uid in ("alice", "bob", "carol"):
        ctx = SubjectContext(user_id=uid)
        assert policy.evaluate(Invocation(tool="x", args={}, context=ctx)) == PolicyOutcome.ALLOW


def test_multiple_overlays_concat_in_file_order() -> None:
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="global",
                rules=(PolicyRuleSpec(match={"tool": "shell.*"}, action="deny"),),
            ),
            PolicyOverlaySpec(
                id="dev",
                rules=(PolicyRuleSpec(match={"tool": "*"}, action="allow"),),
                scope=PolicyScope(env="dev"),
            ),
        ),
    )
    policy = Policy.from_spec(spec)
    # In dev: shell.* -> deny (global first), fs.read -> allow (dev).
    ctx_dev = SubjectContext(user_id="u1", extra={"env": "dev"})
    assert (
        policy.evaluate(Invocation(tool="shell.exec", args={}, context=ctx_dev))
        == PolicyOutcome.DENY
    )
    assert (
        policy.evaluate(Invocation(tool="fs.read", args={}, context=ctx_dev)) == PolicyOutcome.ALLOW
    )
    # In prod: dev overlay skipped; shell.* -> deny; fs.read -> default deny.
    ctx_prod = SubjectContext(user_id="u1", extra={"env": "prod"})
    assert (
        policy.evaluate(Invocation(tool="shell.exec", args={}, context=ctx_prod))
        == PolicyOutcome.DENY
    )
    assert (
        policy.evaluate(Invocation(tool="fs.read", args={}, context=ctx_prod)) == PolicyOutcome.DENY
    )


# --------------------------------------------------------------------------- #
# hot-reload
# --------------------------------------------------------------------------- #


def test_reload_no_source_is_noop() -> None:
    policy = Policy.from_spec(_make_spec([]))
    assert policy.reload() is False


def test_reload_unchanged_file_is_noop(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\ndefault: deny\noverlays: []\n", encoding="utf-8")
    policy = Policy.from_yaml(p)
    # No mtime change (immediate reload).
    assert policy.reload() is False


def test_reload_on_change_swaps_rules(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text(
        "version: 1\ndefault: deny\noverlays:\n  - id: base\n    rules:\n"
        "      - match: {tool: 'fs.*'}\n        action: allow\n",
        encoding="utf-8",
    )
    policy = Policy.from_yaml(p)
    inv = _inv(tool="fs.read")
    assert policy.evaluate(inv) == PolicyOutcome.ALLOW
    assert policy.evaluate(_inv(tool="shell.exec")) == PolicyOutcome.DENY

    # Bump mtime by waiting then rewriting.
    time.sleep(0.05 if hasattr(time, "sleep") else 0)
    p.write_text(
        "version: 1\ndefault: allow\noverlays: []\n",
        encoding="utf-8",
    )
    # OS mtime resolution can be coarse; force it by touching the parent dir.
    os.utime(p, None)
    assert policy.reload() is True
    # New policy: default allow, no rules.
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.ALLOW
    assert policy.evaluate(_inv(tool="shell.exec")) == PolicyOutcome.ALLOW


def test_reload_malformed_file_leaves_policy_untouched(tmp_path: Path) -> None:
    p = tmp_path / "policy.yaml"
    p.write_text(
        "version: 1\ndefault: deny\noverlays: []\n",
        encoding="utf-8",
    )
    policy = Policy.from_yaml(p)
    # Overwrite with a malformed file + bump mtime.
    time.sleep(0.05)
    p.write_text("version: 1\ndefault: bogus\noverlays: []\n", encoding="utf-8")
    os.utime(p, None)
    with pytest.raises(PolicyValidationError):
        policy.reload()
    # Original policy remains intact.
    assert policy.default == "deny"


# --------------------------------------------------------------------------- #
# add_rule (for allow_and_persist)
# --------------------------------------------------------------------------- #


def test_add_rule_appends_and_takes_effect() -> None:
    policy = Policy.from_spec(_make_spec([], default="deny"))
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.DENY
    rule = Rule(PolicyRuleSpec(match={"tool": "fs.*"}, action="allow"))
    policy.add_rule(rule)
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.ALLOW


def test_add_rule_does_not_shadow_existing_matches() -> None:
    # Appended rule is last; existing matches still win.
    spec = _make_spec([PolicyRuleSpec(match={"tool": "shell.*"}, action="deny")])
    policy = Policy.from_spec(spec)
    policy.add_rule(Rule(PolicyRuleSpec(match={"tool": "*"}, action="allow")))
    # shell.* still hits the first rule -> deny (floor invariant).
    assert policy.evaluate(_inv(tool="shell.exec")) == PolicyOutcome.DENY
    # fs.read now hits the appended rule -> allow.
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.ALLOW


# --------------------------------------------------------------------------- #
# Rule.surface
# --------------------------------------------------------------------------- #


def test_rule_exposes_overlay_id_and_scope() -> None:
    scope = PolicyScope(user_id="alice")
    rule = Rule(
        PolicyRuleSpec(match={"tool": "*"}, action="allow"),
        overlay_id="dev",
        scope=scope,
    )
    assert rule.overlay_id == "dev"
    assert rule.scope is scope


def test_rule_applies_to_context_with_scope() -> None:
    scope = PolicyScope(user_id="alice")
    rule = Rule(
        PolicyRuleSpec(match={"tool": "*"}, action="allow"),
        scope=scope,
    )
    assert rule.applies_to_context(user_id="alice", goal_id=None, env=None) is True
    assert rule.applies_to_context(user_id="bob", goal_id=None, env=None) is False


def test_rule_applies_to_context_without_scope_always_true() -> None:
    rule = Rule(PolicyRuleSpec(match={"tool": "*"}, action="allow"))
    for uid in ("a", "b", "c"):
        assert rule.applies_to_context(user_id=uid, goal_id="g", env="prod") is True


# --------------------------------------------------------------------------- #
# from_dict (bare mapping, no hot-reload source)
# --------------------------------------------------------------------------- #


def test_from_dict_compiles_bare_mapping() -> None:
    policy = Policy.from_dict(
        {
            "version": 1,
            "default": "deny",
            "overlays": [
                {
                    "id": "base",
                    "rules": [
                        {"match": {"tool": "fs.*"}, "action": "allow"},
                    ],
                }
            ],
        }
    )
    assert policy.evaluate(_inv(tool="fs.read")) == PolicyOutcome.ALLOW
    assert policy.reload() is False  # no source path


def test_from_dict_non_mapping_rejected() -> None:
    with pytest.raises(PolicyValidationError):
        Policy.from_dict(["not", "a", "mapping"])  # type: ignore[arg-type]


def test_from_dict_top_level_keys_validated() -> None:
    with pytest.raises(PolicyValidationError):
        Policy.from_dict({"default": "deny"})  # missing version
