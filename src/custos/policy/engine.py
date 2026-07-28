"""Deterministic policy engine (..9.7).

The engine is pure and deterministic: same ``(invocation, context,
policy_version)`` yields the same :class:`~custos.schema.PolicyOutcome`. The
only allowed source of non-determinism in the decision pipeline is the
assistant  - the engine never invokes one.

Hot-reload  is mtime-based and atomic. Policy-file signature checking
 is deferred to .
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from custos.policy.match import MatchSpec
from custos.policy.schema import (
    PolicyFile,
    PolicyOverlaySpec,
    PolicyRuleSpec,
    PolicyScope,
    PolicyValidationError,
    validate_policy_file,
    validate_rule,
)
from custos.schema import Invocation, PolicyOutcome

if TYPE_CHECKING:
    pass

__all__ = ["Policy", "Rule"]


class Rule:
    """A single compiled, first-match-wins rule ."""

    __slots__ = ("spec", "_match", "_overlay_id", "_scope")

    def __init__(
        self,
        spec: PolicyRuleSpec,
        *,
        overlay_id: str | None = None,
        scope: PolicyScope | None = None,
    ) -> None:
        # Validate + compile eagerly so construction-time errors surface at
        # load rather than at first evaluation.
        validate_rule(spec)
        self.spec = spec
        self._match = MatchSpec.from_mapping(spec.match)
        self._overlay_id = overlay_id
        self._scope = scope

    def matches(self, inv: Invocation) -> bool:
        """Pure predicate over (invocation, context). ."""
        return self._match.matches(inv)

    @property
    def action(self) -> str:
        return self.spec.action

    @property
    def allow_external_data(self) -> bool:
        return self.spec.allow_external_data

    @property
    def overlay_id(self) -> str | None:
        return self._overlay_id

    @property
    def scope(self) -> PolicyScope | None:
        return self._scope

    def applies_to_context(
        self, *, user_id: str | None, goal_id: str | None, env: str | None
    ) -> bool:
        """Whether this rule's overlay scope matches the given context .

        Always True for rules whose overlay has no scope.
        """
        if self._scope is None:
            return True
        return self._scope.matches(user_id=user_id, goal_id=goal_id, env=env)


class Policy:
    """Ordered, deterministic ruleset .

    Same ``(invocation, context, policy_version)`` MUST yield the same outcome
    unless an assistant intentionally adds non-determinism later in the
    pipeline. Construction validates all rules; loading from a file records the
    path for hot-reload .
    """

    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        *,
        default: str = "deny",
    ) -> None:
        self._lock = threading.RLock()
        self._rules: list[Rule] = list(rules or [])
        self._rules_ro: tuple[Rule, ...] = tuple(self._rules)
        self._persisted_rules: list[Rule] = []
        if default not in ("deny", "allow"):
            raise PolicyValidationError(f"default must be 'deny' or 'allow', got {default!r}")
        self._default = default
        self._source_path: str | None = None
        self._source_mtime: float | None = None
        self._overlays: tuple[PolicyOverlaySpec, ...] = ()

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        """Load + compile a YAML policy file .

        Requires the ``custos[yaml]`` extra (keeps PyYAML out of the
        runtime dep set). Hot-reload records the path + mtime .
        """
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - depends on env
            raise ImportError(
                "PyYAML is required for Policy.from_yaml. Install with: pip install 'custos[yaml]'"
            ) from exc

        path = Path(path)
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        return cls._from_parsed(path, data)

    @classmethod
    def from_dict(cls, data: Mapping[object, object]) -> Policy:
        """Compile a parsed policy mapping . No hot-reload source."""
        return cls._from_parsed(None, data)

    @classmethod
    def from_spec(cls, spec: PolicyFile) -> Policy:
        """Compile a parsed :class:`PolicyFile` into a runnable :class:`Policy`."""
        validate_policy_file(spec)
        rules: list[Rule] = []
        for overlay in spec.overlays:
            for r in overlay.rules:
                rules.append(Rule(r, overlay_id=overlay.id, scope=overlay.scope))
        policy = cls(rules, default=spec.default)
        policy._overlays = tuple(spec.overlays)
        return policy

    @classmethod
    def _from_parsed(cls, path: Path | None, data: Mapping[object, object]) -> Policy:
        if not isinstance(data, Mapping):
            raise PolicyValidationError(
                f"policy file must be a mapping at top level, got {type(data).__name__}"
            )
        spec = _policy_file_from_mapping(data)
        policy = cls.from_spec(spec)
        if path is not None:
            policy._source_path = str(path)
            try:
                policy._source_mtime = path.stat().st_mtime
            except OSError:
                policy._source_mtime = None
        return policy

    def evaluate(self, inv: Invocation) -> PolicyOutcome:
        """First-match-wins evaluation . Pure + deterministic ."""
        env = inv.context.extra.get("env") if inv.context.extra else None
        env_str = env if isinstance(env, str) else None
        for rule in self._rules_ro:
            if not rule.applies_to_context(
                user_id=inv.context.user_id,
                goal_id=inv.context.goal_id,
                env=env_str,
            ):
                continue
            if rule.matches(inv):
                return _action_to_outcome(rule.action)
        return _action_to_outcome(self._default)

    def matched_rule(self, inv: Invocation) -> Rule | None:
        """First-match-wins lookup returning the matched :class:`Rule` .

                Mirrors :meth:`evaluate` so callers (e.g. ``custos audit replay``,
        ) can surface *which* rule fired, not just the outcome. Returns
                ``None`` when the default action applied (no explicit rule matched).
        """
        env = inv.context.extra.get("env") if inv.context.extra else None
        env_str = env if isinstance(env, str) else None
        for rule in self._rules_ro:
            if not rule.applies_to_context(
                user_id=inv.context.user_id,
                goal_id=inv.context.goal_id,
                env=env_str,
            ):
                continue
            if rule.matches(inv):
                return rule
        return None

    def add_rule(self, rule: Rule) -> None:
        """Append a rule (used by the gateway on ``allow_and_persist``).

        The new rule is appended so it does not shadow earlier matches; the
        persisted rule should describe a *narrower* case than what the policy
        already matched to reach the assistant (otherwise it would never fire
        again). Assistant-provided rules are validated before reaching here
        (- assistant output is untrusted).
        """
        with self._lock:
            self._rules.append(rule)
            self._rules_ro = tuple(self._rules)

    def insert_rule(self, index: int, rule: Rule) -> None:
        """Insert a rule at ``index``, pushing existing rules down .

        Used by the gateway for ``allow_and_persist``: the persisted rule is
        inserted *before* the matched rule so it short-circuits future
        identical calls at the policy layer (Janus ``create_policy`` fatigue
        semantics). Rules earlier in the list are untouched, preserving the
        floor invariant  - a persisted allow never shadows an earlier
        deny.
        """
        with self._lock:
            self._rules.insert(index, rule)
            self._rules_ro = tuple(self._rules)

    def track_persisted_rule(self, rule: Rule) -> None:
        """Record a rule persisted by an assistant (``allow_and_persist``, H6).

        Tracked rules are re-appended after file rules on :meth:`reload` so
        in-session learning survives a hot-reload (addendum). Only
        tracks — does not insert into ``_rules`` (the gateway calls
        :meth:`insert_rule` or :meth:`add_rule` separately for the in-session
        short-circuit).
        """
        with self._lock:
            self._persisted_rules.append(rule)

    def reload(self) -> bool:
        """Hot-reload the policy from its source file (H6).

        Returns True if the policy was reloaded (mtime changed), False if
        unchanged. Raises :class:`PolicyValidationError` if the new file is
        malformed (the in-memory policy is left untouched on failure).

        After swapping file rules, persisted rules are re-appended at the
        end so in-session learning survives the reload (addendum, H6).
        Appending after file rules preserves the policy floor: file rules
        win first-match, and a persisted allow that lost its short-circuit
        position may re-run the assistant on next call (safe).
        """
        if self._source_path is None:
            return False
        path = Path(self._source_path)
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return False
        if self._source_mtime is not None and mtime == self._source_mtime:
            return False

        new_policy = Policy.from_yaml(path)
        # Atomic swap under lock: replace internals with freshly loaded policy,
        # then re-append persisted rules (H6).
        with self._lock:
            self._rules = new_policy._rules
            self._default = new_policy._default
            self._overlays = new_policy._overlays
            self._source_mtime = mtime
            self._rules.extend(self._persisted_rules)
            self._rules_ro = tuple(self._rules)
        return True

    def overlays(self) -> Sequence[PolicyOverlaySpec]:
        """Return the parsed overlay specs ."""
        with self._lock:
            return self._overlays

    @property
    def default(self) -> str:
        return self._default

    @property
    def rules(self) -> Sequence[Rule]:
        return self._rules_ro


def _action_to_outcome(action: str) -> PolicyOutcome:
    """Map a policy action string to a :class:`PolicyOutcome` .

    ``assist:<name>`` collapses to :attr:`PolicyOutcome.ASSIST`; the named
    assistant is selected by the gateway, not the engine.
    """
    head = action.split(":", 1)[0]
    mapping: Mapping[str, PolicyOutcome] = {
        "allow": PolicyOutcome.ALLOW,
        "allow_and_audit": PolicyOutcome.ALLOW,
        "deny": PolicyOutcome.DENY,
        "deny_and_alert": PolicyOutcome.DENY,
        "prompt": PolicyOutcome.PROMPT,
        "assist": PolicyOutcome.ASSIST,
    }
    if head not in mapping:
        raise PolicyValidationError(f"unknown policy action: {action!r}")
    return mapping[head]


def _policy_file_from_mapping(data: Mapping[object, object]) -> PolicyFile:
    """Parse a raw mapping into a :class:`PolicyFile` ."""
    version = data.get("version")
    if not isinstance(version, int):
        raise PolicyValidationError(f"policy version must be an int, got {type(version).__name__}")
    default = data.get("default", "deny")
    if not isinstance(default, str):
        raise PolicyValidationError(f"default must be a string, got {type(default).__name__}")

    overlays_raw = data.get("overlays", [])
    if not isinstance(overlays_raw, Sequence):
        raise PolicyValidationError(f"overlays must be a list, got {type(overlays_raw).__name__}")

    overlays: list[PolicyOverlaySpec] = []
    for ov in overlays_raw:
        if not isinstance(ov, Mapping):
            raise PolicyValidationError(f"overlay must be a mapping, got {type(ov).__name__}")
        ov_id = ov.get("id")
        if not isinstance(ov_id, str) or not ov_id:
            raise PolicyValidationError("overlay.id must be a non-empty string")

        scope: PolicyScope | None = None
        if "scope" in ov:
            scope_raw = ov["scope"]
            if not isinstance(scope_raw, Mapping):
                raise PolicyValidationError(
                    f"overlay scope must be a mapping, got {type(scope_raw).__name__}"
                )
            scope = PolicyScope(
                user_id=scope_raw.get("user_id"),
                goal_id=scope_raw.get("goal_id"),
                env=scope_raw.get("env"),
            )

        rules_raw = ov.get("rules", [])
        if not isinstance(rules_raw, Sequence):
            raise PolicyValidationError(
                f"overlay.rules must be a list, got {type(rules_raw).__name__}"
            )
        rules: list[PolicyRuleSpec] = []
        for r in rules_raw:
            if not isinstance(r, Mapping):
                raise PolicyValidationError(f"rule must be a mapping, got {type(r).__name__}")
            match = r.get("match", {})
            if not isinstance(match, Mapping):
                raise PolicyValidationError(
                    f"rule.match must be a mapping, got {type(match).__name__}"
                )
            action = r.get("action")
            if not isinstance(action, str):
                raise PolicyValidationError(
                    f"rule.action must be a string, got {type(action).__name__}"
                )
            options_raw = r.get("options", ())
            if not isinstance(options_raw, Sequence):
                raise PolicyValidationError(
                    f"rule.options must be a list, got {type(options_raw).__name__}"
                )
            options_typed: tuple[str, ...] = tuple(
                o if isinstance(o, str) else str(o) for o in options_raw
            )
            batching_raw = r.get("batching")
            #   quorum / approver config (rule-level, sibling of
            # ``match``/``action``). Validated by :func:`validate_rule`.
            quorum_val = r.get("quorum")
            quorum_int = (
                int(quorum_val)
                if isinstance(quorum_val, int) and not isinstance(quorum_val, bool)
                else None
            )
            roles_raw = r.get("approver_roles") or ()
            roles_typed: tuple[str, ...] = tuple(
                s if isinstance(s, str) and s else str(s) for s in roles_raw
            )
            allow_raw = r.get("approver_allowlist") or ()
            allow_typed: tuple[str, ...] = tuple(
                s if isinstance(s, str) and s else str(s) for s in allow_raw
            )
            allow_ext_raw = r.get("allow_external_data", False)
            if not isinstance(allow_ext_raw, bool):
                raise PolicyValidationError(
                    f"allow_external_data must be a bool, got {type(allow_ext_raw).__name__}"
                )
            rules.append(
                PolicyRuleSpec(
                    match=match,
                    action=action,
                    options=options_typed,
                    batching=batching_raw if isinstance(batching_raw, Mapping) else None,
                    quorum=quorum_int,
                    approver_roles=roles_typed,
                    approver_allowlist=allow_typed,
                    allow_external_data=allow_ext_raw,
                )
            )
        overlays.append(PolicyOverlaySpec(id=ov_id, rules=tuple(rules), scope=scope))

    return PolicyFile(version=version, default=default, overlays=tuple(overlays))
