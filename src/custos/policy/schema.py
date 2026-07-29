"""Parsed policy-file representation .

Status: . Validation helpers enforce the policy-file shape before the
engine compiles it  and again when an assistant emits an
``allow_and_persist`` rule (- assistant output is untrusted).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "PolicyFile",
    "PolicyRuleSpec",
    "PolicyOverlaySpec",
    "PolicyScope",
    "PolicyValidationError",
    "validate_rule",
    "validate_policy_file",
]

# Recognized policy actions . ``assist:<name>`` is matched by head.
_ALLOWED_ACTIONS: frozenset[str] = frozenset(
    {"allow", "deny", "prompt", "allow_and_audit", "deny_and_alert", "inspect"}
)
_ASSIST_PREFIX = "assist:"
_INSPECT_PREFIX = "inspect:"


class PolicyValidationError(ValueError):
    """Raised when a policy file or rule fails validation ."""


@dataclass(frozen=True)
class PolicyScope:
    """Optional overlay scope . All non-None fields must match the
    :class:`~custos.schema.SubjectContext` for the overlay to apply.

    Attributes:
        user_id: restricts the overlay to a single principal.
        goal_id: restricts the overlay to a single goal scope (US-10).
        env: free-form environment tag (e.g. ``prod``, ``dev``).
    """

    user_id: str | None = None
    goal_id: str | None = None
    env: str | None = None

    def matches(self, *, user_id: str | None, goal_id: str | None, env: str | None) -> bool:
        if self.user_id is not None and self.user_id != user_id:
            return False
        if self.goal_id is not None and self.goal_id != goal_id:
            return False
        return not (self.env is not None and self.env != env)


@dataclass(frozen=True)
class PolicyRuleSpec:
    """One entry in a policy overlay .

    Attributes:
        match: mapping of match criteria (see :class:`~custos.policy.match.MatchSpec`).
        action: one of ``allow``, ``deny``, ``prompt``, ``allow_and_audit``,
            ``deny_and_alert``, or ``assist:<name>`` .
        options: for ``prompt`` actions, the responder option set
            (subset of Decision values). Defaults to the responder default.
        batching: optional fatigue-layer config (; preserved verbatim).
        quorum: optional  quorum config . When set on a
            ``prompt`` rule, instructs the responder to require ``quorum``
            distinct approvers from disjoint ``approver_roles`` before
            resolving to ``met``; otherwise the gateway surfaces ``DEFER``
            (pending) until met or ``DENY`` on disagreement/timeout. NOT a
            MatchSpec predicate (does not filter invocations) - a rule-side
            responder hint, analogous to ``batching``. The  Q10
            resolution calls these "generic policy match criterion" in the
            sense any rule may declare them, not ``risk_tier 5``-only; the
            structural placement is on the rule, not in MatchSpec.
        approver_roles: roles whose approvers count toward ``quorum`` .
        approver_allowlist: explicit allowlist of approver ids (
            portion; complements the Slack responder's per-responder allowlist
            by letting the policy express it at the rule level).
    """

    match: Mapping[str, Any]
    action: str
    options: Sequence[str] = ()
    batching: Mapping[str, Any] | None = None
    quorum: int | None = None
    approver_roles: Sequence[str] = ()
    approver_allowlist: Sequence[str] = ()
    allow_external_data: bool = False


@dataclass(frozen=True)
class PolicyOverlaySpec:
    """An overlay: an ordered list of rules with an optional scope ."""

    id: str
    rules: Sequence[PolicyRuleSpec] = field(default_factory=tuple)
    scope: PolicyScope | None = None


@dataclass(frozen=True)
class PolicyFile:
    """Top-level parsed policy file .

    Attributes:
        version: schema version (currently 1).
        default: default action when no rule matches . ``deny`` or ``allow``.
        overlays: ordered list of overlays; applied in order .
    """

    version: int
    default: str = "deny"
    overlays: Sequence[PolicyOverlaySpec] = field(default_factory=tuple)


def validate_rule(rule: PolicyRuleSpec) -> None:
    """Validate a rule's action and match shape .

    Raises :class:`PolicyValidationError` on any malformed field.
    """
    action = rule.action
    if action in _ALLOWED_ACTIONS:
        pass
    elif action.startswith(_ASSIST_PREFIX):
        name = action[len(_ASSIST_PREFIX) :]
        if not name:
            raise PolicyValidationError(f"assist action requires a name, got {action!r}")
    elif action == "inspect:":
        pass
    elif action.startswith(_INSPECT_PREFIX):
        name = action[len(_INSPECT_PREFIX) :]
        if not name:
            raise PolicyValidationError(f"inspect action requires a name, got {action!r}")
    else:
        raise PolicyValidationError(
            f"unknown policy action {action!r}; allowed: "
            f"{sorted(_ALLOWED_ACTIONS)} or 'assist:<name>' or 'inspect:<name>'"
        )

    match = rule.match
    if not isinstance(match, Mapping):
        raise PolicyValidationError(f"rule match must be a mapping, got {type(match).__name__}")

    # Match criteria are validated by MatchSpec at compile time; here we only
    # reject keys that are obviously typos to catch authoring errors early.
    known_keys = frozenset(
        {
            "tool",
            "risk_tier",
            "side_effects",
            "args",
            "goal_id",
            "delegation_depth",
            "any",
        }
    )
    unknown = set(match) - known_keys
    if unknown:
        raise PolicyValidationError(
            f"unknown match criteria {sorted(unknown)!r}; known: {sorted(known_keys)!r}"
        )

    if "tool" in match and not isinstance(match["tool"], str):
        raise PolicyValidationError("match.tool must be a string glob")

    if "risk_tier" in match:
        rt = match["risk_tier"]
        if isinstance(rt, int):
            if not 1 <= rt <= 5:
                raise PolicyValidationError(f"risk_tier out of 1..5: {rt}")
        elif isinstance(rt, Sequence) and not isinstance(rt, (str, bytes)):
            rt = list(rt)
            if len(rt) != 2 or not all(isinstance(x, int) for x in rt):
                raise PolicyValidationError(f"risk_tier range must be [min, max] ints, got {rt!r}")
            if not (1 <= rt[0] <= 5 and 1 <= rt[1] <= 5):
                raise PolicyValidationError(f"risk_tier range out of 1..5: {rt}")
            if rt[0] > rt[1]:
                raise PolicyValidationError(f"risk_tier range min > max: {rt}")
        else:
            raise PolicyValidationError(f"risk_tier must be int or [min, max], got {rt!r}")

    if "side_effects" in match:
        se = match["side_effects"]
        if not isinstance(se, Sequence) or isinstance(se, (str, bytes)):
            raise PolicyValidationError(f"side_effects must be a list, got {type(se).__name__}")

    if "any" in match and not isinstance(match["any"], bool):
        raise PolicyValidationError("match.any must be a bool")

    if "goal_id" in match and not isinstance(match["goal_id"], str):
        raise PolicyValidationError("match.goal_id must be a string")

    if "delegation_depth" in match:
        dd = match["delegation_depth"]
        if not isinstance(dd, int) or dd < 0:
            raise PolicyValidationError(f"delegation_depth must be a non-negative int, got {dd!r}")

    #   quorum / approver_roles / approver_allowlist are
    # rule-side responder hints, NOT MatchSpec predicates. Authors writing
    # them inside the ``match`` mapping get the existing "unknown match
    # criteria" typo-catch above (the known_keys set above does NOT include
    # them); a further redundant check here is therefore unnecessary.

    # Validate the rule-level quorum fields on the spec itself.
    if rule.quorum is not None:
        if not isinstance(rule.quorum, int) or rule.quorum < 1:
            raise PolicyValidationError(f"quorum must be a positive int (>=1), got {rule.quorum!r}")
        if not rule.approver_roles:
            raise PolicyValidationError(
                "quorum requires approver_roles (the roles whose distinct "
                "approvers count toward the quorum); got empty approver_roles"
            )
        if len(rule.approver_roles) < rule.quorum:
            raise PolicyValidationError(
                f"approver_roles ({list(rule.approver_roles)!r}) has fewer "
                f"distinct roles than quorum={rule.quorum}; quorum cannot "
                f"be satisfied with fewer roles than approvals"
            )
    else:
        if rule.approver_roles:
            raise PolicyValidationError(
                "approver_roles configured without a quorum; either set "
                "quorum>=1 or drop approver_roles"
            )

    if rule.approver_allowlist and not all(
        isinstance(a, str) and a for a in rule.approver_allowlist
    ):
        raise PolicyValidationError(
            f"approver_allowlist must be a list of non-empty strings, "
            f"got {list(rule.approver_allowlist)!r}"
        )

    if not isinstance(rule.allow_external_data, bool):
        raise PolicyValidationError(
            f"allow_external_data must be a bool, got {type(rule.allow_external_data).__name__}"
        )


def validate_policy_file(spec: PolicyFile) -> None:
    """Validate a parsed :class:`PolicyFile` ."""
    if spec.version != 1:
        raise PolicyValidationError(f"unsupported policy version: {spec.version}")
    if spec.default not in ("deny", "allow"):
        raise PolicyValidationError(f"default must be 'deny' or 'allow', got {spec.default!r}")
    seen_ids: set[str] = set()
    for overlay in spec.overlays:
        if not overlay.id:
            raise PolicyValidationError("overlay id must not be empty")
        if overlay.id in seen_ids:
            raise PolicyValidationError(f"duplicate overlay id: {overlay.id!r}")
        seen_ids.add(overlay.id)
        for rule in overlay.rules:
            validate_rule(rule)
