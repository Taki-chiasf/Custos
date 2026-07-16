"""ABAC policy engine — clean-room reproduction of Janus's observable semantics.

Re-implemented (NOT copied) from the architecture documented in
``Janus/architecture.md`` and the observable behaviour of
``Janus/src/permissions/policy_engine.py``. Semantics mirrors Janus's
default-deny-with-permit-precedence model (see ``docs/DECISION_SEMANTICS.md``
 for the deliberate departure from Custos  deny-floor — this engine
intentionally does NOT enforce a deny-floor because parity requires matching
Janus's published numbers).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any

#  : shared operator primitives live in custos.policy.operators;
# the harness's Operator enum (now JanusOperator) imports them as the
# backing functions so the two engines reference one implementation.
from custos.policy.operators import OPERATOR_FUNCS

__all__ = ["Effect", "JanusOperator", "Condition", "Policy", "PolicySet"]


class Effect(Enum):
    PERMIT = auto()
    DENY = auto()


# NOTE: renamed from ``Operator`` to ``JanusOperator`` (dual-type-drift
# mitigation per  review). The enum mirrors Janus's Operator enum
# labels ("approve_once"/"create_policy"/"reject" decision labels are over in
# `` Janus schema``; here these are the ABAC condition operator values like
# "==", "!=", "in", "not in"). The enum's string values match the shared
# OPERATOR_FUNCS keys; note the harness's ``"not in"`` and ``"not contains"``
# space-containing variants are aliased to the production ``"not_in"`` and
# ``"not_contains"`` keys via a small lookup table below so the two engines
# share one implementation.
class JanusOperator(Enum):
    """Operators available for Janus policy conditions (aliases shared funcs)."""

    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    GREATER_EQUAL = ">="
    LESS_EQUAL = "<="
    IN = "in"
    NOT_IN = "not in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not contains"
    MATCHES = "matches"  # regex (anchored at start, like re.match)

    @classmethod
    def from_value(cls, value: str) -> JanusOperator:
        for op in cls:
            if op.value == value:
                return op
        raise ValueError(f"unknown operator: {value!r}")


# Map the harness's space-containing Janus operator values to the shared
# OPERATOR_FUNCS keys ("not in" -> "not_in", "not contains" -> "not_contains")
# so the shared implementations actually run.
_JANUS_OP_LOCATIONS: dict[JanusOperator, str] = {
    JanusOperator.EQUALS: "==",
    JanusOperator.NOT_EQUALS: "!=",
    JanusOperator.GREATER_THAN: ">",
    JanusOperator.LESS_THAN: "<",
    JanusOperator.GREATER_EQUAL: ">=",
    JanusOperator.LESS_EQUAL: "<=",
    JanusOperator.IN: "in",
    JanusOperator.NOT_IN: "not_in",
    JanusOperator.CONTAINS: "contains",
    JanusOperator.NOT_CONTAINS: "not_contains",
    JanusOperator.MATCHES: "matches",
}


_OPS: dict[JanusOperator, Callable[[Any, Any], bool]] = {
    op: OPERATOR_FUNCS[key] for op, key in _JANUS_OP_LOCATIONS.items()
}


@dataclass(frozen=True)
class Condition:
    """A single ABAC condition over a dotted-attribute path into the context dict."""

    attribute: str
    operator: JanusOperator
    value: Any

    def evaluate(self, context: Mapping[str, Any]) -> bool:
        # Walk the dotted path: "subject.type" -> context["subject"]["type"].
        current: Any = context
        for part in self.attribute.split("."):
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            else:
                return False
        try:
            return _OPS[self.operator](current, self.value)
        except (TypeError, ValueError):
            return False


@dataclass
class Policy:
    """A per-(tool, action) ABAC policy with an effect and a list of conditions."""

    id: str
    name: str
    description: str
    tool_name: str
    action: str
    conditions: list[Condition]
    effect: Effect = Effect.PERMIT

    def evaluate(self, context: Mapping[str, Any]) -> bool:
        return all(c.evaluate(context) for c in self.conditions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tool_name": self.tool_name,
            "action": self.action,
            "effect": self.effect.name,
            "conditions": [
                {"attribute": c.attribute, "operator": c.operator.value, "value": c.value}
                for c in self.conditions
            ],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            tool_name=data["tool_name"],
            action=data["action"],
            effect=Effect[data["effect"]],
            conditions=[
                Condition(
                    attribute=c["attribute"],
                    operator=JanusOperator.from_value(c["operator"]),
                    value=c["value"],
                )
                for c in data["conditions"]
            ],
        )


@dataclass
class PolicySet:
    """Ordered set of policies, evaluated Janus-style (permit-precedence).

    Reproduces the observable behaviour of
    ``Janus/src/permissions/policy_engine.py:PolicySet.evaluate``:

      1. Filter policies by (``tool_name``, ``action``).
      2. If none apply -> :attr:`Effect.DENY` (default-deny on empty set).
      3. If any applicable rule with ``Effect.PERMIT`` evaluates True ->
         :attr:`Effect.PERMIT`.
      4. Otherwise -> :attr:`Effect.DENY`.

    Note (see ``docs/DECISION_SEMANTICS.md``): explicit ``DENY``-effect rules
    carry NO precedence; they are shadowed by any permitting rule. This is the
    deliberate Janus-matching departure from Custos 's deny-floor.
    """

    policies: dict[str, Policy] = field(default_factory=dict)

    def add_policy(self, policy: Policy) -> None:
        self.policies[policy.id] = policy

    def remove_policy(self, policy_id: str) -> Policy | None:
        return self.policies.pop(policy_id, None)

    def list_policies(self) -> list[Policy]:
        return list(self.policies.values())

    def evaluate(self, context: Mapping[str, Any]) -> Effect:
        tool_name = context.get("tool_name")
        action = context.get("action")
        applicable = [
            p for p in self.policies.values() if p.tool_name == tool_name and p.action == action
        ]
        if not applicable:
            return Effect.DENY
        for policy in applicable:
            if policy.evaluate(context) and policy.effect == Effect.PERMIT:
                return Effect.PERMIT
        return Effect.DENY

    def save_to_file(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps({"policies": [p.to_dict() for p in self.policies.values()]}, indent=2)
        )

    def load_from_file(self, path: str | Path) -> None:
        data = json.loads(Path(path).read_text())
        self.policies = {p["id"]: Policy.from_dict(p) for p in data["policies"]}


def new_policy_id() -> str:
    """Generate an id for a runtime-created policy (uuid4 hex, matching Janus)."""
    return uuid.uuid4().hex
