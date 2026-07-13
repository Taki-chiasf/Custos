"""Pure match predicate for policy rules .

Compiles a match mapping  into a frozen, dependency-free predicate
over :class:`~custos.schema.Invocation`. Same ``invocation`` + ``context`` +
``policy_version`` MUST yield the same result  - this module performs
no I/O, no time-dependent reads, and no randomness.

Match criteria (all AND-ed; an absent criterion matches everything):

  ``tool``            - glob matched against ``inv.tool`` via :mod:`fnmatch`.
  ``risk_tier``       - int (exact) or ``[min, max]`` (inclusive range).
  ``side_effects``    - list; rule matches if the tool's side_effects intersect
                        the rule's set (any-of semantics).
  ``args``            - mapping of arg-name -> predicate. A bare scalar means
                        ``==``; a ``{operator: value}`` dict applies one of:
                        ``==, !=, >, <, >=, <=, in, not_in, contains,
                        not_contains, matches`` (regex, anchored via
                        :func:`re.match`).
  ``goal_id``         - exact match against ``ctx.goal_id``.
  ``delegation_depth`` - exact match against ``ctx.delegation_depth``.
  ``any``             - ``true`` matches everything (wildcard).

Re-implemented (NOT copied) from the ABAC semantics documented in
``Janus/architecture.md`` and the observable behavior of
``Janus/src/permissions/policy_engine.py``. Production Custos uses the
match shape, not Janus's ``{attribute, operator, value}`` triple - the two
shapes are mechanically equivalent for the operators Custos supports.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from custos.policy.operators import OPERATOR_FUNCS
from custos.policy.schema import PolicyValidationError
from custos.schema import Invocation, SideEffect

__all__ = ["MatchSpec", "ARG_OPERATORS"]


# Arg-predicate operators . The string set is sourced from the shared
# ``custos.policy.operators`` module so both production + harness engines
# reference the exact same primitive set (dual-type-drift fix).
ARG_OPERATORS: frozenset[str] = frozenset(OPERATOR_FUNCS.keys())


def _compile_arg_predicate(pred: Any) -> _ArgPred:
    """Compile an arg match predicate (scalar or ``{op: value}`` dict)."""
    if isinstance(pred, Mapping):
        if len(pred) != 1:
            raise PolicyValidationError(
                f"arg predicate must be a single-operator dict, got {pred!r}"
            )
        ((op, value),) = pred.items()
        if op not in ARG_OPERATORS:
            raise PolicyValidationError(
                f"unknown arg operator {op!r}; allowed: {sorted(ARG_OPERATORS)}"
            )
        return _ArgPred(op, value)
    # Bare scalar -> equality.
    return _ArgPred("==", pred)


@dataclass(frozen=True)
class _ArgPred:
    op: str
    value: Any

    def evaluate(self, arg_value: Any) -> bool:
        op = self.op
        value = self.value
        func = OPERATOR_FUNCS.get(op)
        if func is None:
            # Should be unreachable; operators are validated at compile time.
            raise PolicyValidationError(f"unhandled operator {op!r}")  # pragma: no cover
        # ``matches`` has a special case: the production engine skips non-string
        # arg values (returns False instead of attempting re.match on a non-str).
        # The shared ``matches`` operator already does this; nothing further.
        try:
            return bool(func(arg_value, value))
        except (TypeError, ValueError):
            return False


@dataclass(frozen=True)
class MatchSpec:
    """Compiled, pure match predicate ."""

    tool_glob: str | None = None
    risk_tier_min: int | None = None
    risk_tier_max: int | None = None
    side_effects: frozenset[SideEffect] = frozenset()
    args: Mapping[str, _ArgPred] = field(default_factory=dict)
    goal_id: str | None = None
    delegation_depth: int | None = None
    any: bool = False

    @classmethod
    def from_mapping(cls, match: Mapping[str, Any]) -> MatchSpec:
        """Compile a match mapping  into a :class:`MatchSpec`.

        Raises :class:`PolicyValidationError` on a malformed mapping.
        """
        if "any" in match:
            if not isinstance(match["any"], bool):
                raise PolicyValidationError(
                    f"match.any must be a bool, got {type(match['any']).__name__}"
                )
            if match["any"] is True:
                return cls(any=True)

        tool_glob = match.get("tool")
        if tool_glob is not None and not isinstance(tool_glob, str):
            raise PolicyValidationError("match.tool must be a string glob")

        risk_tier_min: int | None = None
        risk_tier_max: int | None = None
        if "risk_tier" in match:
            rt = match["risk_tier"]
            if isinstance(rt, int):
                risk_tier_min = risk_tier_max = rt
            else:
                # Sequence [min, max] - validated by validate_rule already.
                rt_list = list(rt)
                risk_tier_min, risk_tier_max = rt_list[0], rt_list[1]

        side_effects: frozenset[SideEffect] = frozenset()
        if "side_effects" in match:
            raw = match["side_effects"]
            try:
                side_effects = frozenset(SideEffect(s) for s in raw)
            except ValueError as exc:
                raise PolicyValidationError(f"unknown side_effect in {list(raw)!r}") from exc

        args: dict[str, _ArgPred] = {}
        if "args" in match:
            raw_args = match["args"]
            if not isinstance(raw_args, Mapping):
                raise PolicyValidationError(
                    f"args must be a mapping, got {type(raw_args).__name__}"
                )
            for name, pred in raw_args.items():
                args[name] = _compile_arg_predicate(pred)

        goal_id = match.get("goal_id")
        if goal_id is not None and not isinstance(goal_id, str):
            raise PolicyValidationError("match.goal_id must be a string")

        delegation_depth = match.get("delegation_depth")
        if delegation_depth is not None and (
            not isinstance(delegation_depth, int) or delegation_depth < 0
        ):
            raise PolicyValidationError(
                f"delegation_depth must be a non-negative int, got {delegation_depth!r}"
            )

        return cls(
            tool_glob=tool_glob,
            risk_tier_min=risk_tier_min,
            risk_tier_max=risk_tier_max,
            side_effects=side_effects,
            args=args,
            goal_id=goal_id,
            delegation_depth=delegation_depth,
            any=False,
        )

    def matches(self, inv: Invocation) -> bool:
        """Pure predicate over (invocation, context). ."""
        if self.any:
            return True

        if self.tool_glob is not None and not fnmatch.fnmatchcase(inv.tool, self.tool_glob):
            return False

        if self.risk_tier_min is not None or self.risk_tier_max is not None:
            tier = inv.descriptor.risk_tier if inv.descriptor else 0
            if self.risk_tier_min is not None and tier < self.risk_tier_min:
                return False
            if self.risk_tier_max is not None and tier > self.risk_tier_max:
                return False

        if self.side_effects and (
            inv.descriptor is None or not self.side_effects & inv.descriptor.side_effects
        ):
            return False

        if self.args:
            for name, pred in self.args.items():
                if name not in inv.args:
                    return False
                if not pred.evaluate(inv.args[name]):
                    return False

        if self.goal_id is not None and inv.context.goal_id != self.goal_id:
            return False

        return not (
            self.delegation_depth is not None
            and inv.context.delegation_depth != self.delegation_depth
        )
