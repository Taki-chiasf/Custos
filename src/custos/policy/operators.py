"""Shared ABAC operator primitives (, dr  review).

Both :mod:`custos.policy.match` (production) and
:mod:`custos.eval.harness.policy.engine` (Janus-parity harness) evaluate the
same 11 operators (``==, !=, >, <, >=, <=, in, not_in, contains,
not_contains, matches``). These functions are duplicated in both places; this
module factors them into one miejsce so the test-of-drift invariant is
structural, not a code-review social convention.

The harness's :class:`JanusOperator` enum imports these functions directly;
the production :class:`custos.policy.match._ArgPred.evaluate` dispatches to
them via a string-keyed dict (the operator strings match :data:`ARG_OPERATORS`
in :mod:`custos.policy.match`). The harness's Janus-pity :class:`Operator`
enum is now :class:`JanusOperator` in :mod:`custos.eval.harness.policy.engine`
(renamed per the   dual-type-drift mitigation); it imports
``_eq/_ne/_gt/...`` from here.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = [
    "eq",
    "ne",
    "gt",
    "lt",
    "ge",
    "le",
    "inside",
    "not_inside",
    "contains",
    "not_contains",
    "matches",
    "OPERATOR_FUNCS",
]


def eq(a: Any, b: Any) -> bool:
    return bool(a == b)


def ne(a: Any, b: Any) -> bool:
    return bool(a != b)


def gt(a: Any, b: Any) -> bool:
    return bool(a > b)


def lt(a: Any, b: Any) -> bool:
    return bool(a < b)


def ge(a: Any, b: Any) -> bool:
    return bool(a >= b)


def le(a: Any, b: Any) -> bool:
    return bool(a <= b)


def inside(a: Any, b: Any) -> bool:
    return a in b


def not_inside(a: Any, b: Any) -> bool:
    return a not in b


def contains(a: Any, b: Any) -> bool:
    return b in a


def not_contains(a: Any, b: Any) -> bool:
    return b not in a


def matches(a: Any, b: Any) -> bool:
    return bool(re.match(b, a)) if isinstance(a, str) else False


# Stable string-keyed dict both engines reference so the operator name
# strings can't drift. The keys are intentionally identical to the strings
# used in :data:`custos.policy.match.ARG_OPERATORS` and the harness
# :class:`JanusOperator.value`.
OPERATOR_FUNCS: dict[str, Any] = {
    "==": eq,
    "!=": ne,
    ">": gt,
    "<": lt,
    ">=": ge,
    "<=": le,
    "in": inside,
    "not_in": not_inside,
    "contains": contains,
    "not_contains": not_contains,
    "matches": matches,
}


# ---------------------------------------------------------------------------- #
# Decision-semantics mapping
# ---------------------------------------------------------------------------- #


def to_custos_decision(janus_verdict: str) -> str:
    """Map a Janus assistant verdict label -> Custos :class:`Decision` label.

    Locks the  decision-semantics mapping so it can never drift. The
    machine-checked test in ``tests/eval/test_janus_decision_mapping.py``
    asserts this function against the production
    :class:`custos.schema.Decision` enum.

    Args:
        janus_verdict: one of ``"approve_once"``, ``"create_policy"``,
            ``"reject"``.

    Returns:
        The matching Custos :class:`Decision` enum value: ``"allow_once"``,
        ``"allow_and_persist"``, ``"deny"``.

    Raises:
        ValueError: on an unknown Janus verdict label.
    """
    mapping = {
        "approve_once": "allow_once",
        "create_policy": "allow_and_persist",
        "reject": "deny",
    }
    if janus_verdict not in mapping:
        raise ValueError(f"unknown Janus verdict: {janus_verdict!r}")
    return mapping[janus_verdict]
