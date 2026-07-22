"""Machine-checked Janus verdict → Custos Decision mapping test .

Asserts the  decision-semantics mapping never drifts between the Janus
harness (:class:`custos.eval.harness.JanusAssistantVerdict`) and the
production :class:`custos.schema.Decision`. The mapping is locked in
:func:`custos.policy.operators.to_custos_decision` so both implementations
reference a single source of truth.

The Council 2026-07-16 risk row "Dual policy engine + dual `AssistantOutput`
types drift between `eval/harness/` and `src/custos/`" is closed by this test.
"""

from __future__ import annotations

import pytest

from custos.eval.harness.schema import JanusAssistantVerdict
from custos.policy.operators import to_custos_decision
from custos.schema import Decision


@pytest.mark.parametrize(
    "verdict, expected_decision",
    [
        (JanusAssistantVerdict.APPROVE_ONCE, Decision.ALLOW_ONCE),
        (JanusAssistantVerdict.CREATE_POLICY, Decision.ALLOW_AND_PERSIST),
        (JanusAssistantVerdict.REJECT, Decision.DENY),
    ],
)
def test_janus_verdict_maps_to_correct_custos_decision(
    verdict: JanusAssistantVerdict, expected_decision: Decision
) -> None:
    """Each Janus verdict MUST map to exactly one Custos Decision."""
    from_labels = to_custos_decision(verdict.value)
    assert from_labels == expected_decision.value


def test_unknown_verdict_raises() -> None:
    """An unknown Janus verdict label raises ``ValueError``."""
    with pytest.raises(ValueError, match="unknown Janus verdict"):
        to_custos_decision("malicious_unknown_label")


def test_no_extra_janus_verdicts_introduced() -> None:
    """Catch a future Janus assistant that returns a NEW verdict label
    without updating :func:`to_custos_decision`. Consolidates drift prevention
    into one structural check across the two enum members."""
    expected = {"approve_once", "create_policy", "reject"}
    actual = {v.value for v in JanusAssistantVerdict}
    assert actual == expected, (
        f"JanusAssistantVerdict has new members {actual ^ expected}; thread "
        f"a mapping into :func:`to_custos_decision` in "
        f"`custos.policy.operators`."
    )


def test_no_extra_custos_decisions_in_janus_mapping() -> None:
    """Catches a future Custos extension (`prompt`, `defer`) that's NOT part of
    the Janus-collapsible mapping. The Janus forms collapse to three labels;
    the others stay Custos-only . Asserts the mapping is closed at three
    Custos-side allowed decisions — anything else stays a Custos extension.
    """
    expected = {Decision.ALLOW_ONCE.value, Decision.ALLOW_AND_PERSIST.value, Decision.DENY.value}
    # All three verdicts map to the set of Custos-relevant decisions iff the
    # mapping is closed, i.e. there is no Janus verdict mapping to anything
    # outside this set.
    for verdict in JanusAssistantVerdict:
        mapped = to_custos_decision(verdict.value)
        assert mapped in expected


def test_operator_set_consistent_across_engines() -> None:
    """Both engines (production + harness) reference the same operator set
    via :data:`custos.policy.operators.OPERATOR_FUNCS`. The production
    :data:`custos.policy.match.ARG_OPERATORS` and the harness
    :class:`custos.eval.harness.policy.engine.JanusOperator` both source from
    this dict; assert they cannot drift."""
    from custos.eval.harness.policy.engine import JanusOperator
    from custos.policy.match import ARG_OPERATORS

    # Production engine allowed-operator set.
    prod = set(ARG_OPERATORS)
    # Harness engine allowed-operator values.
    harness_labels = {op.value for op in JanusOperator}
    # Map space-containing Janus labels to the canonical underscores so the
    # shared OPERATOR_FUNCS keys hold.
    harness_canonical = {
        "not in": "not_in",
        "not contains": "not_contains",
    }
    harness_mapped = {harness_canonical.get(lbl, lbl) for lbl in harness_labels}
    # The harness's set is a superset of the production set iff the same set of
    # operator strings (the canonical name from OPERATOR_FUNCS) backs both.
    # The production set has 11 underscore-separated names; the harness has the
    # same 11 (with a couple of space-variant labels for Janus parity).
    assert prod == {
        "==",
        "!=",
        ">",
        "<",
        ">=",
        "<=",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "matches",
    }
    # The shared module keys (no space-separated variants).
    assert prod == set(harness_mapped), (
        f"Production + harness operator sets disagree: {prod} vs {harness_mapped}"
    )
