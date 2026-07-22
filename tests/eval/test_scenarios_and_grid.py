"""Scenario loading + harness grid expansion (no LLM)."""

from __future__ import annotations

from custos.eval.harness.assistants import expand_runs, resolve_risk_tolerance
from custos.eval.harness.run_harness import RunPlan
from custos.eval.harness.scenarios import (
    AVAILABLE_SCENARIOS,
    AVAILABLE_SUBSCENARIOS,
    default_scenarios_dir,
    load_combined_definition,
)


def test_resource_paths_resolve() -> None:
    base = default_scenarios_dir()
    assert base.exists(), f"fixtures missing: {base}"
    assert (base / "scenario_1" / "attack.json").exists()


def test_all_12_subscenario_files_load() -> None:
    base = default_scenarios_dir()
    loaded = 0
    for sid in AVAILABLE_SCENARIOS:
        for sub in AVAILABLE_SUBSCENARIOS:
            d = load_combined_definition(sid, sub)
            assert d.scenario_id == f"scenario_{sid}"
            assert d.subscenario == sub
            assert isinstance(d.goals, tuple)
            assert isinstance(d.attacks, tuple)
            loaded += 1
    assert loaded == 12, f"expected 12 scenario/subscenario files, loaded {loaded}"
    # default.json seed data ok
    assert (base / "default.json").exists()


def test_scenario_1_attack_has_known_shape() -> None:
    d = load_combined_definition(1, "attack")
    assert len(d.goals) == 5
    g1 = next(g for g in d.goals if g.id == "1")
    assert g1.desired_tool_calls[0].tool == "email"
    assert g1.desired_tool_calls[0].action == "list"
    assert g1.desired_tool_calls[0].params["unread"]["eq"] is True
    assert any(p.tool == "email" and p.action == "send" for p in d.attacks)
    assert any(p.tool == "email" and p.action == "delete" for p in d.attacks)


def test_metadata_is_loaded() -> None:
    d = load_combined_definition(1, "attack")
    assert d.metadata.total_potential_desired_tool_calls == 1
    assert d.metadata.total_potential_attack_tool_calls == 2
    assert d.metadata.total_potential_out_of_alignment_tool_calls == 0


def test_resolve_risk_tolerance_per_assistant() -> None:
    tols = (0.2, 0.7)
    assert resolve_risk_tolerance("auto_approve", tols) == 1.0
    assert resolve_risk_tolerance("user_confirmation", tols) == 0.0
    assert resolve_risk_tolerance("constitution", tols) is None
    assert resolve_risk_tolerance("policy_suggestion", tols) is None
    assert resolve_risk_tolerance("risk_assessment", tols) == 0.2
    assert resolve_risk_tolerance("risk_assessment_autonomous", tols) == 0.2


def test_grid_expansion_matches_published_1440_rows() -> None:
    plan = RunPlan(
        scenarios=tuple(AVAILABLE_SCENARIOS),
        subscenarios=tuple(AVAILABLE_SUBSCENARIOS),
        assistants=(
            "auto_approve",
            "user_confirmation",
            "constitution",
            "policy_suggestion",
            "risk_assessment",
            "risk_assessment_autonomous",
        ),
        risk_tolerances=(0.2, 0.7),
        responder_modes=("always_yes", "always_no", "alignment_aware"),
        repetitions=5,
    )
    cells = plan.cells()
    assert len(cells) == 1440, (
        f"expected 1440 cells (matches submission_metrics.csv), got {len(cells)}"
    )
    pairs = plan.assistant_tolerance_pairs
    assert len(pairs) == 8
    risk_pairs = [p for p in pairs if p[0] in {"risk_assessment", "risk_assessment_autonomous"}]
    assert len(risk_pairs) == 4
    non_risk = [p for p in pairs if p[0] not in {"risk_assessment", "risk_assessment_autonomous"}]
    assert len(non_risk) == 4
    assert tuple(sorted({p[1] for p in pairs if p[1] == 0.7})) == (0.7,)


def test_expand_runs_smoke() -> None:
    pairs = expand_runs(("auto_approve", "risk_assessment"), (0.2, 0.7))
    assert pairs == [("auto_approve", 1.0), ("risk_assessment", 0.2), ("risk_assessment", 0.7)]
