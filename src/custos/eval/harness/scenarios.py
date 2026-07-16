"""Scenario loader for Janus-format scenario definition files.

Clean-room re-implementation of the observable behaviour of
``Janus/src/utils/scenario_definitions.py``: loads
``scenarios/definitions/scenario_N/{attack,balanced,permissive,restrictive}.json``
plus a top-level ``default.json``; accepts several legacy key aliases for
trace compatibility.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "ScenarioDefinition",
    "Goal",
    "ToolCallPattern",
    "ScenarioMetadata",
    "load_combined_definition",
    "load_scenario_file",
    "AVAILABLE_SUBSCENARIOS",
    "AVAILABLE_SCENARIOS",
    "default_scenarios_dir",
]

AVAILABLE_SUBSCENARIOS = ("attack", "balanced", "permissive", "restrictive")
AVAILABLE_SCENARIOS = (1, 2, 3)


@dataclass(frozen=True)
class ToolCallPattern:
    tool: str
    action: str
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Goal:
    id: str
    user_goal: str
    desired_tool_calls: Sequence[ToolCallPattern] = field(default_factory=tuple)
    output_criteria: Sequence[Mapping[str, Any]] = field(default_factory=tuple)


@dataclass(frozen=True)
class ScenarioMetadata:
    total_potential_desired_tool_calls: int = 0
    total_potential_attack_tool_calls: int = 0
    total_potential_out_of_alignment_tool_calls: int = 0


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: str  # e.g. "scenario_1"
    subscenario: str  # e.g. "attack"
    data: Mapping[str, Any]  # seed data: emails, calendar_events, files
    goals: Sequence[Goal]
    attacks: Sequence[ToolCallPattern]
    out_of_alignment: Sequence[ToolCallPattern]
    metadata: ScenarioMetadata


def default_scenarios_dir() -> Path:
    """Resolve the path to the bundled janus-v1 fixtures (data copied from Janus).

    Layout: ``eval/suites/janus_v1/fixtures/scenarios/definitions/``. From
    ``eval/harness/scenarios.py`` that is ``../../suites/janus_v1/fixtures/
    scenarios/definitions``.
    """
    here = Path(__file__).resolve()
    return here.parent.parent / "suites" / "janus_v1" / "fixtures" / "scenarios" / "definitions"


def load_scenario_file(path: str | Path) -> dict[str, Any]:
    return dict(json.loads(Path(path).read_text()))


def load_combined_definition(
    scenario_id: str | int,
    subscenario: str,
    scenarios_dir: str | Path | None = None,
) -> ScenarioDefinition:
    """Load and combine ``scenarios_dir/<scenario_id>/<subscenario>.json``.

    Accepts legacy key aliases (``desired_calls``/``desired_tool_calls``/``desired``,
    ``evaluation``/``eval``, ``collections``/``data``, ``attacks``/``attack_calls``,
    ``out_of_alignment``/``out_of_alignment_calls``).
    """
    base = Path(scenarios_dir) if scenarios_dir else default_scenarios_dir()
    sid = scenario_id if isinstance(scenario_id, str) else f"scenario_{scenario_id}"
    path = base / sid / f"{subscenario}.json"
    raw = load_scenario_file(path)

    data = raw.get("collections") or raw.get("data") or {}
    eval_block = raw.get("evaluation") or raw.get("eval") or {}

    def _patterns(items: Sequence[Mapping[str, Any]]) -> tuple[ToolCallPattern, ...]:
        out: list[ToolCallPattern] = []
        for item in items:
            out.append(
                ToolCallPattern(
                    tool=item.get("tool", ""),
                    action=item.get("action", ""),
                    params=item.get("params") or item.get("parameters") or {},
                )
            )
        return tuple(out)

    goals: list[Goal] = []
    for g in eval_block.get("goals", []):
        desired = (
            g.get("desired_tool_calls")
            or g.get("desired_calls")
            or g.get("desired")
            or g.get("tool_calls")
            or []
        )
        goals.append(
            Goal(
                id=str(g.get("id", "")),
                user_goal=g.get("user_goal", ""),
                desired_tool_calls=_patterns(desired),
                output_criteria=g.get("output_criteria", []),
            )
        )

    attacks = _patterns(eval_block.get("attacks") or eval_block.get("attack_calls") or [])
    out_of_alignment = _patterns(
        eval_block.get("out_of_alignment") or eval_block.get("out_of_alignment_calls") or []
    )

    meta = raw.get("metadata", {})
    metadata = ScenarioMetadata(
        total_potential_desired_tool_calls=int(meta.get("total_potential_desired_tool_calls", 0)),
        total_potential_attack_tool_calls=int(meta.get("total_potential_attack_tool_calls", 0)),
        total_potential_out_of_alignment_tool_calls=int(
            meta.get("total_potential_out_of_alignment_tool_calls", 0)
        ),
    )
    return ScenarioDefinition(
        scenario_id=sid,
        subscenario=subscenario,
        data=data,
        goals=tuple(goals),
        attacks=attacks,
        out_of_alignment=out_of_alignment,
        metadata=metadata,
    )
