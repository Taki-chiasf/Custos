"""RunMetrics — emit CSV rows matching `Janus/metrics/submission_metrics.csv` schema.

Clean-room re-implementation of the observable behaviour of
``Janus/src/utils/metrics.py`` (just the row shape + counter helpers we need for
parity). The exact column order and header string are matched so a phase0 CSV
can be concatenated with / diffed against the published baseline.
"""

from __future__ import annotations

import csv
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["RunMetrics", "CSV_HEADER", "new_run_id"]

CSV_HEADER: tuple[str, ...] = (
    "run_id",
    "scenario",
    "subscenario",
    "permission_assistant",
    "risk_tolerance",
    "synthetic_responder_enabled",
    "synthetic_responder_mode",
    "user_messages",
    "agent_messages",
    "permission_assistant_messages",
    "desired_tool_calls",
    "attack_tool_calls",
    "out_of_alignment_tool_calls",
    "other_tool_calls",
    "total_potential_desired_tool_calls",
    "total_potential_attack_tool_calls",
    "total_potential_out_of_alignment_tool_calls",
    "goal_call_breakdown",
    "other_call_breakdown",
    "output_results",
    "output_passes",
    "output_fails",
)


def new_run_id() -> str:
    return uuid.uuid4().hex


@dataclass
class RunMetrics:
    """One row per scenario cell run; emits to a CSV on flush."""

    run_id: str = field(default_factory=new_run_id)
    scenario: str = ""
    subscenario: str = ""
    permission_assistant: str = ""
    risk_tolerance: float | None = None
    synthetic_responder_enabled: bool = False
    synthetic_responder_mode: str = ""
    user_messages: int = 0
    agent_messages: int = 0
    permission_assistant_messages: int = 0
    desired_tool_calls: int = 0
    attack_tool_calls: int = 0
    out_of_alignment_tool_calls: int = 0
    other_tool_calls: int = 0
    total_potential_desired_tool_calls: int = 0
    total_potential_attack_tool_calls: int = 0
    total_potential_out_of_alignment_tool_calls: int = 0
    goal_call_breakdown: str = "[]"
    other_call_breakdown: str = "[]"
    output_results: str = "[]"
    output_passes: int = 0
    output_fails: int = 0

    def increment_user(self) -> None:
        self.user_messages += 1

    def increment_agent(self) -> None:
        self.agent_messages += 1

    def increment_assistant(self) -> None:
        self.permission_assistant_messages += 1

    def increment(self, event: str, payload: dict[str, Any]) -> None:
        """Compatibility shim so the metrics recorder callable matches base.py's type."""
        if event == "user_response":
            self.increment_user()
        elif event == "agent_message":
            self.increment_agent()
        elif event == "assistant_message":
            self.increment_assistant()

    def as_row(self) -> dict[str, Any]:
        risk = self.risk_tolerance if self.risk_tolerance is not None else 0.0
        return {
            "run_id": self.run_id,
            "scenario": self.scenario,
            "subscenario": self.subscenario,
            "permission_assistant": self.permission_assistant,
            "risk_tolerance": risk,
            "synthetic_responder_enabled": int(self.synthetic_responder_enabled),
            "synthetic_responder_mode": self.synthetic_responder_mode,
            "user_messages": self.user_messages,
            "agent_messages": self.agent_messages,
            "permission_assistant_messages": self.permission_assistant_messages,
            "desired_tool_calls": self.desired_tool_calls,
            "attack_tool_calls": self.attack_tool_calls,
            "out_of_alignment_tool_calls": self.out_of_alignment_tool_calls,
            "other_tool_calls": self.other_tool_calls,
            "total_potential_desired_tool_calls": self.total_potential_desired_tool_calls,
            "total_potential_attack_tool_calls": self.total_potential_attack_tool_calls,
            "total_potential_out_of_alignment_tool_calls": self.total_potential_out_of_alignment_tool_calls,
            "goal_call_breakdown": self.goal_call_breakdown,
            "other_call_breakdown": self.other_call_breakdown,
            "output_results": self.output_results,
            "output_passes": self.output_passes,
            "output_fails": self.output_fails,
        }

    def write_header(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(CSV_HEADER))
            writer.writeheader()

    def append_row(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(CSV_HEADER))
            writer.writerow(self.as_row())


def write_rows(path: str | Path, rows: Sequence[RunMetrics]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(CSV_HEADER))
        writer.writeheader()
        for row in rows:
            writer.writerow(row.as_row())
