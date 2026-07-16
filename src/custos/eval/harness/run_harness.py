"""``eval.harness.run_harness`` — janus-v1 matrix CLI (mirrors Janus flags).

Two modes:
  - ``--dry-run`` (default, no backend needed): expand the grid, write a
    manifest of planned cells to ``<output-dir>/manifest.json``, assert the
    planned-cell count matches the published 1440-row baseline.
  - execution mode (needs the [eval] extra + an LLM backend): runs the
    per-cell agent loop and emits ``metrics.csv``. Default backend is Ollama
    (local, key-free); hosted models need their usual API key. See
    :func:`eval.harness.llm.default_model`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from custos.eval.harness.assistants import (
    AVAILABLE_PERMISSION_ASSISTANTS,
    expand_runs,
)
from custos.eval.harness.scenarios import AVAILABLE_SCENARIOS, AVAILABLE_SUBSCENARIOS
from custos.eval.harness.synthetic_responder import AVAILABLE_SYNTHETIC_RESPONDER_MODES

__all__ = ["RunPlan", "Cell", "main", "build_arg_parser"]

AVAILABLE_SCENARIOS_STR = tuple(str(s) for s in AVAILABLE_SCENARIOS)


class _AvailableSubscenariosError(RuntimeError):
    pass


@dataclass(frozen=True)
class Cell:
    """One cell of the matrix — a single scenario/subscenario/assistant/responder/tolerance run."""

    scenario: int
    subscenario: str
    assistant: str
    risk_tolerance: float | None
    responder_mode: str
    repetition: int

    def key(self) -> str:
        tol = self.risk_tolerance if self.risk_tolerance is not None else 0.0
        return (
            f"s{self.scenario}/{self.subscenario}/{self.assistant}/"
            f"tol={tol}/{self.responder_mode}/rep={self.repetition}"
        )


@dataclass
class RunPlan:
    scenarios: tuple[int, ...]
    subscenarios: tuple[str, ...]
    assistants: tuple[str, ...]
    risk_tolerances: tuple[float, ...]
    responder_modes: tuple[str, ...]
    repetitions: int

    @property
    def assistant_tolerance_pairs(self) -> list[tuple[str, float | None]]:
        return expand_runs(self.assistants, self.risk_tolerances)

    def cells(self) -> list[Cell]:
        out: list[Cell] = []
        for s in self.scenarios:
            for sub in self.subscenarios:
                for name, tol in self.assistant_tolerance_pairs:
                    for mode in self.responder_modes:
                        for rep in range(1, self.repetitions + 1):
                            out.append(
                                Cell(
                                    scenario=s,
                                    subscenario=sub,
                                    assistant=name,
                                    risk_tolerance=tol,
                                    responder_mode=mode,
                                    repetition=rep,
                                )
                            )
        return out

    def to_manifest(self) -> dict[str, Any]:
        return {
            "scenarios": list(self.scenarios),
            "subscenarios": list(self.subscenarios),
            "assistants": list(self.assistants),
            "risk_tolerances": list(self.risk_tolerances),
            "responder_modes": list(self.responder_modes),
            "repetitions": self.repetitions,
            "assistant_tolerance_pairs": [
                {"assistant": n, "risk_tolerance": t} for n, t in self.assistant_tolerance_pairs
            ],
            "total_cells": len(self.cells()),
            "matching_janus_submission_metrics_csv_rows": len(self.cells()) == 1440,
        }

    def execute(self, output_dir: Path) -> None:
        """Run the live matrix. Requires the [eval] extra + an LLM backend.

        Default backend is Ollama (local, key-free); hosted models need their
        usual API key. See :func:`eval.harness.llm.default_model`.
        """
        try:
            from custos.eval.harness import cell_runner  # requires litellm
        except ImportError as exc:
            raise ImportError(
                "Execution needs the [eval] extra. Install: pip install -e '.[eval]'"
            ) from exc

        cell_runner.assert_llm_backend_reachable()
        cell_runner.run_matrix(self, output_dir)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eval.harness.run_harness",
        description="Janus parity reproduction matrix runner.",
    )
    p.add_argument("--scenarios", default="all")
    p.add_argument("--subscenarios", default="all")
    p.add_argument(
        "--permission-assistants",
        dest="assistants",
        default=",".join(AVAILABLE_PERMISSION_ASSISTANTS),
    )
    p.add_argument("--synthetic-responder", dest="synthetic_responder_enabled", action="store_true")
    p.add_argument("--synthetic-responder-modes", dest="responder_modes", default="all")
    p.add_argument("--risk-tolerances", dest="risk_tolerances", default="0.2,0.7")
    p.add_argument("--repetitions", type=int, default=5)
    p.add_argument("--output-dir", dest="output_dir", default="runs/full_eval")
    p.add_argument("--dry-run", action="store_true", default=True)
    p.add_argument("--execute", action="store_true", default=False)
    return p


def _parse_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _parse_float_csv(value: str) -> list[float]:
    out: list[float] = []
    for v in _parse_csv(value):
        out.append(float(v))
    return out


def _resolve_scenarios(value: str) -> tuple[int, ...]:
    if value == "all":
        return tuple(sorted(AVAILABLE_SCENARIOS))
    return tuple(int(v) for v in _parse_csv(value))


def _resolve_subscenarios(value: str) -> tuple[str, ...]:
    if value == "all":
        return tuple(AVAILABLE_SUBSCENARIOS)
    out = tuple(_parse_csv(value))
    bad = [s for s in out if s not in AVAILABLE_SUBSCENARIOS]
    if bad:
        raise _AvailableSubscenariosError(f"unknown subscenarios: {bad}")
    return out


def _resolve_responders(value: str, enabled: bool) -> tuple[str, ...]:
    if not enabled:
        return ("alignment_aware",)  # default; ignored when not enabled
    if value == "all":
        return tuple(AVAILABLE_SYNTHETIC_RESPONDER_MODES)
    out = tuple(_parse_csv(value))
    bad = [m for m in out if m not in AVAILABLE_SYNTHETIC_RESPONDER_MODES]
    if bad:
        raise ValueError(f"unknown responder modes: {bad}")
    return out


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        subscenarios = _resolve_subscenarios(
            args.subscenarios if args.subscenarios != "all" else "all"
        )
    except _AvailableSubscenariosError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    plan = RunPlan(
        scenarios=_resolve_scenarios(args.scenarios),
        subscenarios=subscenarios,
        assistants=tuple(_parse_csv(args.assistants)),
        risk_tolerances=tuple(_parse_float_csv(args.risk_tolerances)),
        responder_modes=_resolve_responders(args.responder_modes, args.synthetic_responder_enabled),
        repetitions=args.repetitions,
    )

    # Validate assistant names.
    bad = [a for a in plan.assistants if a not in AVAILABLE_PERMISSION_ASSISTANTS]
    if bad:
        print(f"error: unknown assistants: {bad}", file=sys.stderr)
        return 2

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.execute:
        try:
            plan.execute(output_dir)
        except Exception as exc:  # pragma: no cover - execution requires key
            print(f"execute failed: {exc}", file=sys.stderr)
            return 3
        return 0

    # dry-run (default): write a manifest.
    manifest = plan.to_manifest()
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print(f"wrote {manifest_path}")
    print(f"planned cells: {manifest['total_cells']}")
    if manifest["matching_janus_submission_metrics_csv_rows"]:
        print("matches published Janus baseline: 1440 rows (M7 grid)")
    else:
        print(
            "WARN: planned cell count does NOT match the published 1440-row baseline.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
