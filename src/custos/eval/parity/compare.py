"""Parity comparison tool — diff a phase0 run CSV vs the published Janus baseline.

Usage:
  python -m parity.compare <phase0_metrics.csv> <Janus/metrics/submission_metrics.csv>

Computes per-cell deltas on the four primary count columns (M7: ±5% parity
window per). A cell is identified by the tuple
``(scenario, subscenario, permission_assistant, risk_tolerance, synthetic_responder_mode)``.
Multiple runs/repetitions are averaged per cell.

Exit codes:
  0 — every cell's deltas are within ±5% on desired_tool_calls and
      attack_tool_calls (other columns reported but not gating).
  1 — at least one cell exceeds ±5% on a gating column.
  2 — malformed input / baseline shape mismatch.
"""

from __future__ import annotations

import csv
import json
import statistics
import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

__all__ = ["CellKey", "compare", "main"]

CellKey = tuple[str, str, str, str, str]
GATING_COLUMNS: tuple[str, ...] = ("desired_tool_calls", "attack_tool_calls")
REPORT_COLUMNS: tuple[str, ...] = (
    "desired_tool_calls",
    "attack_tool_calls",
    "out_of_alignment_tool_calls",
    "other_tool_calls",
    "output_passes",
    "output_fails",
)


def _row_key(row: Mapping[str, str]) -> CellKey:
    return (
        row["scenario"],
        row["subscenario"],
        row["permission_assistant"],
        row["risk_tolerance"],
        row["synthetic_responder_mode"],
    )


def _averaged(values: Sequence[float]) -> float:
    return statistics.fmean(values) if values else 0.0


def _load_averaged(path: str | Path) -> dict[CellKey, dict[str, float]]:
    path = Path(path)
    per_cell: dict[CellKey, dict[str, list[float]]] = defaultdict(
        lambda: {col: [] for col in REPORT_COLUMNS}
    )
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = _row_key(row)
            for col in REPORT_COLUMNS:
                try:
                    per_cell[key][col].append(float(row.get(col, 0) or 0))
                except ValueError:
                    per_cell[key][col].append(0.0)
    averaged: dict[CellKey, dict[str, float]] = {}
    for key, cols in per_cell.items():
        averaged[key] = {col: _averaged(vals) for col, vals in cols.items()}
    return averaged


def compare(
    candidate: str | Path,
    baseline: str | Path,
    *,
    tolerance: float = 0.05,
) -> tuple[bool, dict[str, object]]:
    """Return ``(within_tolerance, report_dict)`` over the gating columns."""
    cand = _load_averaged(candidate)
    base = _load_averaged(baseline)
    cells = set(cand) | set(base)
    deltas: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    for cell in sorted(cells):
        c_vals = cand.get(cell, dict.fromkeys(REPORT_COLUMNS, 0.0))
        b_vals = base.get(cell, dict.fromkeys(REPORT_COLUMNS, 0.0))
        for col in GATING_COLUMNS:
            b = b_vals[col]
            delta = c_vals[col] - b
            pct = float("inf") if b == 0 else delta / b
            rec: dict[str, object] = {
                "cell": list(cell),
                "column": col,
                "candidate": c_vals[col],
                "baseline": b,
                "delta": delta,
                "delta_pct": pct,
            }
            deltas.append(rec)
            if abs(pct) > tolerance:
                failures.append(rec)
    return (not failures, {"deltas": deltas, "failures": failures})


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if len(argv) != 2:
        print("usage: python -m parity.compare <candidate.csv> <baseline.csv>", file=sys.stderr)
        return 2
    candidate, baseline = argv
    if not Path(candidate).exists():
        print(f"candidate not found: {candidate}", file=sys.stderr)
        return 2
    if not Path(baseline).exists():
        print(f"baseline not found: {baseline}", file=sys.stderr)
        return 2
    ok, report = compare(candidate, baseline)
    out_path = Path(candidate).with_suffix(".parity_report.json")
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"wrote {out_path}")
    if ok:
        print(f"PARITY OK: all cells within ±5% on {GATING_COLUMNS}")
        return 0
    failures = cast(list[dict[str, object]], report["failures"])
    print(f"PARITY FAIL: {len(failures)} cell/column pairs exceed ±5%", file=sys.stderr)
    for f in failures[:20]:
        cell = cast(list[object], f["cell"])
        col = cast(str, f["column"])
        cand = f["candidate"]
        base = f["baseline"]
        dpct = cast(float, f["delta_pct"])
        print(
            "  " + " ".join(str(x) for x in cell) + f"  {col}: {cand} vs {base} ({dpct:.1%})",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
