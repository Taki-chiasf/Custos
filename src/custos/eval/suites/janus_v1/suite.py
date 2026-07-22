"""``janus-v1`` suite runner - thin wrapper over :mod:`eval.harness.run_harness`.

Two tiering modes :
  - ``--smoke`` : 3-cell subset (scenario_1/attack + A1 + 3 responders, 1 rep)
    - gates every PR; cheap on a local Ollama model.
  - full (default) : 72-cell matrix (3 scenarios x 4 subscenarios x 3
    responders x 2 risk tolerances x 5 reps = 1440 cells), release-gated.

Two execution modes:
  - ``--dry-run`` (default) : expand the grid, write ``manifest.json``; needs no
    LLM backend. Exit 0 if the planned-cell count matches the published 1440
    baseline; 2 otherwise.
  - ``--execute`` : run every cell live, write ``metrics.csv``; needs the
    [eval] extra + a reachable LLM backend (Ollama by default). Exit 0 if all
    cells ran; 3 if the backend is unreachable.

Optional ``--baseline <csv>`` triggers the parity check against the published
Janus baseline (M7, ±5%): exit 0 if within tolerance, 1 otherwise. The full
matrix emit + parity report lands in  .
"""

from __future__ import annotations

import sys
from pathlib import Path

from custos.eval.harness.assistants import AVAILABLE_PERMISSION_ASSISTANTS
from custos.eval.harness.scenarios import AVAILABLE_SCENARIOS, AVAILABLE_SUBSCENARIOS
from custos.eval.harness.synthetic_responder import AVAILABLE_SYNTHETIC_RESPONDER_MODES
from custos.eval.suite import SuiteArgs

__all__ = ["JanusV1Suite"]

_SMOKE_ASSISTANTS = ("auto_approve",)
_SMOKE_SCENARIOS = (1,)
_SMOKE_SUBSCENARIOS = ("attack",)
_SMOKE_TOLERANCES = (0.2,)
_SMOKE_REPS = 1


class JanusV1Suite:
    """Implements :class:`eval.suite.Suite` for the janus-v1 parity matrix."""

    name = "janus-v1"

    def run(self, args: SuiteArgs) -> int:
        from custos.eval.harness.run_harness import RunPlan

        scenarios = _SMOKE_SCENARIOS if args.smoke else tuple(AVAILABLE_SCENARIOS)
        subscenarios = _SMOKE_SUBSCENARIOS if args.smoke else tuple(AVAILABLE_SUBSCENARIOS)
        assistants = _SMOKE_ASSISTANTS if args.smoke else tuple(AVAILABLE_PERMISSION_ASSISTANTS)
        tols = _SMOKE_TOLERANCES if args.smoke else (0.2, 0.7)
        modes = tuple(AVAILABLE_SYNTHETIC_RESPONDER_MODES)
        reps = _SMOKE_REPS if args.smoke else max(1, args.repetitions)
        if args.smoke:
            reps = 1  # smoke always 1 rep regardless of --repetitions

        plan = RunPlan(
            scenarios=scenarios,
            subscenarios=subscenarios,
            assistants=assistants,
            risk_tolerances=tols,
            responder_modes=modes,
            repetitions=reps,
        )
        cells = plan.cells()
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        if args.execute or not args.dry_run:
            try:
                plan.execute(out_dir)
            except ImportError as exc:
                print(f"custos eval: {exc}", file=sys.stderr)
                return 3
            except Exception as exc:  # backend unreachable, etc.
                print(f"custos eval: execute failed: {exc}", file=sys.stderr)
                return 3
            print(f"custos eval: wrote {len(cells)} cells -> {out_dir / 'metrics.csv'}")
        else:
            manifest = plan.to_manifest()
            (out_dir / "manifest.json").write_text(__import__("json").dumps(manifest, indent=2))
            print(f"custos eval: planned {len(cells)} cells -> {out_dir / 'manifest.json'}")
            if not manifest["matching_janus_submission_metrics_csv_rows"] and not args.smoke:
                print(
                    "custos eval: WARN planned-cell count does not match the 1440-row baseline",
                    file=sys.stderr,
                )

        if args.baseline:
            return _parity(out_dir / "metrics.csv", Path(args.baseline))
        return 0


def _parity(candidate: Path, baseline: Path) -> int:
    from collections.abc import Sized
    from typing import cast

    from custos.eval.parity.compare import compare

    if not candidate.exists():
        print(f"custos eval: candidate metrics not found: {candidate}", file=sys.stderr)
        return 2
    if not baseline.exists():
        print(f"custos eval: baseline not found: {baseline}", file=sys.stderr)
        return 2
    ok, report = compare(str(candidate), str(baseline))
    if ok:
        print("custos eval: PARITY OK (all cells within +/-5% on gating columns)")
        return 0
    failures = cast(Sized, report["failures"])
    print(
        f"custos eval: PARITY FAIL - {len(failures)} cell/column pair(s) exceed +/-5%",
        file=sys.stderr,
    )
    return 1
