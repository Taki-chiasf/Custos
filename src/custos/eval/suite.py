"""Eval suite interface + dispatcher .

A *suite* is a named, packaged collection of scenarios that exercises the
permission pipeline and emits a structured result. Two suites ship with
Custos:

  - ``janus-v1``    - parity reproduction of the Janus 72-cell matrix
                      ; powered by ``eval.harness``.
  - ``adversarial`` - Custos-authored regression suite exercising the production
                      gateway against attack patterns ; lands in .

The CLI ``custos eval --suite <name> ...`` (see ``src/custos/cli.py``) routes
to :func:`run_eval`, which dispatches to the registered suite and returns a
process exit code :

  0 - success; no regression vs. baseline (when ``--baseline`` was set).
  1 - policy regression / parity failure vs. baseline.
  2 - misuse (unknown suite, missing args, malformed policy).
  3 - LLM backend unavailable (janus-v1 execute mode only).
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

__all__ = ["Suite", "SuiteArgs", "run_eval", "SUITE_REGISTRY"]


@dataclass
class SuiteArgs:
    """Parsed CLI args common to every suite ."""

    suite: str
    policy: str | None = None
    baseline: str | None = None
    smoke: bool = False
    execute: bool = False
    dry_run: bool = False
    output_dir: str = "runs/eval"
    repetitions: int = 1
    model: str | None = None
    judge_model: str | None = None
    extra: Mapping[str, object] = field(default_factory=dict)


@runtime_checkable
class Suite(Protocol):
    """A packaged eval suite. Implementations register into :data:`SUITE_REGISTRY`."""

    name: str

    def run(self, args: SuiteArgs) -> int:
        """Execute the suite; return a process exit code ."""
        ...


def _registry() -> dict[str, type[Suite]]:
    """Lazy registry: imports suite packages on first lookup so optional
    extras (e.g. litellm for janus-v1) aren't pulled at import time."""
    out: dict[str, type[Suite]] = {}
    try:
        from custos.eval.suites.janus_v1.suite import JanusV1Suite

        out["janus-v1"] = JanusV1Suite
    except ImportError:
        pass
    try:
        from custos.eval.suites.adversarial.suite import AdversarialSuite

        out["adversarial"] = AdversarialSuite
    except ImportError:
        pass
    return out


SUITE_REGISTRY: dict[str, type[Suite]] = {}


def run_eval(args: SuiteArgs) -> int:
    """Dispatch to the suite named by ``args.suite``; return its exit code."""
    reg = SUITE_REGISTRY or _registry()
    cls = reg.get(args.suite)
    if cls is None:
        print(
            f"custos eval: unknown suite {args.suite!r}. "
            f"Available: {', '.join(sorted(reg)) or '(none)'}",
            file=sys.stderr,
        )
        return 2
    return cls().run(args)
