"""Custos eval harness - Janus parity stack .

Clean-room re-implementation of the Janus-Harness evaluation framework
(arXiv:2607.01510, Brigham et al., U. Washington). Treat as a design
reference, NOT a dependency: no Janus ``.py`` code is vendored ; only
scenario JSON + constitution markdown are copied as data fixtures (see
``eval/suites/janus_v1/fixtures/README.md`` for provenance).

This package intentionally keeps **Janus's labels and semantics verbatim**
(``approve_once`` / ``create_policy`` / ``reject``; default-deny-with-permit-
precedence, NO Custos  deny-floor) so parity run output is directly
comparable to ``Janus/metrics/submission_metrics.csv``. See
``eval/suites/janus_v1/DECISION_SEMANTICS.md`` for the locked mapping to the
production ``custos.schema.Decision`` enum and the deny-floor departure.

The production Custos gateway (denys-floor, sync, A5-A9) is exercised by the
adversarial suite (``eval/suites/adversarial/``), NOT by this parity stack.
"""

from __future__ import annotations

from custos.eval.harness.schema import JanusAssistantOutput, JanusAssistantVerdict

__version__ = "0.3.0"

__all__ = ["JanusAssistantOutput", "JanusAssistantVerdict", "__version__"]
