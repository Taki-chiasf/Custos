"""``adversarial`` suite runner - exercises the production sync Gateway .

For each :class:`AttackCell`:

  1. Build a fresh :class:`custos.Gateway` with the cell's inline policy
     (via :meth:`custos.policy.Policy.from_dict`), a ``RulePolicy``
     assistant (A7; deterministic, keyless), and a ``NoopResponder`` (prompts
     auto-deny on timeout).
  2. Evaluate the attack :class:`Invocation` via :meth:`Gateway.decide`.
  3. Compare the returned :class:`Decision` to the cell's ``expected``.
  A miss is a security regression -> non-zero exit (M8: zero false-allows).

Keyless + deterministic: no LLM is invoked (the policy floor + A7 enforce).
LLM-backed injection scenarios (where untrusted text reaches assistant
reasoning) are a  opt-in and live behind ``--execute``; for v0.3 the
default ``--smoke``/``--dry-run`` paths run the keyless cells.

Exit codes :
  0 - all cells matched their expected decision.
  1 - at least one cell missed (security regression).
  2 - misuse (unknown args; suite + policy conflicting args).
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from custos.eval.metrics import from_adversarial_results
from custos.eval.reports.render import emit_suite_artifacts
from custos.eval.suite import SuiteArgs
from custos.eval.suites.adversarial.scenarios import AttackCell, Scenario, build_scenarios
from custos.schema import AssistantOutput, Decision, Invocation, PromptResponse, SubjectContext

__all__ = ["AdversarialSuite", "CellResult", "run_cell"]


@dataclass(frozen=True)
class CellResult:
    """One adversarial cell outcome."""

    category: str
    name: str
    expected: Decision
    actual: Decision
    passed: bool
    reasoning: str = ""


@dataclass
class SuiteReport:
    """Aggregate result; serialized into the JSON/HTML report ."""

    total: int = 0
    passes: int = 0
    failures: list[CellResult] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)

    @property
    def exit_code(self) -> int:
        return 0 if not self.failures else 1


def _gateway_for(cell: AttackCell) -> Any:
    """Build a production Gateway for one adversarial cell (keyless, sync —
    the  expansion also supports `AsyncGateway` for quorum cells via the
    MultiApproverResponder)."""
    from custos.assistants.rule_policy import RulePolicy
    from custos.audit import NullAuditSink
    from custos.gateway import Gateway
    from custos.policy.engine import Policy
    from custos.responders.noop import NoopResponder

    policy = Policy.from_dict(cast("Mapping[object, object]", cell.policy_spec))
    if cell.assistant_kind == "rule_policy":
        assistant: Any = RulePolicy()
    elif cell.assistant_kind == "risk_assessment":
        from custos.assistants.risk_assessment import RiskAssessment
        from custos.llm import FunctionLLMClient

        # Stub LLM client. The cell's llm_stub_output is returned by the
        # assistant regardless of input — exercises  floor against the
        # injected "low-risk allow" verdict.
        if cell.llm_stub_output is None:  # pragma: no cover - defensive
            assistant = RulePolicy()
        else:
            llm_response = _encode_llu_stub_output_for_stub(cell.llm_stub_output)

            # FunctionLLMClient expects ``fn: Callable[[Messages, float], str]``.
            # The stub ignores its inputs and always returns the cell's encoded
            # AssistantOutput JSON (low-risk allow). The RiskAssessment judge
            # parses it via ``_parse_json_loose`` and assigns ``risk = parsed["risk"]``.
            def _stub_fn(_messages: Any, _temperature: float = 0.0) -> str:
                return llm_response

            stub = FunctionLLMClient(_stub_fn)
            assistant = RiskAssessment(tolerance=0.99, llm=stub)
    elif cell.assistant_kind == "learned_policy":
        if cell.llm_stub_output is None:  # pragma: no cover
            assistant = RulePolicy()
        else:
            # A10 assistant stubbed to ALWAYS emit the poisoned ALLOW_AND_PERSIST
            # output (the poisoning attempt). The gateway H3 narrowness check
            # must reject the broad poisoned rule at insert time.
            assistant = _StubAssistant(
                name="learned-policy",
                output=cell.llm_stub_output,
            )
    else:  # pragma: no cover - defensive default
        assistant = RulePolicy()

    return Gateway(
        policy=policy,
        assistant=assistant,
        responder=NoopResponder(),
        audit_sink=NullAuditSink(),
        # The adversarial suite runs headless; never block on responder.
        default_timeout_ms=0,
    )


def _encode_llu_stub_output_for_stub(out: AssistantOutput) -> str:
    """Encode an :class:`AssistantOutput` as the JSON the LLM stub returns.

    The :class:`RiskAssessment` assistant parses the JSON from a stub
    ``FunctionLLMClient`` response (see :func:`_parse_json_loose`). We emit
    ``{"risk": <risk>, "reason": "<reason>"}`` so the assistant's judging
    path picks up the cell's stub values. The cell's stub output's
    ``decision`` is honored by the gateway's pipeline when the assistant's
    ``decide`` returns it directly — but :class:`RiskAssessment.decide`
    re-derives the decision from tolerance vs the parsed risk. To make the
    stub produce a specific decision (e.g., ALLOW_AND_PERSIST) regardless
    of tolerance, the cell's stub output's risk must be low enough to be
    below our set tolerance (0.99 above).
    """
    import json

    return json.dumps({"risk": float(out.risk), "reason": out.reasoning})


class _StubAssistant:
    """Minimal stub assistant that always returns a fixed output."""

    def __init__(self, *, name: str, output: AssistantOutput) -> None:
        self.name = name
        self._output = output

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        return self._output


def run_cell(cell: AttackCell) -> CellResult:
    """Evaluate one attack cell against a fresh Gateway; return the outcome."""
    # Quorum cells need the async path (MultiApproverResponder).
    if cell.quorum_config is not None:
        actual, quorum_state = _run_quorum_cell(cell)
    else:
        gw = _gateway_for(cell)
        # Run any prior invocations first (MultiStepAttackCell pattern for
        # learned-policy poisoning cells).
        for prior in cell.prior_invocations:
            gw.decide(prior)
        actual = gw.decide(cell.invocation).decision
        quorum_state = None
    passed = actual == cell.expected
    if cell.expected_quorum_state is not None:
        passed = passed and quorum_state == cell.expected_quorum_state
    return CellResult(
        category=cell.category,
        name=cell.name,
        expected=cell.expected,
        actual=actual,
        passed=passed,
        reasoning=cell.description,
    )


def _run_quorum_cell(cell: AttackCell) -> tuple[Decision, str | None]:
    """Evaluate a quorum cell via AsyncGateway + MultiApproverResponder.

    Returns ``(decision, quorum_state)``. Drives the full async pipeline so
    the audit ``quorum_state`` field is observable via a stub FileAuditSink.
    """
    import asyncio
    import json
    import tempfile
    from pathlib import Path

    from custos.async_gateway import AsyncGateway
    from custos.audit import FileAuditSink
    from custos.policy.engine import Policy
    from custos.responders.multi_approver import MultiApproverResponder

    cfg = cell.quorum_config
    if cfg is None:  # pragma: no cover
        return Decision.DEFER, None

    # Build per-role child stubs based on child_votes.
    child_votes = cfg.get("child_votes", [])
    role_overlap = cfg.get("child_roles_overlap", False)
    children: list[Any] = []
    child_roles: list[str] = []
    for vote in child_votes:
        role, choice, approver = vote
        if role_overlap:
            # Misconfiguration: all children claim the same role.
            role = "finance"
        children.append(_StubChildResponder(name=role, vote=choice, approver=approver))
        child_roles.append(role)

    multi = MultiApproverResponder(children=children, child_roles=child_roles, timeout=2)
    policy = Policy.from_dict(cast("Mapping[object, object]", cell.policy_spec))

    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "quorum-audit.jsonl"
        gw = AsyncGateway(
            policy=policy,
            responder=multi,
            audit_sink=FileAuditSink(audit_path),
            default_timeout_ms=5_000,
        )
        decision = asyncio.run(gw.decide(cell.invocation)).decision
        # Extract the quorum_state from the last audit line.
        quorum_state: str | None = None
        try:
            lines = audit_path.read_text(encoding="utf-8").strip().splitlines()
            if lines:
                quorum_state = json.loads(lines[-1]).get("quorum_state")
        except Exception:  # noqa: BLE001
            quorum_state = None
    return decision, quorum_state


class _StubChildResponder:
    """Stub child responder for quorum cells."""

    def __init__(self, *, name: str, vote: Decision, approver: str) -> None:
        self.name = name
        self._vote = vote
        self._approver = approver

    def prompt(self, req: Any) -> PromptResponse:  # sync — bridged via to_thread
        return PromptResponse(choice=self._vote, approver=self._approver)


class AdversarialSuite:
    """Implements :class:`eval.suite.Suite` for the adversarial regression matrix."""

    name = "adversarial"

    def run(self, args: SuiteArgs) -> int:
        scenarios: tuple[Scenario, ...] = build_scenarios()
        report = SuiteReport()
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        all_results: list[CellResult] = []
        for scen in scenarios:
            for cell in scen.cells:
                if args.smoke and cell.category not in {
                    "prompt_injection",
                    "confused_deputy",
                }:
                    continue
                result = run_cell(cell)
                report.total += 1
                report.by_category[result.category] = report.by_category.get(result.category, 0) + 1
                if result.passed:
                    report.passes += 1
                else:
                    report.failures.append(result)
                all_results.append(result)
                self._print_cell(result)
        self._write_report(report, all_results, out_dir)
        return report.exit_code

    # -------------------------------------------------------------------- #

    def _print_cell(self, r: CellResult) -> None:
        flag = "PASS" if r.passed else "FAIL"
        print(
            f"[{flag}] adversarial/{r.category}/{r.name}: "
            f"expected={r.expected.value} actual={r.actual.value}"
        )

    def _write_report(
        self,
        report: SuiteReport,
        all_results: list[CellResult],
        out_dir: Path,
    ) -> None:
        import json

        summary = {
            "suite": "adversarial",
            "total": report.total,
            "passes": report.passes,
            "failures": len(report.failures),
            "by_category": report.by_category,
            "failed_cells": [
                {
                    "category": r.category,
                    "name": r.name,
                    "expected": r.expected.value,
                    "actual": r.actual.value,
                    "reasoning": r.reasoning,
                }
                for r in report.failures
            ],
        }
        (out_dir / "adversarial_report.json").write_text(json.dumps(summary, indent=2))

        # also emit the unified report.html + report.json carrying
        # the  metric aggregates (precision/recall/false-allow/...).
        metrics = from_adversarial_results(
            [
                {
                    "category": r.category,
                    "name": r.name,
                    "expected": r.expected.value,
                    "actual": r.actual.value,
                }
                for r in all_results
            ],
            suite=self.name,
        )
        cells_payload: list[dict[str, str]] = [
            {
                "category": r.category,
                "name": r.name,
                "expected": r.expected.value,
                "actual": r.actual.value,
                "passed": "PASS" if r.passed else "FAIL",
                "reasoning": r.reasoning,
            }
            for r in all_results
        ]
        emit_suite_artifacts(
            out_dir,
            metrics=metrics,
            cells=cells_payload,
            title="Custos adversarial eval (FR-9.28)",
            extra_json={"by_category": dict(report.by_category)},
        )
        print(
            f"custos eval adversarial: {report.passes}/{report.total} passed "
            f"({len(report.failures)} regressions) -> {out_dir / 'report.html'}",
            file=sys.stderr,
        )
