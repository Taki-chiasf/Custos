"""Smoke + adversarial suite tests (deterministic, keyless).

Covers both the ``custos eval`` CLI surface added in  and the adversarial
suite added in . These run without an LLM backend (the adversarial cells
exercise the policy floor + A7 ``RulePolicy``, which are keyless and
deterministic).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from custos.cli import main
from custos.eval.suite import SuiteArgs, run_eval
from custos.eval.suites.adversarial.scenarios import build_scenarios
from custos.eval.suites.adversarial.suite import AdversarialSuite, run_cell
from custos.schema import Decision

# ---------------- adversarial scenarios ------------------------------------ #


def test_adversarial_scenarios_cover_all_four_categories() -> None:
    scenarios = build_scenarios()
    cats = {c.category for s in scenarios for c in s.cells}
    # The original 4  categories MUST all be present (added
    # positive_control / learned_policy_poisoning / llm_injection / quorum
    # as additional categories — the assertion is a superset, not equality).
    original_four = {
        "prompt_injection",
        "confused_deputy",
        "tool_spoofing",
        "delegation_depth_abuse",
    }
    assert original_four <= cats, (
        f"adversarial suite missing one of the 4 FR-9.28 categories; have {sorted(cats)}"
    )


def test_adversarial_every_cell_matches_expected_decision() -> None:
    # M8 (reframe): every cell matches its expected decision (covers
    # both "zero false-allows on DENY cells" AND "zero false-denies on ALLOW
    # positive controls" —   expansion).
    scenarios = build_scenarios()
    failures: list[str] = []
    for s in scenarios:
        for c in s.cells:
            result = run_cell(c)
            if not result.passed:
                failures.append(
                    f"{c.category}/{c.name}: expected {c.expected.value}, got {result.actual.value}"
                )
    assert not failures, "\n".join(failures)


def test_adversarial_n_cells_at_least_50() -> None:
    #   portion (M8 categorical claim): N>=50 cells before
    # M8 is reportable as "across the N-cell regression set".
    scenarios = build_scenarios()
    total = sum(len(s.cells) for s in scenarios)
    assert total >= 50, f"adversarial suite has only {total} cells; need >=50"


def test_adversarial_confused_deputy_blocks_via_policy_floor() -> None:
    scen = build_scenarios()[0]
    cell = next(c for c in scen.cells if c.name == "attacker_refund")
    # The cell's policy routes payment.refund -> prompt; the NoopResponder
    # denies on timeout so the deputy cannot auto-allow.
    assert cell.expected is Decision.DENY
    assert run_cell(cell).actual is Decision.DENY


def test_adversarial_tool_spoofing_evaluates_on_invocation_tool() -> None:
    scen = build_scenarios()[0]
    cell = next(c for c in scen.cells if c.name == "shell_disguised_as_read")
    # Descriptor lies (claims fs.read) but the policy evaluates on invocation.tool
    # = "shell.exec", which falls through to default-deny.
    assert cell.invocation.descriptor is not None
    assert cell.invocation.descriptor.name == "fs.read"  # the lie
    assert cell.invocation.tool == "shell.exec"  # the truth
    assert run_cell(cell).actual is Decision.DENY


def test_adversarial_delegation_cap_sorts_before_read_allow() -> None:
    scen = build_scenarios()[0]
    cell = next(c for c in scen.cells if c.name == "deep_chain_exfiltration")
    # The depth-cap overlay MUST precede the read allow so it isn't shadowed
    # (first-match-wins). Sanity-check the overlay ordering.
    overlays = cell.policy_spec["overlays"]
    assert overlays[0]["id"] == "delegation_cap"
    assert overlays[1]["id"] == "base"
    assert run_cell(cell).actual is Decision.DENY


# ---------------- CLI smoke + run_eval dispatch ----------------------------- #


def test_eval_unknown_suite_returns_2() -> None:
    rc = main(["eval", "--suite", "nope", "--dry-run"])
    assert rc == 2


def test_eval_janus_v1_dry_run_smoke(tmp_path: Path) -> None:
    out = tmp_path / "smoke"
    rc = main(
        [
            "eval",
            "--suite",
            "janus-v1",
            "--smoke",
            "--dry-run",
            "--output-dir",
            str(out),
        ]
    )
    assert rc == 0
    manifest = out / "manifest.json"
    assert manifest.exists()
    import json

    data = json.loads(manifest.read_text())
    assert data["total_cells"] == 3


def test_eval_adversarial_runs_keyless_via_cli(tmp_path: Path) -> None:
    out = tmp_path / "adv"
    rc = main(["eval", "--suite", "adversarial", "--output-dir", str(out)])
    assert rc == 0  # all cells pass
    import json

    rep = json.loads((out / "adversarial_report.json").read_text())
    # total grows from 5 to >= 50 (portion).
    assert rep["total"] >= 50
    assert rep["failures"] == 0


def test_eval_adversarial_smoke_runs_keyless_via_cli(tmp_path: Path) -> None:
    # the smoke filter still selects only prompt_injection +
    # confused_deputy cells (per suite.run), but their counts grew.
    out = tmp_path / "adv_smoke"
    rc = main(["eval", "--suite", "adversarial", "--smoke", "--output-dir", str(out)])
    assert rc == 0
    import json

    rep = json.loads((out / "adversarial_report.json").read_text())
    # Smoke ran only prompt_injection + confused_deputy categories.
    assert set(rep["by_category"]) <= {"prompt_injection", "confused_deputy"}
    assert rep["total"] == sum(rep["by_category"].values())
    assert rep["failures"] == 0


def test_run_eval_dispatches_adversarial_suite(tmp_path: Path) -> None:
    args = SuiteArgs(
        suite="adversarial",
        output_dir=str(tmp_path / "adv_disp"),
        dry_run=False,
    )
    rc = run_eval(args)
    assert rc == 0


def test_adversarial_suite_protocol_satisfied() -> None:
    from custos.eval.suite import Suite

    assert isinstance(AdversarialSuite(), Suite)


# ---------------- audit replay  ------------------------------------ #


def test_audit_replay_missing_policy_returns_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    p = tmp_path / "audit.jsonl"
    p.write_text('{"invocation": {"tool": "fs.read"}, "decision": "allow"}\n')
    rc = main(["audit", "replay", str(p), "--policy", str(tmp_path / "nope.yaml")])
    out = capsys.readouterr().err
    assert rc == 1
    assert "not found" in out


def test_audit_replay_runs_against_policy(tmp_path: Path) -> None:
    # Build a policy that allows fs.read* + prompts fs.write; record events
    # from BOTH then replay against a policy that denies fs.write.
    from custos.policy.engine import Policy

    policy_old = tmp_path / "old.yaml"
    policy_old.write_text(
        "version: 1\n"
        "default: deny\n"
        "overlays:\n"
        "  - id: base\n"
        "    rules:\n"
        "      - {match: {tool: fs.read*}, action: allow}\n"
        "      - {match: {tool: fs.write*}, action: prompt}\n"
    )
    policy_new = tmp_path / "new.yaml"
    policy_new.write_text(
        "version: 1\n"
        "default: deny\n"
        "overlays:\n"
        "  - id: base\n"
        "    rules:\n"
        "      - {match: {tool: fs.read*}, action: allow}\n"
        "      - {match: {tool: fs.write*}, action: deny}\n"
    )
    p = _write_audit(
        tmp_path / "audit.jsonl",
        [
            {
                "ts_unix_ms": 1,
                "decision": "allow",
                "invocation": {"tool": "fs.read", "args": {"path": "/etc/hosts"}},
                "subject": {"user_id": "u1"},
            },
            {
                "ts_unix_ms": 2,
                "decision": "prompt",
                "invocation": {"tool": "fs.write", "args": {"path": "/tmp/x"}},
                "subject": {"user_id": "u1"},
            },
        ],
    )
    # Sanity: policies load.
    Policy.from_yaml(str(policy_old))
    Policy.from_yaml(str(policy_new))

    rc = main(["audit", "replay", str(p), "--policy", str(policy_new)])
    # fs.write changes prompt -> deny; fs.read unchanged. Exit 0 (completed).
    assert rc == 0


# ---------------- helpers --------------------------------------------------- #


def _write_audit(path: Path, events: list[dict[str, object]]) -> Path:
    import json

    path.write_text(
        "\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n",
        encoding="utf-8",
    )
    return path
