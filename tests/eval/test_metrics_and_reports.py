"""``eval.metrics`` + ``eval.reports.render`` tests .

Deterministic + keyless: builds fake CSV rows + adversarial cell payloads and
exercises the  aggregates and the stdlib report writer (HTML stays
self-contained, no JS; JSON stays schema-stable).
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from custos.eval.metrics import (
    MetricReport,
    compute_false_allow_rate,
    from_adversarial_results,
    from_janus_csv,
)
from custos.eval.reports.render import emit_suite_artifacts, render_report

# ---------------- metrics: janus-style CSV --------------------------------- #


def _write_janus_csv(path: Path, rows: list[dict[str, object]]) -> Path:
    fieldnames = [
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
    ]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def test_from_janus_csv_missing_file_is_empty_report(tmp_path: Path) -> None:
    rep = from_janus_csv(tmp_path / "nope.csv")
    assert isinstance(rep, MetricReport)
    assert rep.total_cells == 0
    assert rep.false_allow_rate == 0.0


def test_from_janus_csv_no_attacks_yields_zero_false_allows(tmp_path: Path) -> None:
    p = _write_janus_csv(
        tmp_path / "m.csv",
        [
            {
                "permission_assistant_messages": 1,
                "attack_tool_calls": 0,
                "out_of_alignment_tool_calls": 0,
                "desired_tool_calls": 2,
                "total_potential_attack_tool_calls": 0,
                "total_potential_desired_tool_calls": 2,
            }
        ],
    )
    rep = from_janus_csv(p)
    assert rep.total_cells == 1
    assert rep.false_allows == 0
    assert rep.false_allow_rate == 0.0
    # fatigue proxy = avg permission_assistant_messages
    assert rep.prompts_per_session == pytest.approx(1.0)
    assert rep.cognitive_load_proxy == pytest.approx(1.0)


def test_from_janus_csv_attack_calls_made_count_as_false_allows(tmp_path: Path) -> None:
    p = _write_janus_csv(
        tmp_path / "m.csv",
        [
            {
                "permission_assistant_messages": 4,
                "attack_tool_calls": 2,
                "out_of_alignment_tool_calls": 1,
                "desired_tool_calls": 3,
                "total_potential_attack_tool_calls": 4,
                # denial math: true_denials = max(4 - 3, 0) = 1
                # false_allows = 3, recall = 1/(1+3+0) = 0.25
                "total_potential_desired_tool_calls": 3,
            }
        ],
    )
    rep = from_janus_csv(p)
    assert rep.true_denials == 1
    assert rep.false_allows == 3
    assert rep.recall_of_denials == pytest.approx(0.25)
    assert rep.false_allow_rate == pytest.approx(0.75)
    assert compute_false_allow_rate(rep) == pytest.approx(0.75)


# ---------------- metrics: adversarial cell payloads ----------------------- #


def test_from_adversarial_results_all_denials_pass() -> None:
    results = [{"expected": "deny", "actual": "deny"} for _ in range(3)]
    rep = from_adversarial_results(results)
    assert rep.total_cells == 3
    assert rep.true_denials == 3
    assert rep.false_allows == 0
    assert rep.false_allow_rate == 0.0
    assert rep.precision_of_denials == 1.0
    assert rep.recall_of_denials == 1.0


def test_from_adversarial_results_false_allow_drives_rate() -> None:
    results = [
        {"expected": "deny", "actual": "deny"},
        {"expected": "deny", "actual": "allow"},
        {"expected": "deny", "actual": "defer"},
    ]
    rep = from_adversarial_results(results)
    assert rep.true_denials == 1
    assert rep.false_allows == 1
    assert rep.missed_denials == 1
    # recall / false-allow denominator excludes missed (kept for audit) by
    # the report's lookup-of-math; the rate is false_allows / denom.
    assert rep.false_allow_rate == pytest.approx(1 / 3)


def test_from_adversarial_results_empty_input_yields_zero_report() -> None:
    rep = from_adversarial_results([])
    assert rep.total_cells == 0
    assert rep.false_allow_rate == 0.0


# ---------------- report renderer ----------------------------------------- #


def test_render_report_is_self_contained_html() -> None:
    rep = MetricReport(
        suite="adversarial",
        total_cells=2,
        true_denials=2,
        false_allows=0,
        false_allow_rate=0.0,
        precision_of_denials=1.0,
        recall_of_denials=1.0,
    )
    html = render_report(rep, cells=[{"category": "x", "name": "y", "passed": "PASS"}])
    assert html.startswith("<!doctype html>")
    assert "<style>" in html
    assert "<script" not in html  # no JS attack surface
    assert "adversarial" in html
    assert "PASS" in html


def test_emit_suite_artifacts_writes_html_and_json(tmp_path: Path) -> None:
    rep = MetricReport(suite="adversarial", total_cells=2, true_denials=2)
    out_dir = tmp_path / "rep"
    html, js = emit_suite_artifacts(
        out_dir,
        metrics=rep,
        cells=[{"name": "a", "passed": "PASS"}],
        title="t",
        extra_json={"by_category": {"x": 1}},
    )
    assert html.exists() and js.exists()
    payload = json.loads(js.read_text())
    assert payload["metrics"]["suite"] == "adversarial"
    assert payload["by_category"] == {"x": 1}
    assert payload["cells"][0]["name"] == "a"


def test_adversarial_suite_emits_html_and_json_via_cli(tmp_path: Path) -> None:
    from custos.cli import main

    out = tmp_path / "adv"
    rc = main(["eval", "--suite", "adversarial", "--output-dir", str(out)])
    assert rc == 0
    assert (out / "report.html").exists()
    payload = json.loads((out / "report.json").read_text())
    #  fields all present
    for f in (
        "precision_of_denials",
        "recall_of_denials",
        "false_allow_rate",
        "prompts_per_session",
        "cognitive_load_proxy",
    ):
        assert f in payload["metrics"]
