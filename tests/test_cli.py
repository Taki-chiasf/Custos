"""Tests for ``custos audit tail``  + the console entrypoint."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from custos.cli import main


def _write_jsonl(path: Path, events: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n",
        encoding="utf-8",
    )


def test_no_args_prints_usage(capsys: object) -> None:
    rc = main([])
    out = _stdout(capsys)
    assert rc == 0
    assert "custos" in out
    assert "audit" in out


def test_audit_tail_prints_last_n(tmp_path: Path, capsys: object) -> None:
    p = tmp_path / "audit.jsonl"
    events = [{"i": i, "decision": "deny"} for i in range(5)]
    _write_jsonl(p, events)
    rc = main(["audit", "tail", str(p), "-n", "2"])
    out = _stdout(capsys)
    assert rc == 0
    # Last 2 events printed as pretty JSON blocks.
    assert out.count('"i": 3') == 1
    assert out.count('"i": 4') == 1
    assert '"i": 0' not in out


def test_audit_tail_default_n_is_10(tmp_path: Path, capsys: object) -> None:
    p = tmp_path / "audit.jsonl"
    events = [{"i": i} for i in range(15)]
    _write_jsonl(p, events)
    rc = main(["audit", "tail", str(p)])
    out = _stdout(capsys)
    assert rc == 0
    # Only events 5..14 (the last 10) should be present.
    assert '"i": 5' in out
    assert '"i": 14' in out
    assert '"i": 4' not in out


def test_audit_tail_empty_file(tmp_path: Path, capsys: object) -> None:
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    rc = main(["audit", "tail", str(p)])
    _, err = _capture(capsys)
    assert rc == 0
    assert "no events" in err


def test_audit_tail_missing_file(tmp_path: Path, capsys: object) -> None:
    rc = main(["audit", "tail", str(tmp_path / "nope.jsonl")])
    _, err = _capture(capsys)
    assert rc == 1
    assert "not found" in err


def test_audit_tail_skips_unparseable_lines(tmp_path: Path, capsys: object) -> None:
    p = tmp_path / "audit.jsonl"
    p.write_text('{"ok": true}\nnot json\n{"ok": false}\n', encoding="utf-8")
    rc = main(["audit", "tail", str(p)])
    out, err = _capture(capsys)
    assert rc == 0
    assert '"ok": true' in out
    assert '"ok": false' in out
    assert "unparseable" in err


def test_eval_unknown_suite_returns_2(capsys: object) -> None:
    rc = main(["eval", "--suite", "nope", "--dry-run"])
    out, err = _capture(capsys)
    assert rc == 2
    assert "unknown suite" in err


def test_eval_janus_v1_dry_run_smoke(tmp_path: Path, capsys: object) -> None:
    out_dir = tmp_path / "eval_smoke"
    rc = main(
        [
            "eval",
            "--suite",
            "janus-v1",
            "--smoke",
            "--dry-run",
            "--output-dir",
            str(out_dir),
        ]
    )
    assert rc == 0
    assert (out_dir / "manifest.json").exists()


def test_audit_replay_requires_policy_flag(tmp_path: Path) -> None:
    p = tmp_path / "audit.jsonl"
    _write_jsonl(p, [{"invocation": {"tool": "fs.read"}, "decision": "allow"}])
    # argparse rejects subparser without required --policy -> SystemExit(2).
    with pytest.raises(SystemExit) as exc:
        main(["audit", "replay", str(p)])
    assert exc.value.code == 2


# --------------------------------------------------------------------------- #
# capsys helpers (capys yields a (out, err) namedtuple via readouterr)
# --------------------------------------------------------------------------- #


def _capture(capsys: object) -> tuple[str, str]:
    """Call capsys.readouterr once and return (out, err)."""
    readouterr = getattr(capsys, "readouterr", None)
    if readouterr is None:
        return "", ""
    result = readouterr()
    return result.out, result.err


def _stdout(capsys: object) -> str:
    return _capture(capsys)[0]


def _stderr(capsys: object) -> str:
    return _capture(capsys)[1]
