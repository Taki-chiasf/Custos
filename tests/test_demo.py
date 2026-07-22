"""Smoke test for examples/demo.py (verifies the end-to-end demo runs + emits audit)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_demo_runs_and_emits_audit(tmp_path: Path) -> None:
    audit = tmp_path / "demo-audit.jsonl"
    demo = Path(__file__).resolve().parent.parent / "examples" / "demo.py"
    result = subprocess.run(
        [sys.executable, str(demo), "--audit", str(audit), "--tmp", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, f"demo exited {result.returncode}\n{result.stderr}"
    assert "Custos end-to-end demo" in result.stdout
    # fs.read should be ALLOWED; email.send should be DENIED.
    assert "fs.read (policy allow_and_audit): ALLOWED" in result.stdout
    assert "email.send (policy prompt -> noop deny): DENIED" in result.stdout
    # Audit log written and non-empty with 3 events.
    assert audit.exists()
    lines = [ln for ln in audit.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 3
    decisions = [json.loads(ln)["decision"] for ln in lines]
    assert "allow" in decisions
    assert "allow_once" in decisions
    assert "deny" in decisions
