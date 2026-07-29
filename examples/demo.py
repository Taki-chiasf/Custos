"""Custos end-to-end demo (no API key needed).

Runs the full decision pipeline against a small policy with the rule-policy
assistant (A7) and the noop responder, wrapping two plain Python callables.
Emits a JSONL audit log and prints every decision.

Usage:
    python examples/demo.py
    python examples/demo.py --audit /tmp/custos-audit.jsonl
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path
from typing import Any

from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.audit import FileAuditSink
from custos.responders import NoopResponder
from custos.schema import Decision, SideEffect, SubjectContext, ToolDescriptor
from custos.sdk import set_default_context, wrap_callables


def _policy_yaml() -> str:
    return (
        "version: 1\n"
        "default: deny\n"
        "overlays:\n"
        "  - id: base\n"
        "    rules:\n"
        "      - match: { tool: 'fs.read*' }\n"
        "        action: allow_and_audit\n"
        "      - match: { tool: 'fs.write*' }\n"
        "        action: assist:rule-policy\n"
        "      - match: { tool: 'shell.*' }\n"
        "        action: prompt\n"
        "      - match: { tool: 'email.send' }\n"
        "        action: prompt\n"
    )


def _write_policy(tmp: Path) -> Path:
    p = tmp / "demo-policy.yaml"
    p.write_text(_policy_yaml(), encoding="utf-8")
    return p


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    parser = argparse.ArgumentParser(description="Custos end-to-end demo.")
    parser.add_argument(
        "--audit",
        default="audit.jsonl",
        help="Path for the JSONL audit log (default: audit.jsonl).",
    )
    parser.add_argument(
        "--tmp",
        default=None,
        help="Directory for the demo policy file (default: a temp dir).",
    )
    parsed = parser.parse_args(args)

    tmp = Path(parsed.tmp) if parsed.tmp else Path(tempfile.mkdtemp(prefix="custos-demo-"))
    policy_path = _write_policy(tmp)
    audit_path = Path(parsed.audit)

    # Build the gateway: rule-policy assistant + noop responder + file audit.
    policy = Policy.from_yaml(policy_path)
    assistant = RulePolicy(
        rules=[
            # A7 allows low-risk writes to fs.write* (fast path, no LLM).
            (
                {"tool": "fs.write*", "side_effects": ["write"]},
                _allow_once("rule-policy: low-risk write"),
            ),
        ]
    )
    gw = Gateway(
        policy=policy,
        assistant=assistant,
        responder=NoopResponder(),
        audit_sink=FileAuditSink(audit_path),
    )

    # Two plain callables the agent would call.
    def fs_read(path: str) -> str:
        return f"contents of {path}"

    def fs_write(path: str, content: str) -> str:
        return f"wrote {len(content)} bytes to {path}"

    set_default_context(SubjectContext(user_id="demo-user", goal_id="g1"))
    # Map the Python function names to policy-space tool names so the globs
    # `fs.read*` / `fs.write*` match.
    descriptors = {
        "fs_read": ToolDescriptor(
            name="fs.read",
            risk_tier=1,
            side_effects=frozenset({SideEffect.READ}),
        ),
        "fs_write": ToolDescriptor(
            name="fs.write",
            risk_tier=2,
            side_effects=frozenset({SideEffect.WRITE}),
        ),
    }
    wrapped = wrap_callables(gw, [fs_read, fs_write], descriptors=descriptors)

    # Run three invocations exercising allow / assist->allow / prompt->deny.
    print("=== Custos end-to-end demo ===\n")
    cases: list[tuple[str, Any, Any]] = [
        ("fs.read (policy allow_and_audit)", wrapped[0], ("/etc/hosts",)),
        ("fs.write (assist:rule-policy -> allow_once)", wrapped[1], ("/tmp/x", "hello")),
        ("email.send (policy prompt -> noop deny)", _make_email(gw), ("alice@x.com", "hi")),
    ]
    for label, fn, call_args in cases:
        try:
            result = fn(*call_args)
            print(f"  {label}: ALLOWED -> {result}")
        except Exception as exc:  # noqa: BLE001
            print(f"  {label}: DENIED -> {exc}")

    # Show the audit log.
    print(f"\n=== Audit log: {audit_path} ===")
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            print(f"  {line}")
    print(f"\nPolicy file: {policy_path}")
    print(f"Audit log:   {audit_path}")
    return 0


def _allow_once(reason: str):
    from custos.schema import AssistantOutput
    return AssistantOutput(decision=Decision.ALLOW_ONCE, risk=0.1, reasoning=reason)


def _make_email(gw: Gateway):
    """A raw tool the demo calls through the gateway (not wrapped via sdk)."""
    from custos.schema import Invocation

    def _email(to: str, body: str) -> str:
        inv = Invocation(
            tool="email.send",
            args={"to": to, "body": body},
            context=SubjectContext(user_id="demo-user"),
        )
        decision = gw.decide(inv).decision
        if decision in (Decision.DENY, Decision.DEFER):
            raise PermissionDeniedMock("email.send", decision.value)
        return f"sent to {to}"

    return _email


class PermissionDeniedMock(Exception):
    def __init__(self, tool: str, decision: str) -> None:
        super().__init__(f"{tool}: {decision}")


if __name__ == "__main__":
    raise SystemExit(main())