"""Custos quorum / separation-of-duties demo .

End-to-end example of a policy rule that requires ``quorum: 2`` distinct
approvers from disjoint ``approver_roles`` (e.g. ``finance`` + ``security``)
to clear a ``payment.*`` tool call. The responder is a
:class:`~custos.responders.multi_approver.MultiApproverResponder` composing
two stub children (one per role); the demo drives the call through an
:class:`~custos.AsyncGateway` and prints the quorum state recorded in the
audit trail.

Key observations to look for in the audit log:
  - First run with only the ``finance`` role approving: DENY (quorum not met).
  - Second run with both ``finance`` + ``security`` approving: ALLOW
    (quorum ``met``).
  - Third run with ``finance`` deny + ``security`` allow: DENY (a deny vote
    fails the quorum immediately, ``failed``).

Usage:
    python examples/quorum_demo.py
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from custos import AsyncGateway, Policy
from custos.audit import FileAuditSink
from custos.responders import MultiApproverResponder
from custos.schema import (
    Decision,
    Invocation,
    PromptRequest,
    PromptResponse,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)

# --------------------------------------------------------------------------- #
# Stub responders: each child stands in for a Slack / web surface where one
# role would approve. The demo programmatically controls each child's vote.
# --------------------------------------------------------------------------- #


class StubResponder:
    """Sync stub responder that returns a pre-configured vote.

    The ``approver`` field simulates H12 attestation (Slack ``payload.user.id``
    or CLI user). Sync here, but :class:`MultiApproverResponder` bridges sync
    children via :func:`asyncio.to_thread`, so this works in the async demo.
    """

    name: str

    def __init__(self, role_name: str, vote: Decision, approver: str) -> None:
        self.name = role_name
        self._vote = vote
        self._approver = approver

    def prompt(self, req: PromptRequest) -> PromptResponse:
        return PromptResponse(choice=self._vote, approver=self._approver)


def _policy_yaml() -> str:
    return (
        "version: 1\n"
        "default: deny\n"
        "overlays:\n"
        "  - id: base\n"
        "    rules:\n"
        "      - match: { tool: 'payment.*' }\n"
        "        action: prompt\n"
        "        quorum: 2\n"
        "        approver_roles: [finance, security]\n"
        "        approver_allowlist: [alice@corp, bob@corp, carol@corp]\n"
    )


def _write_policy(tmp: Path) -> Path:
    p = tmp / "quorum-policy.yaml"
    p.write_text(_policy_yaml(), encoding="utf-8")
    return p


async def _run_case(
    gw: AsyncGateway,
    vote_finance: Decision,
    vote_security: Decision,
    *,
    label: str,
) -> None:
    """Reconfigure the responder children, drive one call, print the audit row."""
    # We rebuild the gateway per case so the children reflect the case's votes.
    audit_path = gw._audit.path if hasattr(gw._audit, "path") else None  # type: ignore[attr-defined]
    sink = FileAuditSink(audit_path) if audit_path else None
    finance = StubResponder("finance", vote_finance, approver="alice@corp")
    security = StubResponder("security", vote_security, approver="bob@corp")
    multi = MultiApproverResponder(
        children=[finance, security],
        child_roles=["finance", "security"],
    )
    gw2 = AsyncGateway(
        policy=gw.policy,
        responder=multi,
        audit_sink=sink or FileAuditSink("/tmp/custos-quorum-demo.jsonl"),
        default_timeout_ms=5_000,
    )

    inv = Invocation(
        tool="payment.refund",
        args={"order_id": "ord-123", "amount_cents": 4999},
        context=SubjectContext(user_id="ops-user", goal_id="g1"),
        descriptor=ToolDescriptor(
            name="payment.refund",
            risk_tier=5,
            side_effects=frozenset({SideEffect.PAYMENT}),
        ),
    )
    decision = (await gw2.decide(inv)).decision
    print(f"  {label}: {decision.value}")


async def main_async() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="custos-quorum-"))
    policy_path = _write_policy(tmp)
    audit_path = tmp / "quorum-audit.jsonl"
    policy = Policy.from_yaml(policy_path)
    gw = AsyncGateway(
        policy=policy,
        audit_sink=FileAuditSink(audit_path),
        default_timeout_ms=5_000,
    )

    print("=== Custos quorum / separation-of-duties demo ===\n")
    print("Policy rule: payment.* requires quorum=2 from roles [finance, security]\n")
    await _run_case(
        gw, Decision.ALLOW, Decision.DEFER, label="A. finance alone approves (security defers)"
    )
    await _run_case(gw, Decision.ALLOW, Decision.ALLOW, label="B. finance + security both approve")
    await _run_case(
        gw, Decision.DENY, Decision.ALLOW, label="C. finance denies (security approves)"
    )

    print(f"\n=== Audit log: {audit_path} ===")
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        evt = json.loads(line)
        print(
            f"  decision={evt['decision']:<10} "
            f"quorum_state={evt.get('quorum_state') or '-':<8} "
            f"approver={evt.get('approver') or '-'}"
        )
    print(f"\nPolicy file: {policy_path}")
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    raise SystemExit(main())
