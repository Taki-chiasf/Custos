"""``custos audit replay <file> --policy new.yaml`` .

What-if analysis: re-runs a session's recorded decisions against a new policy
floor (deterministic). Reads JSONL audit events written by
:class:`custos.audit.FileAuditSink`; for each event reconstructs the
:class:`~custos.schema.Invocation` and
:class:`~custos.schema.SubjectContext`, evaluates the new
:class:`~custos.policy.engine.Policy`, and prints old decision -> new outcome.

The replay uses ONLY the policy engine (no assistant / responder / fatigue) so
it stays deterministic and dependency-free: ASSIST outcomes resolve to the
matched rule's action label (e.g. ``assist:risk-assessment``), never to an LLM
call. This is a policy-floor what-if, not a full-pipeline replay.

Exit codes:
  0 - replay completed (regardless of how many decisions changed).
  1 - malformed audit log / policy file / CLI args.

Usage:
  custos audit replay audit.jsonl --policy new.yaml [--policy-old old.yaml]
"""

from __future__ import annotations

import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

__all__ = ["replay", "ReplayResult", "main"]


@dataclass(frozen=True)
class ReplayResult:
    """Aggregate of one replay pass ."""

    total: int
    skipped: int  # events missing invocation/subject; not replayable
    changed: int
    by_outcome: dict[str, int]

    @property
    def unchanged(self) -> int:
        return self.total - self.skipped - self.changed


def _load_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"audit log not found: {path}")
    out: list[dict[str, Any]] = []
    for ln in path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _invocation_from(payload: dict[str, Any]) -> tuple[Any, Any] | None:
    """Reconstruct (Invocation, SubjectContext) from an audit-event dict.

    Returns ``None`` if either record is missing the required fields. We avoid
    importing the custos package eagerly so this module stays usable from
    the CLI even when custos is installed but unused.
    """
    inv_data = payload.get("invocation")
    subj_data = payload.get("subject")
    if not isinstance(inv_data, dict) or not isinstance(subj_data, dict):
        return None
    tool = inv_data.get("tool")
    if not tool:
        return None
    user_id = subj_data.get("user_id") or ""
    from custos.schema import Invocation, SideEffect, SubjectContext, ToolDescriptor

    descriptor = None
    desc_data = inv_data.get("descriptor")
    if isinstance(desc_data, dict) and desc_data.get("name"):
        try:
            descriptor = ToolDescriptor(
                name=str(desc_data["name"]),
                risk_tier=int(desc_data.get("risk_tier", 3)),
                reversible=bool(desc_data.get("reversible", False)),
                side_effects=frozenset(
                    SideEffect(se)
                    for se in desc_data.get("side_effects", [])
                    if isinstance(se, str) and se in {member.value for member in SideEffect}
                ),
            )
        except (ValueError, TypeError):
            descriptor = None
    ctx = SubjectContext(
        user_id=str(user_id),
        goal_id=subj_data.get("goal_id"),
        task_id=subj_data.get("task_id"),
        delegation_chain=tuple(subj_data.get("delegation_chain", []) or ()),
        session_ttl=subj_data.get("session_ttl"),
    )
    args = inv_data.get("args")
    if not isinstance(args, dict):
        args = {}
    inv = Invocation(
        tool=str(tool),
        args=args,
        context=ctx,
        descriptor=descriptor,
        request_id=inv_data.get("request_id"),
    )
    return inv, ctx


def _load_policy(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    from custos.policy.engine import Policy

    return Policy.from_yaml(str(path))


def _new_decision_label(outcome: Any, policy: Any, inv: Any) -> str:
    """Map a PolicyOutcome to a display string; for ASSIST expose the rule action."""
    from custos.schema import PolicyOutcome

    if outcome == PolicyOutcome.ALLOW:
        return "allow"
    if outcome == PolicyOutcome.DENY:
        return "deny"
    if outcome == PolicyOutcome.PROMPT:
        return "prompt"
    # ASSIST - resolve the matched rule's action (e.g. ``assist:risk-assessment``)
    rule = policy.matched_rule(inv)
    if rule is not None:
        return str(rule.action)
    return "assist"


def replay(
    audit_path: str | Path,
    policy_path: str | Path,
    *,
    stream: IO[str] | None = None,
) -> ReplayResult:
    """Replay ``audit_path`` against ``policy_path``; return aggregate counts."""
    out_stream: IO[str] = stream if stream is not None else sys.stdout
    audit_path = Path(audit_path)
    policy_path = Path(policy_path)
    events = _load_events(audit_path)
    policy = _load_policy(policy_path)

    total = len(events)
    skipped = 0
    changed = 0
    by_outcome: dict[str, int] = {}
    for ev in events:
        pair = _invocation_from(ev)
        if pair is None:
            skipped += 1
            continue
        inv, _ctx = pair
        old_decision = str(ev.get("decision", "?"))
        outcome = policy.evaluate(inv)
        new_label = _new_decision_label(outcome, policy, inv)
        by_outcome[new_label] = by_outcome.get(new_label, 0) + 1
        line = f"{ev.get('ts_unix_ms', '')} {inv.tool:<20} old={old_decision:<18} new={new_label}"
        print(line, file=out_stream)
        if new_label != old_decision:
            changed += 1
    return ReplayResult(
        total=total,
        skipped=skipped,
        changed=changed,
        by_outcome=by_outcome,
    )


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if len(argv) < 2:
        print(
            "usage: custos audit replay <audit.jsonl> --policy <new.yaml>",
            file=sys.stderr,
        )
        return 1
    audit = Path(argv[0])
    policy: str | None = None
    # Accept `--policy X` or a trailing positional policy path.
    if "--policy" in argv:
        idx = argv.index("--policy")
        if idx + 1 >= len(argv):
            print("custos audit replay: --policy requires a value", file=sys.stderr)
            return 1
        policy = argv[idx + 1]
    elif len(argv) >= 2:
        policy = argv[-1]
    if not policy:
        print("custos audit replay: --policy <file> is required", file=sys.stderr)
        return 1
    try:
        result = replay(audit, Path(policy))
    except (FileNotFoundError, ValueError) as exc:
        print(f"custos audit replay: {exc}", file=sys.stderr)
        return 1
    print(
        f"replay: {result.total} events, "
        f"{result.changed} changed, {result.unchanged} unchanged, "
        f"{result.skipped} skipped -> {dict(result.by_outcome)}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
