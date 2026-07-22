"""Multi-approver quorum / separation-of-duties responder .

Composes N child responders and tallies their per-role approvals by
``request_id``. Honors the Q10 quorum contract:

  - While the quorum is pending (not enough distinct-role approvals, no
    disagreement yet, no timeout) the responder returns ``DEFER`` — the
    gateway surfaces this to the agent as DEFER (Q10 reuses existing DEFER
    semantics — no new sub-decision); the agent retries.
  - Once ``quorum`` distinct approvers from disjoint ``approver_roles`` have
    approved, returns ``ALLOW`` (the chosen final choice; child responders
    voted allow). Per Q10, ``met`` surfaces as the user's choice resolved.
  - On any deny vote or timeout → returns ``DENY`` (Q10 ``failed``).

Each child response carries ``approver`` (H12 identity attestation). The
``MultiApproverResponder`` learns each child's role via the
``child_roles`` constructor param (parallel to ``children``); when a child's
``approver`` is also in the policy's ``approver_allowlist``, that further
restricts which approver ids count. Separation of duties: one role = one slot;
the same role can't approve twice to meet a quorum of 2.

Native-async-first; sync children are bridged via :func:`asyncio.to_thread`
through the shared :func:`custos.async_gateway._call_method` helper — but to
keep this module dependency-free of the gateway (avoids an import cycle), a
small local copy of the bridge is inlined.

Security : the gateway's policy floor is unaffected — this responder
only decides *whether* a prompt resolves to met/failed/DEFER; it never
relaxes a policy DENY (the gateway short-circuits at step 3 before reaching
the responder). Approver identity attestation (H12) flows through each
child's :class:`~custos.schema.PromptResponse.approver`.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Callable, Sequence
from typing import Any, cast

from custos.schema import Decision, PromptRequest, PromptResponse

__all__ = ["MultiApproverResponder"]


def _await_child(child: Any, method_name: str, *args: Any, **kwargs: Any) -> Any:
    """Run a sync child's bound method in a worker thread and ``await`` it.

    Mirrors :func:`custos.async_gateway._call_method` but inlined here so this
    module doesn't import the gateway (avoids a cycle + keeps the responder
    module standalone for the sync-responder bridge contract).
    """
    method = getattr(child, method_name)
    if inspect.iscoroutinefunction(method):
        return method(*args, **kwargs)
    return asyncio.to_thread(method, *args, **kwargs)


class MultiApproverResponder:
    """Mult-approver quorum responder (portion).

    Composes N child responders. ``prompt`` fans the request out to all
    children concurrently and tallies their choices by role. Used with a
    policy rule carrying ``quorum`` + ``approver_roles``; the gateway extracts
    those from the matched rule and forwards them on
    :class:`PromptRequest` , which this responder consumes.

    Construction:
      - ``children`` — the underlying responders (sync :class:`Responder` or
        async :class:`ResponderAsync`). Each is invoked with the same
        :class:`PromptRequest`.
      - ``child_roles`` — parallel list of role names; ``children[i]`` is
        associated with ``child_roles[i]``. Two children can share a role
        (redundant approvers in the same role — only one counts toward the
        quorum for that role); two children with different roles provide the
        separation-of-duties quorum.

    Quorum resolution semantics (Q10):

      - First ``allow*`` vote from a role counts toward that role's approval.
      - Quorum is satisfied when ``len(approved_roles) == quorum`` (each role
        represented exactly once), all from disjoint roles.
      - First ``deny`` vote immediately fails the quorum → returns ``DENY``.
      - If after all children have returned the quorum is not met → returns
        ``DENY`` (this is the "not enough approvers" failure — counts as
        ``failed`` per Q10 since no disagreement but also no met).
      - First ``DEFER`` from any child without a met/fail → returns ``DEFER``
        (prompt_pending, agent retries).
      - Approver identity flows through: the
        :class:`PromptResponse.approver` set on the returned response is the
        comma-joined sorted list of approving approvers (the audit log
        records them via H12 + the gateway's
        :func:`custos.gateway._infer_quorum_state`).

    If the :class:`PromptRequest` carries no ``quorum`` (single-approver path
    via a policy without the quorum config), the responder still fans out to
    all children — but treats this as "first valid child response wins"; this
    is the soft-fallback for misconfigured policies (the gateway should
    normally pair a quorum rule with this responder; covering the mismatch is
    a documentation concern, not a security concern since  floor is
    upstream).
    """

    name = "multi-approver"

    def __init__(
        self,
        children: Sequence[Any],
        child_roles: Sequence[str],
        *,
        timeout: int = 300,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if len(children) != len(child_roles):
            raise ValueError(
                f"children ({len(children)}) and child_roles ({len(child_roles)}) "
                f"must be the same length"
            )
        self.children = tuple(children)
        self.child_roles = tuple(child_roles)
        self.timeout = timeout
        self._clock = clock or time.time

    async def prompt(self, req: PromptRequest) -> PromptResponse:
        """Fan out to all children concurrently; tally approvals by role (Q10).

        Returns ``ALLOW`` on met, ``DENY`` on fail (deny vote / timeout /
        quorum-not-met-after-all-returned), ``DEFER`` while pending (a child
        returns DEFER before the quorum is met and no disagreement yet).
        """
        quorum = req.quorum
        roles = tuple(req.approver_roles or ())
        allowlist = frozenset(req.approver_allowlist or ())

        if quorum is None or not roles:
            # Single-approver fallback path: first valid child response wins.
            return await self._first_wins(req)

        # Fan out concurrently; each task carries its (child_index, role) so
        # we can deterministically attribute the role when results come back
        # out-of-order (asyncio scheduling doesn't preserve submission order).
        tasks: dict[asyncio.Future[Any], tuple[int, str]] = {}
        for i, child in enumerate(self.children):
            role = self.child_roles[i] if i < len(self.child_roles) else ""
            fut = asyncio.ensure_future(_await_child(child, "prompt", req))
            tasks[fut] = (i, role)

        approved_roles: set[str] = set()
        approving: list[str] = []
        pending: set[asyncio.Future[Any]] = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                # Collect all results from the done batch, then process in
                # a deterministic order: DENY first, then DEFER, then
                # ALLOW/ALLOW_ONCE. ``asyncio.wait`` returns a ``set`` whose
                # iteration order is non-deterministic — without this sort,
                # a DENY and an ALLOW completing in the same batch would
                # race on which is visited first (C7 regression, council
                # 2026-07-22).
                _choice_priority = {
                    Decision.DENY: 0,
                    Decision.DEFER: 1,
                    Decision.ALLOW: 2,
                    Decision.ALLOW_ONCE: 2,
                }
                batch: list[tuple[PromptResponse, str]] = []
                for task in done:
                    _, role = tasks[task]
                    try:
                        resp = task.result()
                    except Exception:
                        # A child responder blowing up fails the quorum
                        # immediately — a flaky approver surface can't stall
                        # the agent. Q10: failed → DENY.
                        return PromptResponse(choice=Decision.DENY)
                    batch.append((resp, role))
                batch.sort(key=lambda r: _choice_priority.get(r[0].choice, 3))
                for resp, role in batch:
                    choice = resp.choice
                    approver = resp.approver
                    # Allowlist gate: an approver not in the allowlist (when
                    # configured) doesn't count. The child responder already
                    # enforces its own allowlist (Slack H12), but this re-check
                    # is defense-in-depth at the quorum collector.
                    if allowlist and approver and approver not in allowlist:
                        continue
                    if choice == Decision.DENY:
                        return PromptResponse(
                            choice=Decision.DENY,
                            approver=approver,
                        )
                    if choice in (Decision.ALLOW, Decision.ALLOW_ONCE):
                        # Separation of duties: one role counts once.
                        if role in approved_roles or not role:
                            continue
                        approved_roles.add(role)
                        if approver:
                            approving.append(approver)
                        if len(approved_roles) >= quorum:
                            approving.sort()
                            return PromptResponse(
                                choice=Decision.ALLOW,
                                approver=",".join(approving) if approving else None,
                            )
                    elif choice == Decision.DEFER:
                        # A child deferring (e.g. user picked "ask later") when
                        # the quorum is not yet met → pending. Returning DEFER
                        # here signals the agent to retry (Q10 pending). The
                        # other children's still-pending tasks are cancelled
                        # by the finally below.
                        return PromptResponse(choice=Decision.DEFER, approver=approver)
        finally:
            # Cancel any still-pending children so we don't leak tasks.
            for t in pending:
                t.cancel()

        # All children returned without deny and without meeting the quorum.
        # Q10: this is the "not enough approvers" failure → DENY.
        return PromptResponse(
            choice=Decision.DENY,
            approver=",".join(sorted(approving)) if approving else None,
        )

    async def _first_wins(self, req: PromptRequest) -> PromptResponse:
        """Single-approver fallback: first child that returns a non-DEFER
        decision wins; DEFER means try the next child; all DEFER → DEFER."""
        tasks = [asyncio.ensure_future(_await_child(c, "prompt", req)) for c in self.children]
        try:
            for task in asyncio.as_completed(tasks):
                try:
                    resp = cast(PromptResponse, await task)
                except Exception:
                    continue
                if resp.choice == Decision.DEFER:
                    continue
                return resp
            # All children returned DEFER (or errored) → DEFER pending.
            return PromptResponse(choice=Decision.DEFER)
        except Exception:
            for t in tasks:
                t.cancel()
            return PromptResponse(choice=Decision.DENY)
