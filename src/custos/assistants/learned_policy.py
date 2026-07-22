"""A10 ``learned-policy`` assistant - per-user learned rules, no LLM .

Learns from past user decisions (per-user model) to auto-resolve low-disagreement
calls. Cold-starts to A7 ``rule-policy`` semantics: with no observed decisions,
``decide`` falls back to a composed :class:`~custos.assistants.rule_policy.RulePolicy`.

In-process and deterministic . ``exfiltrates_args = False`` - air-gapped-safe
per Q11. A10 does NOT consume A5/A9 goals (remote-LLM exfiltrated signal); only
:class:`~custos.schema.SubjectContext` + observed decisions feed it.

Learning is fed by the host integration via :meth:`record_decision` - the same
"host calls a documented extension method" precedent as
:meth:`~custos.assistants.AssistantBase.observe_user_message` (NOT a gateway
seam - the gateway returns a bare :class:`~custos.schema.Decision`; the host
knows when a user-resolved prompt produced it and records it here).

Security (A10-poisoning mitigation):
  - Persisted rules from the ``allow_and_persist`` path go through the gateway's
    shared :func:`custos.gateway._persist_assistant_rule_impl` and inherit the
    H3 narrowness invariant (any:true/``tool:"*"``/regex/bare-allow/intersect-
    later-deny all rejected). The poisoning attack ("an attacker or confused
    approver poisons the per-user learned overlay with a broad allow") is
    structurally blocked at the gateway layer, NOT reimplemented here.
  - The ``read_only`` constructor flag (the documented opt-out mode) blocks all
    :meth:`record_decision` calls - the assistant behaves as a pure A7 rule
    policy forever, suitable for regulated deployments where learned behavior
    is disallowed.
  - Disagreement-aware: when the same ``(user, tool, args_hash)`` is observed
    with conflicting user choices, the entry is marked non-confident and
    ``decide`` falls back to the A7 rule policy rather than auto-resolving.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from custos.assistants.base import AssistantBase
from custos.assistants.rule_policy import RulePolicy
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

__all__ = ["LearnedPolicyAssistant", "LearnedPolicyStore"]


# Number of unanimous observations required before auto-resolving. Tunable via
# the constructor (``confidence_threshold``). A single observation is enough
# for the cold-start case (A10's purpose is to reduce fatigue by learning from
# the first user choice); stricter deployments raise this to 2..3.
_DEFAULT_CONFIDENCE_THRESHOLD = 1


class LearnedPolicyStore:
    """In-memory per-user learned-decision store .

    Keyed by ``(user_id, tool, args_hash)``. Each entry records the observed
    decisions + an agreement/confidence tally. ``read_only`` blocks mutation
    (the  A10-poisoning opt-out mode).

    No persistence in v1.0 RC (JSON-file persistence deferred to ; a
    signed/hot-reloadable store is a  hardened-sink concern and would
    introduce new security surface - file signing, atomic-writes integrity -
    not warranted for the RC). The store is in-process only; multi-process /
    HA sharing is a v1.1 concern .
    """

    def __init__(self, *, read_only: bool = False) -> None:
        self.read_only = read_only
        # key -> (decisions list, last_decision, agree_count, disagree_count,
        #         confident: bool). Frozen via the access pattern: callers use
        #         record/lookup and never mutate the inner tuple directly.
        self._entries: dict[
            tuple[str, str, str],
            tuple[tuple[Decision, ...], Decision, int, int, bool],
        ] = {}

    def record(
        self,
        user_id: str,
        tool: str,
        args_hash: str,
        decision: Decision,
        *,
        confidence_threshold: int = _DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        """Record an observed user decision for ``(user_id, tool, args_hash)``.

        A no-op when :attr:`read_only` (the opt-out mode). Updates the agreement
        tally: a matching choice increments ``agree_count``; a conflicting
        choice increments ``disagree_count`` and marks the entry
        non-confident (disagreement-aware fallback).
        """
        if self.read_only:
            return
        key = (user_id, tool, args_hash)
        decisions: tuple[Decision, ...]
        last: Decision
        agree: int
        disagree: int
        prev = self._entries.get(key)
        if prev is None:
            decisions = (decision,)
            last = decision
            agree = 1
            disagree = 0
        else:
            decisions = prev[0] + (decision,)
            last = decision
            # prev is (decisions, last, agree, disagree, confident). The
            # previous "last decision" is prev[1]; the agree/disagree counts
            # are prev[2]/prev[3]. We compare to the *previous* last to tally
            # agreement with the most recent prior observation.
            prev_last = prev[1]
            agree = prev[2] + (1 if decision == prev_last else 0)
            disagree = prev[3] + (1 if decision != prev_last else 0)
        # Confident iff unanimous (zero disagreements) AND enough observations.
        confident = disagree == 0 and agree >= confidence_threshold
        self._entries[key] = (decisions, last, agree, disagree, confident)

    def lookup(self, user_id: str, tool: str, args_hash: str) -> tuple[Decision, bool] | None:
        """Return ``(last_decision, confident)`` for the key, or ``None`` on miss."""
        entry = self._entries.get((user_id, tool, args_hash))
        if entry is None:
            return None
        return (entry[1], entry[4])

    def clear(self) -> None:
        """Invalidate all learned entries (mirrors :meth:`FatigueLayer.clear`)."""
        self._entries.clear()


class LearnedPolicyAssistant(AssistantBase):
    """A10: per-user learned rules .

    Cold-starts to A7 rule-policy semantics. With enough unanimous user
    observations for a ``(user, tool, args)`` triple, ``decide`` returns the
    learned decision directly; on miss / disagreement / ``read_only`` mode it
    falls back to the composed :class:`RulePolicy`.

    The ``allow_and_persist`` path (persisting a *generalized* rule across
    future calls, not just the exact triple) is delegated to the assistant's
    :class:`AssistantOutput.persist_rule` field - the gateway validates + inserts
    it via the shared narrowness-invariant machinery (H3); A10 does not
    reimplement that check (A10-poisoning mitigation).
    """

    name = "learned-policy"
    exfiltrates_args = False

    def __init__(
        self,
        *,
        store: LearnedPolicyStore | None = None,
        fallback: RulePolicy | None = None,
        rules: Sequence[tuple[Mapping[str, object], AssistantOutput]] | None = None,
        confidence_threshold: int = _DEFAULT_CONFIDENCE_THRESHOLD,
        read_only: bool = False,
    ) -> None:
        self.store = store if store is not None else LearnedPolicyStore(read_only=read_only)
        self.fallback = fallback if fallback is not None else RulePolicy(rules)
        self.confidence_threshold = confidence_threshold

    def record_decision(self, inv: Invocation, decision: Decision) -> None:
        """Host hook: record a user-resolved decision for the invocation's triple.

        Called by the host integration (Python SDK / framework adapter) after a
        user responds to a prompt for this invocation - the same "host calls a
        documented extension method" precedent as
        :meth:`~custos.assistants.AssistantBase.observe_user_message`. The
        gateway itself returns a bare :class:`Decision`; the host knows whether
        the decision came from a user-resolved prompt vs the policy floor and
        records only user-resolved outcomes here.

        A no-op when the store is ``read_only`` (the  A10 opt-out mode).
        """
        args_hash = _args_hash(inv.args)
        self.store.record(
            inv.context.user_id,
            inv.tool,
            args_hash,
            decision,
            confidence_threshold=self.confidence_threshold,
        )

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        """Consult the learned store; fall back to A7 rule-policy on miss/disagreement."""
        args_hash = _args_hash(inv.args)
        entry = self.store.lookup(inv.context.user_id, inv.tool, args_hash)
        if entry is not None:
            learned, confident = entry
            if confident:
                return AssistantOutput(
                    decision=learned,
                    risk=0.1,
                    reasoning=(
                        f"learned-policy: confident user-derived decision "
                        f"({learned.value}) for ({inv.tool}, <args-hash>)"
                    ),
                )
            # Non-confident (disagreement): do NOT auto-resolve; fall back.
        return self.fallback.decide(inv, ctx)


def _args_hash(args: Mapping[str, Any]) -> str:
    """Stable SHA-256 hash of invocation args (mirrors the fatigue layer's H13
    canonicalization so learned keys are consistent with dedup keys).

    Imports lazily so :mod:`custos.assistants` has no hard dep on
    :mod:`custos.fatigue` (avoids an import cycle).
    """
    from custos.fatigue import _args_hash as fatigue_args_hash

    return fatigue_args_hash(args)
