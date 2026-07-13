"""A11 ``delegation-aware`` assistant - depth-tiered threshold, no LLM .

Adjusts a risk strictness by :attr:`~custos.schema.SubjectContext.delegation_depth`:
deeper chains get stricter prompts. In-process and deterministic .
``exfiltrates_args = False`` - air-gapped-safe per Q11 (no LLM, no remote calls).

Composes with the existing policy ``delegation_depth`` match criterion (which
already does exact-match deny at a fixed depth - the
``delegation_depth_abuse`` adversarial cell exercises depth=4 deny this way).
A11 handles the *gradient* the policy engine cannot express: instead of a single
hard cutoff, A11 scales the threshold across the depth tiers, so shallow chains
flow through while deep chains are escalated to a prompt or denied.

The  table row ("Adjusts threshold by delegation depth — deeper chains
get stricter prompts") is silent on LLM; the  plan locked A11 as
pure-deterministic + in-process (no LLM). Decided 2026-07-17 at the  plan
question step.

Tier table (defaults; overridable via ``depth_thresholds``):

  depth 0-1 -> ``base`` strictness (use the composed :class:`RulePolicy`)
  depth 2   -> escalate above-base calls to PROMPT
  depth >=3 -> force PROMPT on any call (deep chains must ask)
  depth >=4 -> DENY (deep-chain exfiltration guard, matches the adversarial cell)

The DENY at depth >=4 mirrors the ``delegation_depth_abuse`` adversarial cell
(scenarios.py:300) which uses a policy ``delegation_depth: 4`` deny. A11 makes
that behavior available as an assistant (for routes that choose
``assist:delegation-aware`` instead of a hard policy deny), so the gradient +
the hard cap can coexist on the same call path.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence

from custos.assistants.base import AssistantBase
from custos.assistants.rule_policy import RulePolicy
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

__all__ = ["DelegationAwareAssistant", "DepthThreshold"]


# Tier callable: ``(depth, base_output) -> final_output``. : pure.
_DepthFn = Callable[[int, AssistantOutput], AssistantOutput]


# Default depth->threshold tier table. See module docstring. Each entry is
# ``(min_depth, decision_factory)`` where ``decision_factory(depth, base_out)``
# returns the final AssistantOutput. The first row whose ``min_depth`` is
# reached (deepest-first iteration) wins. Overridable via the constructor for
# deployments that want a tighter/looser gradient.


def _base_passthrough(_depth: int, base: AssistantOutput) -> AssistantOutput:
    return base


def _force_prompt(_depth: int, _base: AssistantOutput) -> AssistantOutput:
    return AssistantOutput(
        decision=Decision.PROMPT,
        risk=0.7,
        reasoning="delegation-aware: deep chain (depth>=3) → forced prompt",
    )


def _force_deny(_depth: int, _base: AssistantOutput) -> AssistantOutput:
    return AssistantOutput(
        decision=Decision.DENY,
        risk=1.0,
        reasoning="delegation-aware: deep chain (depth>=4) → deny (exfiltration guard)",
    )


def _escalate_to_prompt(_depth: int, base: AssistantOutput) -> AssistantOutput:
    if base.decision == Decision.DENY:
        return base  # floor respected — never relax a deny.
    return AssistantOutput(
        decision=Decision.PROMPT,
        risk=max(base.risk, 0.5),
        reasoning=(
            f"delegation-aware: depth={_depth} escalsates above-base "
            f"({base.decision.value}) to prompt"
        ),
    )


# Each tier row: (min_depth, callable). The assistant iterates deepest-tier-first
# and applies the first matching row's callable. This keeps the table static
#  and easily overridable via the ``depth_thresholds`` constructor param.
_DEFAULT_DEPTH_THRESHOLDS: tuple[tuple[int, _DepthFn], ...] = (
    (4, _force_deny),
    (3, _force_prompt),
    (2, _escalate_to_prompt),
    (0, _base_passthrough),
)


class DepthThreshold:
    """One tier row (a (min_depth, decision) pair, frozen + hashable for tests).

    A small typed wrapper so deployment overrides pass a clean structure instead
    of raw tuples. Use :meth:`from_mapping` for a YAML-friendly authoring shape.
    """

    __slots__ = ("min_depth", "decision")

    def __init__(self, min_depth: int, decision: Decision) -> None:
        if min_depth < 0:
            raise ValueError(f"min_depth must be non-negative, got {min_depth}")
        self.min_depth = min_depth
        self.decision = decision

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> DepthThreshold:
        md = data.get("min_depth")
        if not isinstance(md, int) or md < 0:
            raise ValueError(f"min_depth must be a non-negative int, got {md!r}")
        d = data.get("decision")
        if not isinstance(d, str):
            raise ValueError(f"decision must be a string, got {d!r}")
        return cls(min_depth=md, decision=Decision(d))


# Type alias for the internal tier-table callable. Lives at module scope for mypy.
# (The concrete tier callables are defined above: `_base_passthrough` / etc.)


class DelegationAwareAssistant(AssistantBase):
    """A11: depth-tiered threshold scaling .

    The composed :class:`RulePolicy` (A7) is consulted first; its output is then
    adjusted by the active depth tier. Floor invariant : A11 never relaxes
    a base DENY (the ``_escalate_to_prompt`` tier respects ``base.decision == DENY``).
    """

    name = "delegation-aware"
    exfiltrates_args = False

    def __init__(
        self,
        *,
        fallback: RulePolicy | None = None,
        rules: Sequence[tuple[Mapping[str, object], AssistantOutput]] | None = None,
        depth_thresholds: Sequence[tuple[int, _DepthFn]] | None = None,
    ) -> None:
        self.fallback = fallback if fallback is not None else RulePolicy(rules)
        self.depth_thresholds: tuple[tuple[int, _DepthFn], ...] = (
            tuple(depth_thresholds) if depth_thresholds is not None else _DEFAULT_DEPTH_THRESHOLDS
        )

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        base = self.fallback.decide(inv, ctx)
        depth = ctx.delegation_depth
        for min_depth, fn in self.depth_thresholds:
            if depth >= min_depth:
                return fn(depth, base)
        # No tier matched (depth < shallowest threshold). Return the base output.
        return base
