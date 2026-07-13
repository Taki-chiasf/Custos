"""A8 ``summarize-batch`` assistant - batch calls and prompt once .

Returns ``PROMPT`` with ``fatigue_hint=True`` for every call; the fatigue
layer's batcher  collects same-tool calls within a ``window_ms``
window and collapses them into one batched prompt at window close. The
deterministic batch summary is built by
:func:`custos.fatigue.batcher.build_batch_summary` (no LLM).

This assistant is the policy-visible trigger for batching: a rule with
``action: assist:summarize-batch`` + ``batching: {window_ms: ...}`` routes
through here, and the gateway passes the batching config to the fatigue
layer's ``before_prompt`` seam.
"""

from __future__ import annotations

from custos.assistants.base import AssistantBase
from custos.schema import AssistantOutput, Decision, Invocation, SubjectContext

__all__ = ["SummarizeBatchAssistant"]


class SummarizeBatchAssistant(AssistantBase):
    """Batch calls within a window, summarize, prompt once (A8).

    Always returns ``PROMPT`` with ``fatigue_hint=True``. The fatigue layer's
    batcher handles the actual windowing + summary; this assistant just
    signals to the pipeline that the call is batchable.
    """

    name = "summarize-batch"

    def decide(self, inv: Invocation, ctx: SubjectContext) -> AssistantOutput:
        return AssistantOutput(
            decision=Decision.PROMPT,
            risk=0.5,
            reasoning="summarize-batch: deferring to fatigue layer for batching",
            fatigue_hint=True,
        )
