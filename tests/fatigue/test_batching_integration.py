"""Integration tests for batching through the full Gateway pipeline .

These tests exercise the 3-seam gateway with a batching-configured policy:
  - First PROMPT call opens a batch window and blocks until window close.
  - Subsequent same-tool calls within the window join the batch.
  - At window close, one batched PromptRequest goes to the responder with a
    deterministic summary; the responder's choice is shared with all joiners.
  - Only one responder call is made per batch (F4).
"""

from __future__ import annotations

import threading
import time

from custos.audit import NullAuditSink
from custos.fatigue import InMemoryFatigueLayer
from custos.gateway import Gateway
from custos.policy import Policy, PolicyFile, PolicyOverlaySpec, PolicyRuleSpec
from custos.schema import (
    Decision,
    Invocation,
    PromptRequest,
    PromptResponse,
    SubjectContext,
)

# --------------------------------------------------------------------------- #
# Fakes + helpers
# --------------------------------------------------------------------------- #


class CountingResponder:
    name = "fake"

    def __init__(self, choice: Decision = Decision.ALLOW) -> None:
        self.choice = choice
        self.calls = 0
        self.last_req: PromptRequest | None = None

    def prompt(self, req: PromptRequest) -> PromptResponse:
        self.calls += 1
        self.last_req = req
        return PromptResponse(choice=self.choice)


def _ctx() -> SubjectContext:
    return SubjectContext(user_id="u1")


def _inv(tool: str = "email.send", **args: object) -> Invocation:
    return Invocation(tool=tool, args=dict(args), context=_ctx())


def _policy_prompt_batch(window_ms: int, max_count: int = 0) -> Policy:
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="base",
                rules=(
                    PolicyRuleSpec(
                        match={"tool": "*"},
                        action="prompt",
                        batching={"window_ms": window_ms, "max_count": max_count},
                    ),
                ),
            ),
        ),
    )
    return Policy.from_spec(spec)


def _policy_assist_batch(window_ms: int) -> Policy:
    spec = PolicyFile(
        version=1,
        default="deny",
        overlays=(
            PolicyOverlaySpec(
                id="base",
                rules=(
                    PolicyRuleSpec(
                        match={"tool": "*"},
                        action="assist:summarize-batch",
                        batching={"window_ms": window_ms},
                    ),
                ),
            ),
        ),
    )
    return Policy.from_spec(spec)


def _gw(
    policy: Policy,
    *,
    responder: object,
    fatigue: InMemoryFatigueLayer,
    assistant: object | None = None,
) -> Gateway:
    return Gateway(
        policy=policy,
        assistant=assistant,
        responder=responder,  # type: ignore[arg-type]
        fatigue=fatigue,
        audit_sink=NullAuditSink(),
    )


def _run_concurrent(gw: Gateway, invs: list[Invocation]) -> list[Decision]:
    """Run decide for each inv concurrently and collect results."""
    results: list[Decision] = [Decision.DENY] * len(invs)

    def call(i: int) -> None:
        results[i] = gw.decide(invs[i])

    threads = [threading.Thread(target=call, args=(i,)) for i in range(len(invs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    return results


# --------------------------------------------------------------------------- #
# same-tool calls within window collapse to one responder prompt
# --------------------------------------------------------------------------- #


def test_batch_collapses_two_calls_to_one_prompt() -> None:
    """Two same-tool calls within the window -> one responder call ."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=200),
        responder=responder,
        fatigue=fatigue,
    )
    invs = [_inv(args={"to": "a@x.com"}), _inv(args={"to": "b@x.com"})]
    results = _run_concurrent(gw, invs)

    assert all(r == Decision.ALLOW for r in results)
    assert responder.calls == 1  # only one batched prompt


def test_batch_summary_appears_in_responder_reasoning() -> None:
    """The batched PromptRequest carries the deterministic summary (F4)."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=200),
        responder=responder,
        fatigue=fatigue,
    )
    invs = [_inv(args={"to": "a@x.com"}), _inv(args={"to": "b@x.com"})]
    _run_concurrent(gw, invs)

    assert responder.last_req is not None
    assert "batched" in responder.last_req.reasoning.lower()
    assert "2 email.send call(s)" in responder.last_req.reasoning
    # Privacy: arg values must not appear
    assert "a@x.com" not in responder.last_req.reasoning
    assert "b@x.com" not in responder.last_req.reasoning


def test_batch_shares_deny_across_joiners() -> None:
    """When the responder denies the batch, all joiners get DENY."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.DENY)
    gw = _gw(
        _policy_prompt_batch(window_ms=200),
        responder=responder,
        fatigue=fatigue,
    )
    invs = [_inv(args={"to": "a"}), _inv(args={"to": "b"})]
    results = _run_concurrent(gw, invs)

    assert all(r == Decision.DENY for r in results)
    assert responder.calls == 1


def test_single_call_still_works_with_batching() -> None:
    """A single call within a batch window still prompts (no collapse needed)."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=100),
        responder=responder,
        fatigue=fatigue,
    )
    result = gw.decide(_inv(args={"to": "a@x.com"}))
    assert result == Decision.ALLOW
    assert responder.calls == 1


def test_calls_outside_window_are_separate_batches() -> None:
    """Calls separated by > window_ms form separate batches."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=100),
        responder=responder,
        fatigue=fatigue,
    )
    gw.decide(_inv(args={"to": "a@x.com"}))
    assert responder.calls == 1
    time.sleep(0.2)  # wait past the window
    gw.decide(_inv(args={"to": "b@x.com"}))
    assert responder.calls == 2  # separate batch


def test_different_tools_separate_batches() -> None:
    """Calls to different tools form separate batches (keyed by (user, tool))."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=200),
        responder=responder,
        fatigue=fatigue,
    )
    invs = [
        _inv(tool="email.send", to="a"),
        _inv(tool="fs.write", path="/tmp"),
    ]
    _run_concurrent(gw, invs)
    assert responder.calls == 2  # separate batch per tool


def test_max_count_closes_window_early() -> None:
    """max_count=2 closes the window immediately when 2 calls join."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=10000, max_count=2),
        responder=responder,
        fatigue=fatigue,
    )
    invs = [_inv(args={"to": "a"}), _inv(args={"to": "b"})]
    results = _run_concurrent(gw, invs)

    assert all(r == Decision.ALLOW for r in results)
    assert responder.calls == 1
    # Window should close well before the 10s timer.


def test_assist_summarize_batch_works_with_batching() -> None:
    """Full A8 flow: assist:summarize-batch -> A8 returns PROMPT+fatigue_hint
    -> fatigue batcher collapses calls -> one responder prompt."""
    from custos.assistants.summarize_batch import SummarizeBatchAssistant

    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_assist_batch(window_ms=200),
        responder=responder,
        fatigue=fatigue,
        assistant=SummarizeBatchAssistant(),
    )
    invs = [_inv(args={"to": "a"}), _inv(args={"to": "b"})]
    results = _run_concurrent(gw, invs)

    assert all(r == Decision.ALLOW for r in results)
    assert responder.calls == 1
    assert responder.last_req is not None
    assert "batched" in responder.last_req.reasoning.lower()


def test_batch_clears_window_after_resolution() -> None:
    """After a batch resolves, the next same-tool call opens a fresh window
    (not a joiner of the old batch)."""
    fatigue = InMemoryFatigueLayer()
    responder = CountingResponder(choice=Decision.ALLOW)
    gw = _gw(
        _policy_prompt_batch(window_ms=100),
        responder=responder,
        fatigue=fatigue,
    )
    # First batch.
    invs = [_inv(args={"to": "a"}), _inv(args={"to": "b"})]
    _run_concurrent(gw, invs)
    assert responder.calls == 1
    time.sleep(0.2)
    # Second call after window closed -> new batch.
    gw.decide(_inv(args={"to": "c"}))
    assert responder.calls == 2
