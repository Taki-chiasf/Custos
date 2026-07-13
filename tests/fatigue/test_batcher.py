"""Tests for the batcher module: BatchWindow + build_batch_summary ."""

from __future__ import annotations

import threading
import time

from custos.fatigue.batcher import BatchWindow, build_batch_summary
from custos.schema import Invocation, SubjectContext


def _inv(tool: str = "email.send", **args: object) -> Invocation:
    return Invocation(tool=tool, args=dict(args), context=SubjectContext(user_id="u1"))


# --------------------------------------------------------------------------- #
# build_batch_summary
# --------------------------------------------------------------------------- #


def test_summary_single_call() -> None:
    summary = build_batch_summary([_inv("email.send", to="a@x.com")])
    assert "1 email.send call(s)" in summary
    assert "to" in summary


def test_summary_multiple_calls_same_keys() -> None:
    invs = [
        _inv("email.send", to="a@x.com"),
        _inv("email.send", to="b@x.com"),
    ]
    summary = build_batch_summary(invs)
    assert "2 email.send call(s)" in summary
    # Same key set -> single-group format with arg key names
    assert "args: {to}" in summary


def test_summary_multiple_calls_different_keys() -> None:
    invs = [
        _inv("email.send", to="a@x.com", subject="hi"),
        _inv("email.send", to="b@x.com"),
    ]
    summary = build_batch_summary(invs)
    assert "2 email.send call(s)" in summary
    # Two distinct key sets -> two groups
    assert "1x {subject, to}" in summary
    assert "1x {to}" in summary


def test_summary_empty_list() -> None:
    summary = build_batch_summary([])
    assert "0" in summary


def test_summary_no_arg_values_leaked() -> None:
    """Only arg *key sets* are shown; values must never appear ."""
    summary = build_batch_summary([_inv("email.send", to="secret@x.com")])
    assert "secret@x.com" not in summary
    assert "to" in summary  # keys OK


# --------------------------------------------------------------------------- #
# BatchWindow lifecycle
# --------------------------------------------------------------------------- #


def test_first_call_is_first_and_blocks_until_timer() -> None:
    window = BatchWindow(window_ms=100, max_count=0)
    is_first, event = window.add(_inv())
    assert is_first
    assert event is None
    window.wait_for_close(timeout=1.0)
    assert window.is_closed


def test_joining_call_is_not_first_and_gets_result_event() -> None:
    window = BatchWindow(window_ms=500, max_count=0)
    # First call opens the window.
    is_first1, event1 = window.add(_inv())
    assert is_first1
    # Second call joins.
    is_first2, event2 = window.add(_inv())
    assert not is_first2
    assert event2 is not None
    # Third call also joins.
    is_first3, event3 = window.add(_inv())
    assert not is_first3
    assert event3 is not None


def test_max_count_closes_window_early() -> None:
    window = BatchWindow(window_ms=5000, max_count=2)
    is_first, _ = window.add(_inv())
    assert is_first
    _, event2 = window.add(_inv())
    # max_count=2 reached -> window should close immediately.
    time.sleep(0.05)  # let the close event propagate
    assert window.is_closed


def test_signal_result_wakes_joiners() -> None:
    window = BatchWindow(window_ms=5000, max_count=0)
    window.add(_inv())
    _, event = window.add(_inv())
    assert event is not None
    assert not event.is_set()
    # Simulate the leader resolving the batch.
    from custos.schema import Decision

    window.signal_result(Decision.ALLOW)
    assert event.is_set()
    assert window.is_signaled


def test_signal_result_idempotent() -> None:
    """Calling signal_result twice does not re-set events."""
    from custos.schema import Decision

    window = BatchWindow(window_ms=5000, max_count=0)
    window.add(_inv())
    _, event = window.add(_inv())
    assert event is not None
    window.signal_result(Decision.ALLOW)
    window.signal_result(Decision.DENY)  # second call ignored
    assert event.is_set()


def test_joiner_wait_for_result_returns_decision() -> None:
    from custos.schema import Decision

    window = BatchWindow(window_ms=5000, max_count=0)
    window.add(_inv())
    _, event = window.add(_inv())
    assert event is not None

    # Signal from a different thread (simulating the leader's after_prompt).
    def _signal() -> None:
        time.sleep(0.05)
        window.signal_result(Decision.ALLOW)

    t = threading.Thread(target=_signal, daemon=True)
    t.start()
    result = window.wait_for_result(event, timeout=2.0)
    assert result == Decision.ALLOW


def test_joiner_wait_for_result_timeout_returns_none() -> None:
    window = BatchWindow(window_ms=5000, max_count=0)
    window.add(_inv())
    _, event = window.add(_inv())
    assert event is not None
    # No one signals -> timeout.
    result = window.wait_for_result(event, timeout=0.1)
    assert result is None


def test_closed_window_is_done() -> None:
    """After the window closes, is_closed stays True. The fatigue layer
    creates a fresh BatchWindow for the next batch (one-shot window)."""
    window = BatchWindow(window_ms=100, max_count=0)
    window.add(_inv())
    window.wait_for_close(timeout=1.0)
    assert window.is_closed
    # A fresh window is created by the fatigue layer, not reused.
    new_window = BatchWindow(window_ms=100, max_count=0)
    is_first, event = new_window.add(_inv())
    assert is_first
    assert event is None


def test_slots_snapshot_returns_all_invs() -> None:
    window = BatchWindow(window_ms=5000, max_count=0)
    inv1 = _inv(to="a@x.com")
    inv2 = _inv(to="b@x.com")
    window.add(inv1)
    window.add(inv2)
    snapshot = window.slots_snapshot()
    assert len(snapshot) == 2
    assert snapshot[0].tool == "email.send"
    assert snapshot[1].tool == "email.send"
