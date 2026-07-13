"""Batching window for fatigue mitigation (F4).

A :class:`BatchWindow` collects same-tool calls within a ``window_ms``
millisecond window. The first call opens the window and blocks until the
window closes (timer or ``max_count`` reached); subsequent calls join the
window and block until the first call's responder resolves. At window close
a deterministic batch summary is built (no LLM) and the first call
proceeds to the responder with the summary as reasoning. The responder's
choice is then shared with all waiting calls.

Threading model: the window timer is a daemon :class:`threading.Timer`; the
first call blocks on a :class:`threading.Event` (``window_closed``); each
joining call blocks on its own ``result_event``. The batch leader signals
all joiners from :meth:`InMemoryFatigueLayer.after_prompt` (seam C).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from custos.schema import Decision, Invocation

__all__ = ["BatchWindow", "BatchSlot", "build_batch_summary"]


@dataclass
class BatchSlot:
    """One call waiting in or already resolved by a batch window."""

    inv: Invocation
    result_event: threading.Event


class BatchWindow:
    """One open batching window for a (user, tool) pair .

    The first caller (``is_first=True``) blocks on :meth:`wait_for_close`
    until the timer fires or ``max_count`` is reached, then returns PROMPT
    so the gateway routes it through the responder with the batch summary.
    Joining callers block on their ``result_event`` until
    :meth:`signal_result` is called by the leader's ``after_prompt``.
    """

    def __init__(self, window_ms: int, max_count: int) -> None:
        self.window_ms = window_ms
        self.max_count = max_count
        self._slots: list[BatchSlot] = []
        self._lock = threading.Lock()
        self._window_closed = threading.Event()
        self._result: Decision | None = None
        self._signaled = False
        self._timer: threading.Timer | None = None

    @property
    def is_closed(self) -> bool:
        return self._window_closed.is_set()

    @property
    def is_signaled(self) -> bool:
        return self._signaled

    def add(self, inv: Invocation) -> tuple[bool, threading.Event | None]:
        """Add a call to the batch.

        Returns ``(is_first, result_event)``. For the first caller
        ``result_event`` is ``None`` (the caller blocks on
        :meth:`wait_for_close` instead). For joiners, ``result_event`` is the
        per-call event to block on via :meth:`wait_for_result`.
        """
        slot = BatchSlot(inv=inv, result_event=threading.Event())
        with self._lock:
            is_first = len(self._slots) == 0
            self._slots.append(slot)
            if is_first:
                self._timer = threading.Timer(self.window_ms / 1000.0, self._close)
                self._timer.daemon = True
                self._timer.start()
                return (True, None)
            if self.max_count > 0 and len(self._slots) >= self.max_count:
                self._close_locked()
            return (False, slot.result_event)

    def wait_for_close(self, timeout: float | None = None) -> bool:
        """Block until the window closes. Returns ``True`` if closed."""
        # Slight margin over window_ms to let the timer fire.
        if timeout is None:
            timeout = self.window_ms / 1000.0 + 1.0
        return self._window_closed.wait(timeout)

    def wait_for_result(
        self, event: threading.Event, timeout: float | None = None
    ) -> Decision | None:
        """Block until the batch resolves. Returns the decision or ``None`` on timeout."""
        if event.wait(timeout):
            return self._result
        return None

    def signal_result(self, decision: Decision) -> None:
        """Signal all waiting joiners with the batch result (called by the leader)."""
        with self._lock:
            if self._signaled:
                return
            self._signaled = True
            self._result = decision
            for slot in self._slots[1:]:  # skip the leader (slot 0)
                slot.result_event.set()

    def slots_snapshot(self) -> list[Invocation]:
        """Return a snapshot of all calls in the batch (for summary building)."""
        with self._lock:
            return [s.inv for s in self._slots]

    def _close(self) -> None:
        with self._lock:
            self._close_locked()

    def _close_locked(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self._window_closed.set()


def build_batch_summary(invs: list[Invocation]) -> str:
    """Build a deterministic batch summary (no LLM) for the responder.

    Format (F4):
        batched N <tool> call(s) in <window>ms window
          Kx {arg1, arg2, ...}  (grouped by arg-key set)

    Only arg *key sets* are shown (not values) for privacy .
    """
    if not invs:
        return "batched 0 calls (empty window)"
    tool = invs[0].tool
    count = len(invs)
    # Group by sorted arg-key set (privacy: no values).
    groups: dict[frozenset[str], int] = {}
    for inv in invs:
        keyset = frozenset(inv.args.keys()) if isinstance(inv.args, dict) else frozenset()
        groups[keyset] = groups.get(keyset, 0) + 1
    lines = [f"batched {count} {tool} call(s)"]
    if len(groups) == 1:
        keys = sorted(next(iter(groups.keys())))
        lines.append(f"  args: {{{', '.join(keys)}}}")
    else:
        for keyset, cnt in sorted(groups.items(), key=lambda x: -x[1]):
            keys = sorted(keyset)
            lines.append(f"  {cnt}x {{{', '.join(keys)}}}")
    return "\n".join(lines)
