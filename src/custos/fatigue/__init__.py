"""In-memory fatigue mitigation layer (..9.15, F4/F5).

Covers dedup , suppression windows , prompt rate limits
, ask-me-later / ``DEFER`` , and batching .
Deterministic given the monotonic clock (reserves non-determinism for
the LLM assistant, not the cache).

State is single-process: a ``threading.Lock`` guards the cache, rate
counters, and open batch windows. Distributed/HA state  is a v1.1
concern.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from custos.fatigue.base import FatigueDecision, FatigueLayer, FatigueLayerAsync
from custos.fatigue.batcher import BatchWindow, build_batch_summary
from custos.schema import Decision, Invocation, PromptResponse

__all__ = ["FatigueLayer", "FatigueLayerAsync", "FatigueDecision", "InMemoryFatigueLayer"]

# Key for open batch windows: (user_id, tool).
BatchKey = tuple[str, str]


def _canonicalize(obj: object) -> object:
    """Recursively canonicalize a value for deterministic hashing (H13).

    Sorts dict keys, sorts set elements, preserves list/tuple order (positional
    semantics). Non-JSON scalars are stringified via ``repr`` for deterministic
    output across runs.
    """
    if isinstance(obj, dict):
        return {k: _canonicalize(v) for k, v in sorted(obj.items())}
    if isinstance(obj, (list, tuple)):
        return [_canonicalize(v) for v in obj]
    if isinstance(obj, set):
        return sorted(_canonicalize(v) for v in obj)  # type: ignore[type-var]
    if isinstance(obj, (bool, int, float, str, type(None))):
        return obj
    return repr(obj)


def _args_hash(args: object) -> str:
    """Stable SHA-256 hash of invocation args for dedup keying .

    Args are recursively canonicalized before hashing so identical logical
    args hash equal regardless of input ordering (H13). The
    canonical form is documented in ``DECISION_SEMANTICS.md`` for
    cross-language round-tripping (Q12).
    """
    canonical = _canonicalize(args)
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


@dataclass
class _CacheEntry:
    """One dedup/suppression cache entry."""

    decision: Decision
    expires_at: float  # monotonic deadline


class InMemoryFatigueLayer:
    """Single-process fatigue layer: dedup + suppression + rate-limit + batching.

    Dedup  and suppression  share one cache keyed by
    ``(user_id, tool, args_hash)``. The TTL comes from
    ``PromptResponse.ttl`` (set by the user's "allow for N minutes" choice,
    e.g. CLIResponder's ``A``) or falls back to ``dedup_ttl_s`` .

    Rate-limit : at most ``max_per_minute`` prompts per user per
    monotonic-minute; overflow auto-denies with an alert. A per-rule
    ``max_per_minute`` in the ``batching`` config overrides the layer default.

    Batching : when a matched rule carries ``batching`` config with
    ``window_ms``, same-tool calls within the window collapse into one
    batched prompt. The first caller blocks until the window closes (timer
    or ``max_count``), then proceeds to the responder with a deterministic
    batch summary. Joiners block until the leader's responder resolves; the
    choice is shared across the batch.

    Ask-me-later : a responder may return ``DEFER``; the layer
    does NOT cache it, so the next identical call re-prompts.

    Security : the cache stores decisions already gated by the policy
    floor. Call :meth:`clear` after :meth:`Policy.reload` to avoid
    stale-false-allows from a tightened policy.
    """

    name = "in-memory"

    def __init__(
        self,
        *,
        dedup_ttl_s: float = 300.0,
        max_per_minute: int = 0,
    ) -> None:
        self.dedup_ttl_s = dedup_ttl_s
        self.max_per_minute = max_per_minute
        self._cache: dict[tuple[str, str, str], _CacheEntry] = {}
        self._rate: dict[tuple[str, int], int] = {}
        self._batches: dict[BatchKey, BatchWindow] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Seam A: dedup / suppression lookup
    # ------------------------------------------------------------------ #

    def lookup(self, inv: Invocation) -> Decision | None:
        """Seam A: cache hit -> cached Decision; expired/miss -> None (/9.13)."""
        key = self._key(inv)
        now = time.monotonic()
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                del self._cache[key]
                return None
            return entry.decision

    # ------------------------------------------------------------------ #
    # Seam B: rate-limit + batching before the responder
    # ------------------------------------------------------------------ #

    def before_prompt(
        self,
        inv: Invocation,
        decision: Decision,
        *,
        batching: Mapping[str, Any] | None = None,
    ) -> FatigueDecision:
        """Seam B: rate-limit  + batching  before the responder."""
        # Rate limit: per-rule max_per_minute overrides layer default .
        rate_limit = self.max_per_minute
        if batching is not None and "max_per_minute" in batching:
            rate_limit = int(batching["max_per_minute"])
        if rate_limit > 0:
            key = self._rate_key(inv)
            with self._lock:
                count = self._rate.get(key, 0) + 1
                self._rate[key] = count
            if count > rate_limit:
                return FatigueDecision(
                    decision=Decision.DENY,
                    reasoning="fatigue: prompt rate limit exceeded; auto-denying (FR-9.14)",
                    cacheable=False,
                )

        # Batching : open/join a batch window if config is present.
        if batching is not None and "window_ms" in batching and decision == Decision.PROMPT:
            return self._handle_batch(inv, batching)

        return FatigueDecision(decision=decision)

    def _handle_batch(self, inv: Invocation, batching: Mapping[str, Any]) -> FatigueDecision:
        """Open/join a batch window . Returns PROMPT for the leader
        (with batch summary) or the shared decision for joiners."""
        bkey = self._batch_key(inv)
        window_ms = int(batching.get("window_ms", 2000))
        max_count = int(batching.get("max_count", 0))

        with self._lock:
            window = self._batches.get(bkey)
            if window is None or window.is_closed:
                window = BatchWindow(window_ms, max_count)
                self._batches[bkey] = window
            is_first, result_event = window.add(inv)

        if is_first:
            # Leader: block until the window closes, then return PROMPT so
            # the gateway routes through the responder with the batch summary.
            window.wait_for_close(timeout=window_ms / 1000.0 + 1.0)
            summary = build_batch_summary(window.slots_snapshot())
            return FatigueDecision(decision=Decision.PROMPT, reasoning=summary)

        # Joiner: block until the leader's responder resolves.
        # result_event is guaranteed non-None when is_first is False.
        assert result_event is not None
        batch_timeout = window_ms / 1000.0 + 35.0
        result = window.wait_for_result(result_event, timeout=batch_timeout)
        if result is None:
            return FatigueDecision(
                decision=Decision.DENY,
                reasoning="fatigue: batch window timed out waiting for leader",
            )
        return FatigueDecision(decision=result)

    # ------------------------------------------------------------------ #
    # Seam C: signal batch joiners + record dedup/suppression cache
    # ------------------------------------------------------------------ #

    def after_prompt(
        self,
        inv: Invocation,
        decision: Decision,
        response: PromptResponse | None,
        *,
        cacheable: bool = True,
    ) -> None:
        """Seam C: signal batch joiners + record dedup/suppression cache (/9.13).

        DEFER is never cached so the next identical call re-prompts .
        The batch leader (``response is not None``) signals all waiting joiners;
        joiners (``response is None``) just get dedup-cached. The ``cacheable``
        kwarg is threaded by the gateway from seam B's
        :class:`FatigueDecision.cacheable` — when ``False`` (rate-limit overflow,
        gateway-error DENY), the decision is NOT written to the dedup cache
        (C6 regression council 2026-07-22).
        """
        # Signal batch result if this is the batch leader (went through responder).
        if response is not None:
            bkey = self._batch_key(inv)
            with self._lock:
                window = self._batches.pop(bkey, None)
            if window is not None and not window.is_signaled:
                window.signal_result(decision)

        if decision == Decision.DEFER:
            return
        if not cacheable:
            return
        # Dedup/suppression cache.
        if response is not None and response.ttl is not None and response.ttl > 0:
            ttl = float(response.ttl)
        else:
            ttl = self.dedup_ttl_s
        key = self._key(inv)
        expires = time.monotonic() + ttl
        with self._lock:
            self._cache[key] = _CacheEntry(decision=decision, expires_at=expires)

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #

    def clear(self) -> None:
        """Invalidate all cache + rate + batch state — call after Policy.reload ."""
        with self._lock:
            self._cache.clear()
            self._rate.clear()
            self._batches.clear()

    # ------------------------------------------------------------------ #
    # Key helpers
    # ------------------------------------------------------------------ #

    def _key(self, inv: Invocation) -> tuple[str, str, str]:
        return (inv.context.user_id, inv.tool, _args_hash(inv.args))

    def _batch_key(self, inv: Invocation) -> BatchKey:
        return (inv.context.user_id, inv.tool)

    def _rate_key(self, inv: Invocation) -> tuple[str, int]:
        bucket = int(time.monotonic() // 60)
        return (inv.context.user_id, bucket)
