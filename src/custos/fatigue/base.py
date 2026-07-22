"""The pluggable ``FatigueLayer`` interface (..9.15).

The fatigue layer is a cache + rate-limiter that sits between policy
evaluation and the user-facing responder. The policy engine remains the sole
pure/deterministic oracle ; the fatigue layer is a deterministic cache
keyed on the monotonic clock — it never introduces the non-determinism that
 reserves for the LLM assistant.

Three seams (steps 2/4/5):

  Seam A — :meth:`FatigueLayer.lookup`: after policy ALLOW/DENY short-circuit,
    before the assistant. A cache hit returns the cached :class:`Decision` to
    short-circuit (dedup , suppression).

  Seam B — :meth:`FatigueLayer.before_prompt`: when the decision is
    ``PROMPT``, before the responder. May rate-limit , defer
    , or open/join a batch window .

  Seam C — :meth:`FatigueLayer.after_prompt`: after the responder returns.
    Records the dedup/suppression cache entry (/9.13). ``DEFER`` is
    never cached so the next identical call re-prompts .

Security note : the fatigue cache stores decisions that were already
gated by the policy floor. A policy hot-reload that tightens rules can
stale-false-allow a cached entry; callers MUST :meth:`clear` the cache (or
:meth:`Gateway.reload_policy`) after :meth:`Policy.reload`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from custos.schema import Decision, Invocation, PromptResponse

__all__ = ["FatigueLayer", "FatigueLayerAsync", "FatigueDecision"]


@dataclass(frozen=True)
class FatigueDecision:
    """Result of :meth:`FatigueLayer.before_prompt`.

    Attributes:
        decision: the decision to use (may be the original ``PROMPT``, a
            rate-limit ``DENY``, or a batched resolution from).
        reasoning: extra reasoning appended to the audit trail (empty when
            proceeding to the responder unchanged).
        cacheable: whether seam C should cache this decision .
            Transient decisions — rate-limit overflow denials, batcher
            waiting states — set ``cacheable=False`` so a stale deny does
            not poison the dedup cache.
    """

    decision: Decision
    reasoning: str = ""
    cacheable: bool = True


@runtime_checkable
class FatigueLayer(Protocol):
    """Cache + rate-limiter called by the gateway at three seams ."""

    name: str

    def lookup(self, inv: Invocation) -> Decision | None:
        """Seam A: dedup/suppression cache lookup.

        Returns the cached :class:`Decision` to short-circuit (skip assistant +
        responder), or ``None`` to proceed normally.
        """
        ...

    def before_prompt(
        self,
        inv: Invocation,
        decision: Decision,
        *,
        batching: Mapping[str, Any] | None = None,
    ) -> FatigueDecision:
        """Seam B: rate-limit / ask-me-later / batching before the responder.

        Receives the current ``PROMPT`` decision and returns a
        :class:`FatigueDecision` that may transform it (e.g. rate-limit
        overflow -> ``DENY`` with an alert, or open/join a batch window).

        ``batching`` carries the matched rule's fatigue-layer config when
        present (e.g. ``{"window_ms": 2000, "max_count": 5}``); ``None``
        means no batching config and only rate-limiting runs.
        """
        ...

    def after_prompt(
        self,
        inv: Invocation,
        decision: Decision,
        response: PromptResponse | None,
        *,
        cacheable: bool = True,
    ) -> None:
        """Seam C: record the dedup/suppression cache entry.

                ``DEFER`` is never cached so the next identical call re-prompts
                . The TTL comes from ``response.ttl`` (suppression,
        ) or the layer's default dedup TTL . The
                ``cacheable`` kwarg  is threaded by the gateway from the
                seam-B :class:`FatigueDecision.cacheable` flag — transient
                decisions (rate-limit overflow, gateway-error DENY) pass
                ``cacheable=False`` so they do not poison the dedup cache (C6
                regression, council 2026-07-22: the prior instance-slot was
                racy under AsyncGateway concurrency).
        """
        ...

    def clear(self) -> None:
        """Invalidate all cache + rate + batch state .

        Called by :meth:`Gateway.reload_policy` after a policy hot-reload
        so stale cached entries cannot shadow a freshly-tightened policy
        .
        """
        ...


@runtime_checkable
class FatigueLayerAsync(Protocol):
    """Async twin of :class:`FatigueLayer` (, resolves  sync-gateway risk).

    The fatigue layer is a deterministic in-process cache; the async seams are
    primarily a Protocol-mirror so a native-async runtime (e.g. an async
    Redis backend in a future v1.1 HA mode) can plug in without a second
    gateway type. The :class:`~custos.async_gateway.AsyncGateway` also accepts
    a sync :class:`FatigueLayer` and wraps it via :func:`asyncio.to_thread`.
    """

    name: str

    async def lookup(self, inv: Invocation) -> Decision | None:
        """Seam A (async): dedup/suppression cache lookup."""
        ...

    async def before_prompt(
        self,
        inv: Invocation,
        decision: Decision,
        *,
        batching: Mapping[str, Any] | None = None,
    ) -> FatigueDecision:
        """Seam B (async): rate-limit / ask-me-later / batching."""
        ...

    async def after_prompt(
        self,
        inv: Invocation,
        decision: Decision,
        response: PromptResponse | None,
        *,
        cacheable: bool = True,
    ) -> None:
        """Seam C (async): record the dedup/suppression cache entry."""
        ...

    async def clear(self) -> None:
        """Invalidate all cache + rate + batch state (async)."""
        ...
