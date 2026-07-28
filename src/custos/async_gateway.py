"""Async twin of :class:`~custos.gateway.Gateway` .

Resolves the  "Sync gateway blocks async agents" risk: native-async agent
frameworks (AutoGen / OpenAI Agents SDK / Anthropic agent SDK / Google ADK /
LlamaIndex / MCP runtimes, all landing in  behind this surface) can
drive the full 8-step decision pipeline without a single blocking call.

The pipeline is identical to :class:`Gateway.decide`; only the seams that may
perform I/O (assistant ``decide``, responder ``prompt``, fatigue
``lookup``/``before_prompt``/``after_prompt``) are awaited. The deterministic
policy engine (thread-safe via :class:`threading.RLock`) is invoked
synchronously and inline - it performs no I/O.

Bridge contract: the gateway accepts either the async Protocols
(:class:`~custos.assistants.AssistantAsync`,
:class:`~custos.responders.ResponderAsync`,
:class:`~custos.fatigue.FatigueLayerAsync`) - which it awaits directly - OR the
matching sync Protocols, which it isolates in a worker thread via
:func:`asyncio.to_thread`. Native-async impls get zero overhead; sync impls
keep working unchanged (the 350-test sync suite never co-mingles with async).

Invariants  carry over verbatim from the sync gateway:
  - policy is the floor; an assistant may only ESCALATE strictness.
  - assistant output is untrusted; ``allow_and_persist`` rules are validated
    and inserted via the shared :func:`custos.gateway._persist_assistant_rule_impl`.
  - prompt payloads are redacted by the gateway before reaching a responder.
  - the ASSIST/PROMPT branch is exception-safe (H8) - audit + fatigue seam C
    ALWAYS run in ``finally``; assistant/responder/fatigue errors convert to
    a safe ``DENY`` with error reasoning.
"""

from __future__ import annotations

import asyncio
import inspect
import time
import uuid
from collections.abc import Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, Any, cast

from custos.assistants.base import AssistantRegistry
from custos.gateway import (
    _apply_assistant_output_impl,
    _evaluate_with_match,
    _exfiltrates_restricted,
    _infer_quorum_state,
    _resolve_audit_sink,
    _resolve_batching,
    _resolve_quorum,
)
from custos.policy import Policy
from custos.schema import (
    AssistantOutput,
    AuditEvent,
    Decision,
    Invocation,
    PolicyOutcome,
    PromptRequest,
    PromptResponse,
)

if TYPE_CHECKING:
    from custos.assistants.base import Assistant, AssistantAsync
    from custos.audit import AuditSink
    from custos.fatigue.base import FatigueLayer, FatigueLayerAsync
    from custos.responders.base import Responder, ResponderAsync

__all__ = ["AsyncGateway"]


def _await_via_thread(method: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a sync bound method in a worker thread and ``await`` it.

    Used when the supplied assistant / responder / fatigue impl is sync - the
    I/O it performs (LLM HTTP call, Slack webhook POST, ``threading.Event.wait``
    in CLI / Web / Slack responders) must NOT block the event loop. Keyword
    args are forwarded verbatim (the fatigue ``before_prompt`` seam uses
    ``batching=...`` keyword-only per).
    """
    return asyncio.to_thread(method, *args, **kwargs)


async def _call_method(obj: Any, method_name: str, *args: Any, **kwargs: Any) -> Any:
    """Invoke ``obj.<method_name>(*args, **kwargs)``, awaiting native-async impls
    inline and isolating sync impls in a worker thread (bridge).

    Detection is by :func:`inspect.iscoroutinefunction` on the bound method -
    cheap (one attribute check) and exact for ``async def`` on the instance's
    class (covers subclasses and Protocol duck-types alike). Keyword args are
    forwarded verbatim (the fatigue ``before_prompt`` seam uses
    ``batching=...`` keyword-only per).
    """
    method = getattr(obj, method_name)
    if inspect.iscoroutinefunction(method):
        return await method(*args, **kwargs)
    return await _await_via_thread(method, *args, **kwargs)


class AsyncGateway:
    """The async middleware an agent wraps its tool registry with .

    See module docstring for the bridge contract and  invariants.
    """

    def __init__(
        self,
        policy: Policy,
        assistant: Assistant | AssistantAsync | None = None,
        responder: Responder | ResponderAsync | None = None,
        audit_sink: (AuditSink | str | list[AuditSink] | tuple[AuditSink, ...] | None) = None,
        fatigue: FatigueLayer | FatigueLayerAsync | None = None,
        *,
        default_timeout_ms: int = 30_000,
        assistants: list[Assistant | AssistantAsync] | None = None,
        local_only: bool = False,
    ) -> None:
        """``local_only`` enables the air-gapped profile (H4). See
        :class:`custos.gateway.Gateway` (C4 regression, council 2026-07-22).
        The ``audit_sink`` typing mirrors the sync gateway so the
        ``[FileAuditSink, OTLPAuditSink, PrometheusMetricsSink]`` wiring shape
        type-checks (arch #2, council 2026-07-22)."""
        self.policy = policy
        self.responder = responder
        self.fatigue = fatigue
        self.default_timeout_ms = default_timeout_ms
        self.local_only = local_only
        self._audit = _resolve_audit_sink(audit_sink)
        self.last_event: AuditEvent | None = None

        registry = AssistantRegistry(local_only=local_only)
        if assistants:
            for a in cast("list[Assistant]", assistants):
                registry.register(a)
        if assistant is not None:
            registry.register(cast("Assistant", assistant))
        self._assistant_registry = registry

    async def decide(self, inv: Invocation) -> Decision:
        """Run the full async pipeline for one invocation (steps 1-8).

        Returns the final :class:`Decision`. Emits exactly one
        :class:`AuditEvent` per call . The ASSIST/PROMPT branch is
        exception-safe (H8): assistant/responder/fatigue errors are
        caught and converted to a safe ``DENY`` with error reasoning; the
        audit event and fatigue seam C ALWAYS run (finally).
        """
        start = time.monotonic()
        request_id = inv.request_id or uuid.uuid4().hex

        # 1. Parse - already structured in ``inv``.
        # 2. Policy evaluation (deterministic, pure, thread-safe) + resolve match in one scan.
        outcome, policy_match, matched = _evaluate_with_match(self.policy, inv)

        # 3. Floor/ceiling : policy DENY/ALLOW short-circuit before the
        #    try block so their audit events are always emitted directly.
        if outcome == PolicyOutcome.DENY:
            self._emit_audit(
                inv,
                Decision.DENY,
                policy_match,
                start,
                assistant=None,
                risk=0.0,
                reasoning="policy: deny",
                responder=None,
            )
            return Decision.DENY

        if outcome == PolicyOutcome.ALLOW:
            self._emit_audit(
                inv,
                Decision.ALLOW,
                policy_match,
                start,
                assistant=None,
                risk=0.0,
                reasoning="policy: allow",
                responder=None,
            )
            return Decision.ALLOW

        # Seam A: dedup/suppression cache lookup (awaited — may be async).
        if self.fatigue is not None:
            cached = cast("Decision | None", await _call_method(self.fatigue, "lookup", inv))
            if cached is not None:
                fatigue_name = getattr(self.fatigue, "name", "fatigue")
                self._emit_audit(
                    inv,
                    cached,
                    policy_match,
                    start,
                    assistant=None,
                    risk=0.0,
                    reasoning=f"fatigue: cache hit ({fatigue_name})",
                    responder=None,
                )
                return cached

        # Steps 4–6 — the ASSIST/PROMPT/fatigue/responder branch. Wrapped in
        # try/finally so the audit event and seam C ALWAYS execute (H8).
        assistant_name: str | None = None
        risk = 0.0
        reasoning = f"policy: {outcome.value}"
        response: PromptResponse | None = None
        decision: Decision = Decision.DENY
        fatigue_cacheable: bool = True

        try:
            if outcome == PolicyOutcome.ASSIST:
                assistant_name_raw = matched.action if matched else "assist"
                _, sep, name_suffix = assistant_name_raw.partition(":")
                resolved = (
                    self._assistant_registry.get(name_suffix)
                    if sep
                    else self._assistant_registry.default
                )
                if resolved is None and sep:
                    resolved = self._assistant_registry.default

                if resolved is None:
                    decision = Decision.DENY
                    reasoning = (
                        f"assist requested but no assistant registered "
                        f"(action: {assistant_name_raw})"
                    )
                elif _exfiltrates_restricted(resolved, inv, matched_rule=matched):
                    if self.responder is not None:
                        decision = Decision.PROMPT
                        reasoning = (
                            "assistant is exfiltrating (sends args to remote LLM) "
                            "and args contain restricted data; routing to prompt"
                        )
                    else:
                        decision = Decision.DENY
                        reasoning = (
                            "assistant is exfiltrating (sends args to remote LLM) "
                            "and args contain restricted data; no responder configured"
                        )
                else:
                    assistant_name = getattr(resolved, "name", None)
                    out: AssistantOutput = await _call_method(resolved, "decide", inv, inv.context)
                    risk = out.risk
                    reasoning = out.reasoning or f"assistant: {out.decision.value}"
                    decision = _apply_assistant_output_impl(self.policy, out, inv, policy_match)
            else:
                decision = Decision.PROMPT

            # 5. PROMPT: fatigue seam B then responder.
            if decision == Decision.PROMPT:
                if self.fatigue is not None:
                    batching_config = _resolve_batching(self.policy, inv, matched)
                    fd = await _call_method(
                        self.fatigue,
                        "before_prompt",
                        inv,
                        decision,
                        batching=batching_config,
                    )
                    decision = fd.decision
                    fatigue_cacheable = fd.cacheable
                    if fd.reasoning:
                        reasoning = f"{reasoning} | {fd.reasoning}"
                if decision == Decision.PROMPT:
                    quorum_cfg = _resolve_quorum(self.policy, inv, matched)
                    fatigue_cacheable = True
                    response = await self._route_prompt(
                        inv, request_id, risk, reasoning, quorum_cfg=quorum_cfg
                    )
                    decision = response.choice

            return decision

        except Exception as exc:
            decision = Decision.DENY
            reasoning = f"gateway error: {type(exc).__name__}"
            risk = 1.0
            response = None
            fatigue_cacheable = False
            return decision

        finally:
            # 7. Timeout enforcement is handled inside the responder.
            # 8. Audit + fatigue seam C — ALWAYS (H8). The audit sink is
            #    invoked inline (sync) — Null/Stdout/File are microseconds; a
            #    remote OTLP-style sink is a  concern and would warrant
            #    its own async seam. Seam C is awaited (fatigue may be async).
            self._emit_audit(
                inv,
                decision,
                policy_match,
                start,
                assistant=assistant_name,
                risk=risk,
                reasoning=reasoning,
                responder=getattr(self.responder, "name", None) if self.responder else None,
                approver=response.approver if response else None,
                quorum_state=_infer_quorum_state(self.policy, inv, decision, matched),
            )
            if self.fatigue is not None:
                with suppress(Exception):
                    await _call_method(
                        self.fatigue,
                        "after_prompt",
                        inv,
                        decision,
                        response,
                        cacheable=fatigue_cacheable,
                    )

    async def reload_policy(self) -> bool:
        """Atomically reload policy + clear fatigue cache (H6 , async).

        ``Policy.reload`` is pure/non-async; ``fatigue.clear`` is awaited
        (a remote fatigue backend would need the network call off the loop).
        """
        reloaded = self.policy.reload()
        if reloaded and self.fatigue is not None:
            await _call_method(self.fatigue, "clear")
        return reloaded

    async def _route_prompt(
        self,
        inv: Invocation,
        request_id: str,
        risk: float,
        reasoning: str,
        quorum_cfg: Mapping[str, Any] | None = None,
    ) -> PromptResponse:
        """Build a redacted :class:`PromptRequest`, call the responder (step 4).

        If no responder is configured, return a safe ``DENY`` response
        (the gateway must never silently allow a prompted call). Mirrors the
        sync :meth:`custos.gateway.Gateway._route_prompt`.

        ``quorum_cfg``  carries the matched rule's
        ``quorum``/``approver_roles``/``approver_allowlist`` to the
        :class:`PromptRequest` so the responder can enforce the quorum /
        separation-of-duties contract (e.g. via
        :class:`~custos.responders.multi_approver.MultiApproverResponder`).
        """
        if self.responder is None:
            return PromptResponse(choice=Decision.DENY)
        redacted_inv = inv.with_redacted_args()
        deadline = int(time.time() * 1000) + self.default_timeout_ms
        req = PromptRequest(
            tool=redacted_inv.tool,
            args_redacted=redacted_inv.args,
            risk=risk,
            reasoning=reasoning,
            request_id=request_id,
            deadline_unix_ms=deadline,
            quorum=quorum_cfg.get("quorum") if quorum_cfg else None,
            approver_roles=tuple(quorum_cfg.get("approver_roles", ()) or ()) if quorum_cfg else (),
            approver_allowlist=tuple(quorum_cfg.get("approver_allowlist", ()) or ())
            if quorum_cfg
            else (),
        )
        return cast(PromptResponse, await _call_method(self.responder, "prompt", req))

    def _emit_audit(
        self,
        inv: Invocation,
        decision: Decision,
        policy_match: str,
        start: float,
        *,
        assistant: str | None,
        risk: float,
        reasoning: str,
        responder: str | None,
        approver: str | None = None,
        quorum_state: str | None = None,
    ) -> None:
        """Emit the structured audit event . Redacts args first .

        Synchronous - matches the sync gateway. See the ``finally`` note in
        :meth:`decide` for the latency rationale.
        """
        latency_ms = int((time.monotonic() - start) * 1000)
        redacted_inv = inv.with_redacted_args()
        event = AuditEvent(
            ts_unix_ms=int(time.time() * 1000),
            invocation=redacted_inv,
            decision=decision,
            policy_match=policy_match,
            assistant=assistant,
            risk_score=risk,
            reasoning=reasoning,
            responder=responder,
            latency_ms=latency_ms,
            subject=inv.context,
            approver=approver,
            quorum_state=quorum_state,
        )
        self._audit.emit(event)
        self.last_event = event

    def wrap(self, tools: Any) -> list[Any]:
        """Wrap an agent's tool registry so every call is gated (US-1).

        Async dispatcher . Routes by tool shape:

          - Plain callables -> async gated proxies (``await self.decide``).
          - LangChain ``BaseTool`` -> raises ``NotImplementedError`` with a
            pointer: LangChain runtimes are sync by design, use a sync
            :class:`Gateway` for them.
          - Async-native vendor adapters (OpenAI Agents / Anthropic / MCP /
            etc. -) live in their own ``wrap_*`` functions in
            :mod:`custos.integrations` and bypass this dispatcher.

        Building proxies is pure (no awaiting), so this method is sync and
        returns a list of ``async`` gated callables - mirroring
        :meth:`custos.gateway.Gateway.wrap` (which returns sync proxies).
        """
        if not tools:
            return []
        has_langchain = any(hasattr(t, "_run") and hasattr(t, "args_schema") for t in tools)
        if has_langchain:
            raise NotImplementedError(
                "AsyncGateway.wrap does not accept LangChain BaseTool objects. "
                "LangChain runtimes are sync by design; use a sync custos.Gateway "
                "with custos.integrations.langchain.wrap_langchain_tools."
            )
        return self._wrap_callables_async(list(tools))

    def _wrap_callables_async(
        self, tools: list[Any], descriptors: Mapping[str, Any] | None = None
    ) -> list[Any]:
        """Wrap plain sync or async callables as async gated proxies ."""
        import functools

        from custos.exceptions import PermissionDenied
        from custos.schema import Invocation, ToolDescriptor
        from custos.sdk import _minimal_signature_args, get_default_context

        descriptors = descriptors or {}
        gw = self

        def _make_proxy(tool: Any, name: str, desc: Any) -> Any:
            @functools.wraps(tool)
            async def proxy(*args: Any, **kwargs: Any) -> Any:
                ctx = kwargs.pop("custos_context", None) or get_default_context()
                call_args = _minimal_signature_args(tool, args, kwargs)
                inv = Invocation(
                    tool=name,
                    args=call_args,
                    context=ctx,
                    descriptor=desc,
                )
                decision = await gw.decide(inv)
                if decision in (Decision.DENY, Decision.DEFER):
                    last = gw.last_event
                    raise PermissionDenied(
                        name,
                        decision.value,
                        reasoning=last.reasoning if last else "",
                        risk=last.risk_score if last else 0.0,
                        policy_match=last.policy_match if last else None,
                        assistant=last.assistant if last else None,
                    )
                res = tool(*args, **kwargs)
                if inspect.isawaitable(res):
                    return await res
                return res

            return proxy

        wrapped: list[Any] = []
        for tool in tools:
            py_name = getattr(tool, "__name__", None) or repr(tool)
            descriptor = descriptors.get(py_name) or ToolDescriptor(name=py_name, risk_tier=3)
            tool_name = descriptor.name or py_name
            wrapped.append(_make_proxy(tool, tool_name, descriptor))
        return wrapped
