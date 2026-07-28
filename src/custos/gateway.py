"""The Custos decision pipeline .

The gateway runs the full 8-step flow for each invocation: parse -> policy
evaluation -> (assistant if ASSIST) -> (responder if PROMPT) -> fatigue ->
timeout -> audit -> return. It enforces the floor/ceiling invariant :
a policy ``deny`` is final and can never be relaxed by an assistant; the
assistant is only ever invoked when policy says ``ASSIST`` or ``PROMPT``.
"""

from __future__ import annotations

import fnmatch
import time
import uuid
from collections.abc import Mapping, Sequence
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from custos.assistants.base import AssistantRegistry
from custos.policy import PolicyRuleSpec, Rule
from custos.policy.engine import _action_to_outcome
from custos.policy.schema import PolicyValidationError
from custos.schema import (
    AssistantOutput,
    AuditEvent,
    Decision,
    Invocation,
    PolicyOutcome,
    PromptRequest,
    PromptResponse,
    SideEffect,
    ToolDescriptor,
)

if TYPE_CHECKING:
    from custos.assistants.base import Assistant, AssistantRegistry
    from custos.audit import AuditSink
    from custos.fatigue.base import FatigueLayer
    from custos.policy import Policy
    from custos.responders.base import Responder

__all__ = ["Gateway"]


class Gateway:
    """The middleware an agent wraps its tool registry with .

    Invariants :
      - policy is the floor; an assistant may only ESCALATE strictness.
      - assistant output is untrusted; it cannot relax a policy ``deny``.
      - prompt payloads are redacted by the gateway before reaching a responder.
    """

    def __init__(
        self,
        policy: Policy,
        assistant: Assistant | None = None,
        responder: Responder | None = None,
        audit_sink: AuditSink | str | list[AuditSink] | tuple[AuditSink, ...] | None = None,
        fatigue: FatigueLayer | None = None,
        *,
        default_timeout_ms: int = 30_000,
        assistants: list[Assistant] | None = None,
        local_only: bool = False,
    ) -> None:
        """``local_only`` enables the air-gapped profile (H4): the
        registry refuses to register any assistant with ``exfiltrates_args=True``
        — a remote-LLM assistant cannot exfiltrate args from a network-isolated
        deployment. Default ``False``. (C4 regression, council 2026-07-22.)"""
        self.policy = policy
        self.responder = responder
        self.fatigue = fatigue
        self.default_timeout_ms = default_timeout_ms
        self.local_only = local_only
        self._audit = _resolve_audit_sink(audit_sink)
        self.last_event: AuditEvent | None = None

        registry = AssistantRegistry(local_only=local_only)
        if assistants:
            for a in assistants:
                registry.register(a)
        if assistant is not None:
            registry.register(assistant)
        self._assistant_registry = registry

    @property
    def audit_sink(self) -> AuditSink:
        """Accessor to the resolved audit sink .

        Used by the sidecar's :class:`CapturingAuditSink` to mount + wrap
        the operator's configured sink at runtime without a private-attr
        write. The setter exists ONLY for the sidecar's one-shot wrapping
        mount; per-call re-aiming is a configuration change, not a per-call
        one. The ``_audit`` slot otherwise stays stable for the lifetime of
        the in-process :class:`Gateway`.
        """
        return self._audit

    @audit_sink.setter
    def audit_sink(self, sink: AuditSink) -> None:
        self._audit = sink

    def decide(self, inv: Invocation) -> Decision:
        """Run the full pipeline for one invocation (steps 1-8).

        Returns the final :class:`Decision`. Emits exactly one
        :class:`AuditEvent` per call . The ASSIST/PROMPT branch is
        exception-safe (H8): assistant/responder/fatigue errors are
        caught and converted to a safe ``DENY`` with error reasoning; the
        audit event and fatigue seam C ALWAYS run (finally).
        """
        start = time.monotonic()
        request_id = inv.request_id or uuid.uuid4().hex

        # 1. Parse - already structured in ``inv``.
        # 2. Policy evaluation (deterministic, pure) + resolve match in one scan.
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

        # Seam A: dedup/suppression cache lookup.
        if self.fatigue is not None:
            cached = self.fatigue.lookup(inv)
            if cached is not None:
                self._emit_audit(
                    inv,
                    cached,
                    policy_match,
                    start,
                    assistant=None,
                    risk=0.0,
                    reasoning=f"fatigue: cache hit ({self.fatigue.name})",
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
                    reasoning = f"assist requested but no assistant registered (action: {assistant_name_raw})"
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
                    out = resolved.decide(inv, inv.context)
                    risk = out.risk
                    reasoning = out.reasoning or f"assistant: {out.decision.value}"
                    decision = self._apply_assistant_output(out, inv, policy_match)
            else:
                decision = Decision.PROMPT

            # 5. PROMPT: fatigue seam B then responder.
            if decision == Decision.PROMPT:
                if self.fatigue is not None:
                    batching_config = _resolve_batching(self.policy, inv, matched)
                    fd = self.fatigue.before_prompt(inv, decision, batching=batching_config)
                    decision = fd.decision
                    fatigue_cacheable = fd.cacheable
                    if fd.reasoning:
                        reasoning = f"{reasoning} | {fd.reasoning}"
                if decision == Decision.PROMPT:
                    quorum_cfg = _resolve_quorum(self.policy, inv, matched)
                    fatigue_cacheable = True
                    response = self._route_prompt(
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
            # 8. Audit + fatigue seam C — ALWAYS (H8).
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
                    self.fatigue.after_prompt(inv, decision, response, cacheable=fatigue_cacheable)

    def _apply_assistant_output(
        self,
        out: AssistantOutput,
        inv: Invocation,
        policy_match: str,
    ) -> Decision:
        """Map an :class:`AssistantOutput` to a :class:`Decision` (step 3).

        ``allow_and_persist`` validates the untrusted ``persist_rule`` and
        appends it to the in-memory policy so future identical calls
        short-circuit at step 2 (Janus ``create_policy`` semantics).
        """
        return _apply_assistant_output_impl(self.policy, out, inv, policy_match)

    def _persist_assistant_rule(self, persist_rule: Any, inv: Invocation) -> None:
        """Validate + compile + insert an assistant-suggested rule (H3).

        Delegates to :func:`_persist_assistant_rule_impl` (shared with
        :class:`~custos.async_gateway.AsyncGateway` to avoid drift).
        """
        _persist_assistant_rule_impl(self.policy, persist_rule, inv)

    def reload_policy(self) -> bool:
        """Atomically reload policy + clear fatigue cache (H6).

        Calls :meth:`Policy.reload` and then :meth:`FatigueLayer.clear` so a
        stale cached allow cannot shadow a freshly-tightened policy .
        Returns ``True`` if the policy was reloaded, ``False`` otherwise.
        """
        reloaded = self.policy.reload()
        if reloaded and self.fatigue is not None:
            self.fatigue.clear()
        return reloaded

    def _route_prompt(
        self,
        inv: Invocation,
        request_id: str,
        risk: float,
        reasoning: str,
        quorum_cfg: Mapping[str, Any] | None = None,
    ) -> PromptResponse:
        """Build a redacted :class:`PromptRequest`, call the responder (step 4).

        If no responder is configured, return a safe ``DENY`` response
        (the gateway must never silently allow a prompted call). The
        responder's :class:`PromptResponse` is returned so the fatigue seam C
        can read ``ttl`` for the suppression cache .

        ``quorum_cfg``  carries the matched rule's
        ``quorum``/``approver_roles``/``approver_allowlist`` to the
        :class:`PromptRequest` so the responder (e.g.
        :class:`~custos.responders.multi_approver.MultiApproverResponder`) can
        enforce the quorum / separation-of-duties contract.
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
        return self.responder.prompt(req)

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
        """Emit the structured audit event . Redacts args first ."""
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

    def wrap(self, tools: Sequence[Any]) -> list[Any]:
        """Wrap an agent's tool registry so every call is gated (US-1).

        Dispatcher (D17): routes by tool shape. Plain callables are wrapped by
        :func:`custos.sdk.wrap_callables`; LangChain ``BaseTool`` objects are
        wrapped by :func:`custos.integrations.langchain.wrap_langchain_tools`.
        Unknown tool types raise with a message pointing at the right adapter.
        """
        if not tools:
            return []
        # Heuristic: detect LangChain BaseTool by attribute presence without
        # importing langchain (keeps the runtime dep-free).
        has_langchain = any(hasattr(t, "_run") and hasattr(t, "args_schema") for t in tools)
        if has_langchain:
            from custos.integrations.langchain import wrap_langchain_tools

            return wrap_langchain_tools(self, list(tools))
        # Otherwise assume plain callables.
        from custos.sdk import wrap_callables

        return wrap_callables(self, list(tools))


def _apply_assistant_output_impl(
    policy: Policy,
    out: AssistantOutput,
    inv: Invocation,
    policy_match: str,
) -> Decision:
    """Pure mapping of :class:`AssistantOutput` -> :class:`Decision` (step 3).

    Shared by the sync :class:`Gateway` and the async
    :class:`~custos.async_gateway.AsyncGateway` so the ``allow_and_persist``
    journey cannot drift between the two runtime surfaces (H3).
    """
    decision = out.decision
    if decision == Decision.ALLOW_AND_PERSIST:
        _persist_assistant_rule_impl(policy, out.persist_rule, inv)
        # The one-time allow is returned; the persisted rule fires next time.
        return Decision.ALLOW_ONCE
    # allow, allow_once, deny, prompt, defer pass through unchanged.
    return decision


def _persist_assistant_rule_impl(policy: Policy, persist_rule: Any, inv: Invocation) -> None:
    """Validate + compile + insert an assistant-suggested rule (H3).

    Assistant output is untrusted: a malformed or invalid rule is rejected
    and never added to the policy. A valid rule is inserted *before* the
    rule that matched so future identical calls short-circuit at the policy
    layer (Janus ``create_policy`` fatigue semantics). Rules earlier in
    the list are untouched, preserving the floor invariant  - a persisted
    allow never shadows an earlier deny.

    Narrowness invariant (H3): the persisted rule's match-set MUST be
    provably narrower than the matched rule. ``any:true``, broad globs
    (``*``), ``matches`` regex operators, bare ``allow``/``allow_and_audit``
    actions, and persisted rules whose tool glob would intersect a later
    ``deny*`` rule are all rejected.

    Pure with respect to ``policy`` (no I/O, no time); safe to call from
    either the sync or the async gateway under the existing threading model.
    """
    if not isinstance(persist_rule, dict):
        return
    action = persist_rule.get("action")
    match = persist_rule.get("match")
    if not isinstance(action, str) or not isinstance(match, dict):
        return

    # H3 narrowness: reject any:true (matches everything).
    if match.get("any") is True or match.get("any") == "true":
        return

    # H3 narrowness: reject tool "*" glob (broadest possible).
    tool = match.get("tool")
    if isinstance(tool, str) and tool == "*":
        return

    # H3 narrowness: reject bare allow/allow_and_audit — allow actions
    # with no narrowing match criteria (empty match dict or only tool="*").
    # Standing allows are acceptable for provably-narrower tool patterns.
    if action in ("allow", "allow_and_audit"):
        has_narrowing = bool(tool) and tool != "*"
        has_args = bool(match.get("args")) or bool(match.get("risk_tier"))
        has_side = bool(match.get("side_effects"))
        has_goal = bool(match.get("goal_id"))
        has_depth = match.get("delegation_depth") is not None
        if not (has_narrowing or has_args or has_side or has_goal or has_depth):
            return

    # H3 narrowness: reject args predicates using the matches (regex)
    # operator — a regex can broaden beyond the matched rule's scope
    # in ways that are undecidable to verify statically.
    args_match = match.get("args")
    if isinstance(args_match, dict):
        for arg_val in args_match.values():
            if isinstance(arg_val, dict) and "matches" in arg_val:
                return

    # H3 narrowness: check that a later deny* rule is not shadowed.
    matched_index = _resolve_policy_match_index(policy, inv)
    if matched_index is not None:
        for i, later_rule in enumerate(policy.rules):
            if i <= matched_index:
                continue
            if later_rule.action.startswith("deny"):
                later_tool = later_rule.spec.match.get("tool")
                if later_tool is None or later_tool == "*":
                    return
                if tool is not None and (
                    fnmatch.fnmatchcase(tool, later_tool) or fnmatch.fnmatchcase(later_tool, tool)
                ):
                    return

    try:
        spec = PolicyRuleSpec(match=match, action=action)
        new_rule = Rule(spec)  # validates eagerly
        if matched_index is not None:
            policy.insert_rule(matched_index, new_rule)
        else:
            policy.add_rule(new_rule)
        policy.track_persisted_rule(new_rule)
    except PolicyValidationError:
        return


def _has_secret_args(descriptor: ToolDescriptor | None) -> bool:
    """Check whether the tool descriptor declares any secret/PII fields (H4)."""
    if descriptor is None:
        return False
    if SideEffect.PII in descriptor.side_effects:
        return True
    schema = descriptor.schema
    if isinstance(schema, Mapping):
        return _schema_has_secret(schema)
    return False


def _schema_has_secret(schema: Mapping[str, Any]) -> bool:
    """Recursively check for secret:true/format:password in a JSON-schema (H4)."""
    if schema.get("secret") is True or schema.get("format") == "password":
        return True
    props = schema.get("properties")
    if isinstance(props, Mapping):
        for v in props.values():
            if isinstance(v, Mapping) and _schema_has_secret(v):
                return True
    items = schema.get("items")
    return isinstance(items, Mapping) and _schema_has_secret(items)


def _exfiltrates_restricted(assistant: Any, inv: Invocation, matched_rule: Any = None) -> bool:
    """True when a remote assistant would receive restricted args (H4).

    The matched policy rule may set ``allow_external_data: true`` to vet the
    exfiltration  — when set, the gate is relaxed and the assistant is
    invoked. Default ``False`` (the floor): restricted args + remote
    assistant -> route to ``prompt``/``deny``. (C4 regression, council 2026-07-22.)
    """
    if matched_rule is not None and getattr(matched_rule, "allow_external_data", False):
        return False
    exfiltrates = getattr(assistant, "exfiltrates_args", False)
    if not exfiltrates:
        return False
    return _has_secret_args(inv.descriptor)


def _resolve_audit_sink(
    sink: AuditSink | str | list[AuditSink] | tuple[AuditSink, ...] | None,
) -> AuditSink:
    from custos.audit import AuditSink, CompositeAuditSink, NullAuditSink

    if sink is None:
        return NullAuditSink()
    if isinstance(sink, str):
        return AuditSink.from_path(sink)
    if isinstance(sink, (list, tuple)):
        # Fan out to a Composite — the  telemetry surface covers the
        # [FileAuditSink, OTLPAuditSink, PrometheusMetricsSink] wiring
        # shape directly from the gateway constructor (no per-host fanout
        # helper needed).
        return CompositeAuditSink(sink)
    return sink


def _resolve_policy_match(policy: Policy, inv: Invocation) -> str:
    """Derive the audit label for which policy entry matched .

    Returns the matched rule's action string, or ``"default:<action>"`` when
    no rule matched. Re-evaluates the overlay-filtered rules; this is a pure
    read  and runs only once more per call.
    """
    idx = _resolve_policy_match_index(policy, inv)
    rules = policy.rules
    if idx is None:
        return f"default:{policy.default}"
    rule = rules[idx]
    overlay = rule.overlay_id or "inline"
    return f"{overlay}:{rule.action}"


def _resolve_policy_match_index(policy: Policy, inv: Invocation) -> int | None:
    """Return the index of the first matching (scope-filtered) rule, or None."""
    env = inv.context.extra.get("env") if inv.context.extra else None
    env_str = env if isinstance(env, str) else None
    for i, rule in enumerate(policy.rules):
        if not rule.applies_to_context(
            user_id=inv.context.user_id,
            goal_id=inv.context.goal_id,
            env=env_str,
        ):
            continue
        if rule.matches(inv):
            return i
    return None


def _evaluate_with_match(policy: Policy, inv: Invocation) -> tuple[PolicyOutcome, str, Rule | None]:
    """Evaluate the policy and return (outcome, policy_match_label, matched_rule)
    in a single ruleset scan, avoiding redundant iteration."""
    env = inv.context.extra.get("env") if inv.context.extra else None
    env_str = env if isinstance(env, str) else None
    rules = policy.rules
    for rule in rules:
        if not rule.applies_to_context(
            user_id=inv.context.user_id,
            goal_id=inv.context.goal_id,
            env=env_str,
        ):
            continue
        if rule.matches(inv):
            outcome = _action_to_outcome(rule.action)
            overlay = rule.overlay_id or "inline"
            label = f"{overlay}:{rule.action}"
            return outcome, label, rule
    default_outcome = _action_to_outcome(policy.default)
    return default_outcome, f"default:{policy.default}", None


def _resolve_batching(
    policy: Policy, inv: Invocation, matched: Rule | None = None
) -> Mapping[str, Any] | None:
    """Extract the matched rule's ``batching`` config for the fatigue layer .

    When ``matched`` is provided (pre-resolved, avoiding a second scan), uses it
    directly. Otherwise falls back to the index-based scan.
    """
    if matched is not None:
        return matched.spec.batching
    idx = _resolve_policy_match_index(policy, inv)
    if idx is None:
        return None
    return policy.rules[idx].spec.batching


def _resolve_quorum(
    policy: Policy, inv: Invocation, matched: Rule | None = None
) -> Mapping[str, Any] | None:
    """Extract the matched rule's quorum config for the responder .

    When ``matched`` is provided (pre-resolved), uses it directly.
    """
    if matched is not None:
        spec = matched.spec
        if spec.quorum is None:
            return None
        return {
            "quorum": spec.quorum,
            "approver_roles": tuple(spec.approver_roles),
            "approver_allowlist": tuple(spec.approver_allowlist),
        }
    idx = _resolve_policy_match_index(policy, inv)
    if idx is None:
        return None
    spec = policy.rules[idx].spec
    if spec.quorum is None:
        return None
    return {
        "quorum": spec.quorum,
        "approver_roles": tuple(spec.approver_roles),
        "approver_allowlist": tuple(spec.approver_allowlist),
    }


def _infer_quorum_state(
    policy: Policy, inv: Invocation, decision: Decision, matched: Rule | None = None
) -> str | None:
    """Derive the ``quorum_state`` audit label from the matched rule + decision
    (Q10). Pure - no responder field required.

    When ``matched`` is provided (pre-resolved), uses it directly to avoid
    a redundant policy scan.

    Returns one of:
      - ``"met"``    — quorum configured AND decision is allow*: distinct-role
        approvals were collected (the responder resolved to ALLOW/ALLOW_ONCE).
      - ``"failed"`` — quorum configured AND decision is DENY (timeout or
        approver disagreement; per Q10 a quorum-time DENY falls to DENY).
      - ``"pending"`` — quorum configured AND decision is DEFER (reuses
        existing DEFER semantics, Q10; the agent will retry).
      - ``None``     — no quorum configured (single-approver path, or not a
        prompt-resolved path). Matches the  audit surface for v0.4 single-
        approver prompts, leaving their audit events unchanged.
    """
    if matched is not None and matched.spec.quorum is not None:
        return _infer_quorum_state_from_decision(decision)
    if _resolve_quorum(policy, inv) is None:
        return None
    return _infer_quorum_state_from_decision(decision)


def _infer_quorum_state_from_decision(decision: Decision) -> str | None:
    if decision.is_allow:
        return "met"
    if decision == Decision.DEFER:
        return "pending"
    if decision == Decision.DENY:
        return "failed"
    return "pending"
