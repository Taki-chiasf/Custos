"""Core data types for the Custos decision pipeline.

This module is the single source of truth for the types that flow through
``Gateway.decide`` . It is intentionally dependency-free: importing
``custos.schema`` must not transitively pull the JSON-schema validator or any
other third-party package .

References:
  ..  (core abstractions)
              (decision pipeline + ``Decision`` enum)
               (API sketch)
               (security invariants)
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "SideEffect",
    "Decision",
    "PolicyOutcome",
    "InspectionVerdict",
    "WipeStrategy",
    "ToolDescriptor",
    "SubjectContext",
    "Invocation",
    "AssistantOutput",
    "InputSource",
    "ContextSnapshot",
    "InjectionFinding",
    "InspectionResult",
    "PromptRequest",
    "PromptResponse",
    "AuditEvent",
]


class SideEffect(str, Enum):
    """Side-effect taxonomy for a tool ."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    NETWORK = "network"
    PAYMENT = "payment"
    DESTRUCTIVE = "destructive"
    PII = "pii"


class Decision(str, Enum):
    """Final decision emitted by the gateway .

    ``allow``            - standing allow (persisted policy rule).
    ``allow_once``       - one-time, no persistence.
    ``allow_and_persist`` - one-time + persist a new rule (Janus ``create_policy``).
    ``deny``             - final deny; an assistant can never relax this .
    ``prompt``           - hand to the responder for user input.
    ``defer``             - defer the call (fatigue / ask-me-later).
    ``quarantine``       - block call + trigger SDK context sanitization (A12).
    """

    ALLOW = "allow"
    ALLOW_ONCE = "allow_once"
    ALLOW_AND_PERSIST = "allow_and_persist"
    DENY = "deny"
    PROMPT = "prompt"
    DEFER = "defer"
    QUARANTINE = "quarantine"

    @property
    def is_allow(self) -> bool:
        return self in (Decision.ALLOW, Decision.ALLOW_ONCE, Decision.ALLOW_AND_PERSIST)


class PolicyOutcome(str, Enum):
    """Intermediate outcome of deterministic policy evaluation (step 2).

    A policy ``DENY`` is final - the pipeline MUST NOT invoke an assistant to
    relax it (floor/ceiling invariant).
    """

    ALLOW = "allow"
    DENY = "deny"
    PROMPT = "prompt"
    ASSIST = "assist"
    INSPECT = "inspect"


class InspectionVerdict(str, Enum):
    """Verdict from a context inspector (A12)."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    INJECTION = "injection"


class WipeStrategy(str, Enum):
    """Memory-wipe strategy for SDK context sanitization."""

    FULL = "full"
    SELECTIVE = "selective"
    ROLLBACK = "rollback"


@dataclass(frozen=True)
class ToolDescriptor:
    """Static description of a registered tool .

    Attributes:
        name: dotted/glob-able tool identifier, e.g. ``fs.read``, ``email.send``.
        risk_tier: 1 (trivial) .. 5 (catastrophic).
        schema: JSON-schema dict describing the tool's input params.
        reversible: whether the call can be undone.
        side_effects: set of :class:`SideEffect` declared by the tool.
    """

    name: str
    risk_tier: int
    schema: Mapping[str, Any] = field(default_factory=dict)
    reversible: bool = False
    side_effects: frozenset[SideEffect] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not 1 <= self.risk_tier <= 5:
            raise ValueError(f"risk_tier must be in 1..5, got {self.risk_tier}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "risk_tier": self.risk_tier,
            "reversible": self.reversible,
            "side_effects": sorted(se.value for se in self.side_effects),
        }


def _simple_pattern_match(pattern: str, value: str) -> bool:
    """Simple regex pattern match for JSON-schema patternProperties (H5)."""
    try:
        return re.search(pattern, value) is not None
    except re.error:
        return False


def _redact_args(args: Mapping[str, Any], descriptor: ToolDescriptor | None) -> dict[str, Any]:
    """Strip secret/PII fields from ``args`` before responder/audit (H5).

    Recurses through nested JSON-schema constructs (``properties``, ``items``,
    ``patternProperties``, ``additionalProperties``, ``allOf``/``anyOf``) so
    deeply-nested secrets are redacted. A tool declaring
    :attr:`~SideEffect.PII` without any per-field secret annotations defaults
    to redacting ALL arg values (conservative).

    Redacted values are replaced with ``"[REDACTED]"``.
    """
    redacted: dict[str, Any] = dict(args)
    if descriptor is None:
        return redacted
    schema = descriptor.schema
    if not isinstance(schema, Mapping):
        return redacted

    _REDACT_MAX_DEPTH = 10
    _redact_walk(redacted, schema, depth=0, max_depth=_REDACT_MAX_DEPTH, root_schema=schema)

    has_pii = SideEffect.PII in descriptor.side_effects
    if has_pii and not _has_secret_annotation(schema):
        for key in redacted:
            redacted[key] = "[REDACTED]"

    return redacted


def _has_secret_annotation(schema: object) -> bool:
    """Check whether any field in the schema declares secret/password."""
    if not isinstance(schema, Mapping):
        return False
    if schema.get("secret") is True or schema.get("format") == "password":
        return True
    props = schema.get("properties")
    if isinstance(props, Mapping):
        for field_schema in props.values():
            if _has_secret_annotation(field_schema):
                return True
    items = schema.get("items")
    return isinstance(items, Mapping) and _has_secret_annotation(items)


def _redact_walk(
    args: dict[str, Any],
    schema: Mapping[str, Any],
    *,
    depth: int,
    max_depth: int,
    root_schema: Mapping[str, Any],
) -> None:
    """Recursively walk JSON-schema + args to redact secret/PII fields (H5)."""
    if depth >= max_depth:
        return
    if not isinstance(schema, Mapping):
        return

    # Process direct properties.
    props = schema.get("properties")
    if isinstance(props, Mapping):
        for name, field_schema in props.items():
            if name not in args:
                continue
            if not isinstance(field_schema, Mapping):
                continue
            if field_schema.get("secret") is True or field_schema.get("format") == "password":
                args[name] = "[REDACTED]"
            elif isinstance(args[name], dict):
                _redact_walk(
                    args[name],
                    field_schema,
                    depth=depth + 1,
                    max_depth=max_depth,
                    root_schema=root_schema,
                )
            elif isinstance(args[name], list):
                items_schema = field_schema.get("items")
                if isinstance(items_schema, Mapping):
                    for elem in args[name]:
                        if isinstance(elem, dict):
                            _redact_walk(
                                elem,
                                items_schema,
                                depth=depth + 1,
                                max_depth=max_depth,
                                root_schema=root_schema,
                            )

    # Process patternProperties (wildcard property schemas).
    pattern_props = schema.get("patternProperties")
    if isinstance(pattern_props, Mapping):
        for key, val in list(args.items()):
            for pat, pat_schema in pattern_props.items():
                if not isinstance(pat_schema, Mapping):
                    continue
                try:
                    matched = _simple_pattern_match(pat, key)
                except re.error:
                    continue
                if matched and isinstance(val, dict):
                    _redact_walk(
                        val,
                        pat_schema,
                        depth=depth + 1,
                        max_depth=max_depth,
                        root_schema=root_schema,
                    )

    # Process additionalProperties (catch-all property schema).
    addl = schema.get("additionalProperties")
    if isinstance(addl, Mapping):
        processed = set(props.keys()) if isinstance(props, Mapping) else set()
        for key, val in list(args.items()):
            if key in processed:
                continue
            if isinstance(val, dict):
                _redact_walk(
                    val,
                    addl,
                    depth=depth + 1,
                    max_depth=max_depth,
                    root_schema=root_schema,
                )

    # Process composite schemas: allOf / anyOf / oneOf.
    for comp_key in ("allOf", "anyOf", "oneOf"):
        comp = schema.get(comp_key)
        if isinstance(comp, list):
            for sub_schema in comp:
                if isinstance(sub_schema, Mapping):
                    _redact_walk(
                        args,
                        sub_schema,
                        depth=depth + 1,
                        max_depth=max_depth,
                        root_schema=root_schema,
                    )


AUDIT_SUBJECT_FIELDS: frozenset[str] = frozenset({"user_id", "goal_id", "task_id"})
"""Allowlist of ``SubjectContext.extra`` fields that may appear in audit logs (H5).

Fields not in this set are NOT serialised by :meth:`SubjectContext.to_dict`.
"""


@dataclass(frozen=True)
class SubjectContext:
    """Who/what the agent is acting for .

    Attributes:
        user_id: the principal the agent acts on behalf of.
        goal_id: the active goal scope; consent does not leak across goals (US-10).
        task_id: the active task scope.
        delegation_chain: ordered list of delegators, shallowest first.
        session_ttl: seconds after which the session is invalid.
        extra: free-form metadata bag (never trusted for policy decisions).
    """

    user_id: str
    goal_id: str | None = None
    task_id: str | None = None
    delegation_chain: tuple[str, ...] = ()
    session_ttl: int | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def delegation_depth(self) -> int:
        return len(self.delegation_chain)

    def to_dict(self) -> dict[str, Any]:
        extra_filtered = {k: v for k, v in self.extra.items() if k in AUDIT_SUBJECT_FIELDS}
        return {
            "user_id": self.user_id,
            "goal_id": self.goal_id,
            "task_id": self.task_id,
            "delegation_chain": list(self.delegation_chain),
            "session_ttl": self.session_ttl,
            "extra": extra_filtered,
        }


@dataclass(frozen=True)
class Invocation:
    """A single agent -> tool call entering the gateway ."""

    tool: str
    args: Mapping[str, Any]
    context: SubjectContext
    descriptor: ToolDescriptor | None = None
    request_id: str | None = None

    def with_redacted_args(self) -> Invocation:
        """Return a copy with secret/PII fields redacted .

        Used by the gateway before building :class:`PromptRequest` and
        :class:`AuditEvent` so neither the responder nor the audit log ever
        sees a secret argument value.
        """
        redacted = _redact_args(self.args, self.descriptor)
        return Invocation(
            tool=self.tool,
            args=redacted,
            context=self.context,
            descriptor=self.descriptor,
            request_id=self.request_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": dict(self.args),
            "request_id": self.request_id,
            "descriptor": self.descriptor.to_dict() if self.descriptor else None,
        }


@dataclass(frozen=True)
class AssistantOutput:
    """Result returned by a :class:`~custos.assistants.Assistant` .

    Attributes:
        decision: assistant's proposed decision.
        risk: 0.0..1.0 risk score.
        reasoning: human-readable trace for audit/eval.
        fatigue_hint: when True, the fatigue layer may collapse this call into a batch.
        persist_rule: optional ABAC rule dict to persist (only honored on
            ``allow_and_persist``). Treated as UNTRUSTED input .
    """

    decision: Decision
    risk: float = 0.0
    reasoning: str = ""
    fatigue_hint: bool = False
    persist_rule: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError(f"risk must be in 0.0..1.0, got {self.risk}")


@dataclass(frozen=True)
class InputSource:
    """A discrete piece of untrusted input within an agent's context (A12).

    Each input source represents one segment of external data (email body,
    document content, web search result, tool output) that could contain
    an indirect prompt injection.
    """

    source_id: str
    source_type: str
    content: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def content_hash(self) -> str:
        import hashlib

        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ContextSnapshot:
    """Full agent context at a point in time (A12).

    Captures the complete conversation state — messages, tool outputs,
    segmentable untrusted inputs — that a context inspector analyses.
    """

    ts_unix_ms: int
    messages: tuple[dict[str, Any], ...] = ()
    sources: tuple[InputSource, ...] = ()
    system_prompt: str | None = None

    @property
    def active_sources(self) -> tuple[InputSource, ...]:
        return self.sources


@dataclass(frozen=True)
class InjectionFinding:
    """One attributed injection source with confidence + affected indices (A12)."""

    source: InputSource
    confidence: float
    affected_indices: tuple[int, ...] = ()
    method: str = "pattern_match"

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in 0.0..1.0, got {self.confidence}")


@dataclass(frozen=True)
class InspectionResult:
    """Result from a :class:`~custos.inspectors.base.ContextInspector` (A12).

    Attributes:
        verdict: SAFE, SUSPICIOUS, or INJECTION.
        findings: the attributed injection sources (empty when SAFE).
        confidence: 0.0..1.0 overall confidence in the verdict.
        masked_snapshot: when not None, a sanitised context with CoT steps
            influenced by the injection source masked/redacted.
        reasoning: human-readable trace for audit/eval.
    """

    verdict: InspectionVerdict
    findings: tuple[InjectionFinding, ...] = ()
    confidence: float = 0.0
    masked_snapshot: ContextSnapshot | None = None
    reasoning: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be in 0.0..1.0, got {self.confidence}")


@dataclass(frozen=True)
class PromptRequest:
    """Payload handed to a responder .

    ``args_redacted`` must already have secret/PII fields stripped .

    Attributes:
        quorum: optional  number of distinct approvers
            required to resolve the prompt to ``met``; carried from the matched
            policy rule's :attr:`~custos.policy.schema.PolicyRuleSpec.quorum`.
            When ``None``, single-approver semantics (.5 H12) apply.
        approver_roles: the roles whose distinct approvers count toward
            :attr:`quorum`; disjoint-role separation-of-duties.
        approver_allowlist: explicit allowlist of approver ids complements the
            responder's own allowlist (Slack H12); carried from the rule.
    """

    tool: str
    args_redacted: Mapping[str, Any]
    risk: float
    reasoning: str
    options: Sequence[Decision] = (Decision.ALLOW, Decision.DENY, Decision.ALLOW_ONCE)
    request_id: str | None = None
    deadline_unix_ms: int | None = None
    quorum: int | None = None
    approver_roles: Sequence[str] = ()
    approver_allowlist: Sequence[str] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError(f"risk must be in 0.0..1.0, got {self.risk}")


@dataclass(frozen=True)
class PromptResponse:
    """User response from a responder (H12).

    For webhook responders, ``signature`` carries the HMAC of (choice, ttl,
    nonce, timestamp); the gateway rejects unsigned/expired responses .

    Attributes:
        choice: the user's chosen decision.
        ttl: seconds to cache this decision (suppression).
        signature: HMAC signature for webhook responses .
        nonce: nonce for webhook-replay prevention .
        approver: responder-attested identity of the approver (H12).
    """

    choice: Decision
    ttl: int | None = None
    signature: bytes | None = None
    nonce: str | None = None
    approver: str | None = None


@dataclass(frozen=True)
class AuditEvent:
    """One structured decision record ."""

    ts_unix_ms: int
    invocation: Invocation
    decision: Decision
    policy_match: str | None
    assistant: str | None
    risk_score: float
    reasoning: str
    responder: str | None
    latency_ms: int
    subject: SubjectContext
    approver: str | None = None
    inspector: str | None = None
    """Name of the context inspector (A12) that ran on this invocation, if any."""
    quorum_state: str | None = None
    """Quorum state observability (quorum, Q10). One of ``"met"``,
    ``"failed"``, or ``None`` (no quorum configured or not a prompt-resolved
    path). ``met`` = the required distinct-role approvals were collected;
    ``failed`` = timeout or an approver disagreement caused a DENY. This
    field is purely informational - it does NOT change the decision (the
    decision is recorded above) so a compliance tool can correlate WHY a
    quorum-resolved prompt resolved one way vs. ``prompt_pending`` (DEFER)."""
    schema_version: str = "1.0"
    """Wire schema version of this event (IR_CONTRACT).
    Defaults to ``"1.0"`` so v1.0rc1-era callers keep working without code
    changes. The hash-chained audit sink emits the envelope-level field at
    the same value; a contract-bump (any change to the wire shape) MUST
    bump this field at both ends (Python ``custos`` + TS ``@taqiy/custos-core``)."""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSONL/structured sinks ."""
        return {
            "ts_unix_ms": self.ts_unix_ms,
            "invocation": self.invocation.to_dict(),
            "decision": self.decision.value,
            "policy_match": self.policy_match,
            "assistant": self.assistant,
            "risk_score": self.risk_score,
            "reasoning": self.reasoning,
            "responder": self.responder,
            "latency_ms": self.latency_ms,
            "subject": self.subject.to_dict(),
            "approver": self.approver,
            "inspector": self.inspector,
            "quorum_state": self.quorum_state,
            "schema_version": self.schema_version,
        }
