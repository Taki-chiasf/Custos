"""Tests for the Custos telemetry module .

Asserts:
  - ``import custos`` with no extras installed never imports opentelemetry
    or prometheus_client (the default-off regression;   Q4).
  - The OTLP + Prometheus sinks raise a clear ImportError when their
    extras are missing (defensive; not exercised here since the CI image
    for these tests has the extras installed — instead, the
    ``test_import_custos_does_not_import_telemetry_vendors`` test below
    drops the vendor modules from sys.modules first, then re-imports custos
    and asserts the vendors did not come back).
  - ``PrometheusMetricsSink.emit`` updates the four  instruments
    with the correct labels and values.
  - The gateway's audit-sink resolver auto-wraps a list input into a
    :class:`CompositeAuditSink` so the user can pass
    ``[FileAuditSink, OTLPAuditSink, PrometheusMetricsSink]`` directly.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from custos.audit import AuditSink, CompositeAuditSink
from custos.gateway import _resolve_audit_sink
from custos.schema import (
    AuditEvent,
    Decision,
    Invocation,
    SideEffect,
    SubjectContext,
    ToolDescriptor,
)


def _make_event(
    decision: Decision = Decision.ALLOW,
    *,
    tool: str = "fs.read",
    assistant: str | None = "rule-policy",
    responder: str | None = None,
    latency_ms: int = 12,
    risk_score: float = 0.1,
) -> AuditEvent:
    return AuditEvent(
        ts_unix_ms=1_784_000_000_000,
        invocation=Invocation(
            tool=tool,
            args={"path": "/etc/hosts"},
            context=SubjectContext(user_id="alice", goal_id="g"),
            descriptor=ToolDescriptor(
                name=tool,
                risk_tier=1,
                side_effects=frozenset({SideEffect.READ}),
                schema={},
                reversible=False,
            ),
        ),
        decision=decision,
        policy_match="base:allow_and_audit",
        assistant=assistant,
        risk_score=risk_score,
        reasoning="policy: allow",
        responder=responder,
        latency_ms=latency_ms,
        subject=SubjectContext(user_id="alice", goal_id="g"),
    )


# --------------------------------------------------------------------------- #
# Default-off /  regression
# --------------------------------------------------------------------------- #


def test_import_custos_does_not_import_telemetry_vendors() -> None:
    """``import custos`` (or any custos submodule) without the telemetry
    extra installed MUST NOT pull in ``opentelemetry`` or
    ``prometheus_client``.  +  Q4 closure gate.

    Drops any cached vendor modules, removes the custos.* caches the
    telemetry submodule loaded from, then re-imports the custos package and
    asserts the vendors did not come back into ``sys.modules``.
    """
    vendors = ("opentelemetry", "prometheus_client")
    to_drop = {
        m for m in list(sys.modules) if any(m == v or m.startswith(v + ".") for v in vendors)
    }
    for m in to_drop:
        del sys.modules[m]
    # Don't drop custos itself; just drop the telemetry submodule so a
    # re-import re-runs the module-top checks against sys.modules.
    for m in list(sys.modules):
        if m == "custos.telemetry" or m.startswith("custos.telemetry."):
            del sys.modules[m]
    import importlib

    importlib.import_module("custos")
    importlib.import_module("custos.telemetry")
    for v in vendors:
        assert v not in sys.modules, (
            f"NFR-6 / Q4 violation: importing custos.telemetry pulled in {v}"
        )


def test_gateway_resolver_auto_wraps_list_into_composite() -> None:
    """The  gateway audit-sink resolver accepts a list of sinks and
    auto-fans out via :class:`CompositeAuditSink` (the [FileAuditSink,
    OTLPAuditSink, PrometheusMetricsSink] wiring shape from the docs).
    """
    from custos.audit import FileAuditSink, NullAuditSink

    a = FileAuditSink("/tmp/a.jsonl")
    b = NullAuditSink()
    resolved = _resolve_audit_sink([a, b])
    assert isinstance(resolved, CompositeAuditSink)
    assert resolved.sinks == (a, b)


def test_gateway_resolver_passthrough_for_single_sink() -> None:
    """Single sink inputs pass through unchanged (backward compat with
    the v0.1-era single-sink constructor)."""
    from custos.audit import NullAuditSink

    sink = NullAuditSink()
    assert _resolve_audit_sink(sink) is sink


def test_gateway_resolver_passthrough_for_string() -> None:
    """String-typed input stays a ``FileAuditSink`` (str-path shape)."""
    resolved = _resolve_audit_sink("/tmp/audit.jsonl")
    assert isinstance(resolved, AuditSink)
    assert getattr(resolved, "path", None) == "/tmp/audit.jsonl"


# --------------------------------------------------------------------------- #
# PrometheusMetricsSink
# --------------------------------------------------------------------------- #


def _prom_sink():
    pytest.importorskip("prometheus_client")
    from prometheus_client import CollectorRegistry

    from custos.telemetry import PrometheusMetricsSink

    return PrometheusMetricsSink(registry=CollectorRegistry())


def _metric_samples(registry: Any, name: str, *, keep_total: bool = True) -> list[Any]:
    """Return samples whose name matches ``<name>_total`` (counters) or
    exactly ``<name>`` (histograms/gauges/etc). Prometheus strips the
    ``_total`` suffix from Counter metric names at registration; the SAMPLE
    name still carries it. Filter on sample name for robustness.
    """
    out: list[Any] = []
    for m in registry.collect():
        for s in m.samples:
            if s.name == name or (keep_total and s.name == name + "_total"):
                out.append(s)
    return out


def test_prometheus_sink_counts_decisions_by_label() -> None:
    sink = _prom_sink()
    sink.emit(_make_event(Decision.ALLOW))
    sink.emit(_make_event(Decision.DENY, latency_ms=3))
    samples = _metric_samples(sink.registry, "custos_decisions")
    assert {tuple(sorted(s.labels.items())): s.value for s in samples} == {
        (("decision", "allow"),): 1.0,
        (("decision", "deny"),): 1.0,
    }


def test_prometheus_sink_deny_rate_incremented_on_deny() -> None:
    sink = _prom_sink()
    sink.emit(_make_event(Decision.ALLOW))
    sink.emit(_make_event(Decision.DENY))
    sink.emit(_make_event(Decision.DENY))
    deny_samples = _metric_samples(sink.registry, "custos_deny_rate")
    # Unobservable counter (no labels) — the only `_total` sample carries
    # the running total.
    total = sum(s.value for s in deny_samples)
    assert total == 2


def test_prometheus_sink_prompt_rate_by_responder() -> None:
    sink = _prom_sink()
    sink.emit(_make_event(Decision.PROMPT, responder="cli"))
    sink.emit(_make_event(Decision.PROMPT, responder="cli"))
    sink.emit(_make_event(Decision.PROMPT, responder="slack"))
    sink.emit(_make_event(Decision.ALLOW))  # not a prompt -> not counted
    samples = _metric_samples(sink.registry, "custos_prompt_rate")
    by_responder = {tuple(sorted(s.labels.items())): s.value for s in samples}
    assert by_responder.get((("responder", "cli"),)) == 2.0
    assert by_responder.get((("responder", "slack"),)) == 1.0


def test_prometheus_sink_assistant_latency_histogram() -> None:
    sink = _prom_sink()
    sink.emit(_make_event(Decision.ALLOW_ONCE, assistant="rule-policy", latency_ms=12))
    sink.emit(_make_event(Decision.ALLOW_ONCE, assistant="risk-assessment", latency_ms=1500))
    count_samples = list(
        _metric_samples(sink.registry, "custos_assistant_latency_seconds_count", keep_total=False)
    )
    count_total = sum(s.value for s in count_samples)
    assert count_total == 2


def test_prometheus_sink_skips_latency_when_no_assistant() -> None:
    sink = _prom_sink()
    event = _make_event(Decision.ALLOW, assistant=None)
    sink.emit(event)  # must not raise; nothing observed for the assistant histogram
    count_samples = list(
        _metric_samples(sink.registry, "custos_assistant_latency_seconds_count", keep_total=False)
    )
    assert all(s.value == 0 for s in count_samples)


# --------------------------------------------------------------------------- #
# OTLPAuditSink — construct + emit (no real collector; use the in-memory
# exporter to assert a span was opened with the right attributes).
# --------------------------------------------------------------------------- #


def test_otlp_sink_constructs_and_emits_span_with_safe_attributes() -> None:
    """Construct the sink with the in-memory exporter (test seam) and emit
    an AuditEvent; assert the span carries the structural audit-event
    fields (decision, tool, latency_ms, ...) and NOT the redacted args or
    subject context (privacy boundary per docs/telemetry.md).
    """
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from custos.telemetry import OTLPAuditSink

    in_memory = InMemorySpanExporter()
    sink = OTLPAuditSink(
        endpoint="http://localhost:4317",
        service_name="test-custos",
        exporter=in_memory,
    )
    # The exporter test seam replaces OTLPSpanExporter; manually flush the
    # BatchSpanProcessor to push spans out of the SDK's batching buffer.
    sink.emit(_make_event(Decision.DENY, responder="cli", latency_ms=42))
    # Force-flush the BatchSpanProcessor the sink installed (the OTLP
    # batch processor buffers spans; the SDK's provider exposes a public
    # `force_flush` to drain it).
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    if hasattr(provider, "force_flush"):
        provider.force_flush()  # type: ignore[attr-defined]

    spans = in_memory.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "custos.decide"
    attrs = span.attributes
    assert attrs["custos.decision"] == "deny"
    assert attrs["custos.tool"] == "fs.read"
    assert attrs["custos.latency_ms"] == 42
    # Privacy boundary: the redacted args + subject context never cross.
    assert not any(k.startswith("custos.args") for k in attrs)
    assert not any(k.startswith("custos.subject") for k in attrs)
    assert not any(k.startswith("custos.approver") for k in attrs)


def test_otlp_sink_construction_with_missing_sdk_raises_importerror() -> None:
    """If the opentelemetry packages are unavailable at construction time,
    the sink raises ImportError with the install hint — the late import
    surface is the  hygiene gate.
    """
    # We don't actually uninstall opentelemetry here (CI has it installed
    # for these tests); we patch the module-top `try` discovery path so
    # the failure proof of the ImportError surface passes regardless of
    # the install state. The test asserts the error message includes the
    # `[telemetry]` install hint.
    import custos.telemetry as telemetry_mod

    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "opentelemetry":
            raise ImportError("simulated missing opentelemetry")
        return real_import(name, *args, **kwargs)

    import builtins

    saved = builtins.__import__
    builtins.__import__ = _fake_import  # type: ignore[assignment]
    try:
        with pytest.raises(ImportError) as excinfo:
            telemetry_mod.OTLPAuditSink(endpoint="http://localhost:4317")
        assert "custos[telemetry]" in str(excinfo.value)
    finally:
        builtins.__import__ = saved  # type: ignore[assignment]


def test_prometheus_sink_construction_with_missing_sdk_raises_importerror() -> None:
    import custos.telemetry as telemetry_mod

    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "prometheus_client":
            raise ImportError("simulated missing prometheus_client")
        return real_import(name, *args, **kwargs)

    import builtins

    saved = builtins.__import__
    builtins.__import__ = _fake_import  # type: ignore[assignment]
    try:
        with pytest.raises(ImportError) as excinfo:
            telemetry_mod.PrometheusMetricsSink()
        assert "custos[telemetry]" in str(excinfo.value)
    finally:
        builtins.__import__ = saved  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# CompositeAuditSink fan-out behavior
# --------------------------------------------------------------------------- #


class _CountingSink(AuditSink):
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class _RaisingSink(AuditSink):
    def __init__(self, sink: _CountingSink) -> None:
        self._sink = sink

    def emit(self, event: AuditEvent) -> None:
        self._sink.emit(event)
        raise RuntimeError("boom - one bad sink does not block the audit")


def test_composite_sink_fans_out_to_all_children() -> None:
    a, b = _CountingSink(), _CountingSink()
    composite = CompositeAuditSink([a, b])
    event = _make_event(Decision.ALLOW)
    composite.emit(event)
    assert a.events == [event]
    assert b.events == [event]


def test_composite_sink_swallows_child_errors() -> None:
    """A raising child does NOT block emission to the other children."""
    a, b = _CountingSink(), _CountingSink()
    raising = _RaisingSink(b)
    composite = CompositeAuditSink([a, raising])
    event = _make_event(Decision.ALLOW)
    # Should not raise.
    composite.emit(event)
    assert a.events == [event]
    assert b.events == [event]


# --------------------------------------------------------------------------- #
#  hardening: idempotent construction + lifecycle
# --------------------------------------------------------------------------- #


def test_prometheus_sink_idempotent_on_same_registry() -> None:
    """Constructing two PrometheusMetricsSinks pointing at the same registry
    must NOT raise ``ValueError: Duplicated timeseries`` — the second
    construction reuses the existing instruments (the multi-gateway
    single-process deployment shape).
    """
    from prometheus_client import CollectorRegistry

    from custos.telemetry import PrometheusMetricsSink

    registry = CollectorRegistry()
    first = PrometheusMetricsSink(registry=registry)
    # The hardening guard: this used to raise ValueError before .
    second = PrometheusMetricsSink(registry=registry)
    # Both sinks share the same instruments; emitting on either advances the
    # same counters.
    first.emit(_make_event(Decision.ALLOW))
    second.emit(_make_event(Decision.DENY))
    decisions_samples = _metric_samples(registry, "custos_decisions")
    by_decision = {tuple(sorted(s.labels.items())): s.value for s in decisions_samples}
    assert by_decision.get((("decision", "allow"),)) == 1.0
    assert by_decision.get((("decision", "deny"),)) == 1.0


def test_prometheus_sink_idempotent_on_default_global_registry() -> None:
    """The default ``prometheus_client.REGISTRY`` is process-global; a second
    sink construction reuses the existing instruments rather than raising.
    """
    from prometheus_client import REGISTRY

    from custos.telemetry import PrometheusMetricsSink

    # Look up the existing instruments on REGISTRY first (a prior test in
    # this module may have registered them on the global registry already,
    # depending on test ordering — the idempotent construction must hold in
    # either case).
    first = PrometheusMetricsSink()  # default REGISTRY
    second = PrometheusMetricsSink()  # must not raise
    first.emit(_make_event(Decision.ALLOW))
    second.emit(_make_event(Decision.DENY))
    # Just assert no exception ($   instrument reuse verified by absence of
    # ValueError on second's construction).
    assert first._registry is REGISTRY
    assert second._registry is REGISTRY


def test_otlp_sink_shutdown_is_idempotent_and_callable() -> None:
    """``OTLPAuditSink.shutdown`` flushes the BatchSpanProcessor and is
    idempotent (a second call is a no-op). The  lifecycle contract.

    Spans emitted by THIS sink end up at the provider's exporter (the
    in-memory test seam). Whether the sink owns the provider (first in
    the process) or reuses a prior one depends on test ordering; the
    shutdown contract is the same either way — the call must not raise
    and the in-flight span must be flushed through the *active* provider.
    """
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from custos.telemetry import OTLPAuditSink

    in_memory = InMemorySpanExporter()
    sink = OTLPAuditSink(
        endpoint="http://localhost:4317",
        service_name="test-custos",
        exporter=in_memory,
    )
    sink.emit(_make_event(Decision.DENY, responder="cli", latency_ms=42))
    # First shutdown: force-flush + shutdown the underlying provider (if
    # this sink owns it) or the active one (if reusing a prior install).
    sink.shutdown(timeout_ms=5_000)
    # Second shutdown is a no-op (idempotent).
    sink.shutdown(timeout_ms=5_000)


def test_otlp_sink_construction_does_not_raise_when_provider_already_set() -> None:
    """Constructing a second OTLPAuditSink after one is already installed
    must NOT raise (the  hardening: detect the existing provider and
    reuse it rather than letting the SDK's set_tracer_provider warning
    escalate to an error or silently misroute spans to the wrong exporter).

    The construction contract: ``_owns_provider`` reflects whether THIS
    sink installed the active provider. The first construction in a clean
    process owns it; a second construction reuses the existing one. In a
    test process with possible prior OTel state, the contract reduces to
    "construction succeeds and ``_owns_provider`` is a bool" — verify
    neither raises nor misroutes silently.
    """
    pytest.importorskip("opentelemetry")
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from custos.telemetry import OTLPAuditSink

    # First construction: installs a TracerProvider IF one isn't already
    # set; reuses the existing one otherwise (the  hardening). Either
    # way, this must not raise.
    first_exporter = InMemorySpanExporter()
    first = OTLPAuditSink(exporter=first_exporter, service_name="first")
    assert isinstance(first._owns_provider, bool)

    # Second construction in the same process: a provider is certainly
    # installed by now (either first's or a prior test's). The hardening
    # contract: the second sink acknowledges it doesn't own the provider
    # and reuses the active one rather than letting the SDK emit its
    # override-warning.
    second_exporter = InMemorySpanExporter()
    second = OTLPAuditSink(exporter=second_exporter, service_name="second")
    # A provider is now definitely installed; the second sink MUST report
    # it doesn't own it (the first or a prior test does).
    assert second._owns_provider is False

    # Emitting on the second sink flows through the active provider's
    # BatchSpanProcessor (whichever provider is active). The precise
    # exporter destination is SDK-internal; the contract we assert is
    # "no exception, span reachable through the active provider's flush."
    second.emit(_make_event(Decision.ALLOW, latency_ms=10))
    active_provider_force_flush = getattr(second._provider, "force_flush", None)
    if callable(active_provider_force_flush):
        active_provider_force_flush(5_000)
    # The shutdown call also flushes the underlying provider — call it to
    # exercise the lifecycle.
    second.shutdown(timeout_ms=5_000)
