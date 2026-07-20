"""Telemetry: opt-in OTLP traces + Prometheus metrics .

Two sinks ship under the ``custos[telemetry]`` extra (default-off):

  - :class:`OTLPAuditSink` — an :class:`~custos.audit.AuditSink` that
    emits one OTLP span per :class:`~custos.schema.AuditEvent` (no log
    records — v1.1 target per the docs).
  - :class:`PrometheusMetricsSink` — an :class:`~custos.audit.AuditSink`
    that updates the four  Prometheus instruments
    (``custos_decisions_total``, ``custos_prompt_rate``,
    ``custos_deny_rate``, ``custos_assistant_latency_seconds``).

Both are drop-in replacements for ``FileAuditSink`` on the gateway's
``audit_sink=`` parameter — pass a single one, or a list to fan out via
:class:`~custos.audit.CompositeAuditSink` (the gateway resolver auto-wraps
list inputs).

 : the ``opentelemetry-sdk`` +
``opentelemetry-exporter-otlp-proto-grpc`` + ``prometheus-client`` packages
are optional extras (``custos[telemetry]``). Vendor imports happen strictly
inside the construct / emit paths, never at module top — ``import custos``
with no extras installed never imports ``opentelemetry`` or
``prometheus_client``. Asserted by ``tests/telemetry/test_default_off.py``.

Default-off contract (Q4 closure  Q4 resolution): an
``import custos`` with no extras and default config produces no OTLP spans
and no Prometheus registry. The opt-in is the user constructing an
:class:`OTLPAuditSink` or :class:`PrometheusMetricsSink` and wiring it into
the gateway. There is no auto-instrumentation.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from custos.audit import AuditSink

if TYPE_CHECKING:
    from custos.schema import AuditEvent

__all__ = ["OTLPAuditSink", "PrometheusMetricsSink"]

_log = logging.getLogger("custos.telemetry")


def _try_install_tracer_provider(provider: Any) -> bool:
    """Install ``provider`` as the process-global OTel TracerProvider if no
    non-default provider has been installed yet. Returns ``True`` if we
    installed it; ``False`` if a provider was already set (in which case the
    OpenTelemetry SDK emits a warning and keeps the existing provider —
    we reuse it instead so this sink's spans don't silently misroute).

    Detection: ``trace.set_tracer_provider`` raises on a second call OR
    warns and no-ops depending on the SDK version. We catch the result
    via the API's idempotency: call it, then read back
    ``trace.get_tracer_provider`` and compare identity.
    """
    from opentelemetry import trace

    try:
        trace.set_tracer_provider(provider)
    except Exception:  # noqa: BLE101 - the SDK raises on override; treat as "already set".
        return False
    # The call succeeded; read back to confirm we actually installed it.
    # If the SDK silently no-op'd (older impls), the read-back will be the
    # prior provider rather than ours.
    installed = trace.get_tracer_provider()
    return installed is provider


class OTLPAuditSink(AuditSink):
    """An :class:`AuditSink` that emits one OTLP span per decision .

    Each :meth:`emit` call opens a tracer span named ``custos.decide``,
    recording the structural audit-event fields that are safe to ship
    (tool, decision, policy_match, latency_ms). The redacted args and the
    subject context are NEVER attached (privacy boundary per
    ``docs/telemetry.md`` and the threat model row
    "Process | telemetry backend").

    Args:
        endpoint: OTLP gRPC endpoint (e.g. ``http://localhost:4317``).
        service_name: OTLP resource service.name attribute.
        service_namespace: optional OTLP resource service.namespace.
        resource_attributes: extra OTLP resource attributes (free-form
            dict; values are stringified).
        exporter: optional pre-constructed OTLP exporter (test seam). When
            provided, ``endpoint`` is unused.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:4317",
        *,
        service_name: str = "custos",
        service_namespace: str | None = None,
        resource_attributes: dict[str, Any] | None = None,
        exporter: Any | None = None,
    ) -> None:
        # Late imports — never at module top (+ the default-off
        # regression test). Failing to import opentelemetry here surfaces a
        # clear ImportError with the install hint.
        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError as exc:
            raise ImportError(
                "OTLPAuditSink requires the `custos[telemetry]` extra "
                "(opentelemetry-sdk + opentelemetry-exporter-otlp-proto-grpc). "
                f"Original error: {exc}"
            ) from exc

        attrs: dict[str, str] = {"service.name": service_name}
        if service_namespace is not None:
            attrs["service.namespace"] = service_namespace
        if resource_attributes:
            for k, v in resource_attributes.items():
                attrs[k] = str(v)
        resource = Resource.create(attrs)
        self._exporter = exporter or OTLPSpanExporter(endpoint=endpoint)
        provider = TracerProvider(resource=resource)
        provider.add_span_processor(BatchSpanProcessor(self._exporter))
        self._trace = trace
        self._owns_provider = _try_install_tracer_provider(provider)
        if self._owns_provider:
            self._provider: Any = provider
        else:
            # A TracerProvider was already installed (another OTLPAuditSink
            # in this process, or the host's own OTel setup). Reuse it so
            # this sink's spans flow through the existing provider rather
            # than silently misrouting to nowhere (set_tracer_provider is
            # a no-op-with-warning on a second call). The exporter passed
            # to this constructor is still held on `self._exporter` for
            # `shutdown` to drain — but the OTLP batch processor attached
            # to the active provider is what actually flushes.
            self._provider = trace.get_tracer_provider()
        self._tracer = trace.get_tracer("custos")

    def emit(self, event: AuditEvent) -> None:
        """Emit one OTLP span for an :class:`AuditEvent`.

        Span name: ``custos.decide``. Span attributes (privacy
        boundary — never the args, never the subject context):
          - ``custos.decision``: the decision value (``allow`` / ``deny`` / ...).
          - ``custos.tool``: the tool name.
          - ``custos.policy_match``: the matched rule label (may be empty).
          - ``custos.assistant``: the assistant name (may be empty).
          - ``custos.responder``: the responder name (may be empty).
          - ``custos.latency_ms``: the decision latency in milliseconds.
          - ``custos.risk_score``: the risk score (float).
          - ``custos.quorum_state``: the quorum state (may be empty).
        """
        with self._tracer.start_as_current_span("custos.decide") as span:
            span.set_attribute("custos.decision", event.decision.value)
            span.set_attribute("custos.tool", event.invocation.tool)
            if event.policy_match is not None:
                span.set_attribute("custos.policy_match", event.policy_match)
            if event.assistant is not None:
                span.set_attribute("custos.assistant", event.assistant)
            if event.responder is not None:
                span.set_attribute("custos.responder", event.responder)
            span.set_attribute("custos.latency_ms", event.latency_ms)
            span.set_attribute("custos.risk_score", float(event.risk_score))
            if event.quorum_state is not None:
                span.set_attribute("custos.quorum_state", event.quorum_state)

    def shutdown(self, *, timeout_ms: int | None = 30_000) -> None:
        """Flush the in-flight spans + shut down the BatchSpanProcessor.

        Call this at process exit (or at Conv checkpoint) so the
        BatchSpanProcessor's buffered spans are pushed to the OTLP
        exporter before the process terminates; otherwise in-flight spans
        may be lost. Idempempotent.

        Args:
            timeout_ms: max wait in milliseconds (default 30s). Pass
                ``None`` for no timeout (the OTel SDK's own default for
                ``force_flush`` — ``shutdown`` is parameterless).
        """
        provider = getattr(self, "_provider", None)
        if provider is None:
            return
        force_flush = getattr(provider, "force_flush", None)
        if callable(force_flush):
            try:
                if timeout_ms is None:
                    force_flush()
                else:
                    force_flush(timeout_ms)
            except TypeError:
                # Some provider impls accept ``timeout_millis`` as a keyword
                # only; fall through to the positional/keyword-tolerant call.
                try:
                    if timeout_ms is None:
                        force_flush(timeout_millis=30_000)
                    else:
                        force_flush(timeout_millis=timeout_ms)
                except TypeError:
                    force_flush()
        shutdown = getattr(provider, "shutdown", None)
        if callable(shutdown):
            try:
                shutdown()
            except TypeError:
                # Some impls accept a timeout_ms kwarg; try the keyword, then
                # fall back to parameterless.
                try:
                    if timeout_ms is None:
                        shutdown(timeout_millis=30_000)
                    else:
                        shutdown(timeout_millis=timeout_ms)
                except TypeError:
                    shutdown()


class PrometheusMetricsSink(AuditSink):
    """An :class:`AuditSink` that updates the four  Prometheus
    instruments.

    Instruments:

      - ``custos_decisions_total`` (counter, label ``decision``)
      - ``custos_prompt_rate`` (counter, label ``responder``)
      - ``custos_deny_rate`` (counter, no labels — derived in queries)
      - ``custos_assistant_latency_seconds`` (histogram, label ``assistant``)

    Labels are bounded enumerations; the tool name is intentionally NOT a
    label to avoid cardinality blow-up (per the threat model row
    "Process | telemetry backend" + ``docs/telemetry.md``).

    Args:
        registry: a pre-constructed ``prometheus_client.CollectorRegistry``
            (defaults to ``prometheus_client.REGISTRY`` — the global). Pass
            a fresh one in tests to avoid cross-test leak.
        path: the path the operator should scrape (default ``/metrics``
            — informational; this sink does NOT serve HTTP itself; the
            operator runs ``prometheus_client.start_http_server`` or a
            WSGI bridge separately).
    """

    def __init__(self, registry: Any | None = None, *, path: str = "/metrics") -> None:
        # Late imports — never at module top (+ the default-off
        # regression test).
        try:
            from prometheus_client import (
                REGISTRY,
                Counter,
                Histogram,
            )
        except ImportError as exc:
            raise ImportError(
                "PrometheusMetricsSink requires the `custos[telemetry]` extra "
                "(prometheus-client). "
                f"Original error: {exc}"
            ) from exc

        self._registry = registry if registry is not None else REGISTRY
        self._path = path
        # Idempotent per-registry instrument memoization: a second
        # PrometheusMetricsSink pointing at the same registry must NOT raise
        # `ValueError: Duplicated timeseries`. We look up existing
        # instruments by name; if they exist (a sibling sink in the same
        # process got there first), reuse them rather than re-registering.
        self._decisions = _get_or_create_counter(
            self._registry,
            "custos_decisions_total",
            "Total Custos decisions by outcome.",
            ("decision",),
            Counter,
        )
        self._prompts = _get_or_create_counter(
            self._registry,
            "custos_prompt_rate",
            "Total prompts sent by responder (FR-9.14 / FR-9.20).",
            ("responder",),
            Counter,
        )
        self._denies = _get_or_create_counter(
            self._registry,
            "custos_deny_rate",
            "Total Custos deny decisions (no labels — query as "
            "`rate(custos_deny_rate_total[5m])`).",
            (),
            Counter,
        )
        self._assistant_latency = _get_or_create_histogram(
            self._registry,
            "custos_assistant_latency_seconds",
            "Assistant round-trip latency in seconds.",
            ("assistant",),
            Histogram,
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        )

    @property
    def registry(self) -> Any:
        return self._registry

    @property
    def path(self) -> str:
        return self._path

    def emit(self, event: AuditEvent) -> None:
        """Update the four  instruments from an :class:`AuditEvent`."""
        decision_value = event.decision.value
        self._decisions.labels(decision=decision_value).inc()
        if decision_value == "deny":
            self._denies.inc()
        if decision_value == "prompt" and event.responder is not None:
            self._prompts.labels(responder=event.responder).inc()
        if event.assistant is not None and event.latency_ms >= 0:
            self._assistant_latency.labels(assistant=event.assistant).observe(
                event.latency_ms / 1000.0
            )


def _get_or_create_counter(
    registry: Any,
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    counter_cls: Any,
) -> Any:
    """Look up an existing ``prometheus_client.Counter`` named ``name`` on
    ``registry`` and reuse it; construct a fresh one if no such instrument
    exists yet. Guards against ``ValueError: Duplicated timeseries`` when
    a second :class:`PrometheusMetricsSink` is pointed at the same registry
    (a multi-gateway single-process deployment shape).
    """
    existing = _lookup_metric(registry, name)
    if existing is not None:
        return existing
    return counter_cls(
        name,
        documentation,
        labelnames=labelnames,
        registry=registry,
    )


def _get_or_create_histogram(
    registry: Any,
    name: str,
    documentation: str,
    labelnames: tuple[str, ...],
    histogram_cls: Any,
    *,
    buckets: tuple[float, ...] | None = None,
) -> Any:
    """Look up an existing ``prometheus_client.Histogram`` named ``name`` on
    ``registry`` and reuse it; construct a fresh one if no such instrument
    exists yet. Guards against ``ValueError: Duplicated timeseries`` (same
    rationale as :func:`_get_or_create_counter`).
    """
    existing = _lookup_metric(registry, name)
    if existing is not None:
        return existing
    kwargs: dict[str, Any] = {
        "labelnames": labelnames,
        "registry": registry,
    }
    if buckets is not None:
        kwargs["buckets"] = buckets
    return histogram_cls(name, documentation, **kwargs)


def _lookup_metric(registry: Any, name: str) -> Any | None:
    """Best-effort lookup of a registered metric by name. Returns the
    metric object if found, ``None`` otherwise. Uses the
    ``prometheus_client.CollectorRegistry._names_to_collectors`` mapping
    (the canonical accessor on the 0.x line; falls back to iterating
    ``registry.collect`` and matching on ``metric.name`` if the private
    accessor is unavailable across versions).
    """
    # Fast path: the private accessor.
    names = getattr(registry, "_names_to_collectors", None)
    if isinstance(names, dict):
        existing = names.get(name)
        if existing is not None:
            return existing
        # prometheus_client registers the metric under BOTH <name> and
        # <name>_total for Counter (the OpenMetrics name). Try the _total
        # alias for Counter callers who pass the _total-suffixed name.
        if not name.endswith("_total") and f"{name}_total" in names:
            return names[f"{name}_total"]
        return None
    # Fallback: walk the registry. Slower but version-agnostic.
    try:
        for metric in registry.collect():
            if getattr(metric, "name", None) == name:
                return metric
    except Exception:  # noqa: BLE101 - registry API drift; fall through.
        return None
    return None
