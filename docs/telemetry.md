# Telemetry (opt-in, default-off)

Custos telemetry (Q4 resolution): OTLP traces + Prometheus
metrics behind the `custos[telemetry]` extra, **default-off**. An
`import custos` with no extras installed produces no OTLP spans and no
Prometheus registry.

## Install

```bash
pip install "custos-middleware[telemetry]"   # adds opentelemetry-sdk + prometheus-client
```

## Wire

The OTLP sink is a drop-in audit sink:

```python
from custos import Gateway, Policy
from custos.assistants import RulePolicy
from custos.audit import FileAuditSink
from custos.telemetry import OTLPAuditSink, PrometheusCollector

gw = Gateway(policy=Policy.from_yaml("policy.yaml"),
    assistant=RulePolicy,
    responder=NoopResponder,
    audit_sink=[
        FileAuditSink("audit.jsonl"),
        OTLPAuditSink(endpoint="http://localhost:4317",
                      service_name="my-custos"),
    ],
    metrics=PrometheusCollector,     # exposes /metrics)
```

## Scope

Each `Gateway.decide` emits:
- An OTLP span (one per decision) carrying the audit-event fields that are
  safe to ship (tool, decision, policy_match, latency_ms; **never** the
  redacted args or the subject context).
- A Prometheus counter / histogram update for the metrics below.

## Prometheus metrics

| Metric | Type | Labels |
|---|---|---|
| `custos_decisions_total` | counter | `decision` (`allow`/`deny`/`prompt`/`defer`/...) |
| `custos_prompt_rate` | counter | `responder` (e.g. `cli`, `slack`, `web`) |
| `custos_deny_rate` | counter | (none — derived in queries) |
| `custos_assistant_latency_seconds` | histogram | `assistant` (e.g. `rule-policy`, `risk-assessment`) |

Labels are bounded enumerations — no per-tool-name dimensions (avoids
cardinality blow-up). For richer per-tool breakdown, ship the standard
audit log to your log pipeline (the OTLP sink is supplement, not
replacement).

## Privacy

The OTLP sink **doesn't** ship the redacted args or the subject context.
Only structural fields (`tool`, `decision`, `policy_match`, `latency_ms`)
flow to the backend. Same convention as the Prometheus metrics. This is the
[threat model](THREAT_MODEL.md) boundary row "Process \| telemetry backend".

##  + the default-off regression

A regression test asserts `import custos` with no extras + default config
produces no telemetry spans or metrics endpoint. The test is at
`tests/telemetry/test_default_off.py`. The fixed surface stays pinned:
any future telemetry default-on change re-opens Q4.

## v1.1 forward-looking

- OTLP log records as a sink form: today the OTLP sink ships as OTLP
  traces; the v1.1 plan is to round out a `OTLPLogSink` carrying audit
  events as OTLP log records (the audit-event JSON shape already matches
  OTLP's log records semantically).
- A native ClickHouse / S3 sink is out of v1.0 scope; the pluggable
  `AuditSink` Protocol is the surface for community contributors.