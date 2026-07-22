# Audit

Every `Gateway.decide` emits a structured `AuditEvent` . The event
carries: `ts_unix_ms`, `invocation`, `decision`, `policy_match`, `assistant`,
`risk_score`, `reasoning`, `responder`, `latency_ms`, `subject`, `approver`,
`quorum_state`, `schema_version`.

## Sinks

| Sink | Path | Tamper-evident |
|---|---|---|
| `NullAuditSink` (default) | drops | n/a |
| `FileAuditSink` | JSONL append | NO (documented) |
| `StdoutAuditSink` | stdout | NO (documented) |
| `HashChainedAuditSink` | JSONL hash-chained envelope; optional HMAC per-line | YES  |
| OTLP / S3 | via `custos[telemetry]`/custom | operator-managed |

## Hash-chained sink

```python
from custos.audit import HashChainedAuditSink

gw = Gateway(policy=policy, assistant=RulePolicy, responder=CLIResponder,
    audit_sink=HashChainedAuditSink("audit.jsonl", signing_key=b"shared-secret"),)
```

Each line is `{schema_version: "1.0", prev_hash: <hex>, event: <dict>, sig?: <hmac>}`.
The first line's `prev_hash` is the GENESIS sentinel (`"0"*64`); subsequent
lines link back to `sha256(prev_line_bytes).hexdigest`. A fresh sink
re-anchors by reading the last line's bytes — appending across process
restarts is safe.

v1.0 ships **symmetric HMAC-SHA256** (the documented v1.0 compliance primitive
for the P3 claim). Asymmetric (Ed25519) `--pubkey` is a v1.1 target gated on a
future `custos[crypto]` extra (no new hard dep at v1.0;  unchanged).

For two sinks (file + tamper-evident together):

```python
gw = Gateway(...
    audit_sink=[
        FileAuditSink("audit.jsonl"),
        HashChainedAuditSink("audit.chain.jsonl", signing_key=b"..."),
    ],)
```

## `custos audit verify`

```bash
custos audit verify audit.jsonl --hmac-key shared-secret
# exit 0 = OK; 1 = defect (reports per-line: parse_error / missing_prev_hash /
#                 bad_genesis / broken_chain / bad_signature / missing_signature
#                 / bad_schema_version); 2 = --pubkey-only attempt (v1.1 target).
```

## Replay

`custos audit replay <file> --policy new.yaml` re-runs a session's
decisions against a new policy for what-if analysis. Deterministic — uses
only the policy engine; ASSIST resolves to the matched rule's action label.

## PII redaction

`_redact_args` recurses through `properties/items/patternProperties/
additionalProperties/allOf/anyOf/$ref` (H5 deep redaction). A tool
declaring `SideEffect.PII` without a per-field redaction spec redacts ALL
arg values for responder + audit + LLM paths. `SubjectContext.extra` is
filtered by the `AUDIT_SUBJECT_FIELDS` allowlist before serialization.

See the [threat model](THREAT_MODEL.md) row 4 + row 9.