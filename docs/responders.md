# Responders

The user-prompt backends . Each responder implements the
`Responder` Protocol (sync) or `ResponderAsync` (native-async); they are
swappable via the gateway constructor.

| Responder | Use | Notes |
|---|---|---|
| `NoopResponder` | Tests / headless | Auto-denies; surfaces the prompt content in the audit log only. |
| `CLIResponder` | Inline CLI agents | y/N/a/A/l/d; 30s default timeout; `A` caches the allow via `PromptResponse.ttl`. |
| `WebResponder` | Browser widget | stdlib `ThreadingHTTPServer`; SSE stream; default bind `127.0.0.1`; bearer-token-authed (H10). |
| `WebhookResponder` | Slack / Teams / out-of-band | HMAC-signed outbound; HMAC + nonce + timestamp verified inbound. |
| `SlackResponder` | Slack Block Kit | v0 Slack signing scheme; `approver_allowlist`; `_escape_mrkdwn`. |
| `MultiApproverResponder` | Quorum  | Composes N child responders; tallies per-role approvals until `quorum` met. |

## Defaults + timeouts

| Surface | Default timeout |
|---|---|
| CLI inline | 30s |
| Web widget | 90s |
| Slack | 300s |
| Webhook (per-payload) | up to 300s |

Late responses compose with the dedup cache (Q8) — a slow human does not
penalize the next identical call.

## Approver identity (/ H12)

Every `PromptResponse` carries the responder-attested **approver identity**:
- CLI: the configured `approver` login-UID string.
- Slack: `payload.user.id`.
- Webhook: HMAC-key-id / client cert principal.
- Web widget: authenticated-session subject.

The audit log records `approver` alongside `decision` .
A decision emitted without an approver on a `prompt`-resolved path is itself
an audit anomaly.

## Failure-mode

A responder can declare a degrade policy; the gateway's circuit breaker opens
after N consecutive failures within T seconds -> permanent `DENY` + audit
alert until a half-open probe succeeds. An optional secondary-responder
fallback chains `slack -> webhook -> email`.

## Responder surface hardening (H10)

- Web: default bind `127.0.0.1`; explicit `host="0.0.0.0"` opt-in; bearer
  token on `/`, `/events`, `/respond`; `Origin`/`Sec-Fetch-Site` check;
  `textContent` interpolation (never `innerHTML`).
- Slack: `application/x-www-form-urlencoded` `payload=` (H2);
  `_escape_mrkdwn`; `approver_allowlist`.

See the [threat model](THREAT_MODEL.md) rows 2 + 11.