"""Tests for :class:`custos.responders.webhook.WebhookResponder` .

Uses an injectable ``http_post`` fake so no real HTTP is needed. Verifies:
  - Success: valid HMAC signature -> correct Decision
  - Timeout/error -> DENY
  - Non-200 status -> DENY
  - Unsigned (missing signature) -> DENY
  - Wrong HMAC -> DENY
  - Replayed nonce -> second response DENIED
  - Expired timestamp -> DENY
  - Malformed JSON -> DENY
  - Invalid choice string -> DENY
  - ttl carried through
  - Outbound payload includes X-Custos-Signature header
  - name attribute
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

from custos.responders.webhook import WebhookResponder, WebhookResponse
from custos.schema import Decision, PromptRequest

_SECRET = b"test-secret-32-bytes-long-aaaaaaaa"


def _req(**kwargs: Any) -> PromptRequest:
    defaults: dict[str, Any] = {
        "tool": "email.send",
        "args_redacted": {"to": "alice@x.com"},
        "risk": 0.6,
        "reasoning": "outside trusted set",
        "request_id": "req-123",
    }
    defaults.update(kwargs)
    return PromptRequest(**defaults)  # type: ignore[arg-type]


def _sign(choice: str, ttl: int | None, nonce: str, timestamp: int) -> str:
    """Produce a valid HMAC signature for the given response fields."""
    signed = f"{choice}:{ttl or 0}:{nonce}:{timestamp}"
    return hmac.new(_SECRET, signed.encode(), hashlib.sha256).hexdigest()


def _resp_body(
    choice: str = "allow",
    ttl: int | None = None,
    nonce: str = "n1",
    timestamp: int | None = None,
    signature: str | None = None,
) -> bytes:
    """Build a signed response body. Auto-generates signature if not given."""
    if timestamp is None:
        timestamp = int(time.time())
    if signature is None:
        signature = _sign(choice, ttl, nonce, timestamp)
    return json.dumps(
        {
            "choice": choice,
            "ttl": ttl,
            "nonce": nonce,
            "timestamp": timestamp,
            "signature": signature,
        }
    ).encode()


def _fake_post(body: bytes):
    """Return an http_post fake that responds with ``body``."""

    def post(_url: str, _data: bytes, _headers: dict, _timeout: int) -> WebhookResponse:
        return WebhookResponse(status=200, body=body)

    return post


def _responder(http_post: Any | None = None, **kwargs: Any) -> WebhookResponder:
    """Build a WebhookResponder with a fake http_post by default."""
    if http_post is None:
        http_post = _fake_post(_resp_body())
    return WebhookResponder(
        url="http://localhost/hook",
        secret=_SECRET,
        http_post=http_post,
        clock=lambda: time.time(),
        **kwargs,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Success
# --------------------------------------------------------------------------- #


def test_valid_signed_allow_response() -> None:
    body = _resp_body(choice="allow", nonce="n1")
    r = _responder(_fake_post(body))
    resp = r.prompt(_req())
    assert resp.choice == Decision.ALLOW
    assert resp.nonce == "n1"


def test_valid_signed_deny_response() -> None:
    body = _resp_body(choice="deny", nonce="n1")
    r = _responder(_fake_post(body))
    resp = r.prompt(_req())
    assert resp.choice == Decision.DENY


def test_valid_signed_allow_once_response() -> None:
    body = _resp_body(choice="allow_once", nonce="n1")
    r = _responder(_fake_post(body))
    resp = r.prompt(_req())
    assert resp.choice == Decision.ALLOW_ONCE


def test_ttl_carried_through() -> None:
    body = _resp_body(choice="allow", ttl=600, nonce="n1")
    r = _responder(_fake_post(body))
    resp = r.prompt(_req())
    assert resp.choice == Decision.ALLOW
    assert resp.ttl == 600


def test_signature_stored_in_response() -> None:
    body = _resp_body(choice="allow", nonce="n1")
    r = _responder(_fake_post(body))
    resp = r.prompt(_req())
    assert resp.signature is not None
    assert len(resp.signature) > 0


# --------------------------------------------------------------------------- #
# Failure -> DENY
# --------------------------------------------------------------------------- #


def test_http_error_returns_deny() -> None:
    def post(*a: Any, **kw: Any) -> WebhookResponse:
        raise ConnectionError("boom")

    r = _responder(post)
    assert r.prompt(_req()).choice == Decision.DENY


def test_non_200_returns_deny() -> None:
    def post(_u: str, _d: bytes, _h: dict, _t: int) -> WebhookResponse:
        return WebhookResponse(status=500, body=b"")

    r = _responder(post)
    assert r.prompt(_req()).choice == Decision.DENY


def test_unsigned_response_returns_deny() -> None:
    body = json.dumps(
        {
            "choice": "allow",
            "ttl": None,
            "nonce": "n1",
            "timestamp": int(time.time()),
            # no signature
        }
    ).encode()
    r = _responder(_fake_post(body))
    assert r.prompt(_req()).choice == Decision.DENY


def test_wrong_hmac_returns_deny() -> None:
    body = json.dumps(
        {
            "choice": "allow",
            "ttl": None,
            "nonce": "n1",
            "timestamp": int(time.time()),
            "signature": "deadbeef" * 8,  # wrong
        }
    ).encode()
    r = _responder(_fake_post(body))
    assert r.prompt(_req()).choice == Decision.DENY


def test_replayed_nonce_returns_deny() -> None:
    """The same nonce used twice: first response accepted, second denied."""
    ts = int(time.time())
    nonce = "replay-test"
    body1 = _resp_body(choice="allow", nonce=nonce, timestamp=ts)
    body2 = _resp_body(choice="allow", nonce=nonce, timestamp=ts)

    responses = [WebhookResponse(status=200, body=body1), WebhookResponse(status=200, body=body2)]

    def post(*a: Any, **kw: Any) -> WebhookResponse:
        return responses.pop(0)

    r = _responder(post)
    resp1 = r.prompt(_req())
    assert resp1.choice == Decision.ALLOW
    resp2 = r.prompt(_req())
    assert resp2.choice == Decision.DENY  # replay denied


def test_expired_timestamp_returns_deny() -> None:
    old_ts = int(time.time()) - 3600  # 1 hour ago
    body = _resp_body(choice="allow", nonce="n1", timestamp=old_ts)
    r = _responder(_fake_post(body), max_stale_seconds=300)
    assert r.prompt(_req()).choice == Decision.DENY


def test_future_timestamp_returns_deny() -> None:
    future_ts = int(time.time()) + 3600
    body = _resp_body(choice="allow", nonce="n1", timestamp=future_ts)
    r = _responder(_fake_post(body), max_stale_seconds=300)
    assert r.prompt(_req()).choice == Decision.DENY


def test_malformed_json_returns_deny() -> None:
    r = _responder(_fake_post(b"not json"))
    assert r.prompt(_req()).choice == Decision.DENY


def test_invalid_choice_string_returns_deny() -> None:
    ts = int(time.time())
    sig = _sign("bogus", None, "n1", ts)
    body = json.dumps(
        {
            "choice": "bogus",
            "ttl": None,
            "nonce": "n1",
            "timestamp": ts,
            "signature": sig,
        }
    ).encode()
    r = _responder(_fake_post(body))
    assert r.prompt(_req()).choice == Decision.DENY


def test_missing_nonce_returns_deny() -> None:
    body = json.dumps(
        {
            "choice": "allow",
            "ttl": None,
            "timestamp": int(time.time()),
            "signature": _sign("allow", None, "n1", int(time.time())),
            # no nonce
        }
    ).encode()
    r = _responder(_fake_post(body))
    assert r.prompt(_req()).choice == Decision.DENY


# --------------------------------------------------------------------------- #
# Outbound payload verification
# --------------------------------------------------------------------------- #


def test_outbound_payload_signed() -> None:
    """The outbound POST includes an X-Custos-Signature header."""
    captured: dict[str, Any] = {}

    def post(url: str, data: bytes, headers: dict, timeout: int) -> WebhookResponse:
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        return WebhookResponse(status=200, body=_resp_body())

    r = _responder(post)
    r.prompt(_req())

    assert "X-Custos-Signature" in captured["headers"]
    sig_header = captured["headers"]["X-Custos-Signature"]
    assert sig_header.startswith("sha256=")
    # Verify the signature matches the body.
    expected = "sha256=" + hmac.new(_SECRET, captured["data"], hashlib.sha256).hexdigest()
    assert sig_header == expected


def test_outbound_payload_includes_request_fields() -> None:
    captured: dict[str, Any] = {}

    def post(url: str, data: bytes, headers: dict, timeout: int) -> WebhookResponse:
        captured["data"] = data
        return WebhookResponse(status=200, body=_resp_body())

    r = _responder(post)
    r.prompt(_req(tool="fs.write", risk=0.7, reasoning="dangerous"))

    payload = json.loads(captured["data"])
    assert payload["tool"] == "fs.write"
    assert payload["risk"] == 0.7
    assert payload["reasoning"] == "dangerous"
    assert payload["request_id"] == "req-123"


# --------------------------------------------------------------------------- #
# Deadline handling
# --------------------------------------------------------------------------- #


def test_deadline_reduces_timeout() -> None:
    """When deadline is near, the POST timeout is reduced."""
    captured: dict[str, Any] = {}

    def post(url: str, data: bytes, headers: dict, timeout: int) -> WebhookResponse:
        captured["timeout"] = timeout
        return WebhookResponse(status=200, body=_resp_body())

    r = _responder(post, timeout=30)
    past_deadline = int(time.time() * 1000) + 3000  # 3s from now
    r.prompt(_req(deadline_unix_ms=past_deadline))
    assert captured["timeout"] <= 3


# --------------------------------------------------------------------------- #
# Attributes
# --------------------------------------------------------------------------- #


def test_name_attribute() -> None:
    assert _responder().name == "webhook"
