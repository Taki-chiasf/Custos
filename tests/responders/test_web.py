"""Tests for :class:`custos.responders.web.WebResponder` (MVP).

Uses ``handle_respond`` directly (no real HTTP server needed) to test the
blocking prompt + resolution model. Verifies:
  - handle_respond resolves the blocked prompt with the correct Decision
  - Timeout -> DENY
  - Unknown request_id -> not resolved
  - Invalid choice string -> not resolved
  - SSE broadcast data format
  - name attribute
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from custos.responders.web import WebResponder
from custos.schema import Decision, PromptRequest


def _req(**kwargs: Any) -> PromptRequest:
    defaults: dict[str, Any] = {
        "tool": "email.send",
        "args_redacted": {"to": "alice@x.com"},
        "risk": 0.6,
        "reasoning": "outside trusted set",
        "request_id": "req-001",
    }
    defaults.update(kwargs)
    return PromptRequest(**defaults)  # type: ignore[arg-type]


def _responder(**kwargs: Any) -> WebResponder:
    return WebResponder(port=0, clock=lambda: time.time(), **kwargs)  # type: ignore[arg-type]


def _prompt_and_respond(req: PromptRequest, choice: str, delay: float = 0.05) -> Decision:
    """Run prompt in a thread, fire handle_respond after a delay."""
    r = _responder(timeout=5)
    result: list[Decision] = [Decision.DENY]

    def _prompt() -> None:
        result[0] = r.prompt(req).choice

    t = threading.Thread(target=_prompt)
    t.start()

    def _respond() -> None:
        time.sleep(delay)
        r.handle_respond(req.request_id or "", choice)

    tr = threading.Thread(target=_respond, daemon=True)
    tr.start()
    t.join(timeout=5.0)
    return result[0]


# --------------------------------------------------------------------------- #
# handle_respond resolves blocked prompts
# --------------------------------------------------------------------------- #


def test_respond_allow_resolves_prompt() -> None:
    assert _prompt_and_respond(_req(), "allow") == Decision.ALLOW


def test_respond_deny_resolves_prompt() -> None:
    assert _prompt_and_respond(_req(), "deny") == Decision.DENY


def test_respond_allow_once_resolves_prompt() -> None:
    assert _prompt_and_respond(_req(), "allow_once") == Decision.ALLOW_ONCE


def test_respond_defer_resolves_prompt() -> None:
    assert _prompt_and_respond(_req(), "defer") == Decision.DEFER


# --------------------------------------------------------------------------- #
# Timeout -> DENY
# --------------------------------------------------------------------------- #


def test_timeout_returns_deny() -> None:
    r = _responder(timeout=1)
    resp = r.prompt(_req())
    assert resp.choice == Decision.DENY


# --------------------------------------------------------------------------- #
# Unknown / invalid responses
# --------------------------------------------------------------------------- #


def test_unknown_request_id_not_resolved() -> None:
    r = _responder(timeout=1)
    assert r.handle_respond("nonexistent", "allow") is False


def test_invalid_choice_not_resolved() -> None:
    r = _responder(timeout=1)
    # Start a prompt to populate _pending
    result: list[Decision] = []

    def _prompt() -> None:
        result.append(r.prompt(_req()).choice)

    t = threading.Thread(target=_prompt)
    t.start()
    time.sleep(0.05)
    assert r.handle_respond("req-001", "bogus") is False
    t.join(timeout=5.0)
    # Should time out since the response was invalid
    assert result[0] == Decision.DENY


# --------------------------------------------------------------------------- #
# SSE broadcast
# --------------------------------------------------------------------------- #


def test_sse_broadcast_sends_prompt_data() -> None:
    """_broadcast_sse sends JSON with tool/risk/reasoning/request_id to clients."""
    r = _responder()
    captured: list[str] = []

    class FakeClient:
        def write(self, msg: str) -> None:
            captured.append(msg)

        def flush(self) -> None:
            pass

    with r._lock:
        r._sse_clients.append(FakeClient())
    r._broadcast_sse(_req(tool="fs.write", risk=0.7, reasoning="dangerous"))
    assert len(captured) == 1
    assert "data: " in captured[0]
    import json

    data = json.loads(captured[0].removeprefix("data: ").strip())
    assert data["tool"] == "fs.write"
    assert data["risk"] == 0.7
    assert data["reasoning"] == "dangerous"
    assert data["request_id"] == "req-001"


def test_sse_broadcast_handles_client_error() -> None:
    """A broken SSE client should not crash the broadcast."""
    r = _responder()

    class BrokenClient:
        def write(self, msg: str) -> None:
            raise BrokenPipeError("gone")

        def flush(self) -> None:
            pass

    with r._lock:
        r._sse_clients.append(BrokenClient())
    # Should not raise
    r._broadcast_sse(_req())


# --------------------------------------------------------------------------- #
# Attributes
# --------------------------------------------------------------------------- #


def test_name_attribute() -> None:
    assert _responder().name == "web"


# --------------------------------------------------------------------------- #
# HTTP server (do_GET / do_POST) — C3 regression (council 2026-07-22)
# --------------------------------------------------------------------------- #


def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_http_respond_same_origin_approves() -> None:
    """A same-origin browser POST to /respond (valid bearer) resolves the prompt.

    Regression for C3: the old ``if origin or sec_site=='cross-site'`` guard
    rejected any POST carrying an ``Origin`` header, and browsers always
    send ``Origin`` on a fetch POST -> every approve was 403'd.
    """
    import urllib.error
    import urllib.request

    port = _free_port()
    r = WebResponder(port=port, bearer_token="sekret", clock=lambda: time.time())
    try:
        result: list[Decision] = [Decision.DENY]

        def _prompt() -> None:
            result[0] = r.prompt(_req(request_id="web-req")).choice

        t = threading.Thread(target=_prompt)
        t.start()
        time.sleep(0.1)
        body = json.dumps({"request_id": "web-req", "choice": "allow"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/respond",
            data=body,
            headers={
                "Authorization": "Bearer sekret",
                "Content-Type": "application/json",
                # Browser sends Origin same-origin + Sec-Fetch-Site same-origin.
                "Origin": f"http://127.0.0.1:{port}",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200
        t.join(timeout=5.0)
        assert result[0] == Decision.ALLOW
    finally:
        r.shutdown()


def test_http_respond_cross_site_denied() -> None:
    """A cross-site POST is 403'd even with a valid bearer (CSRF guard, H10/C3)."""
    import urllib.error
    import urllib.request

    port = _free_port()
    r = WebResponder(port=port, bearer_token="sekret")
    try:
        body = json.dumps({"request_id": "x", "choice": "allow"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/respond",
            data=body,
            headers={
                "Authorization": "Bearer sekret",
                "Content-Type": "application/json",
                "Origin": "https://evil.example",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected 403")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        r.shutdown()


def test_http_respond_no_bearer_denied() -> None:
    import urllib.error
    import urllib.request

    port = _free_port()
    r = WebResponder(port=port, bearer_token="sekret")
    try:
        body = json.dumps({"request_id": "x", "choice": "allow"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/respond",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{port}",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected 403")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        r.shutdown()


def test_http_sse_token_query_authenticates() -> None:
    """``EventSource`` cannot set headers; /events accepts a ``?token=`` query.

    Regression for C3(a): SSE always 403'd because /events only checked the
    ``Authorization`` header.
    """
    import urllib.error
    import urllib.request

    port = _free_port()
    r = WebResponder(port=port, bearer_token="sekret")
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/events?token=sekret",
            headers={"Accept": "text/event-stream"},
        )
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200
        assert resp.headers.get("Content-Type", "").startswith("text/event-stream")
    finally:
        r.shutdown()


def test_http_sse_bad_token_denied() -> None:
    import urllib.error
    import urllib.request

    port = _free_port()
    r = WebResponder(port=port, bearer_token="sekret")
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/events?token=wrong",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected 403")
        except urllib.error.HTTPError as exc:
            assert exc.code == 403
    finally:
        r.shutdown()
