"""Tests for :class:`custos.responders.slack.SlackResponder` .

Uses injectable ``http_post`` + ``handle_interaction`` (no real Slack/HTTP).
Verifies:
  - Block Kit message format (buttons, action_id carries choice|request_id)
  - Action_id → Decision mapping (allow/deny/allow_once/defer)
  - Timeout → DENY
  - HTTP POST error → DENY
  - Late interaction resolves the blocked prompt
  - name attribute
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from custos.responders.slack import (
    SlackResponder,
    _verify_slack_signature,
)
from custos.schema import Decision, PromptRequest

_SECRET = b"slack-signing-secret"


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


def _noop_post(*a: Any, **kw: Any) -> Any:
    """Fake http_post that does nothing (prompt blocks on interaction)."""
    return None


def _responder(**kwargs: Any) -> SlackResponder:
    """Build a SlackResponder without starting the inbound server."""
    return SlackResponder(
        slack_webhook_url="http://localhost/hook",
        signing_secret=_SECRET,
        listen_port=0,
        http_post=_noop_post,
        clock=lambda: time.time(),
        **kwargs,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# Block Kit message format
# --------------------------------------------------------------------------- #


def test_block_kit_has_action_buttons() -> None:
    r = _responder()
    msg = r._build_block_kit(_req(), "req-001")
    blocks = msg["blocks"]
    assert blocks[0]["type"] == "section"
    assert blocks[1]["type"] == "actions"
    elements = blocks[1]["elements"]
    assert len(elements) == 4  # allow, deny, allow_once, defer
    action_ids = [e["action_id"] for e in elements]
    assert "allow|req-001" in action_ids
    assert "deny|req-001" in action_ids
    assert "allow_once|req-001" in action_ids
    assert "defer|req-001" in action_ids


def test_block_kit_includes_tool_and_risk() -> None:
    r = _responder()
    msg = r._build_block_kit(_req(tool="fs.write", risk=0.7), "r1")
    text = msg["blocks"][0]["text"]["text"]
    assert "fs.write" in text
    assert "7/10" in text


def test_block_kit_includes_reasoning() -> None:
    r = _responder()
    msg = r._build_block_kit(_req(reasoning="dangerous op"), "r1")
    text = msg["blocks"][0]["text"]["text"]
    assert "dangerous op" in text


# --------------------------------------------------------------------------- #
# Action_id → Decision mapping (handle_interaction)
# --------------------------------------------------------------------------- #


def _prompt_with_interaction(req: PromptRequest, action_id: str, delay: float = 0.05) -> Decision:
    """Run prompt in a thread, fire handle_interaction after a delay."""
    r = _responder()
    result: list[Decision] = [Decision.DENY]

    def _prompt() -> None:
        result[0] = r.prompt(req).choice

    t = threading.Thread(target=_prompt)
    t.start()

    def _interact() -> None:
        time.sleep(delay)
        r.handle_interaction(action_id, req.request_id or "")

    ti = threading.Thread(target=_interact, daemon=True)
    ti.start()
    t.join(timeout=5.0)
    return result[0]


def test_interaction_allow_resolves_prompt() -> None:
    assert _prompt_with_interaction(_req(), "allow|req-001") == Decision.ALLOW


def test_interaction_deny_resolves_prompt() -> None:
    assert _prompt_with_interaction(_req(), "deny|req-001") == Decision.DENY


def test_interaction_allow_once_resolves_prompt() -> None:
    assert _prompt_with_interaction(_req(), "allow_once|req-001") == Decision.ALLOW_ONCE


def test_interaction_defer_resolves_prompt() -> None:
    assert _prompt_with_interaction(_req(), "defer|req-001") == Decision.DEFER


def test_interaction_unknown_action_denies() -> None:
    assert _prompt_with_interaction(_req(), "bogus|req-001") == Decision.DENY


def test_interaction_for_unknown_request_id_ignored() -> None:
    """Interaction for a request_id not in _pending → prompt times out → DENY."""
    r = _responder(timeout=1)
    result: list[Decision] = [Decision.ALLOW]

    def _prompt() -> None:
        result[0] = r.prompt(_req(request_id="known")).choice

    t = threading.Thread(target=_prompt)
    t.start()
    time.sleep(0.05)
    # Fire interaction for a different request_id
    r.handle_interaction("allow|unknown", "unknown")
    t.join(timeout=5.0)
    assert result[0] == Decision.DENY  # timed out


# --------------------------------------------------------------------------- #
# Timeout → DENY
# --------------------------------------------------------------------------- #


def test_timeout_returns_deny() -> None:
    r = _responder(timeout=1)
    resp = r.prompt(_req())
    assert resp.choice == Decision.DENY


# --------------------------------------------------------------------------- #
# HTTP POST error → DENY
# --------------------------------------------------------------------------- #


def test_post_error_returns_deny() -> None:
    def boom(*a: Any, **kw: Any) -> Any:
        raise ConnectionError("nope")

    r = SlackResponder(
        slack_webhook_url="http://localhost/hook",
        signing_secret=_SECRET,
        listen_port=0,
        http_post=boom,
    )
    assert r.prompt(_req()).choice == Decision.DENY


# --------------------------------------------------------------------------- #
# Outbound POST
# --------------------------------------------------------------------------- #


def test_outbound_post_called_with_block_kit() -> None:
    captured: dict[str, Any] = {}

    def post(url: str, body: bytes, headers: dict, timeout: int) -> Any:
        captured["url"] = url
        captured["body"] = body
        captured["headers"] = headers
        return None

    r = SlackResponder(
        slack_webhook_url="http://slack/hook",
        signing_secret=_SECRET,
        listen_port=0,
        http_post=post,
        timeout=1,
    )
    r.prompt(_req())
    assert captured["url"] == "http://slack/hook"
    payload = json.loads(captured["body"])
    assert "blocks" in payload


# --------------------------------------------------------------------------- #
# Slack signature verification
# --------------------------------------------------------------------------- #


def _slack_sig(body: bytes, timestamp: str) -> str:
    import hashlib
    import hmac

    basestring = f"v0:{timestamp}:".encode() + body
    return "v0=" + hmac.new(_SECRET, basestring, hashlib.sha256).hexdigest()


def test_verify_slack_signature_valid() -> None:
    body = b'{"payload":"..."}'
    ts = str(int(time.time()))
    sig = _slack_sig(body, ts)
    assert _verify_slack_signature(_SECRET, body, ts, sig, time.time())


def test_verify_slack_signature_wrong_secret() -> None:
    body = b'{"payload":"..."}'
    ts = str(int(time.time()))
    sig = _slack_sig(body, ts)
    assert not _verify_slack_signature(b"wrong", body, ts, sig, time.time())


def test_verify_slack_signature_expired() -> None:
    body = b'{"payload":"..."}'
    old_ts = str(int(time.time()) - 3600)
    sig = _slack_sig(body, old_ts)
    assert not _verify_slack_signature(_SECRET, body, old_ts, sig, time.time())


def test_verify_slack_signature_missing() -> None:
    assert not _verify_slack_signature(_SECRET, b"body", "", "", time.time())


# --------------------------------------------------------------------------- #
# Attributes
# --------------------------------------------------------------------------- #


def test_name_attribute() -> None:
    assert _responder().name == "slack"


# --------------------------------------------------------------------------- #
# Inbound HTTP server (do_POST) — end-to-end interaction callback (C1 regression)
# --------------------------------------------------------------------------- #


def _free_port() -> int:
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_inbound_http_resolves_pending_prompt() -> None:
    """A real Slack interaction callback over HTTP resolves the blocked prompt.

    Regression for C1 (2026-07-22 council): the inbound ``do_POST`` only
    called ``handle_interaction`` inside an ``isinstance(data, str)`` guard
    that was never true for a real Slack ``payload=`` (JSON-object string),
    so interactions silently no-op'd and prompts blocked to deadline.
    """
    import urllib.request

    port = _free_port()
    r = SlackResponder(
        slack_webhook_url="http://localhost/hook",
        signing_secret=_SECRET,
        listen_port=port,
        http_post=_noop_post,
        clock=lambda: time.time(),
    )
    try:
        result: list[Decision] = [Decision.DENY]

        def _prompt() -> None:
            result[0] = r.prompt(_req(request_id="http-req")).choice

        t = threading.Thread(target=_prompt)
        t.start()
        time.sleep(0.1)  # let prompt register as pending

        payload = json.dumps(
            {
                "type": "block_actions",
                "actions": [{"action_id": "allow|http-req", "block_id": "custos_actions_http-req"}],
                "user": {"id": "U123"},
            }
        )
        body = urllib.parse.urlencode({"payload": payload}).encode()
        ts = str(int(time.time()))
        sig = _slack_sig(body, ts)
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/slack/interactions",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": ts,
                "X-Slack-Signature": sig,
            },
        )
        resp = urllib.request.urlopen(req, timeout=5)
        assert resp.status == 200
        t.join(timeout=5.0)
        assert result[0] == Decision.ALLOW
    finally:
        r.shutdown()


def test_inbound_http_rejects_bad_signature() -> None:
    import urllib.request

    port = _free_port()
    r = SlackResponder(
        slack_webhook_url="http://localhost/hook",
        signing_secret=_SECRET,
        listen_port=port,
        http_post=_noop_post,
    )
    try:
        payload = json.dumps({"type": "block_actions", "actions": []})
        body = urllib.parse.urlencode({"payload": payload}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/slack/interactions",
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Slack-Request-Timestamp": str(int(time.time())),
                "X-Slack-Signature": "v0=bogus",
            },
        )
        import urllib.error

        try:
            urllib.request.urlopen(req, timeout=5)
            raise AssertionError("expected 401")
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
    finally:
        r.shutdown()
