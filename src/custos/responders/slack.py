"""Slack adapter: formats prompts as Block Kit, receives signed interactions .

Extends :class:`~custos.responders.webhook.WebhookResponder` for the outbound
POST (reuses HMAC signing of the payload). Adds:

  - Block Kit message formatting (action buttons: allow/deny/allow_once/defer).
  - An inbound ``http.server.ThreadingHTTPServer`` on ``listen_port`` that
    receives Slack interaction callbacks, verifies the ``v0`` signing secret,
    extracts the ``action_id`` (carries ``choice|request_id``), and resolves
    the blocked ``prompt`` call via a ``threading.Event``.

No new runtime deps (: stdlib ``http.server`` + ``hmac`` + ``json``).
Delegation-to-teammate deferred to .
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from custos.responders.base import PromptRequest, PromptResponse
from custos.schema import Decision

__all__ = ["SlackResponder"]


def _escape_mrkdwn(text: str) -> str:
    """Escape structural Slack mrkdwn characters (H10)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


_ACTION_MAP: dict[str, Decision] = {
    "allow": Decision.ALLOW,
    "deny": Decision.DENY,
    "allow_once": Decision.ALLOW_ONCE,
    "defer": Decision.DEFER,
}

_MAX_STALE_SECONDS = 300


class _PendingPrompt:
    """One blocked prompt waiting for a Slack interaction callback."""

    __slots__ = ("event", "result")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: PromptResponse | None = None


class SlackResponder:
    """Slack Block Kit responder with signed interaction callbacks .

    POSTs a Block Kit message to the Slack incoming webhook URL; starts an
    inbound HTTP server to receive interaction callbacks. The ``prompt``
    call blocks until a callback arrives (with a valid ``v0`` signature) or
    the deadline expires (-> ``DENY``).
    """

    name = "slack"

    def __init__(
        self,
        slack_webhook_url: str,
        signing_secret: bytes,
        *,
        listen_port: int = 0,
        listen_path: str = "/slack/interactions",
        timeout: int = 300,
        approver_allowlist: list[str] | None = None,
        http_post: Callable[[str, bytes, dict[str, str], int], Any] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.slack_webhook_url = slack_webhook_url
        self.signing_secret = signing_secret
        self.listen_port = listen_port
        self.listen_path = listen_path
        self.timeout = timeout
        self._clock = clock or time.time
        self._allowlist: frozenset[str] | None = (
            frozenset(approver_allowlist) if approver_allowlist else None
        )
        self._pending: dict[str, _PendingPrompt] = {}
        self._lock = threading.Lock()
        self._http_post = http_post or _default_slack_post
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        if listen_port > 0:
            self._start_server(listen_port)

    def prompt(self, req: PromptRequest) -> PromptResponse:
        """POST Block Kit message, block for interaction callback ."""
        request_id = req.request_id or ""
        pending = _PendingPrompt()
        with self._lock:
            self._pending[request_id] = pending

        message = self._build_block_kit(req, request_id)
        body = json.dumps(message).encode()
        try:
            self._http_post(
                self.slack_webhook_url,
                body,
                {"Content-Type": "application/json"},
                self.timeout,
            )
        except Exception:
            self._cleanup(request_id)
            return PromptResponse(choice=Decision.DENY)

        timeout = self.timeout
        if req.deadline_unix_ms is not None:
            remaining = max(1, (req.deadline_unix_ms - int(self._clock() * 1000)) // 1000)
            timeout = min(self.timeout, remaining)

        if pending.event.wait(timeout=timeout):
            self._cleanup(request_id)
            return pending.result or PromptResponse(choice=Decision.DENY)
        self._cleanup(request_id)
        return PromptResponse(choice=Decision.DENY)

    def handle_interaction(self, action_id: str, request_id: str, user_id: str = "") -> None:
        """Called by the inbound server (or tests) to resolve a pending prompt (H12, H10).

        If an ``approver_allowlist`` is configured, non-listed user IDs result in a safe
        ``DENY`` (H10)."""
        with self._lock:
            pending = self._pending.get(request_id)
        if pending is None:
            return
        if self._allowlist is not None and user_id not in self._allowlist:
            pending.result = PromptResponse(choice=Decision.DENY, approver=user_id or None)
            pending.event.set()
            return
        choice_str = action_id.split("|", 1)[0]
        choice = _ACTION_MAP.get(choice_str, Decision.DENY)
        pending.result = PromptResponse(choice=choice, approver=user_id or None)
        pending.event.set()

    def _build_block_kit(self, req: PromptRequest, request_id: str) -> dict[str, Any]:
        """Build a Slack Block Kit message with action buttons."""
        risk_str = f"{round(req.risk * 10)}/10"
        text = (
            f"*Custos permission request*\n"
            f"Tool: `{_escape_mrkdwn(req.tool)}`\n"
            f"Risk: {risk_str}\n"
            f"Reasoning: {_escape_mrkdwn(req.reasoning) or '(none)'}"
        )
        return {
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": text}},
                {
                    "type": "actions",
                    "block_id": f"custos_actions_{request_id}",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Allow"},
                            "action_id": f"allow|{request_id}",
                            "style": "primary",
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Deny"},
                            "action_id": f"deny|{request_id}",
                            "style": "danger",
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Allow once"},
                            "action_id": f"allow_once|{request_id}",
                        },
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Later"},
                            "action_id": f"defer|{request_id}",
                        },
                    ],
                },
            ]
        }

    def _cleanup(self, request_id: str) -> None:
        with self._lock:
            self._pending.pop(request_id, None)

    def _start_server(self, port: int) -> None:
        responder = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != responder.listen_path:
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                ts = self.headers.get("X-Slack-Request-Timestamp", "")
                sig = self.headers.get("X-Slack-Signature", "")
                if not _verify_slack_signature(
                    responder.signing_secret, body, ts, sig, responder._clock()
                ):
                    self.send_error(401)
                    return
                try:
                    content_type = self.headers.get("Content-Type", "")
                    if "application/x-www-form-urlencoded" in content_type:
                        params = urllib.parse.parse_qs(body.decode())
                        payload_str = params.get("payload", ["{}"])[0]
                    else:
                        payload_str = body.decode()
                    data = json.loads(payload_str)
                    if isinstance(data, str):
                        # Double-encoded payload (rare) — parse again.
                        data = json.loads(data)
                    if isinstance(data, dict):
                        actions = data.get("actions", [])
                        if actions:
                            action_id = actions[0].get("action_id", "")
                            block_id = actions[0].get("block_id", "")
                            request_id = block_id.replace("custos_actions_", "")
                            user_id = data.get("user", {}).get("id", "")
                            responder.handle_interaction(action_id, request_id, user_id)
                except (json.JSONDecodeError, TypeError, KeyError):
                    pass
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"ok": true}')

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("0.0.0.0", port), _Handler)
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()

    def shutdown(self) -> None:
        """Stop the inbound interaction server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=5.0)
            self._server_thread = None


def _verify_slack_signature(
    secret: bytes,
    body: bytes,
    timestamp: str,
    signature: str,
    now: float,
) -> bool:
    """Verify Slack's v0 signing scheme ."""
    if not timestamp or not signature:
        return False
    try:
        ts_int = int(timestamp)
    except ValueError:
        return False
    if abs(int(now) - ts_int) > _MAX_STALE_SECONDS:
        return False
    basestring = f"v0:{timestamp}:".encode() + body
    expected = "v0=" + hmac.new(secret, basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def _default_slack_post(url: str, body: bytes, headers: dict[str, str], timeout: int) -> Any:
    """Default HTTP POST for the Slack incoming webhook (: stdlib)."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    return urllib.request.urlopen(req, timeout=timeout)
