"""Webhook responder: POST prompt to a URL, verify signed response .

POSTs a signed JSON payload (PromptRequest) to the webhook URL. The external
server processes the prompt (e.g. sends a Slack card with action buttons)
and returns a signed JSON response within the deadline. The response's
HMAC-SHA256 signature over ``(choice, ttl, nonce, timestamp)`` is verified;
unsigned, expired, or replayed responses are denied .

On timeout or verification failure, returns ``DENY`` (safe default).

Security :
  - Outbound payload signed with HMAC-SHA256 (``X-Custos-Signature`` header).
  - Inbound response HMAC-verified over ``choice:ttl:nonce:timestamp``.
  - Nonce tracked to prevent replay.
  - Timestamp checked against ``max_stale_seconds`` to reject old responses.
  - Uses ``hmac.compare_digest`` for constant-time comparison.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import urllib.request
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from custos.responders.base import PromptRequest, PromptResponse
from custos.schema import Decision

__all__ = ["WebhookResponder", "WebhookResponse"]


@dataclass
class WebhookResponse:
    """Raw HTTP response from the webhook endpoint."""

    status: int
    body: bytes


def _default_http_post(
    url: str, body: bytes, headers: dict[str, str], timeout: int
) -> WebhookResponse:
    """Default HTTP POST via stdlib ``urllib.request`` (: no new deps)."""
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return WebhookResponse(status=resp.status, body=resp.read())


class WebhookResponder:
    """POST prompt to a webhook URL; verify the signed response .

    The external server receives the signed PromptRequest as JSON, delivers
    it to a user (Slack/Teams/email), collects the user's decision, and
    returns a signed JSON response::

        {"choice": "allow", "ttl": null, "nonce": "...", "timestamp": 123,
         "signature": "hex..."}

    The ``signature`` is HMAC-SHA256 of ``f"{choice}:{ttl}:{nonce}:{timestamp}"``
    using the shared ``secret``. Expired, unsigned, or replayed responses are
    denied .
    """

    name = "webhook"

    def __init__(
        self,
        url: str,
        secret: bytes,
        *,
        timeout: int = 30,
        max_stale_seconds: int = 300,
        http_post: Callable[[str, bytes, dict[str, str], int], WebhookResponse] | None = None,
        clock: Callable[[], float] | None = None,
        max_nonce_cache: int = 100_000,
    ) -> None:
        self.url = url
        self.secret = secret
        self.timeout = timeout
        self.max_stale_seconds = max_stale_seconds
        self._http_post = http_post or _default_http_post
        self._clock = clock or time.time
        self._max_nonce_cache = max_nonce_cache
        self._seen_nonces: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def prompt(self, req: PromptRequest) -> PromptResponse:
        """POST the signed prompt and verify the response ."""
        payload = self._build_payload(req)
        body = json.dumps(payload, sort_keys=True).encode()
        signature = hmac.new(self.secret, body, hashlib.sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Custos-Signature": f"sha256={signature}",
        }

        timeout = self.timeout
        if req.deadline_unix_ms is not None:
            remaining = max(1, (req.deadline_unix_ms - int(self._clock() * 1000)) // 1000)
            timeout = min(self.timeout, remaining)

        try:
            resp = self._http_post(self.url, body, headers, timeout)
        except Exception:
            return PromptResponse(choice=Decision.DENY)

        if resp.status != 200:
            return PromptResponse(choice=Decision.DENY)

        return self._verify_response(resp.body)

    def _build_payload(self, req: PromptRequest) -> dict[str, Any]:
        """Build the outbound JSON payload from a PromptRequest."""
        return {
            "tool": req.tool,
            "args_redacted": dict(req.args_redacted),
            "risk": req.risk,
            "reasoning": req.reasoning,
            "options": [o.value for o in req.options],
            "request_id": req.request_id,
            "deadline_unix_ms": req.deadline_unix_ms,
        }

    def _verify_response(self, body: bytes) -> PromptResponse:
        """Parse + HMAC-verify + nonce-check + timestamp-check the response ."""
        try:
            data: dict[str, Any] = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return PromptResponse(choice=Decision.DENY)

        choice_str = data.get("choice")
        ttl = data.get("ttl")
        nonce = data.get("nonce")
        timestamp = data.get("timestamp")
        signature_hex = data.get("signature")

        if not all([choice_str, nonce, timestamp is not None, signature_hex]):
            return PromptResponse(choice=Decision.DENY)

        # Verify HMAC over "choice:ttl:nonce:timestamp" .
        signed_str = f"{choice_str}:{ttl or 0}:{nonce}:{timestamp}"
        expected = hmac.new(self.secret, signed_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(signature_hex)):
            return PromptResponse(choice=Decision.DENY)

        # Verify timestamp is not stale (replay defense).
        try:
            ts_int = int(timestamp)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return PromptResponse(choice=Decision.DENY)
        now = int(self._clock())
        if abs(now - ts_int) > self.max_stale_seconds:
            return PromptResponse(choice=Decision.DENY)

        # Verify nonce has not been seen (replay defense).
        nonce_str = str(nonce)
        with self._lock:
            if nonce_str in self._seen_nonces:
                return PromptResponse(choice=Decision.DENY)
            # Evict oldest entry when at capacity (LRU — memory guard).
            if len(self._seen_nonces) >= self._max_nonce_cache:
                self._seen_nonces.popitem(last=False)
            self._seen_nonces[nonce_str] = None

        # Map choice string to Decision enum.
        try:
            choice = Decision(str(choice_str))
        except ValueError:
            return PromptResponse(choice=Decision.DENY)

        return PromptResponse(
            choice=choice,
            ttl=int(ttl) if ttl is not None else None,
            signature=str(signature_hex).encode(),
            nonce=str(nonce),
        )
