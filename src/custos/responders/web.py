"""Web widget responder: stdlib HTTP + SSE prompt surface (MVP).

Serves a single embedded HTML page and an SSE stream of pending prompts.
``prompt`` enqueues the request to the SSE stream and blocks on a
``threading.Event`` until a POST to ``/respond`` resolves it or the deadline
expires (-> ``DENY``).

No new runtime deps (: stdlib ``http.server``). Delegation-to-teammate
deferred to .
"""

from __future__ import annotations

import contextlib
import json
import secrets
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from custos.responders.base import PromptRequest, PromptResponse
from custos.schema import Decision

__all__ = ["WebResponder"]

_WIDGET_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Custos Permission Prompts</title>
<style>
body{font-family:system-ui,sans-serif;max-width:640px;margin:2rem auto;padding:0 1rem}
.prompt{border:1px solid #ddd;border-radius:8px;padding:1rem;margin-bottom:1rem}
.prompt h3{margin:0 0 .5rem}
.risk{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.85rem;color:#fff}
.risk-low{background:#2d7d2d}.risk-mid{background:#b80}.risk-high{background:#c33}
.args{font-size:.85rem;color:#666;margin:.25rem 0 0}
button{margin-right:.5rem;padding:.4rem 1rem;border:1px solid #ccc;border-radius:4px;cursor:pointer}
.allow{background:#2d7d2d;color:#fff}.deny{background:#c33;color:#fff}
</style>
</head>
<body>
<h1>Custos Prompts</h1>
<div id="prompts"></div>
<script>
function esc(s){var d=document.createElement("div");d.appendChild(document.createTextNode(s));return d.innerHTML;}
function token(){return localStorage.getItem("custos_bearer")||"";}
function getToken(){var t=token();return t?"Bearer "+t:"";}
var es=new EventSource("/events?token="+encodeURIComponent(token()));
es.onmessage=function(e){
  var req=JSON.parse(e.data);
  var div=document.createElement("div");
  div.className="prompt";
  var h3=document.createElement("h3");
  h3.textContent=req.tool;
  div.appendChild(h3);
  var riskClass=req.risk<0.4?"risk-low":req.risk<0.7?"risk-mid":"risk-high";
  var risk=document.createElement("div");
  risk.className="risk "+riskClass;
  risk.textContent="risk "+Math.round(req.risk*10)+"/10";
  div.appendChild(risk);
  var p=document.createElement("p");
  p.textContent=req.reasoning||"";
  div.appendChild(p);
  var ar=req.args_redacted||req.args;
  if(ar){
    var args=document.createElement("div");
    args.className="args";
    args.textContent="args: "+esc(JSON.stringify(ar));
    div.appendChild(args);
  }
  function btn(label,cls,choice){
    var b=document.createElement("button");
    b.textContent=label;
    if(cls){b.className=cls;}
    b.onclick=function(){respond(req.request_id,choice);};
    div.appendChild(b);
  }
  btn("Allow","allow","allow");
  btn("Deny","deny","deny");
  btn("Allow once",null,"allow_once");
  document.getElementById("prompts").prepend(div);
};
function respond(rid,choice){
  fetch("/respond",{method:"POST",headers:{"Authorization":getToken(),"Content-Type":"application/json"},
    body:JSON.stringify({request_id:rid,choice:choice})})
  .then(function(){});
}
var prompt=document.createElement("p");
prompt.textContent="Enter bearer token (printed at server start):";
var input=document.createElement("input");
input.type="password";
input.id="tokenInput";
var btn=document.createElement("button");
btn.textContent="Set Token";
btn.onclick=function(){
  localStorage.setItem("custos_bearer",document.getElementById("tokenInput").value);
  document.getElementById("authBox").style.display="none";
  document.getElementById("prompts").style.display="block";
};
var authBox=document.createElement("div");
authBox.id="authBox";
authBox.appendChild(prompt);
authBox.appendChild(input);
authBox.appendChild(btn);
document.body.insertBefore(authBox,document.getElementById("prompts"));
if(localStorage.getItem("custos_bearer")){
  authBox.style.display="none";
  document.getElementById("prompts").style.display="block";
}else{
  document.getElementById("prompts").style.display="none";
}
</script>
</body>
</html>"""


class _PendingWebPrompt:
    """One blocked web prompt waiting for a /respond POST."""

    __slots__ = ("req", "event", "result")

    def __init__(self, req: PromptRequest) -> None:
        self.req = req
        self.event = threading.Event()
        self.result: PromptResponse | None = None


class WebResponder:
    """Stdlib HTTP + SSE web widget responder (MVP, H10).

    Serves an HTML page at ``/``, an SSE stream at ``/events``, and accepts
    POST responses at ``/respond``. Binds ``127.0.0.1`` by default ;
    ``host="0.0.0.0"`` is an explicit opt-in. A bearer token (generated at
    startup or passed via ``bearer_token``) gates all three endpoints.
    ``Origin`` / ``Sec-Fetch-Site`` checks are enforced on ``/respond`` (H10).
    """

    name = "web"

    def __init__(
        self,
        *,
        port: int = 0,
        host: str = "127.0.0.1",
        timeout: int = 90,
        bearer_token: str | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.timeout = timeout
        self._clock = clock or time.time
        self._pending: dict[str, _PendingWebPrompt] = {}
        self._lock = threading.Lock()
        self._sse_clients: list[Any] = []
        self._server: ThreadingHTTPServer | None = None
        self._server_thread: threading.Thread | None = None
        self._host = host
        bearer = bearer_token or secrets.token_urlsafe(24)
        self._bearer = f"Bearer {bearer}"
        if port > 0:
            print(f"[Custos web] bearer token: {bearer}", flush=True)
            self._start_server(port)

    def prompt(self, req: PromptRequest) -> PromptResponse:
        """Enqueue to SSE stream, block for /respond POST ."""
        request_id = req.request_id or ""
        pending = _PendingWebPrompt(req)
        with self._lock:
            self._pending[request_id] = pending
        self._broadcast_sse(req)

        timeout = self.timeout
        if req.deadline_unix_ms is not None:
            remaining = max(1, (req.deadline_unix_ms - int(self._clock() * 1000)) // 1000)
            timeout = min(self.timeout, remaining)

        if pending.event.wait(timeout=timeout):
            with self._lock:
                self._pending.pop(request_id, None)
            return pending.result or PromptResponse(choice=Decision.DENY)
        with self._lock:
            self._pending.pop(request_id, None)
        return PromptResponse(choice=Decision.DENY)

    def handle_respond(self, request_id: str, choice: str) -> bool:
        """Called by the HTTP handler (or tests) to resolve a pending prompt."""
        with self._lock:
            pending = self._pending.get(request_id)
        if pending is None:
            return False
        try:
            decision = Decision(choice)
        except ValueError:
            return False
        pending.result = PromptResponse(choice=decision)
        pending.event.set()
        return True

    def _broadcast_sse(self, req: PromptRequest) -> None:
        """Send the prompt to all connected SSE clients."""
        data = json.dumps(
            {
                "tool": req.tool,
                "args_redacted": dict(req.args_redacted),
                "risk": req.risk,
                "reasoning": req.reasoning,
                "request_id": req.request_id,
            }
        )
        msg = f"data: {data}\n\n"
        with self._lock:
            clients = list(self._sse_clients)
        for client in clients:
            try:
                client.write(msg)
                client.flush()
            except Exception:
                pass

    def _start_server(self, port: int) -> None:
        responder = self

        class _Handler(BaseHTTPRequestHandler):
            def _check_auth(self) -> bool:
                """Verify bearer token on protected routes (H10).

                Accepts the ``Authorization: Bearer <token>`` header (used by
                ``/`` and ``/respond``) OR a ``?token=<raw>`` query string —
                ``EventSource`` cannot set custom headers, so ``/events``
                authentication relies on the query param (C3 regression,
                council 2026-07-22).
                """
                auth = self.headers.get("Authorization", "")
                if secrets.compare_digest(auth, responder._bearer):
                    return True
                # Parse the query string for a `?token=` fallback.
                path = self.path or ""
                if "?" in path:
                    query = path.split("?", 1)[1]
                    params = {
                        k: v for k, _, v in (item.partition("=") for item in query.split("&"))
                    }
                    raw = params.get("token", "")
                    if raw and secrets.compare_digest(f"Bearer {raw}", responder._bearer):
                        return True
                return False

            def _origin_ok(self) -> bool:
                """Same-origin check for ``/respond`` (H10 CSRF guard, C3).

                Accepts a request when there is no browser-supplied cross-site
                signal: ``Sec-Fetch-Site`` is absent/none/same-origin/same-site,
                OR an explicit ``Origin`` headers matches the server's own
                address. Rejects only genuine cross-site submissions.
                """
                sec_site = self.headers.get("Sec-Fetch-Site", "")
                if sec_site == "cross-site":
                    return False
                origin = self.headers.get("Origin", "")
                if not origin:
                    return True  # non-browser client (curl, agent) — bearer covers it
                if sec_site in ("same-origin", "same-site", "none"):
                    return True
                # Browser sending Origin but no recognized Sec-Fetch-Site:
                # require the Origin to match the server's own address.
                port = getattr(self.server, "server_port", 0)
                own = {
                    f"http://127.0.0.1:{port}",
                    f"http://localhost:{port}",
                }
                host = responder._host or getattr(self.server, "server_name", "") or ""
                if host and host not in ("127.0.0.1", "0.0.0.0", "localhost", ""):
                    own.add(f"http://{host}:{port}")
                return origin in own

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if path in ("/", "/index.html"):
                    if not self._check_auth():
                        self.send_error(403)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(_WIDGET_HTML.encode())
                elif path == "/events":
                    if not self._check_auth():
                        self.send_error(403)
                        return
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    with responder._lock:
                        responder._sse_clients.append(self.wfile)
                    try:
                        while True:
                            self.wfile.write(b": ping\n\n")
                            self.wfile.flush()
                            time.sleep(30)
                    except Exception:
                        pass
                    finally:
                        with responder._lock, contextlib.suppress(ValueError):
                            responder._sse_clients.remove(self.wfile)
                else:
                    self.send_error(404)

            def do_POST(self) -> None:
                if self.path != "/respond":
                    self.send_error(404)
                    return
                if not self._check_auth():
                    self.send_error(403)
                    return
                if not self._origin_ok():
                    self.send_error(403)
                    return
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                try:
                    data = json.loads(body)
                    request_id = data.get("request_id", "")
                    choice = data.get("choice", "")
                except (json.JSONDecodeError, TypeError):
                    self.send_error(400)
                    return
                ok = responder.handle_respond(request_id, choice)
                self.send_response(200 if ok else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"ok": true}' if ok else b'{"ok": false}')

            def log_message(self, fmt: str, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer((self._host, port), _Handler)
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()

    def shutdown(self) -> None:
        """Stop the HTTP server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
        if self._server_thread is not None:
            self._server_thread.join(timeout=5.0)
            self._server_thread = None
