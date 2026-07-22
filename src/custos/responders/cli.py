"""CLI inline responder (F1, US-8).

Prints the F1 prompt banner (tool, redacted args, risk, reasoning, options)
and reads a y/N/a/A/l/d answer from stdin with a cross-platform timeout
(``threading``). On expiry the call is denied (US-8). The ``A`` choice sets
``PromptResponse.ttl`` for the fatigue suppression layer . The
``l`` choice returns ``DEFER`` (ask me later). The ``d`` choice
prints full details and re-prompts.
"""

from __future__ import annotations

import queue
import sys
import threading
import time
from collections.abc import Callable

from custos.responders.base import PromptRequest, PromptResponse
from custos.schema import Decision

__all__ = ["CLIResponder"]


# Default minutes granted by the "A" (allow-for-N-mins) choice; the fatigue
# layer  consumes ``PromptResponse.ttl`` to cache the decision.
_DEFAULT_TTL_MINUTES = 10


class CLIResponder:
    """Inline CLI prompter with timeout (F1, US-8)."""

    name = "cli"

    def __init__(
        self,
        *,
        timeout: int = 30,
        ttl_minutes: int = _DEFAULT_TTL_MINUTES,
        stream: object | None = None,
        input_fn: Callable[[str], str] | None = None,
        approver: str | None = None,
    ) -> None:
        self.timeout = timeout
        self.ttl_minutes = ttl_minutes
        self._stream = stream if stream is not None else sys.stderr
        self._input_fn = input_fn if input_fn is not None else input
        self._approver = approver

    def prompt(self, req: PromptRequest) -> PromptResponse:
        """Deliver the prompt and wait for y/N/a/A/l/d with a timeout .

        The ``d`` key prints full details and re-prompts (the loop continues
        until a non-``d`` answer is given or the deadline expires).
        """
        banner = _format_banner(req)
        self._write(banner)

        deadline_ms = req.deadline_unix_ms
        while True:
            if deadline_ms is not None:
                remaining_s = max(1, (deadline_ms - int(time.time() * 1000)) // 1000)
                timeout = min(self.timeout, remaining_s)
            else:
                timeout = self.timeout

            answer = _read_with_timeout(self._prompt_str(req, timeout), timeout, self._input_fn)
            if answer is None:
                self._write(f"[Custos] prompt timed out after {timeout}s; denying.\n")
                return PromptResponse(choice=Decision.DENY, approver=self._approver)

            stripped = answer.strip()
            if stripped.lower() == "d":
                self._write(self._format_details(req))
                continue

            return self._parse_answer(answer)

    def _parse_answer(self, answer: str) -> PromptResponse:
        """Map a raw input line to a :class:`PromptResponse` (F1, H12).

        The configured ``approver`` identity is attested on every response (H12,
). Mapping (case matters for the allow-all variant, per F1):
          y/yes  -> ALLOW
          n/no   -> DENY
          a      -> ALLOW_ONCE
          A      -> ALLOW + ttl
          l      -> DEFER
          d      -> details (handled in prompt loop; fallback: DENY)
          other  -> DENY
        """
        stripped = answer.strip()
        if not stripped:
            return PromptResponse(choice=Decision.DENY, approver=self._approver)
        if stripped == "A" or stripped.lower() == "a":
            if stripped == "A":
                return PromptResponse(
                    choice=Decision.ALLOW, ttl=self.ttl_minutes * 60, approver=self._approver
                )
            return PromptResponse(choice=Decision.ALLOW_ONCE, approver=self._approver)
        key = stripped.lower()
        if key in ("y", "yes"):
            return PromptResponse(choice=Decision.ALLOW, approver=self._approver)
        if key in ("n", "no"):
            return PromptResponse(choice=Decision.DENY, approver=self._approver)
        if key == "l":
            return PromptResponse(choice=Decision.DEFER, approver=self._approver)
        if key == "d":
            return PromptResponse(choice=Decision.DENY, approver=self._approver)
        self._write(f"[Custos] unrecognized input {stripped!r}; denying.\n")
        return PromptResponse(choice=Decision.DENY, approver=self._approver)

    def _format_details(self, req: PromptRequest) -> str:
        """Format the full details view for the ``d`` option ."""
        lines = [
            "[Custos] --- details ---",
            f"  tool: {req.tool}",
            f"  args: {dict(req.args_redacted)}",
            f"  risk: {round(req.risk * 10)}/10 ({req.risk:.2f})",
            f"  reasoning: {req.reasoning or '(none)'}",
        ]
        if req.request_id:
            lines.append(f"  request_id: {req.request_id}")
        opts = ", ".join(o.value for o in req.options)
        lines.append(f"  options: {opts}")
        lines.append("[Custos] --- end details ---")
        return "\n".join(lines) + "\n"

    def _write(self, text: str) -> None:
        write = getattr(self._stream, "write", None)
        if callable(write):
            write(text)
            flush = getattr(self._stream, "flush", None)
            if callable(flush):
                flush()

    def _prompt_str(self, req: PromptRequest, timeout: int) -> str:
        return (
            f"[Custos] risk {round(req.risk * 10)}/10 | "
            f"[y]es [n]o [a]llow once [A]llow {self.ttl_minutes} min "
            f"[l]ater ({timeout}s) > "
        )


def _format_banner(req: PromptRequest) -> str:
    """Format the F1 prompt banner ."""
    args_str = ", ".join(f"{k}={v!r}" for k, v in req.args_redacted.items())
    risk_str = f"{round(req.risk * 10)}/10"
    reasoning = f" | {req.reasoning}" if req.reasoning else ""
    return f"[Custos] agent wants: {req.tool}({args_str})\n[Custos] risk: {risk_str}{reasoning}\n"


def _read_with_timeout(prompt: str, timeout: int, input_fn: Callable[[str], str]) -> str | None:
    """Read a line from stdin with a cross-platform timeout (``threading``).

    Returns ``None`` on timeout (caller denies), or the stripped input line.
    The input thread is a daemon so it dies with the process if it lingers
    past the timeout (stdlib threads cannot be killed).
    """
    result: queue.Queue[str] = queue.Queue()

    def _read() -> None:
        try:
            result.put(input_fn(prompt))
        except (EOFError, KeyboardInterrupt):
            result.put("n")

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    t.join(max(1, timeout))
    if t.is_alive():
        return None
    return result.get_nowait()
