"""Tests for :class:`custos.responders.cli.CLIResponder` (F1, US-8)."""

from __future__ import annotations

import io

from custos.responders.cli import CLIResponder
from custos.schema import Decision, PromptRequest


def _req(**kwargs: object) -> PromptRequest:
    defaults: dict[str, object] = {
        "tool": "fs.write",
        "args_redacted": {"path": "/tmp/x"},
        "risk": 0.6,
        "reasoning": "write op",
    }
    defaults.update(kwargs)
    return PromptRequest(**defaults)  # type: ignore[arg-type]


def _responder(input_lines: list[str], **kwargs: object) -> tuple[CLIResponder, io.StringIO]:
    """Build a CLIResponder with a canned input sequence + captured stream."""
    stream = io.StringIO()
    it = iter(input_lines)

    def fake_input(_prompt: str) -> str:
        try:
            return next(it)
        except StopIteration:
            return "n"

    responder = CLIResponder(
        timeout=30,
        stream=stream,
        input_fn=fake_input,
        **kwargs,  # type: ignore[arg-type]
    )
    return responder, stream


def test_y_maps_to_allow() -> None:
    r, _ = _responder(["y"])
    assert r.prompt(_req()).choice == Decision.ALLOW


def test_yes_maps_to_allow() -> None:
    r, _ = _responder(["yes"])
    assert r.prompt(_req()).choice == Decision.ALLOW


def test_n_maps_to_deny() -> None:
    r, _ = _responder(["n"])
    assert r.prompt(_req()).choice == Decision.DENY


def test_no_maps_to_deny() -> None:
    r, _ = _responder(["no"])
    assert r.prompt(_req()).choice == Decision.DENY


def test_lowercase_a_maps_to_allow_once() -> None:
    r, _ = _responder(["a"])
    assert r.prompt(_req()).choice == Decision.ALLOW_ONCE


def test_uppercase_A_maps_to_allow_with_ttl() -> None:
    r, _ = _responder(["A"])
    resp = r.prompt(_req())
    assert resp.choice == Decision.ALLOW
    assert resp.ttl == 10 * 60  # default 10 min -> 600s


def test_uppercase_A_custom_ttl_minutes() -> None:
    r, _ = _responder(["A"], ttl_minutes=5)  # type: ignore[arg-type]
    resp = r.prompt(_req())
    assert resp.choice == Decision.ALLOW
    assert resp.ttl == 5 * 60


def test_d_shows_details_then_re_prompts() -> None:
    """The 'd' key prints full details and re-prompts ."""
    r, stream = _responder(["d", "y"])
    resp = r.prompt(_req())
    assert resp.choice == Decision.ALLOW
    out = stream.getvalue()
    assert "--- details ---" in out
    assert "fs.write" in out  # tool name appears in details
    assert "write op" in out  # reasoning appears in details


def test_d_then_n_denies() -> None:
    r, _ = _responder(["d", "n"])
    assert r.prompt(_req()).choice == Decision.DENY


def test_d_then_l_defers() -> None:
    r, _ = _responder(["d", "l"])
    assert r.prompt(_req()).choice == Decision.DEFER


def test_empty_input_maps_to_deny() -> None:
    r, _ = _responder([""])
    assert r.prompt(_req()).choice == Decision.DENY


def test_unrecognized_input_maps_to_deny() -> None:
    r, _ = _responder(["xyz"])
    assert r.prompt(_req()).choice == Decision.DENY


def test_timeout_maps_to_deny() -> None:
    # A slow input fn that sleeps longer than the timeout.
    import time

    def slow_input(_prompt: str) -> str:
        time.sleep(2)
        return "y"

    stream = io.StringIO()
    r = CLIResponder(timeout=1, stream=stream, input_fn=slow_input)
    resp = r.prompt(_req())
    assert resp.choice == Decision.DENY
    assert "timed out" in stream.getvalue()


def test_banner_includes_tool_args_risk_reasoning() -> None:
    r, stream = _responder(["y"])
    r.prompt(
        _req(
            tool="email.send",
            args_redacted={"to": "alice@x.com"},
            risk=0.6,
            reasoning="outside trusted set",
        )
    )
    out = stream.getvalue()
    assert "email.send" in out
    assert "alice@x.com" in out
    assert "6/10" in out  # round(0.6 * 10)
    assert "outside trusted set" in out


def test_banner_omits_reasoning_when_empty() -> None:
    r, stream = _responder(["y"])
    r.prompt(_req(reasoning=""))
    out = stream.getvalue()
    # No trailing " | " when reasoning is empty.
    assert "|" not in out.splitlines()[1]


def test_deadline_passed_uses_min_timeout() -> None:
    # A deadline already in the past -> min(self.timeout, remaining>=1) = 1.
    import time

    past_deadline = int(time.time() * 1000) - 5000
    r, _ = _responder(["y"])
    resp = r.prompt(_req(deadline_unix_ms=past_deadline))
    assert resp.choice == Decision.ALLOW


def test_responder_has_name_attribute() -> None:
    assert CLIResponder(timeout=30).name == "cli"
