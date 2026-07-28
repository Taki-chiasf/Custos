"""Custos exceptions for the Python SDK ."""

from __future__ import annotations

__all__ = ["PermissionDenied"]


class PermissionDenied(Exception):
    """Raised by wrapped tools when ``Gateway.decide`` returns ``deny``/``defer``.

    The caller's underlying tool is never invoked. Carries the final
    :class:`~custos.schema.Decision`, the tool name, and optional
    diagnostic context for programmatic recovery.
    """

    def __init__(
        self,
        tool: str,
        decision: str,
        *,
        reasoning: str = "",
        risk: float = 0.0,
        policy_match: str | None = None,
        assistant: str | None = None,
    ) -> None:
        self.tool = tool
        self.decision = decision
        self.reasoning = reasoning
        self.risk = risk
        self.policy_match = policy_match
        self.assistant = assistant
        super().__init__(f"Permission denied for tool {tool!r}: {decision}")
