"""Custos exceptions for the Python SDK ."""

from __future__ import annotations

__all__ = ["PermissionDenied"]


class PermissionDenied(Exception):
    """Raised by wrapped tools when ``Gateway.decide`` returns ``deny``/``defer``.

    The caller's underlying tool is never invoked. Carries the final
    :class:`~custos.schema.Decision` and the tool name for diagnostic context.
    """

    def __init__(self, tool: str, decision: str) -> None:
        self.tool = tool
        self.decision = decision
        super().__init__(f"Permission denied for tool {tool!r}: {decision}")
