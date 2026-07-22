"""Noop responder: logs the prompt and auto-denies .

Intended for tests and headless runs where no human is present.
"""

from __future__ import annotations

from custos.responders.base import PromptRequest, PromptResponse
from custos.schema import Decision

__all__ = ["NoopResponder"]


class NoopResponder:
    name = "noop"

    def prompt(self, req: PromptRequest) -> PromptResponse:
        return PromptResponse(choice=Decision.DENY)
