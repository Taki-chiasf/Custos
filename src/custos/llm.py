"""Sync LLM client protocol for Custos assistants (D7).

The production ``Assistant.decide`` is sync ; LLM-backed assistants
wrap their provider clients to satisfy this sync interface. ``MissingLLMClient``
raises a clear error so the no-LLM assistants (A7) and tests work without any
provider credentials.

The LiteLLM adapter lives in ``custos.integrations`` under the ``custos[llm]``
extra (keeps litellm out of the runtime dep set).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, runtime_checkable

__all__ = [
    "LLMClient",
    "NoLLMClientError",
    "MissingLLMClient",
    "FunctionLLMClient",
    "Messages",
    "Message",
]

# A chat message: ``{"role": "system"|"user"|"assistant", "content": "..."}``.
Message = Mapping[str, str]
Messages = Sequence[Message]


@runtime_checkable
class LLMClient(Protocol):
    """Minimal sync chat completion interface used by LLM-backed assistants.

    Implementations MAY be backed by any provider (OpenAI, Anthropic, Gemini,
    a local model); the runtime only depends on this Protocol .
    """

    model: str

    def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        """Return the assistant content for ``messages`` (single completion)."""
        ...


class NoLLMClientError(RuntimeError):
    """Raised when an LLM-backed assistant is invoked without a configured client."""


class MissingLLMClient:
    """Default :class:`LLMClient`. Raises on every call (use for no-key setups)."""

    model = "unconfigured"

    def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        raise NoLLMClientError(
            "No LLM client configured. Install a provider client "
            "(e.g. `custos[llm]` for the LiteLLM adapter) and pass it to the "
            "assistant constructor."
        )


class FunctionLLMClient:
    """An :class:`LLMClient` backed by a plain callable (for tests/fakes).

    The callable receives ``(messages, temperature)`` and returns a string.
    Records every call for test assertions.
    """

    def __init__(
        self,
        fn: Callable[[Messages, float], str],
        *,
        model: str = "function",
    ) -> None:
        self._fn = fn
        self.model = model
        self.calls: list[tuple[Messages, float]] = []

    def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        self.calls.append((list(messages), temperature))
        return str(self._fn(list(messages), temperature))
