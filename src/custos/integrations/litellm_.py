"""LiteLLM adapter for LLM-backed assistants .

Lives in the ``custos[llm]`` extra (``litellm`` is not a runtime dependency).
Provides a sync :class:`~custos.llm.LLMClient` backed by LiteLLM's sync
``completion`` so production assistants (A5/A6) keep the sync ``decide``
contract (D7).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from custos.llm import Messages

if TYPE_CHECKING:
    pass

__all__ = ["LiteLLMClient"]


class LiteLLMClient:
    """A sync :class:`LLMClient` backed by LiteLLM (requires ``custos[llm]``).

    Resolves the provider from the model string (e.g. ``"openai/gpt-4o-mini"``,
    ``"anthropic/claude-3-5-sonnet"``). The API key is taken from the env var
    LiteLLM expects for the provider (``OPENAI_API_KEY``,
    ``ANTHROPIC_API_KEY``, etc.) unless explicitly passed.

    ``litellm.drop_params = True`` is set so providers that reject
    ``temperature=0.0`` (o-series, some gemini tiers) silently ignore it.
    """

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
    ) -> None:
        self.model = model
        self._api_key = api_key

    def _litellm(self) -> object:
        try:
            import litellm
        except ImportError as exc:  # pragma: no cover - depends on env
            raise ImportError(
                "litellm is not installed. Install with: pip install 'custos[llm]'"
            ) from exc
        litellm.drop_params = True  # tolerate provider-specific param rejection
        return litellm

    def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        litellm = self._litellm()
        kwargs: dict[str, object] = {
            "model": self.model,
            "messages": list(messages),
            "temperature": temperature,
        }
        if self._api_key is not None:
            kwargs["api_key"] = self._api_key
        result = litellm.completion(**kwargs)  # type: ignore[attr-defined]
        return str(result.choices[0].message.content)
