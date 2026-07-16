"""Pluggable LLM client for the janus-v1 parity assistants.

The default client raises :class:`NoApiKeyError` so the no-LLM parts of the
harness (A1, A2, the scenario loader, the synthetic responders, the policy
engine, and the no-key test suite) work without any model server running.

When a backend is reachable the harness installs a LiteLLM-backed client (see
:func:`litellm_client`); the assistant implementations accept any client
satisfying :class:`LLMClient`.

Default backend is **Ollama** (local, no API key, no spend) so the full 72-cell
matrix can run on a developer machine. Set the env vars below to override or to
point at a hosted provider:

  - ``CUSTOS_EVAL_AGENT_MODEL``  - the agent loop LLM and the default for
    LLM-backed assistants. Default ``ollama/llama3.1:8b``.
  - ``CUSTOS_EVAL_JUDGE_MODEL``  - LLM used by goal/output criteria judges.
    Default ``ollama/llama3.1:8b``.

Any LiteLLM model string works (e.g. ``openai/gpt-4o-mini``,
``anthropic/claude-3-5-sonnet``, ``gemini/gemini-1.5-flash``). Hosted providers
require their usual API key env var (``OPENAI_API_KEY`` etc.); Ollama needs
none.

``litellm.drop_params = True`` is set globally so providers that reject
``temperature=0.0`` (o-series, some gemini tiers) silently ignore it instead of
erroring. Ollama accepts ``temperature`` so it is unaffected.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

__all__ = [
    "LLMClient",
    "NoApiKeyError",
    "MissingLLMClient",
    "Messages",
    "default_model",
    "default_judge_model",
    "ollama_host",
    "is_ollama_reachable",
    "resolve_api_key",
    "is_ollama_model",
    "litellm_client",
]

Messages = Sequence[dict[str, str]]
ToolSpec = Sequence[dict[str, Any]]
"""OpenAI-function-call shaped tool schemas (as produced by ``as_litellm_tools``)."""
ChatMessage = dict[str, Any]
"""OpenAI-format assistant message: ``{role, content, tool_calls?}``."""

DEFAULT_OLLAMA_MODEL = "ollama/llama3.1:8b"

DEFAULT_OLLAMA_TIMEOUT = int(os.environ.get("CUSTOS_EVAL_OLLAMA_TIMEOUT", "120"))
"""Per-request HTTP socket timeout for the native Ollama client. Bigger local
models or slower hosts can raise this via env without a code change."""


class _OllamaClient:
    """Native stdlib Ollama HTTP client (no litellm, no extra deps).

    Uses Ollama's OpenAI-compatible ``/v1/chat/completions`` endpoint so the
    request/response shape matches LiteLLM's. Falls back in
    :func:`litellm_client` for hosted providers.
    """

    def __init__(self, model: str, *, host: str | None = None) -> None:
        # Litellm uses the ``ollama/<model>`` prefix; strip it for the API call.
        self.model = model.split("/", 1)[-1] if model.startswith("ollama/") else model
        self._base = (host or ollama_host()).rstrip("/")

    async def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        msg = await self.complete_with_tools(
            messages, tools=[], tool_choice="none", temperature=temperature
        )
        return str(msg.get("content") or "")

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        tools: ToolSpec,
        tool_choice: str = "auto",
        temperature: float = 0.0,
    ) -> ChatMessage:
        import asyncio
        import json as _json
        import urllib.request

        body_dict: dict[str, Any] = {
            "model": self.model,
            "messages": list(messages),
            "temperature": temperature,
            "stream": False,
        }
        if tools:
            body_dict["tools"] = list(tools)
            body_dict["tool_choice"] = tool_choice
        body = _json.dumps(body_dict).encode("utf-8")
        req = urllib.request.Request(
            self._base + "/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

        def _do() -> ChatMessage:
            with urllib.request.urlopen(req, timeout=DEFAULT_OLLAMA_TIMEOUT) as resp:  # noqa: S310
                payload = _json.loads(resp.read().decode("utf-8"))
            return dict(payload["choices"][0]["message"])

        return await asyncio.to_thread(_do)


@runtime_checkable
class LLMClient(Protocol):
    """Minimal async chat completion interface used by A3/A4/A5/A6 + the agent loop."""

    model: str

    async def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        """Return the assistant content for ``messages`` (single completion)."""
        ...

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        tools: ToolSpec,
        tool_choice: str = "auto",
        temperature: float = 0.0,
    ) -> ChatMessage:
        """Return the OpenAI-format assistant message dict (content + tool_calls)."""
        ...


class NoApiKeyError(RuntimeError):
    """Raised when an LLM-backed assistant is invoked without a configured client."""


class MissingLLMClient:
    """Default :class:`LLMClient`. Raises on every call (use for no-key runs)."""

    model = "unconfigured"

    async def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
        raise NoApiKeyError(
            "No LLM client configured. Start Ollama (`ollama serve` + "
            "`ollama pull llama3.1:8b`) or set CUSTOS_EVAL_AGENT_MODEL to a "
            "hosted model and its API key, then call "
            "`eval.harness.llm.litellm_client()` from your harness entrypoint."
        )

    async def complete_with_tools(
        self,
        messages: Sequence[dict[str, Any]],
        *,
        tools: ToolSpec,
        tool_choice: str = "auto",
        temperature: float = 0.0,
    ) -> ChatMessage:
        raise NoApiKeyError(
            "No LLM client configured for tool-calling. Start Ollama or set a "
            "hosted model + key, then call `eval.harness.llm.litellm_client()`."
        )


def default_model() -> str:
    return os.environ.get("CUSTOS_EVAL_AGENT_MODEL", DEFAULT_OLLAMA_MODEL)


def default_judge_model() -> str:
    return os.environ.get("CUSTOS_EVAL_JUDGE_MODEL", default_model())


def ollama_host() -> str:
    """Ollama HTTP base URL (``OLLAMA_HOST`` or ``localhost:11434``).

    LiteLLM reads ``OLLAMA_API_BASE`` itself; we use a plain connectivity probe.
    """
    host = os.environ.get("OLLAMA_HOST", "").strip()
    if not host:
        return "http://localhost:11434"
    if host.startswith("http://") or host.startswith("https://"):
        return host
    return f"http://{host}"


def is_ollama_reachable(*, timeout_s: float = 2.0) -> bool:
    """Cheap liveness probe: GET ``/api/tags`` against the Ollama server."""
    url = ollama_host().rstrip("/") + "/api/tags"
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:  # noqa: S310 - localhost
            return 200 <= int(resp.status) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def is_ollama_model(model: str | None = None) -> bool:
    return (model or default_model()).lower().startswith("ollama/")


def resolve_api_key(model: str | None = None) -> str | None:
    """Resolve a provider API key for hosted models; ``None`` for Ollama."""
    if is_ollama_model(model):
        return None
    return (
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or None
    )


def litellm_client(
    model: str | None = None,
    *,
    api_key: str | None = None,
) -> LLMClient:
    """Build an :class:`LLMClient` for the configured model.

    Routing:
      - ``ollama/...`` models -> native stdlib :class:`_OllamaClient` (no
        litellm, no fastapi drag) via the OpenAI-compatible ``/v1/chat/
        completions`` endpoint. This keeps local Ollama runs zero-dep .
      - any other LiteLLM model string -> :mod:`litellm` (requires [eval]
        extra). Hosted providers need their usual API key env var.
    """
    chosen_model = model or default_model()

    if is_ollama_model(chosen_model):
        return _OllamaClient(chosen_model)

    try:
        import litellm
    except ImportError as exc:
        raise ImportError(
            "litellm is not installed. Install with `pip install -e '.[eval]'`."
        ) from exc
    litellm.drop_params = True  # tolerate provider-specific param rejection

    if api_key is None:
        api_key = resolve_api_key(chosen_model)
    if not api_key:
        raise NoApiKeyError(
            "No LLM provider API key found in env (OPENAI_API_KEY / "
            "GEMINI_API_KEY / ANTHROPIC_API_KEY) and model is not an "
            "`ollama/...` model. Either set a key or point "
            "CUSTOS_EVAL_AGENT_MODEL at a local Ollama model."
        )

    class _LitellmClient:
        model = chosen_model

        async def complete(self, messages: Messages, *, temperature: float = 0.0) -> str:
            kwargs: dict[str, object] = {
                "model": chosen_model,
                "messages": list(messages),
                "temperature": temperature,
                "api_key": api_key,
            }
            result = await litellm.acompletion(**kwargs)
            return str(result.choices[0].message.content)

        async def complete_with_tools(
            self,
            messages: Sequence[dict[str, Any]],
            *,
            tools: ToolSpec,
            tool_choice: str = "auto",
            temperature: float = 0.0,
        ) -> ChatMessage:
            assert api_key is not None
            result = await litellm.acompletion(
                model=chosen_model,
                messages=list(messages),
                tools=list(tools) if tools else None,
                tool_choice=tool_choice,
                temperature=temperature,
                api_key=api_key,
            )
            return dict(result.choices[0].message.model_dump(exclude_none=True))

    return _LitellmClient()
