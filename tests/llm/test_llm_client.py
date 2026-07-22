"""Tests for :mod:`custos.llm` - the sync LLM client protocol (D7)."""

from __future__ import annotations

import pytest

from custos.llm import (
    FunctionLLMClient,
    LLMClient,
    MissingLLMClient,
    NoLLMClientError,
)


def test_llm_client_is_runtime_checkable_protocol() -> None:
    # FunctionLLMClient satisfies the LLMClient Protocol structurally.
    client: FunctionLLMClient = FunctionLLMClient(lambda msgs, t: "ok")
    assert isinstance(client, LLMClient)


def test_missing_llm_client_raises_on_complete() -> None:
    with pytest.raises(NoLLMClientError):
        MissingLLMClient().complete([{"role": "user", "content": "hi"}])


def test_missing_llm_client_model_name() -> None:
    assert MissingLLMClient().model == "unconfigured"


def test_function_llm_client_records_calls() -> None:
    calls: list[str] = []

    def fn(messages, temperature: float) -> str:
        calls.append(messages[0]["content"])
        return f"echo:{messages[0]['content']}"

    client = FunctionLLMClient(fn, model="test")
    result = client.complete([{"role": "user", "content": "hello"}], temperature=0.0)
    assert result == "echo:hello"
    assert len(client.calls) == 1
    assert client.calls[0][0][0]["content"] == "hello"
    assert client.calls[0][1] == 0.0
    assert client.model == "test"


def test_function_llm_client_passes_temperature() -> None:
    seen: list[float] = []

    def fn(_msgs, temperature: float) -> str:
        seen.append(temperature)
        return "ok"

    client = FunctionLLMClient(fn)
    client.complete([{"role": "user", "content": "x"}], temperature=0.7)
    assert seen == [0.7]


def test_function_llm_client_string_coerces_return() -> None:
    # Non-string return is coerced to str.
    client = FunctionLLMClient(lambda _m, _t: 42)
    assert client.complete([]) == "42"
