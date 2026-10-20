"""AUD-66 LSM-L1..L6: the Low findings of the llm, schemas and memory audit."""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Iterator
from typing import Any

import httpx
import openai
import pytest
from langchain_core.messages import HumanMessage

from maljan.core.config import Settings
from maljan.llm.openai_provider import OpenAIProvider, forget_standard_only
from maljan.memory.attck_case_index import AttckCaseIndex
from maljan.schemas.evidence import parse_structured
from maljan.schemas.evidence_spill import spill_part
from maljan.schemas.sandbox_report import _split_host_port, cape_report_to_sandbox_report


@pytest.fixture(autouse=True)
def _forget() -> Any:
    forget_standard_only()
    yield
    forget_standard_only()


# LSM-L1 ---------------------------------------------------------------------


def test_l1_a_case_is_not_its_own_prior_art() -> None:
    cases = [
        {
            "sample_id": "own",
            "summary_text": "beacon network injection CreateRemoteThread",
            "technique_ids": ["T1055"],
        },
        {
            "sample_id": "other",
            "summary_text": "beacon network injection CreateRemoteThread",
            "technique_ids": ["T1071"],
        },
    ]
    index = AttckCaseIndex.from_records(cases)
    found = index.search(
        "beacon network injection", top_k=5, min_score=0.0, exclude_sample_id="own"
    )
    assert [n.sample_id for n in found] == ["other"]
    techniques = index.recommend_techniques(
        "beacon network injection",
        top_k=5,
        min_score=0.0,
        max_techniques=5,
        exclude_sample_id="own",
    )
    assert [t.technique_id for t in techniques] == ["T1071"]


# LSM-L2 ---------------------------------------------------------------------


def test_l2_a_structure_nested_past_the_interpreter_is_not_structured() -> None:
    assert parse_structured("[" * 200_000 + "]" * 200_000) is None


def test_l2_a_spill_of_a_too_deep_structure_is_stated_not_raised() -> None:
    deep: Any = []
    node = deep
    for _ in range(100_000):
        child: list[Any] = []
        node.append(child)
        node = child

    class _Sink:
        max_bytes = 0
        bound_by = ""

        def put(self, digest: str, blob: bytes, content_type: str) -> str:
            return digest

    from maljan.schemas import evidence_spill

    part = next(p for p, t in evidence_spill.CONTENT_TYPES.items() if t == evidence_spill.JSON)
    ref = spill_part(_Sink(), part, deep)  # type: ignore[arg-type]
    assert ref["error"].startswith("not_serialisable")


# LSM-L3 ---------------------------------------------------------------------


def test_l3_a_logged_base_url_carries_no_credential(caplog: pytest.LogCaptureFixture) -> None:
    from types import SimpleNamespace

    from maljan.llm.registry import LLMProviderRegistry

    secret = "-".join(("pw", "9f2c"))
    url = f"https://user:{secret}@llm.internal/v1"
    choice = SimpleNamespace(
        provider="openai", model="m", temperature=None, base_url=url, effort=None
    )
    registry = LLMProviderRegistry(Settings(_env_file=None))
    with caplog.at_level(logging.DEBUG, logger="maljan"):
        try:
            registry._build_choice("static", choice, None)
        except Exception:  # noqa: BLE001 - built or refused, the log line is what is read
            pass
    assert "Building dedicated LLM" in caplog.text
    assert secret not in caplog.text


# LSM-L4 ---------------------------------------------------------------------


def _sse(text: str, finish: str | None) -> bytes:
    body = {
        "id": "c",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "m",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": finish}],
    }
    return f"data: {json.dumps(body)}\n\n".encode()


def _openai_model(parts: list[bytes]) -> Any:
    def _sync(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, content=iter(parts), headers={"content-type": "text/event-stream"}
        )

    def _async(request: httpx.Request) -> httpx.Response:
        async def _body() -> AsyncIterator[bytes]:
            for part in parts:
                yield part

        return httpx.Response(200, content=_body(), headers={"content-type": "text/event-stream"})

    settings = Settings(
        _env_file=None,
        llm={
            "openai": {
                "api_key": "not-a-key",
                "base_url": "http://127.0.0.1:8080/v1",
                "compat": "llama_cpp",
            }
        },
    )
    return OpenAIProvider(settings).build_model(
        "m",
        0.0,
        max_tokens=512,
        http_client=httpx.Client(transport=httpx.MockTransport(_sync)),
        http_async_client=httpx.AsyncClient(transport=httpx.MockTransport(_async)),
    )


def test_l4_an_openai_stream_cut_before_its_finish_is_a_dropped_connection() -> None:
    model = _openai_model([_sse("CLAIM: a", None)])
    with pytest.raises(openai.APIConnectionError):
        model.invoke([HumanMessage(content="go")])


@pytest.mark.asyncio
async def test_l4_the_async_path_refuses_it_too() -> None:
    model = _openai_model([_sse("CLAIM: a", None)])
    with pytest.raises(openai.APIConnectionError):
        await model.ainvoke([HumanMessage(content="go")])


def test_l4_a_stream_that_finished_is_the_answer() -> None:
    model = _openai_model([_sse("CLAIM: a", None), _sse("", "stop"), b"data: [DONE]\n\n"])
    assert model.invoke([HumanMessage(content="go")]).content == "CLAIM: a"


def test_l4_an_ollama_stream_without_done_is_a_dropped_connection() -> None:
    from maljan.llm.ollama_provider import OllamaProvider

    model = OllamaProvider(Settings(_env_file=None)).build_model("m", 0.0, max_tokens=512)

    def _cut(*_a: Any, **_k: Any) -> Iterator[dict[str, Any]]:
        yield {"model": "m", "message": {"role": "assistant", "content": "CLAIM: x\n"}}

    object.__setattr__(model, "_create_chat_stream", _cut)
    with pytest.raises(openai.APIConnectionError):
        model.invoke([HumanMessage(content="go")])


# LSM-L5 ---------------------------------------------------------------------


@pytest.mark.parametrize("wrong", [7, "text", None, ["x"]])
@pytest.mark.parametrize(
    "where",
    [
        ("info",),
        ("behavior", "apistats"),
        ("behavior", "summary"),
        ("behavior", "processes"),
        ("behavior", "generic"),
        ("network", "dns"),
        ("network", "domains"),
        ("signatures",),
        ("dropped",),
    ],
)
def test_l5_a_block_of_the_wrong_shape_is_read_as_empty(where: tuple[str, ...], wrong: Any) -> None:
    raw: dict[str, Any] = {
        "info": {"id": 1},
        "behavior": {"processes": [], "apistats": {}, "generic": [], "summary": {}},
        "network": {"dns": [], "domains": []},
        "signatures": [],
        "dropped": [],
    }
    node = raw
    for key in where[:-1]:
        node = node[key]
    node[where[-1]] = wrong
    cape_report_to_sandbox_report(raw, provider="cape", source_format="cape")


# LSM-L6 ---------------------------------------------------------------------


def test_l6_a_bracketed_ipv6_flow_endpoint_keeps_no_brackets() -> None:
    assert _split_host_port("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert _split_host_port("[2001:db8::1]") == ("2001:db8::1", None)
    assert _split_host_port("192.0.2.1:80") == ("192.0.2.1", 80)
    assert _split_host_port("2001:db8::1") == ("2001:db8::1", None)
