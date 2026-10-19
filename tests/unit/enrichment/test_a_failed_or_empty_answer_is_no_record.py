"""A source's failure, or an answer that counted nothing, is no reputation record.

A tool server's structured failure (not configured, rate-limited, a refused
argument) is a JSON object too, and read through a source's record paths it
made a record of the source's name and zero counts: the indicator was marked
looked up, the next source was never asked, and the report said no engine
flagged it. Now a failure is no record, a count the answer did not give stays
absent, and an answer no declared field reads is no record either. Every
source is read this way, whatever its server or tool.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from maljan.enrichment.declared import (
    EnrichmentSource,
    ReadySource,
    SourceAsker,
    is_malicious,
    read_record,
)
from maljan.tools.errors import BAD_ARGUMENT, NOT_CONFIGURED, TIMEOUT, TOOL_FAILED, tool_error

SOURCE = EnrichmentSource.model_validate(
    {
        "kinds": ["ip"],
        "server": "intel",
        "tool": "lookup",
        "arguments": {"ip": "address"},
        "record": [
            {"name": "malicious", "path": "/stats/malicious", "read": "count"},
            {"name": "suspicious", "path": "/stats/suspicious", "read": "count"},
        ],
        "malicious_when": [{"field": "malicious", "at_least": 1}],
    }
)


async def _asked(answer: Any) -> dict[str, Any] | None:
    async def _caller(server: str, tool: str, args: dict[str, Any]) -> Any:
        return answer

    async with httpx.AsyncClient() as http:
        return await SourceAsker(http, tool_caller=_caller).ask(
            ReadySource(key="intel", source=SOURCE), "ip", "8.8.8.8"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [NOT_CONFIGURED, TIMEOUT, TOOL_FAILED, BAD_ARGUMENT])
@pytest.mark.parametrize("as_text", [True, False])
async def test_a_structured_failure_is_no_record(code: str, as_text: bool) -> None:
    failure = tool_error(code, "the service answered 429", tool="lookup")
    assert await _asked(json.dumps(failure) if as_text else failure) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        {"found": False, "summary": "8.8.8.8 not found"},
        {"stats": {}},
        "{}",
    ],
)
async def test_an_answer_that_counted_nothing_is_no_record(answer: Any) -> None:
    assert await _asked(answer) is None


@pytest.mark.asyncio
async def test_a_count_the_answer_did_not_give_stays_absent() -> None:
    record = await _asked({"stats": {"malicious": 2}})

    assert record == {"source": "intel", "malicious": 2}
    assert is_malicious(record, SOURCE)


@pytest.mark.parametrize("value", ["", "many", None, True])
def test_an_unreadable_count_is_not_zero(value: Any) -> None:
    record = read_record("intel", SOURCE, {"stats": {"malicious": value, "suspicious": 1}})

    assert record == {"source": "intel", "suspicious": 1}
    assert not is_malicious(record, SOURCE)


class _Listener:
    """The disclosure's listener: each question told, and whether it settled answered."""

    def __init__(self) -> None:
        self.told: list[tuple[str, str]] = []
        self.settled: list[bool] = []

    def __call__(self, source: str, host: str, kind: str, server: str) -> Any:
        self.told.append((source, kind))
        return self.settled.append


class _Caller:
    def __init__(self, answer: Any, withheld: str | None = None) -> None:
        self.answer, self.withheld, self.calls = answer, withheld, 0

    async def withheld_reason(self, server: str, tool: str) -> str | None:
        return self.withheld

    async def __call__(self, server: str, tool: str, args: dict[str, Any]) -> Any:
        self.calls += 1
        return self.answer


async def _told(caller: _Caller) -> tuple[_Listener, dict[str, Any] | None]:
    listener = _Listener()
    async with httpx.AsyncClient() as http:
        record = await SourceAsker(http, tool_caller=caller, on_ask=listener).ask(
            ReadySource(key="intel", source=SOURCE), "ip", "8.8.8.8"
        )
    return listener, record


@pytest.mark.asyncio
async def test_a_withheld_source_is_never_told_as_asked() -> None:
    caller = _Caller({"stats": {"malicious": 1}}, withheld="INTEL_KEY is not configured")

    listener, record = await _told(caller)

    assert record is None and caller.calls == 0
    assert listener.told == [] and listener.settled == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer", [None, json.dumps(tool_error(TOOL_FAILED, "429", tool="lookup"))]
)
async def test_a_failed_answer_is_not_settled_as_answered(answer: Any) -> None:
    listener, record = await _told(_Caller(answer))

    assert record is None
    assert listener.told == [("intel", "ip")] and listener.settled == [False]


@pytest.mark.asyncio
async def test_an_answer_is_settled_as_answered() -> None:
    listener, record = await _told(_Caller({"stats": {"malicious": 1}}))

    assert record == {"source": "intel", "malicious": 1}
    assert listener.settled == [True]
