"""A delivery primitive's answer is read whole, strictly and within a bound (T-006).

``run_reader`` answers the worker with what a server read out of the sample,
so its answer is held to strict JSON and to
``mcp_client.DELIVERY_ANSWER_MAX_CHARS``, the call to its own clock, and the
session of a block that runs readings waits as long as a reading may take.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.agents import mcp_client
from maljan.agents.mcp_client import MCPLangChainToolkit


class _Session:
    def __init__(self, text: str, *, error: bool = False, structured: Any = None) -> None:
        self.text, self.error, self.structured = text, error, structured
        self.asked: list[dict[str, Any]] = []

    async def call_tool(self, name: str, arguments: dict[str, Any], **timing: Any) -> Any:
        self.asked.append({"name": name, "arguments": arguments, **timing})
        return SimpleNamespace(
            content=[SimpleNamespace(text=self.text)],
            isError=self.error,
            structuredContent=self.structured,
        )


def _deliver(session: _Session, timeout: float | None = None) -> Any:
    toolkit = MCPLangChainToolkit(None)
    toolkit.session = session  # type: ignore[assignment]
    return asyncio.run(toolkit.deliver("run_reader", {"reader": "pe_info"}, timeout))


def test_the_answer_is_its_json_and_the_call_waits_its_clock() -> None:
    session = _Session('{"value": {"sections": [1, 2]}}')
    assert _deliver(session, 90.0) == {"value": {"sections": [1, 2]}}
    assert session.asked[0]["read_timeout_seconds"].total_seconds() == 90.0


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_an_answer_holding_no_json_value_is_refused(constant: str) -> None:
    with pytest.raises(ValueError, match="no JSON value"):
        _deliver(_Session(f'{{"value": {constant}}}'))


def test_an_answer_past_the_bound_is_refused_unread(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mcp_client, "DELIVERY_ANSWER_MAX_CHARS", 16)
    with pytest.raises(ValueError, match="past the 16"):
        _deliver(_Session('{"value": "' + "x" * 32 + '"}'))


def test_an_answer_marked_as_an_error_is_raised_with_its_words() -> None:
    with pytest.raises(RuntimeError, match="no such reading"):
        _deliver(_Session("no such reading", error=True))


def test_a_block_that_runs_readings_opens_a_session_that_waits_for_them() -> None:
    from maljan.core.config import Settings
    from maljan.providers.servers import READING_SESSION_READ_TIMEOUT_SECONDS, ServerHandle

    servers = Settings(_env_file=None).mcp.servers
    analysis = ServerHandle("analysis", servers["analysis"])
    die = ServerHandle("die", servers["die"])
    assert analysis._reading_session() == {
        "http_read_timeout": READING_SESSION_READ_TIMEOUT_SECONDS
    }
    assert die._reading_session() == {}
    assert MCPLangChainToolkit(None).http_read_timeout == mcp_client.HTTP_READ_TIMEOUT_SECONDS
