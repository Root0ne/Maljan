"""An in-process sandbox view's answer is sized like an MCP tool's, and every row stays reachable.

The views answer every row by default. A busy CAPE report's API view came to
2,000 rows and 337,125 characters in one answer, and nothing sized it: the MCP
toolkit's guardrail ran only on MCP answers. The views now go through that
same guardrail, with the job's limit, ledger and context budget, and a
shortened answer's notice names ``offset`` and ``limit``.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.evidence_recorder import shortened_notice
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.agents.output_shortening import BOOKKEEPING_KEY
from maljan.core.truncation_ledger import TruncationLedger
from maljan.providers import sandbox_tools

ROOM = 20_000


def _busy_report() -> dict[str, Any]:
    processes = [
        {
            "pid": 1000 + p,
            "process_name": f"proc{p}.exe",
            "calls": [
                {"api": f"Api{p}_{a}", "arguments": {"Arg": "x" * 40}, "timestamp": "t"}
                for a in range(40)
            ],
        }
        for p in range(50)
    ]
    return {"behavior": {"processes": processes}}


class _Registry:
    def __init__(self) -> None:
        self.ledger = TruncationLedger()

    def answer_sizer(self) -> MCPLangChainToolkit:
        return MCPLangChainToolkit(None, max_output_chars=ROOM, truncation_ledger=self.ledger)


class _Container:
    def __init__(self, report: dict[str, Any]) -> None:
        self.sandbox_report = report
        self.registry = _Registry()

    def get_server_registry(self) -> _Registry:
        return self.registry


def _tool(container: _Container, name: str) -> Any:
    return next(t for t in sandbox_tools.sandbox_tools(container) if t.name == name)


def test_a_two_thousand_row_view_answers_within_the_room_and_says_how_to_page() -> None:
    container = _Container(_busy_report())
    assert sandbox_tools.sandbox_api_calls(container.sandbox_report)["total"] == 2000

    answer = _tool(container, "sandbox_api_calls").invoke({})

    assert len(answer) <= ROOM
    parsed = json.loads(answer)
    assert BOOKKEEPING_KEY in parsed
    assert parsed["total"] == 2000
    notice = shortened_notice(answer, narrowing=("offset", "limit"))
    assert "`offset`" in notice and "`limit`" in notice
    assert container.registry.ledger.snapshot()["tool_output_shortened"] == 1


def test_the_rows_left_out_are_one_page_away() -> None:
    container = _Container(_busy_report())
    tool = _tool(container, "sandbox_api_calls")
    shown = len(json.loads(tool.invoke({}))["apis"])

    page = json.loads(tool.invoke({"offset": shown, "limit": 50}))

    assert len(page["apis"]) == 50
    assert page["next_offset"] == shown + 50


def test_a_view_that_fits_is_handed_over_whole() -> None:
    container = _Container({"network": {"udp": [{"dst": "198.51.100.1", "dport": 53}]}})

    answer = json.loads(_tool(container, "sandbox_network").invoke({}))

    assert answer["udp"] == [{"dst": "198.51.100.1", "dport": 53}]
    assert BOOKKEEPING_KEY not in answer


def test_a_container_with_no_registry_answers_unsized() -> None:
    class _Bare:
        sandbox_report = {"network": {"udp": []}}

    answer = _tool(_Bare(), "sandbox_network").invoke({})  # type: ignore[arg-type]

    assert isinstance(answer, dict)
