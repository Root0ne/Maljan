"""A loaded program must also become the current one.

Ghidra's `load_program` sets the current program only when nothing is current
yet. Every later load answers `{"success": true, "program": "<name>"}` and
leaves Ghidra looking at the *first* binary of the container's lifetime, so
every analysis after the first silently describes the wrong file — decompiled
functions, imports, call graph, all of it.

Measured against the live container on 2026-08-10: two samples of 241 KB and
139 KB produced call graphs identical to the character (404,337 chars), and
`run_analysis` reported `"program": "000ac83f…"` — a third binary entirely,
left current by an earlier session. After `switch_program`, the same second
sample analysed to **5** functions rather than the 5,074 it had been
inheriting.

These tests pin the two halves: the pure parsing decisions, and the client's
obligation to follow a successful load with a switch.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from maljan.analysis.ghidra_program import (
    SWITCH_PARAM,
    SWITCH_PATH,
    program_name_from_load,
    switch_is_confirmed,
)

LOAD_OK = json.dumps({"success": True, "program": "b.exe"})
SWITCH_OK = json.dumps({"success": True, "switched_to": "b.exe", "path": "/b.exe"})


class TestProgramNameFromLoad:
    def test_a_successful_load_yields_its_program_name(self) -> None:
        assert program_name_from_load(LOAD_OK) == "b.exe"

    def test_a_failed_load_yields_nothing_to_switch_to(self) -> None:
        assert program_name_from_load(json.dumps({"success": False, "program": "b.exe"})) is None
        assert program_name_from_load(json.dumps({"error": "File not found"})) is None

    def test_a_tool_error_envelope_is_not_a_load(self) -> None:
        """The HTTP client returns these instead of raising."""
        assert program_name_from_load('{"tool_error": "http_status", "status": 401}') is None

    def test_junk_is_not_guessed_at(self) -> None:
        for junk in ("", "not json", "[]", "null", json.dumps({"success": True, "program": "  "})):
            assert program_name_from_load(junk) is None


class TestSwitchConfirmation:
    def test_a_matching_switch_is_confirmed(self) -> None:
        assert switch_is_confirmed(SWITCH_OK, "b.exe")

    def test_a_switch_to_something_else_is_not(self) -> None:
        assert not switch_is_confirmed(SWITCH_OK, "a.exe")

    def test_the_not_found_error_is_not_a_confirmation(self) -> None:
        assert not switch_is_confirmed('{"error":"Program not found: b.exe"}', "b.exe")


class _Response:
    def __init__(self, text: str, status: int = 200) -> None:
        self.text = text
        self.status_code = status

    def raise_for_status(self) -> None:
        return None


class _FakeHTTP:
    """Records every request the client makes, in order."""

    def __init__(self, replies: dict[str, str]) -> None:
        self.replies = replies
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def post(self, url: str, params=None, json=None, headers=None) -> _Response:  # noqa: A002
        self.calls.append(("POST", url, dict(params or {})))
        return _Response(self._reply(url))

    async def get(self, url: str, params=None) -> _Response:
        self.calls.append(("GET", url, dict(params or {})))
        return _Response(self._reply(url))

    def _reply(self, url: str) -> str:
        for frag, body in self.replies.items():
            if frag in url:
                return body
        return "{}"


def _client(replies: dict[str, str]) -> tuple[Any, _FakeHTTP]:
    from maljan.agents.ghidra_http_client import GhidraHTTPClient

    c = GhidraHTTPClient(base_url="http://ghidra.invalid")
    http = _FakeHTTP(replies)
    c._http = http  # type: ignore[assignment]
    return c, http


def _paths(http: _FakeHTTP) -> list[str]:
    return [u.replace("http://ghidra.invalid", "") for _, u, _ in http.calls]


class TestTheClientFollowsALoadWithASwitch:
    def test_a_successful_load_is_followed_by_a_switch(self) -> None:
        c, http = _client({"/load_program": LOAD_OK, SWITCH_PATH: SWITCH_OK})
        out = asyncio.run(
            c._call_endpoint(
                "/load_program", "POST", [{"name": "file", "source": "body"}], {"file": "/x/b.exe"}
            )
        )
        assert _paths(http) == ["/load_program", SWITCH_PATH]
        assert http.calls[1][2] == {SWITCH_PARAM: "b.exe"}, "the switch must be query-encoded"
        assert "success" in out, "the caller still receives the load response"

    def test_a_failed_load_is_not_followed_by_a_switch(self) -> None:
        c, http = _client({"/load_program": json.dumps({"error": "File not found"})})
        asyncio.run(
            c._call_endpoint(
                "/load_program", "POST", [{"name": "file", "source": "body"}], {"file": "/x/b.exe"}
            )
        )
        assert _paths(http) == ["/load_program"]

    def test_a_refused_switch_does_not_break_the_load(self) -> None:
        """A stale current program is a wrong answer; a raised exception here
        would be a broken analysis. Warn, do not throw."""
        c, http = _client(
            {"/load_program": LOAD_OK, SWITCH_PATH: '{"error":"Program not found: b.exe"}'}
        )
        out = asyncio.run(
            c._call_endpoint(
                "/load_program", "POST", [{"name": "file", "source": "body"}], {"file": "/x/b.exe"}
            )
        )
        assert "success" in out

    def test_other_endpoints_are_left_alone(self) -> None:
        c, http = _client({"/decompile_function": "int main(){}"})
        asyncio.run(c._call_endpoint("/decompile_function", "GET", [], {}))
        assert _paths(http) == ["/decompile_function"]
