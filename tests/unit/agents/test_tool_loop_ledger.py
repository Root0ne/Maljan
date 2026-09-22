"""The tool loop writes each call down and shows the model the id it wrote.

Exercised through the recorder's wrapper rather than a real ReAct loop: the
wrapper is the seam the loop runs every tool through, so what it records and
what it hands back is exactly what the loop produces.
"""

from __future__ import annotations

from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import BaseAnalyst
from maljan.agents.evidence_recorder import EvidenceRecorder, RepeatGuard, record_tools
from maljan.schemas.evidence import EvidenceCounter


class _StubAnalyst(BaseAnalyst):
    """Minimal concrete analyst, so the publish path can be exercised."""

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(  # pragma: no cover - unused
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        return ""


def _agent() -> _StubAnalyst:
    return _StubAnalyst(llm=None, name="static")  # type: ignore[arg-type]


def _tool(func: Any, name: str, metadata: dict | None = None) -> StructuredTool:
    return StructuredTool.from_function(func=func, name=name, metadata=metadata)


class TestRecordedCalls:
    def test_a_call_becomes_an_entry_with_timing(self) -> None:
        def identify_file(path: str) -> dict[str, str]:
            """Identify a file."""
            return {"file_type": "PE"}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(identify_file, "identify_file")], recorder)[0]
        wrapped.invoke({"path": "/samples/evil.exe"})

        assert len(recorder.entries) == 1
        entry = recorder.entries[0]
        assert entry.id == "ev_0001"
        assert entry.agent == "static"
        assert entry.tool == "identify_file"
        assert entry.args == {"path": "/samples/evil.exe"}
        assert entry.ok is True
        assert entry.structured == {"file_type": "PE"}
        assert entry.duration_ms >= 0
        assert entry.seq == 1

    def test_the_result_the_model_sees_carries_the_entry_id(self) -> None:
        def strings(path: str) -> dict[str, list[str]]:
            """List strings."""
            return {"strings": ["hello"]}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(strings, "strings")], recorder)[0]
        result = wrapped.invoke({"path": "/samples/evil.exe"})
        assert result.startswith("[ev_0001]\n")
        assert "hello" in result

    def test_the_ledger_stores_what_the_model_was_handed(self) -> None:
        # What a tool result costs in a prompt is decided by the output
        # guardrail; what the record holds is the same text, so a citation is
        # checkable past the first few thousand characters of it. The one
        # bound on the stored size is the per-agent byte budget, which says so.
        big = "A" * 20000

        def dump(path: str) -> str:
            """Return a lot of text."""
            return big

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(dump, "dump")], recorder)[0]
        result = wrapped.invoke({"path": "/samples/evil.exe"})

        assert result == f"[ev_0001]\n{big}"
        assert recorder.entries[0].output == big
        assert recorder.entries[0].truncated is False

    def test_a_raising_tool_is_recorded_as_a_failure(self) -> None:
        def pe_info(path: str) -> dict[str, str]:
            """Parse a PE."""
            raise RuntimeError("pefile exploded")

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(pe_info, "pe_info")], recorder)[0]
        result = wrapped.invoke({"path": "/samples/evil.exe"})

        entry = recorder.entries[0]
        assert entry.ok is False
        assert "pefile exploded" in (entry.error or "")
        # The model is told which entry failed, so it can cite the attempt.
        assert result.startswith("[ev_0001]")
        assert "pefile exploded" in result

    def test_the_server_a_tool_came_from_is_recorded(self) -> None:
        def decompile_function(name: str) -> str:
            """Decompile."""
            return "void f() {}"

        recorder = EvidenceRecorder("static")
        tool = _tool(decompile_function, "decompile_function", {"maljan_server": "ghidra"})
        record_tools([tool], recorder)[0].invoke({"name": "FUN_00401310"})
        assert recorder.entries[0].server == "ghidra"

    def test_an_in_process_tool_has_no_server(self) -> None:
        def hashes(path: str) -> dict[str, str]:
            """Hash a file."""
            return {"sha256": "0" * 64}

        recorder = EvidenceRecorder("static")
        record_tools([_tool(hashes, "hashes")], recorder)[0].invoke({"path": "/x"})
        assert recorder.entries[0].server is None

    def test_ids_are_shared_across_agents_in_one_job(self) -> None:
        def probe() -> str:
            """Probe."""
            return "ok"

        counter = EvidenceCounter()
        first = EvidenceRecorder("static", counter=counter)
        second = EvidenceRecorder("dynamic", counter=counter)
        record_tools([_tool(probe, "probe")], first)[0].invoke({})
        record_tools([_tool(probe, "probe")], second)[0].invoke({})
        assert first.entries[0].id == "ev_0001"
        assert second.entries[0].id == "ev_0002"


class TestARepeatedCall:
    """The live run's static analyst called ``identify_file`` with identical
    arguments ten times in a row: ten steps of its budget spent, and the same
    bytes back through the context every time."""

    @staticmethod
    def _counting_tool(calls: list[str]) -> Any:
        def identify_file(path: str) -> dict[str, str]:
            """Identify a file."""
            calls.append(path)
            return {"file_type": "PE"}

        return identify_file

    def test_the_third_identical_call_is_answered_from_the_first(self) -> None:
        calls: list[str] = []
        recorder = EvidenceRecorder("static")
        wrapped = record_tools(
            [_tool(self._counting_tool(calls), "identify_file")], recorder, RepeatGuard()
        )[0]

        for _ in range(4):
            answer = wrapped.invoke({"path": "/samples/evil.exe"})

        assert calls == ["/samples/evil.exe"] * 2, "one repeat is served, the rest are not"
        assert "You already called identify_file with these arguments" in answer
        assert "[ev_0001]" in answer

        # The refusal is a message to the model and nothing else. It used to be
        # written to the ledger as a successful call — ok=true, 0 ms — which
        # inflated the ledger and the report's "tool call(s) recorded" line and
        # handed the model a citable id for an entry holding no evidence.
        assert len(recorder.entries) == 2, "no tool ran, so nothing was recorded"
        assert all(entry.repeated_of is None for entry in recorder.entries)
        assert not answer.startswith("[ev_")

    def test_different_arguments_are_not_affected(self) -> None:
        calls: list[str] = []
        recorder = EvidenceRecorder("static")
        wrapped = record_tools(
            [_tool(self._counting_tool(calls), "identify_file")], recorder, RepeatGuard()
        )[0]

        for path in ("/samples/a.exe", "/samples/b.exe", "/samples/c.exe", "/samples/a.exe"):
            wrapped.invoke({"path": path})

        assert calls == ["/samples/a.exe", "/samples/b.exe", "/samples/c.exe", "/samples/a.exe"]
        assert all(entry.repeated_of is None for entry in recorder.entries)

    def test_argument_order_does_not_make_it_a_different_call(self) -> None:
        seen: list[dict[str, Any]] = []

        def scan(path: str, deep: bool = False) -> dict[str, Any]:
            """Scan a file."""
            seen.append({"path": path, "deep": deep})
            return {"hits": 0}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(scan, "scan")], recorder, RepeatGuard())[0]

        wrapped.invoke({"path": "/s.exe", "deep": True})
        wrapped.invoke({"deep": True, "path": "/s.exe"})
        wrapped.invoke({"deep": True, "path": "/s.exe"})

        assert len(seen) == 2

    def test_a_call_that_raises_counts_against_the_budget_too(self) -> None:
        """A tool that throws on the same arguments was re-run without bound:
        the guard was only told about calls that returned, so an unreachable
        server or a path the sidecar will never read could spend a whole step
        budget failing identically."""
        calls: list[str] = []

        def identify_file(path: str) -> dict[str, str]:
            """Identify a file."""
            calls.append(path)
            raise RuntimeError("no such file")

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(identify_file, "identify_file")], recorder, RepeatGuard())[0]

        for _ in range(4):
            answer = wrapped.invoke({"path": "/samples/gone.exe"})

        assert calls == ["/samples/gone.exe"] * 2, "one repeat is served, the rest are not"
        # And it says what is in the entry it points at, which here is a
        # failure: the live notice sent a model to [ev_0017] for "the result"
        # and ev_0017 had raised.
        assert "You already called identify_file with these arguments and it failed" in answer
        assert [entry.ok for entry in recorder.entries] == [False, False]

    def test_a_call_that_starts_failing_still_counts_from_the_first(self) -> None:
        outcomes = iter([RuntimeError("transient"), None])

        def identify_file(path: str) -> dict[str, str]:
            """Identify a file."""
            outcome = next(outcomes, None)
            if isinstance(outcome, Exception):
                raise outcome
            return {"file_type": "PE"}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(identify_file, "identify_file")], recorder, RepeatGuard())[0]

        for _ in range(3):
            wrapped.invoke({"path": "/samples/evil.exe"})

        # The retry after the transient failure is the repeat the guard serves;
        # the third call is refused and writes no entry.
        assert [entry.ok for entry in recorder.entries] == [False, True]

    def test_without_a_guard_every_call_still_runs(self) -> None:
        calls: list[str] = []
        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(self._counting_tool(calls), "identify_file")], recorder)[0]

        for _ in range(3):
            wrapped.invoke({"path": "/samples/evil.exe"})

        assert len(calls) == 3


class TestPublishing:
    def test_the_agent_publishes_entries_and_the_legacy_view(self) -> None:
        def probe() -> str:
            """Probe."""
            return "ok"

        recorder = EvidenceRecorder("static")
        record_tools([_tool(probe, "probe")], recorder)[0].invoke({})

        agent = _agent()
        agent._finish_evidence(recorder)
        captured = agent.get_last_tool_evidence()
        assert captured[0].tool_name == "probe"
        assert captured[0].agent_id == "static"
        # Draining hands over ownership: the second read is empty.
        assert [e.id for e in agent.drain_evidence_entries()] == ["ev_0001"]
        assert agent.drain_evidence_entries() == []
        assert agent.get_last_tool_evidence() == []

    def test_the_budget_trim_is_counted_in_the_truncation_ledger(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        def bulk() -> str:
            """Return a lot."""
            return "A" * 500

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(bulk, "bulk")], recorder)[0]
        for _ in range(4):
            wrapped.invoke({})

        agent = _agent()
        agent.truncation_ledger = TruncationLedger()

        import maljan.agents.base_agent as base_agent_module

        class _Reporting:
            evidence_budget_bytes = 600

        class _Settings:
            reporting = _Reporting()

        original = base_agent_module.get_settings
        base_agent_module.get_settings = lambda: _Settings()  # type: ignore[assignment]
        try:
            agent._finish_evidence(recorder)
        finally:
            base_agent_module.get_settings = original  # type: ignore[assignment]

        snapshot = agent.truncation_ledger.snapshot()
        assert snapshot["evidence_entries"] == 4
        assert snapshot["evidence_trimmed"] == 3
        assert agent.drain_evidence_entries()[3].truncated is True

    def test_a_loop_that_raises_still_publishes_what_it_gathered(self) -> None:
        # The run whose evidence is worth the most is the one that died.
        from unittest.mock import MagicMock, patch

        def probe() -> str:
            """Probe."""
            return "ok"

        agent = _agent()
        agent.llm = MagicMock()
        agent.tools = [_tool(probe, "probe")]

        def _boom(coro, timeout, label=""):
            # Make the calls the loop would have made, then die the way the
            # hard cap does.
            coro.close()
            for wrapped in captured_tools[0]:
                wrapped.invoke({})
            raise TimeoutError("hard cap")

        captured_tools: list = []

        def _create(llm, tools, **_kwargs):
            captured_tools.append(tools)
            return MagicMock()

        with (
            patch("langgraph.prebuilt.create_react_agent", _create),
            patch("maljan.agents.base_agent._run_coro_blocking", _boom),
            pytest.raises(TimeoutError),
        ):
            agent.execute_tool_loop([("system", "s"), ("human", "h")])

        assert [e.tool for e in agent.drain_evidence_entries()] == ["probe"]

    def test_two_loops_accumulate_until_the_node_drains(self) -> None:
        # A chunked analysis re-enters the loop once per chunk and the node
        # reads once at the end; a buffer reset per loop would keep only the
        # last chunk while the earlier ones had already consumed ids.
        def probe() -> str:
            """Probe."""
            return "ok"

        counter = EvidenceCounter()
        agent = _agent()
        for _ in range(2):
            recorder = EvidenceRecorder("static", counter=counter)
            record_tools([_tool(probe, "probe")], recorder)[0].invoke({})
            agent._finish_evidence(recorder)

        assert [e.id for e in agent.drain_evidence_entries()] == ["ev_0001", "ev_0002"]
        assert agent.drain_evidence_entries() == []

    def test_no_calls_publishes_nothing(self) -> None:
        agent = _agent()
        agent._finish_evidence(EvidenceRecorder("static"))
        assert agent.drain_evidence_entries() == []
        assert agent.get_last_tool_evidence() == []


class TestTheRepeatMessageSteers:
    """The guard bounded the waste; it did not reduce it. A live static analyst
    called ``strings`` seventeen times with identical arguments — ten of them
    short-circuited — because "the result is in [ev_0007]" answers where the
    answer is and not what to do instead."""

    @staticmethod
    def _strings_tool(calls: list[dict[str, Any]]) -> Any:
        def strings(path: str, pattern: str = "", start: int = 0, end: int = 0) -> dict[str, Any]:
            """Extract strings."""
            calls.append({"path": path, "pattern": pattern, "start": start, "end": end})
            return {"total": 400, "runs": ["MZ"]}

        return strings

    def _wrapped(self, calls: list[dict[str, Any]]) -> tuple[Any, EvidenceRecorder]:
        recorder = EvidenceRecorder("static")
        wrapped = record_tools(
            [_tool(self._strings_tool(calls), "strings")], recorder, RepeatGuard()
        )[0]
        return wrapped, recorder

    def test_the_second_call_is_served_and_carries_the_steering(self) -> None:
        calls: list[dict[str, Any]] = []
        wrapped, _recorder = self._wrapped(calls)

        first = wrapped.invoke({"path": "/s.exe"})
        second = wrapped.invoke({"path": "/s.exe"})

        assert len(calls) == 2, "the second call still runs"
        assert "total" in second, "and its answer still comes back"
        assert "steering" not in first
        assert "This is the second call to strings with these arguments" in second
        assert "A third will not be run" in second

    def test_the_steering_names_the_arguments_this_tool_takes(self) -> None:
        calls: list[dict[str, Any]] = []
        wrapped, _recorder = self._wrapped(calls)

        wrapped.invoke({"path": "/s.exe"})
        second = wrapped.invoke({"path": "/s.exe"})

        for argument in ("`pattern`", "`start`", "`end`"):
            assert argument in second
        assert "`path`" not in second, "the argument it did set is not offered back to it"

    def test_the_third_call_says_the_same_thing_and_runs_nothing(self) -> None:
        calls: list[dict[str, Any]] = []
        wrapped, recorder = self._wrapped(calls)

        for _ in range(3):
            answer = wrapped.invoke({"path": "/s.exe"})

        assert len(calls) == 2
        assert "Do not call it again with these arguments" in answer
        assert "narrow it with `pattern`, `start`, `end`" in answer
        assert "[ev_0001]" in answer

    def test_the_ledger_records_what_the_tool_said_and_not_the_steering(self) -> None:
        calls: list[dict[str, Any]] = []
        wrapped, recorder = self._wrapped(calls)

        wrapped.invoke({"path": "/s.exe"})
        wrapped.invoke({"path": "/s.exe"})

        assert "second call" not in recorder.entries[1].output
        assert "total" in recorder.entries[1].output

    def test_a_tool_with_nothing_else_to_offer_says_so_plainly(self) -> None:
        calls: list[str] = []

        def identify_file(path: str) -> dict[str, str]:
            """Identify a file."""
            calls.append(path)
            return {"file_type": "PE"}

        recorder = EvidenceRecorder("static")
        wrapped = record_tools([_tool(identify_file, "identify_file")], recorder, RepeatGuard())[0]

        wrapped.invoke({"path": "/s.exe"})
        second = wrapped.invoke({"path": "/s.exe"})

        assert "call it with different arguments, or call another tool." in second

    def test_a_different_call_carries_no_steering(self) -> None:
        calls: list[dict[str, Any]] = []
        wrapped, _recorder = self._wrapped(calls)

        wrapped.invoke({"path": "/s.exe"})
        other = wrapped.invoke({"path": "/s.exe", "pattern": "AsyncRAT"})

        assert "second call" not in other
