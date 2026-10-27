"""An identical call of the job is answered from the entry that holds it, across agents and rounds.

haiku7 asked VirusTotal for the same two domain reports eight times (four
agents, two domains) and for the same file report four times, and re-decompiled
functions an earlier batch held whole; no entry was answered from the ledger.
A call to a tool its own server marks read-only and idempotent (MCP
``readOnlyHint`` and ``idempotentHint``), and that no declaration vetoes (one
stating it is not read-only, or a kind whose answer moves), is now answered
from the job's
earlier entry for it: any agent, any round, the same server and the same
arguments. The model reads the same text under the earlier entry's id and is
told so; the call is filed with ``repeated_of``. A tool nothing declares, a
failed or cut earlier answer, a change on the server in between, and another
job all keep running.
"""

from __future__ import annotations

import json
import threading
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.evidence_recorder import (
    EvidenceRecorder,
    RepeatGuard,
    holds_a_settled_answer,
    record_tools,
)
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.agents.tool_pinning import (
    DECLARED_NAME_METADATA_KEY,
    READ_ONLY_METADATA_KEY,
    SERVER_HINTS_METADATA_KEY,
    SERVER_METADATA_KEY,
)
from maljan.llm.context_window import note_answer_cut
from maljan.schemas.evidence import EvidenceCounter, build_entry

REPORT = json.dumps({"status": "found", "domain": "example.test", "malicious": 3, "harmless": 60})
IMPORTS = "KERNEL32.dll!CreateMutexW\nKERNEL32.dll!VirtualAlloc\n"
FIRST = "\nundefined8 FUN_1360bc0ae78(void)\n\n{\n  FUN_1360bc09040(0);\n  return 0;\n}\n\n"
SECOND = "\nuint FUN_1360bc08d90(longlong *param_1)\n\n{\n  *param_1 = 0;\n  return 1;\n}\n\n"
BATCH = json.dumps({"0x1360bc0ae78": FIRST, "0x1360bc08d90": SECOND})
BOTH_HINTS = {"readOnlyHint": True, "idempotentHint": True}
# How the MCP toolkit attaches a VirusTotal tool whose server gave both hints.
VT_SERVER = {
    SERVER_METADATA_KEY: "virustotal",
    SERVER_HINTS_METADATA_KEY: BOTH_HINTS,
    READ_ONLY_METADATA_KEY: True,
}


class _Domain(BaseModel):
    domain: str = ""


class _Program(BaseModel):
    program: str | None = None


class _Single(BaseModel):
    address: str = ""
    program: str | None = None
    timeout: int | None = None


class _Batch(BaseModel):
    functions: str = ""
    program: str | None = None
    image_base: str | None = None


class _Edit(BaseModel):
    name: str = ""
    program: str | None = None


def _runs(name: str, answer: Any, calls: list) -> Any:
    def _run(**kwargs: Any) -> str:
        calls.append(name)
        if isinstance(answer, BaseException):
            raise answer
        return answer(kwargs) if callable(answer) else answer

    return _run


def _mcp(name: str, answer: Any, calls: list, *, hints: dict[str, bool] | None = None) -> Any:
    """A tool of an MCP server named ``reputation`` with the hints that server gave it."""
    metadata: dict[str, Any] = {SERVER_METADATA_KEY: "reputation"}
    if hints:
        metadata[SERVER_HINTS_METADATA_KEY] = dict(hints)
        if hints.get("readOnlyHint") is True:
            metadata[READ_ONLY_METADATA_KEY] = True
    return StructuredTool.from_function(
        func=_runs(name, answer, calls),
        name=name,
        description="d",
        args_schema=_Domain,
        infer_schema=False,
        metadata=metadata,
    )


def _ghidra(
    name: str,
    schema: type[BaseModel],
    answer: Any,
    calls: list,
    *,
    hints: dict[str, bool] | None = None,
) -> Any:
    """A tool the built-in Ghidra declaration declares (``provider:ghidra``), with ``hints``."""
    tool = StructuredTool.from_function(
        func=_runs(name, answer, calls),
        name=name,
        description="d",
        args_schema=schema,
        infer_schema=False,
        metadata={SERVER_HINTS_METADATA_KEY: dict(hints)} if hints else None,
    )
    (stamped,) = stamp_source([tool], PROVIDER_FAMILY, declared="provider:ghidra")
    return stamped


def _read(name: str, schema: type[BaseModel], answer: Any, calls: list) -> Any:
    """A declared read-only Ghidra read its server marks read-only and idempotent."""
    return _ghidra(name, schema, answer, calls, hints=BOTH_HINTS)


def _single_answer(kwargs: dict[str, Any]) -> str:
    return {0x1360BC0AE78: FIRST, 0x1360BC08D90: SECOND}[int(kwargs["address"], 16)]


def _agent(name: str, counter: EvidenceCounter, tools: list[Any]) -> tuple[dict, EvidenceRecorder]:
    """One agent's loop: its own recorder and repeat guard, on the job's counter."""
    recorder = EvidenceRecorder(name, counter=counter)
    wrapped = record_tools(tools, recorder, RepeatGuard())
    return {tool.name: tool for tool in wrapped}, recorder


class TestAReputationLookupOfTheJob:
    def test_a_second_agent_s_identical_lookup_is_answered_from_the_first_entry(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, first = _agent(
            "triage", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )
        network, second = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        triage["domain_report"].invoke({"domain": "example.test"})
        answer = network["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report"], "the lookup ran once for the job"
        (held,) = first.entries
        (repeat,) = second.entries
        assert repeat.repeated_of == held.id
        assert repeat.agent == "network"
        assert answer.startswith(f"[{held.id}]\n")
        assert REPORT in answer, "the same content as the entry that holds it"
        assert repeat.id not in answer, "the model is never shown the repeat's own id"
        assert "answered from the ledger" in answer and "by triage" in answer
        assert REPORT not in repeat.output, "the repeat keeps a note, not a second copy"

    def test_a_later_round_of_the_same_agent_is_answered_too(self) -> None:
        counter, calls = EvidenceCounter(), []
        tool = _mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)
        first_round, first = _agent("static", counter, [tool])
        revision, second = _agent("static", counter, [tool])

        first_round["domain_report"].invoke({"domain": "example.test"})
        revision["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report"]
        assert second.entries[0].repeated_of == first.entries[0].id

    def test_other_arguments_run(self) -> None:
        counter, calls = EvidenceCounter(), []
        triage, _ = _agent(
            "triage", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )
        network, second = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        triage["domain_report"].invoke({"domain": "example.test"})
        network["domain_report"].invoke({"domain": "other.test"})

        assert calls == ["domain_report", "domain_report"]
        assert second.entries[0].repeated_of is None

    def test_another_job_runs(self) -> None:
        calls: list = []
        triage, _ = _agent(
            "triage", EvidenceCounter(), [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )
        network, second = _agent(
            "network", EvidenceCounter(), [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        triage["domain_report"].invoke({"domain": "example.test"})
        network["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report", "domain_report"], "no answer crosses jobs"
        assert second.entries[0].repeated_of is None


class TestWhatQualifiesComesFromTheDeclaration:
    @pytest.mark.parametrize(
        "hints",
        [
            None,
            {"readOnlyHint": True},
            {"idempotentHint": True},
            {"readOnlyHint": False, "idempotentHint": True},
        ],
    )
    def test_a_tool_whose_server_does_not_say_read_only_and_idempotent_runs(
        self, hints: dict[str, bool] | None
    ) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("triage", counter, [_mcp("domain_report", REPORT, calls, hints=hints)])
        two, second = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=hints)]
        )

        one["domain_report"].invoke({"domain": "example.test"})
        two["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report", "domain_report"]
        assert second.entries[0].repeated_of is None

    def test_a_declared_read_only_mark_alone_grants_nothing(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("static", counter, [_ghidra("list_imports", _Program, IMPORTS, calls)])
        two, second = _agent(
            "reverser", counter, [_ghidra("list_imports", _Program, IMPORTS, calls)]
        )

        one["list_imports"].invoke({})
        two["list_imports"].invoke({})

        assert calls == ["list_imports", "list_imports"]
        assert second.entries[0].repeated_of is None

    def test_a_silent_declaration_with_both_hints_and_a_settled_nested_answer_is_reused(
        self,
    ) -> None:
        counter, calls = EvidenceCounter(), []
        nested = json.dumps({"status": "found", "data": {"attributes": {"state": "done"}}})

        def lookup() -> Any:
            return StructuredTool.from_function(
                func=_runs("get_domain_report", nested, calls),
                name="get_domain_report",
                description="d",
                args_schema=_Domain,
                infer_schema=False,
                metadata=dict(VT_SERVER),
            )

        one, first = _agent("triage", counter, [lookup()])
        two, second = _agent("network", counter, [lookup()])

        one["get_domain_report"].invoke({"domain": "example.test"})
        two["get_domain_report"].invoke({"domain": "example.test"})

        assert calls == ["get_domain_report"]
        assert second.entries[0].repeated_of == first.entries[0].id

    def test_a_moving_kind_with_both_hints_runs_again(self) -> None:
        counter, calls = EvidenceCounter(), []
        done = json.dumps({"data": {"attributes": {"status": "completed"}}})

        def poll() -> Any:
            return StructuredTool.from_function(
                func=_runs("get_analysis", done, calls),
                name="get_analysis",
                description="d",
                args_schema=_Domain,
                infer_schema=False,
                metadata=dict(VT_SERVER),
            )

        one, _ = _agent("dynamic", counter, [poll()])
        two, second = _agent("judge", counter, [poll()])

        one["get_analysis"].invoke({"domain": "x"})
        two["get_analysis"].invoke({"domain": "x"})

        assert calls == ["get_analysis", "get_analysis"]
        assert second.entries[0].repeated_of is None

    def test_a_tool_its_declaration_marks_read_only_and_its_server_hints_is_answered(
        self,
    ) -> None:
        counter, calls = EvidenceCounter(), []
        one, first = _agent("static", counter, [_read("list_imports", _Program, IMPORTS, calls)])
        two, second = _agent("reverser", counter, [_read("list_imports", _Program, IMPORTS, calls)])

        one["list_imports"].invoke({})
        answer = two["list_imports"].invoke({})

        assert calls == ["list_imports"]
        assert second.entries[0].repeated_of == first.entries[0].id
        assert IMPORTS in answer

    def test_a_tool_its_declaration_does_not_mark_read_only_runs(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("static", counter, [_ghidra("rename_function", _Edit, "renamed", calls)])
        two, second = _agent(
            "reverser", counter, [_ghidra("rename_function", _Edit, "renamed", calls)]
        )

        one["rename_function"].invoke({"name": "decrypt"})
        two["rename_function"].invoke({"name": "decrypt"})

        assert calls == ["rename_function", "rename_function"]
        assert second.entries[0].repeated_of is None


class TestOnlyAWholeSettledAnswerIsHeld:
    def test_a_failed_entry_is_never_reused(self) -> None:
        counter, calls = EvidenceCounter(), []
        failing = _mcp("domain_report", RuntimeError("quota"), calls, hints=BOTH_HINTS)
        one, _ = _agent("triage", counter, [failing])
        two, second = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        one["domain_report"].invoke({"domain": "example.test"})
        two["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report", "domain_report"]
        assert second.entries[0].repeated_of is None and second.entries[0].ok

    def test_an_answer_that_only_says_it_failed_is_never_reused(self) -> None:
        counter, calls = EvidenceCounter(), []
        said = json.dumps({"error": "rate limited", "retry_after": 60})
        one, _ = _agent("triage", counter, [_mcp("domain_report", said, calls, hints=BOTH_HINTS)])
        two, _ = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        one["domain_report"].invoke({"domain": "example.test"})
        two["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report", "domain_report"]

    def test_a_lookup_still_waiting_on_its_service_is_never_reused(self) -> None:
        counter, calls = EvidenceCounter(), []
        said = json.dumps({"status": "pending", "domain": "example.test"})
        one, _ = _agent("triage", counter, [_mcp("domain_report", said, calls, hints=BOTH_HINTS)])
        two, _ = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        one["domain_report"].invoke({"domain": "example.test"})
        two["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report", "domain_report"]

    def test_a_cut_answer_runs_again_and_returns_what_is_asked(self) -> None:
        counter, calls = EvidenceCounter(), []

        def cut(_kwargs: dict[str, Any]) -> str:
            note_answer_cut(400)
            return REPORT

        one, _ = _agent("triage", counter, [_mcp("domain_report", cut, calls, hints=BOTH_HINTS)])
        two, second = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )

        one["domain_report"].invoke({"domain": "example.test"})
        answer = two["domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report", "domain_report"]
        assert second.entries[0].repeated_of is None
        assert answer.startswith(f"[{second.entries[0].id}]\n")

    def test_a_change_on_the_server_by_another_agent_forgets_the_answer(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("static", counter, [_read("list_imports", _Program, IMPORTS, calls)])
        editor, _ = _agent(
            "reverser", counter, [_ghidra("rename_function", _Edit, "renamed", calls)]
        )
        two, second = _agent("network", counter, [_read("list_imports", _Program, IMPORTS, calls)])

        one["list_imports"].invoke({})
        editor["rename_function"].invoke({"name": "decrypt"})
        two["list_imports"].invoke({})

        assert calls == ["list_imports", "rename_function", "list_imports"]
        assert second.entries[0].repeated_of is None


class TestABatchMemberOfTheJob:
    def test_another_agent_s_single_read_of_a_batch_member_is_answered(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, first = _agent("reverser", counter, [_read("batch_decompile", _Batch, BATCH, calls)])
        two, second = _agent(
            "static", counter, [_read("decompile_function", _Single, _single_answer, calls)]
        )

        one["batch_decompile"].invoke({"functions": "1360bc0ae78,1360bc08d90"})
        answer = two["decompile_function"].invoke({"address": "1360bc08d90"})

        assert calls == ["batch_decompile"], "the declaration ties the read to the batch"
        assert second.entries[0].repeated_of == first.entries[0].id
        assert SECOND in answer and answer.startswith(f"[{first.entries[0].id}]\n")
        assert "batch_decompile" in answer

    def test_a_function_the_batch_did_not_hold_runs(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("reverser", counter, [_read("batch_decompile", _Batch, BATCH, calls)])
        two, _ = _agent("static", counter, [_read("decompile_function", _Single, FIRST, calls)])

        one["batch_decompile"].invoke({"functions": "1360bc0ae78,1360bc08d90"})
        two["decompile_function"].invoke({"address": "1360bc0ae7c"})

        assert calls == ["batch_decompile", "decompile_function"]


class TestTheLoopsGuardCountsAsBefore:
    def test_a_loop_s_repeats_are_counted_as_when_the_second_call_ran(self) -> None:
        counter, calls = EvidenceCounter(), []
        recorder = EvidenceRecorder("triage", counter=counter)
        guard = RepeatGuard()
        (tool,) = record_tools(
            [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)], recorder, guard
        )

        tool.invoke({"domain": "example.test"})
        served = tool.invoke({"domain": "example.test"})
        refused = tool.invoke({"domain": "example.test"})

        first = recorder.entries[0]
        assert calls == ["domain_report"]
        assert REPORT in served, "the served repeat still reads the answer"
        assert REPORT not in refused, "the third identical call is refused as before"
        assert guard.served_repeats == 2
        assert [e.repeated_of for e in recorder.entries] == [None, first.id, first.id]


def _poll(answers: list[str], calls: list) -> Any:
    """An undeclared server's status poll that carries both hints, answering in turn."""
    left = iter(answers)
    return _mcp("analysis_status", lambda _kwargs: next(left), calls, hints=BOTH_HINTS)


QUEUED = json.dumps({"data": {"attributes": {"status": "queued", "stats": {}}}})
DONE = json.dumps({"data": {"attributes": {"status": "completed", "stats": {"malicious": 5}}}})


class TestTheDeclarationDecidesBeforeTheHints:
    def test_a_declared_tool_that_is_not_read_only_runs_again_whatever_its_hints(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.tool_declarations import ToolFacts

        stated = ToolFacts.model_validate({"kind": "program_edit", "read_only": False})
        monkeypatch.setattr("maljan.agents.tool_pinning.declared_facts_of", lambda _t: stated)
        counter, calls = EvidenceCounter(), []

        def hinted() -> Any:
            return _ghidra("rename_function", _Edit, "renamed", calls, hints=BOTH_HINTS)

        one, _ = _agent("static", counter, [hinted()])
        two, second = _agent("reverser", counter, [hinted()])

        one["rename_function"].invoke({"name": "decrypt"})
        two["rename_function"].invoke({"name": "decrypt"})

        assert calls == ["rename_function", "rename_function"]
        assert second.entries[0].repeated_of is None


class TestAStatusThatIsStillWaiting:
    def test_a_same_loop_re_poll_of_a_nested_pending_status_runs_again(self) -> None:
        counter, calls = EvidenceCounter(), []
        recorder = EvidenceRecorder("dynamic", counter=counter)
        guard = RepeatGuard()
        (poll,) = record_tools([_poll([QUEUED, DONE], calls)], recorder, guard)

        poll.invoke({"domain": "job-1"})
        again = poll.invoke({"domain": "job-1"})

        assert calls == ["analysis_status", "analysis_status"], "the second poll ran"
        assert "completed" in again, "it reads the fresh answer"
        assert recorder.entries[1].repeated_of is None
        assert guard.served_repeats == 1, "counted as the served repeat it was before"

    def test_another_agent_s_poll_of_a_nested_pending_status_runs(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("dynamic", counter, [_poll([QUEUED], calls)])
        two, second = _agent("judge", counter, [_poll([DONE], calls)])

        one["analysis_status"].invoke({"domain": "job-1"})
        answer = two["analysis_status"].invoke({"domain": "job-1"})

        assert calls == ["analysis_status", "analysis_status"]
        assert second.entries[0].repeated_of is None and "completed" in answer


def _entry(output: str) -> Any:
    return build_entry(
        entry_id="ev_0001", seq=1, agent="a", tool="t", args={}, server=None, output=output
    )


class TestStatusAndExplanationKeysAtEveryDepthForTheJob:
    @pytest.mark.parametrize(
        "answer",
        [
            {"data": {"attributes": {"status": "queued"}}},
            {"data": [{"id": 1}, {"analysis_status": "running"}]},
            {"report": {"detail": "backend unavailable"}},
            {"rows": [{"errors": ["timeout"]}]},
            {"status": "found", "analysis": {"status": "pending"}},
        ],
    )
    def test_a_nested_unsettled_answer_is_not_settled(self, answer: Any) -> None:
        assert not holds_a_settled_answer(_entry(json.dumps(answer)), deep=True)

    @pytest.mark.parametrize(
        "answer",
        [
            {"data": {"attributes": {"status": "completed", "stats": {"malicious": 5}}}},
            {"status": "found", "data": {"detections": ["clean"], "matches": []}},
            {"rows": [{"name": "a"}, {"name": "b", "error": ""}]},
        ],
    )
    def test_a_settled_answer_at_every_depth_is_settled(self, answer: Any) -> None:
        assert holds_a_settled_answer(_entry(json.dumps(answer)), deep=True)


# Answers whose nested fields are data, which the loop's own rounds and chunks
# hand back as they did before the job-wide answers.
DATA_FIELDS = [
    {"services": [{"name": "svc", "status": "running"}]},
    {"processes": [{"pid": 4, "state": "terminated"}]},
    {"sections": [{"name": ".text", "details": "rwx"}]},
    {"state": "x86"},
]


class TestTheLoopsOwnRoundsReadTheTopLevelAsBefore:
    @pytest.mark.parametrize("answer", DATA_FIELDS)
    def test_an_answer_with_nested_data_fields_is_settled_for_the_loop(self, answer: Any) -> None:
        assert holds_a_settled_answer(_entry(json.dumps(answer)))

    @pytest.mark.parametrize("answer", DATA_FIELDS)
    def test_the_same_answer_is_not_handed_to_another_agent(self, answer: Any) -> None:
        assert not holds_a_settled_answer(_entry(json.dumps(answer)), deep=True)

    def test_a_top_level_pending_status_is_unsettled_for_both(self) -> None:
        entry = _entry(json.dumps({"status": "pending"}))
        assert not holds_a_settled_answer(entry)
        assert not holds_a_settled_answer(entry, deep=True)

    def test_a_found_status_is_settled_only_for_the_job(self) -> None:
        entry = _entry(json.dumps({"status": "found"}))
        assert not holds_a_settled_answer(entry), "the loop's rule is as it was"
        assert holds_a_settled_answer(entry, deep=True)

    @pytest.mark.parametrize("origin", ["round", "chunk"])
    def test_a_nested_running_service_is_still_seeded_across_rounds_and_chunks(
        self, origin: str
    ) -> None:
        from maljan.agents.evidence_recorder import seeded_repeat_guard

        services = json.dumps({"services": [{"name": "svc", "status": "running"}]})
        entry = build_entry(
            entry_id="ev_0007",
            seq=7,
            agent="dynamic",
            tool="services",
            args={"pid": 4},
            server=None,
            output=services,
        )
        guard = (
            seeded_repeat_guard([], earlier_rounds=[entry])
            if origin == "round"
            else seeded_repeat_guard([entry])
        )
        assert guard.recorded_answer("services", {"pid": 4}) == ("ev_0007", services)

    def test_a_nested_queued_poll_is_still_not_served_job_wide(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("dynamic", counter, [_poll([QUEUED], calls)])
        two, second = _agent("judge", counter, [_poll([QUEUED], calls)])

        one["analysis_status"].invoke({"domain": "job-1"})
        two["analysis_status"].invoke({"domain": "job-1"})

        assert calls == ["analysis_status", "analysis_status"]
        assert second.entries[0].repeated_of is None


def _through(tool: Any, handle: str, *, quiet: bool) -> Any:
    """``tool`` as merged from the server handle ``handle``, its server quiet or not."""
    from maljan.agents.tool_pinning import (
        SERVER_CHANGES_NOTHING_METADATA_KEY,
        SERVER_HANDLE_METADATA_KEY,
    )

    metadata = {
        **tool.metadata,
        SERVER_HANDLE_METADATA_KEY: handle,
        SERVER_CHANGES_NOTHING_METADATA_KEY: quiet,
    }
    return tool.model_copy(update={"metadata": metadata})


class TestAnotherHandleOfTheServer:
    def _run(
        self, first: str, second: str, *, quiet: bool, asker_quiet: bool | None = None
    ) -> tuple[list, Any]:
        counter, calls = EvidenceCounter(), []
        lookup = _mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)
        asks = quiet if asker_quiet is None else asker_quiet
        one, _ = _agent("triage", counter, [_through(lookup, first, quiet=quiet)])
        two, recorder = _agent("network", counter, [_through(lookup, second, quiet=asks)])
        one["domain_report"].invoke({"domain": "example.test"})
        two["domain_report"].invoke({"domain": "example.test"})
        return calls, recorder.entries[0]

    def test_a_call_through_the_same_handle_is_answered(self) -> None:
        calls, entry = self._run("reputation#1", "reputation#1", quiet=False)
        assert calls == ["domain_report"] and entry.repeated_of

    def test_a_call_through_another_handle_of_a_server_that_may_change_runs(self) -> None:
        calls, entry = self._run("reputation#1", "reputation#2", quiet=False)
        assert calls == ["domain_report", "domain_report"] and entry.repeated_of is None

    def test_a_call_through_another_handle_of_a_quiet_server_is_answered(self) -> None:
        calls, entry = self._run("reputation#1", "reputation#2", quiet=True)
        assert calls == ["domain_report"] and entry.repeated_of

    def test_a_quiet_asker_is_not_served_what_a_handle_that_was_not_quiet_read(self) -> None:
        calls, entry = self._run("reputation#1", "reputation#2", quiet=False, asker_quiet=True)
        assert calls == ["domain_report", "domain_report"], "both handles must say quiet"
        assert entry.repeated_of is None


class TestAReadRacingAChange:
    def test_a_read_a_change_started_during_and_ended_after_is_not_held(self) -> None:
        counter, calls = EvidenceCounter(), []
        reading, change_started, read_done = (threading.Event() for _ in range(3))

        def read(_kwargs: dict[str, Any]) -> str:
            reading.set()
            assert change_started.wait(5)
            return IMPORTS

        def write(_kwargs: dict[str, Any]) -> str:
            change_started.set()
            assert read_done.wait(5)
            return "renamed"

        reader, _ = _agent("static", counter, [_read("list_imports", _Program, read, calls)])
        editor, _ = _agent("reverser", counter, [_ghidra("rename_function", _Edit, write, calls)])
        later, second = _agent(
            "network", counter, [_read("list_imports", _Program, IMPORTS, calls)]
        )

        def _reading() -> None:
            reader["list_imports"].invoke({})
            read_done.set()

        def _edit() -> None:
            assert reading.wait(5)
            editor["rename_function"].invoke({"name": "decrypt"})

        threads = [threading.Thread(target=_reading), threading.Thread(target=_edit)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        later["list_imports"].invoke({})

        assert calls.count("list_imports") == 2, "the read beside a change was not held"
        assert second.entries[0].repeated_of is None


class TestAToolOfferedRenamed:
    def test_a_renamed_tool_is_keyed_by_the_name_its_source_declares(self) -> None:
        counter, calls = EvidenceCounter(), []
        plain = _mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)
        offered = _mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)
        renamed = offered.model_copy(
            update={
                "name": "reputation__domain_report",
                "metadata": {**offered.metadata, DECLARED_NAME_METADATA_KEY: "domain_report"},
            }
        )
        one, first = _agent("triage", counter, [plain])
        two, second = _agent("network", counter, [renamed])

        one["domain_report"].invoke({"domain": "example.test"})
        answer = two["reputation__domain_report"].invoke({"domain": "example.test"})

        assert calls == ["domain_report"]
        assert second.entries[0].repeated_of == first.entries[0].id
        assert REPORT in answer


class TestAMemberUnderOtherRoles:
    def test_a_single_read_whose_program_differs_from_the_batch_s_runs(self) -> None:
        counter, calls = EvidenceCounter(), []
        one, _ = _agent("reverser", counter, [_read("batch_decompile", _Batch, BATCH, calls)])
        two, second = _agent(
            "static", counter, [_read("decompile_function", _Single, _single_answer, calls)]
        )

        one["batch_decompile"].invoke(
            {"functions": "1360bc0ae78,1360bc08d90", "program": "sample.exe"}
        )
        two["decompile_function"].invoke({"address": "1360bc08d90"})
        two["decompile_function"].invoke({"address": "1360bc0ae78", "program": "other.exe"})

        assert calls == ["batch_decompile", "decompile_function", "decompile_function"]
        assert [e.repeated_of for e in second.entries] == [None, None]


class TestTheHolderReachesTheRunsLedger:
    def test_the_entry_another_agent_s_repeat_names_is_collected_with_it(self) -> None:
        """The holder is on the run's ledger whenever its repeat is.

        Each agent the container builds is a holder of its entries until a
        node drains them (``collect_undrained_evidence``), and an agent lets go
        of them only at the job's teardown (``close_tools``, from
        ``ServiceContainer.aclose``), after the ledger is stored.
        """
        from unittest.mock import MagicMock, patch

        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(Settings(_env_file=None), mock=True)
        with patch.object(container, "get_agent_llm", return_value=MagicMock()):
            static, network = container.get_agent("static"), container.get_agent("network")
        counter, calls = container.get_evidence_counter(), []
        one, first = _agent(
            "static", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )
        two, second = _agent(
            "network", counter, [_mcp("domain_report", REPORT, calls, hints=BOTH_HINTS)]
        )
        one["domain_report"].invoke({"domain": "example.test"})
        two["domain_report"].invoke({"domain": "example.test"})
        # What each loop's ``finally`` does with its recorder's entries.
        static._evidence_entries.extend(first.entries)
        network._evidence_entries.extend(second.entries)

        collected = {e.id: e for e in container.collect_undrained_evidence()}

        (repeat,) = second.entries
        assert repeat.id in collected and repeat.repeated_of in collected
        assert collected[repeat.repeated_of].output == REPORT
