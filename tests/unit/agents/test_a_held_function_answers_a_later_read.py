"""A whole-function read the ledger already holds is answered from its entry, not run.

Two live runs (run3, run5) decompiled a batch of functions and then asked for
one of the batch's members again by itself: the tool ran and answered the same
text the batch entry already held. A whole-function read is now answered from
the entry that provably holds it before the tool runs: an identical earlier
call of the same tool, or a member of an earlier call of a tool that declares
itself the aggregate of this one (``ToolFacts.aggregate_of``), keyed by the
same address under the same declared roles. Everything is read off the tools'
declarations and the answer's shape, never a tool's name. A truncated answer,
an argument nothing declares, a call that may change the program in between,
or a tool that declares nothing keeps running.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.delegation import TEAM_SERVER
from maljan.agents.evidence_recorder import (
    EvidenceRecorder,
    RepeatGuard,
    aggregate_members,
    member_request,
    record_tools,
)
from maljan.agents.prompt_fragments import PROVIDER_FAMILY, stamp_source
from maljan.agents.tool_pinning import SERVER_METADATA_KEY, declared_facts_of
from maljan.schemas.evidence import EvidenceCounter

PROGRAM = "sample.exe"
FIRST = "\nundefined8 FUN_1360bc0ae78(void)\n\n{\n  FUN_1360bc09040(0);\n  return 0;\n}\n\n"
SECOND = "\nuint FUN_1360bc08d90(longlong *param_1)\n\n{\n  *param_1 = 0;\n  return 1;\n}\n\n"
BATCH = json.dumps({"0x1360bc0ae78": FIRST, "0x1360bc08d90": SECOND})


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


def _tool(name: str, schema: type[BaseModel], answer: Any, calls: list, *, declared: bool = True):
    def _run(**kwargs: Any) -> str:
        calls.append((name, kwargs))
        return answer(kwargs) if callable(answer) else answer

    tool = StructuredTool.from_function(
        func=_run, name=name, description="d", args_schema=schema, infer_schema=False
    )
    if not declared:
        return tool
    (stamped,) = stamp_source([tool], PROVIDER_FAMILY, declared="provider:ghidra")
    return stamped


def _single_answer(kwargs: dict[str, Any]) -> str:
    return {0x1360BC0AE78: FIRST, 0x1360BC08D90: SECOND}[int(kwargs["address"], 16)]


def _loop(
    *,
    batch: Any = BATCH,
    single: Any = _single_answer,
    declared: bool = True,
    counter: EvidenceCounter | None = None,
    calls: list | None = None,
    single_schema: type[BaseModel] | None = None,
):
    calls = [] if calls is None else calls
    recorder = EvidenceRecorder("reverser", counter=counter or EvidenceCounter())
    tools = record_tools(
        [
            _tool("batch_decompile", _Batch, batch, calls, declared=declared),
            _tool("decompile_function", single_schema or _Single, single, calls, declared=declared),
            _tool("rename_function", _Edit, "renamed", calls, declared=declared),
        ],
        recorder,
        RepeatGuard(),
    )
    return {tool.name: tool for tool in tools}, recorder, calls


def _ran(calls: list) -> list[str]:
    return [name for name, _kwargs in calls]


class TestABatchMember:
    def test_a_later_single_read_is_answered_from_the_batch_entry(self) -> None:
        tools, recorder, calls = _loop()

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        answer = tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile"], "the single read did not run"
        batch, single = recorder.entries
        assert single.repeated_of == batch.id
        assert answer.startswith(f"[{batch.id}]\n")
        assert FIRST in answer, "the member text exactly as the batch entry holds it"
        assert json.loads(batch.output)["0x1360bc0ae78"] == FIRST
        assert single.id not in answer
        assert "answered from the ledger" in answer and "batch_decompile" in answer
        assert FIRST not in single.output, "the repeat keeps a note, not a second copy"

    def test_a_bare_spelling_of_the_address_is_the_same_function(self) -> None:
        tools, recorder, calls = _loop()

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "1360BC08D90"})

        assert _ran(calls) == ["batch_decompile"]
        assert recorder.entries[1].repeated_of == recorder.entries[0].id

    def test_an_address_the_batch_did_not_hold_runs(self) -> None:
        tools, _recorder, calls = _loop(single=FIRST)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae7c"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_another_program_runs(self) -> None:
        tools, _recorder, calls = _loop()

        tools["batch_decompile"].invoke(
            {"functions": "0x1360bc0ae78,0x1360bc08d90", "program": PROGRAM}
        )
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        tools["decompile_function"].invoke({"address": "0x1360bc08d90", "program": PROGRAM})

        assert _ran(calls) == ["batch_decompile", "decompile_function"], (
            "a program given on one side only is not provably the same program"
        )

    def test_the_same_program_is_answered(self) -> None:
        tools, _recorder, calls = _loop()

        tools["batch_decompile"].invoke(
            {"functions": "0x1360bc0ae78,0x1360bc08d90", "program": PROGRAM}
        )
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78", "program": PROGRAM})

        assert _ran(calls) == ["batch_decompile"]

    def test_an_argument_nothing_declares_runs(self) -> None:
        tools, _recorder, calls = _loop()

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78", "timeout": 120})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_a_truncated_batch_answers_nothing(self) -> None:
        cut = BATCH[: len(BATCH) - 40]
        tools, _recorder, calls = _loop(batch=cut)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_a_member_that_failed_answers_nothing(self) -> None:
        failed = json.dumps({"0x1360bc0ae78": "Error: no function at address", "0x1": SECOND})
        tools, _recorder, calls = _loop(batch=failed)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_a_call_that_may_change_the_program_forgets_the_batch(self) -> None:
        tools, _recorder, calls = _loop()

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["rename_function"].invoke({"name": "decrypt"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "rename_function", "decompile_function"]

    def test_tools_that_declare_nothing_keep_running(self) -> None:
        tools, _recorder, calls = _loop(declared=False)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_asking_again_is_counted_as_any_repeat(self) -> None:
        tools, recorder, calls = _loop()

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        first = tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        second = tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        third = tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        batch = recorder.entries[0]
        assert _ran(calls) == ["batch_decompile"]
        assert "second call" not in first
        assert FIRST in second and "A third will not be run" in second
        assert FIRST not in third and f"[{batch.id}]" in third
        assert [e.repeated_of for e in recorder.entries[1:]] == [batch.id] * 3


class TestAnIdenticalWholeRead:
    def test_the_second_identical_call_is_answered_from_its_entry(self) -> None:
        tools, recorder, calls = _loop()

        tools["decompile_function"].invoke({"address": "0x1360bc0ae78", "timeout": 120})
        answer = tools["decompile_function"].invoke({"address": "0x1360BC0AE78", "timeout": 120})

        assert _ran(calls) == ["decompile_function"]
        first, second = recorder.entries
        assert second.repeated_of == first.id
        assert answer.startswith(f"[{first.id}]\n") and FIRST in answer
        assert "answered from the ledger" in answer and "A third will not be run" in answer

    def test_an_empty_answer_runs_again(self) -> None:
        # local6: the first decompile answered nothing, the identical second
        # call answered the function.
        answers = ["", FIRST]
        tools, _recorder, calls = _loop(single=lambda _kwargs: answers.pop(0))

        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        answer = tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["decompile_function", "decompile_function"]
        assert FIRST in answer

    def test_a_listing_cut_short_runs_again(self) -> None:
        tools, _recorder, calls = _loop(single=FIRST + "\n\n[OUTPUT TRUNCATED]")

        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["decompile_function", "decompile_function"]

    def test_a_failed_read_runs_again(self) -> None:
        def _fails(_kwargs: dict[str, Any]) -> str:
            raise RuntimeError("decompiler busy")

        tools, _recorder, calls = _loop(single=_fails)

        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["decompile_function", "decompile_function"]


class TestTheReaders:
    def _facts(self, name: str) -> Any:
        tool = _tool(name, _Single, "", [])
        return declared_facts_of(tool)

    def test_a_request_needs_a_declared_whole_read_and_a_plain_address(self) -> None:
        facts = self._facts("decompile_function")
        assert member_request(facts, {"address": "0x401000"})[0] == 0x401000
        assert member_request(facts, {"address": "main"}) is None
        assert member_request(facts, {"address": "add1"}) is None, "a short bare word"
        assert member_request(facts, {"address": "401000"}) is None, "bare decimal digits"
        assert member_request(None, {"address": "0x401000"}) is None
        assert member_request(self._facts("batch_decompile"), {"address": "0x401000"}) is None

    def test_an_aggregate_is_read_by_its_shape(self) -> None:
        facts = self._facts("batch_decompile")
        listed = {"functions": "0x1360bc0ae78,0x1360bc08d90"}
        roles, members = aggregate_members(facts, listed, BATCH)
        assert members == {0x1360BC0AE78: FIRST, 0x1360BC08D90: SECOND}
        assert aggregate_members(facts, {"functions": "x"}, BATCH) is None
        assert aggregate_members(facts, {"limit": 5}, BATCH) is None
        assert aggregate_members(facts, {}, BATCH) is None, "no member list"
        assert aggregate_members(facts, listed, json.dumps({"main": FIRST})) is None
        assert aggregate_members(self._facts("decompile_function"), listed, BATCH) is None
        # Two spellings of one address: neither is read as the member.
        twice = json.dumps({"0x1360bc0ae78": FIRST, "1360bc0ae78": SECOND})
        assert aggregate_members(facts, {"functions": "0x1360bc0ae78"}, twice)[1] == {}


class TestWhatTheReviewFound:
    """One case per finding of the review: each makes the read run."""

    def test_a_rename_that_ends_while_a_read_runs_leaves_nothing_held(self) -> None:
        holder: dict[str, Any] = {}

        def _read_while_renamed(kwargs: dict[str, Any]) -> str:
            holder["tools"]["rename_function"].invoke({"name": "decrypt"})
            return _single_answer(kwargs)

        tools, _recorder, calls = _loop(single=_read_while_renamed)
        holder["tools"] = tools
        calls_before = len(calls)

        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        holder["tools"] = {"rename_function": _NoOp()}
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls[calls_before:]) == [
            "decompile_function",
            "rename_function",
            "decompile_function",
        ]

    def test_a_delegate_s_rename_on_the_same_server_makes_the_next_read_run(self) -> None:
        counter = EvidenceCounter()
        calls: list = []
        tools, _recorder, _calls = _loop(counter=counter, calls=calls)
        delegate, _delegate_recorder, _delegate_calls = _loop(counter=counter, calls=calls)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "0x1360bc08d90"})
        delegate["rename_function"].invoke({"name": "decrypt"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        tools["decompile_function"].invoke({"address": "0x1360bc08d90"})

        assert _ran(calls) == [
            "batch_decompile",
            "rename_function",
            "decompile_function",
            "decompile_function",
        ]

    def test_a_change_through_the_team_server_makes_the_next_read_run(self) -> None:
        tools, recorder, calls = _loop()
        ask = StructuredTool.from_function(
            func=lambda question="": calls.append(("ask_static", {})) or "done",
            name="ask_static",
            description="d",
            metadata={SERVER_METADATA_KEY: TEAM_SERVER},
        )
        (asked,) = record_tools([ask], recorder, RepeatGuard())

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        asked.invoke({"question": "rename it"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "ask_static", "decompile_function"]

    def test_an_undeclared_argument_beside_the_member_list_runs(self) -> None:
        tools, _recorder, calls = _loop()

        tools["batch_decompile"].invoke(
            {"functions": "0x1360bc0ae78,0x1360bc08d90", "image_base": "0x1360bc00000"}
        )
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_a_member_list_that_misses_a_key_runs(self) -> None:
        tools, _recorder, calls = _loop()

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_a_member_the_batch_tool_cut_short_runs(self) -> None:
        cuts = {
            "ellipsis": FIRST.rstrip() + "\n  ...",
            "timed out": FIRST.rstrip() + "\n/* decompilation timed out */",
            "open brace": FIRST.rstrip()[:-1],
        }
        for label, cut in cuts.items():
            batch = json.dumps({"0x1360bc0ae78": cut, "0x1360bc08d90": SECOND})
            tools, _recorder, calls = _loop(batch=batch, single=FIRST)

            tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
            tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

            assert _ran(calls) == ["batch_decompile", "decompile_function"], label

    def test_an_integer_address_runs(self) -> None:
        tools, _recorder, calls = _loop(single=FIRST, single_schema=_AnySingle)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": 0x1360BC0AE78})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]
        assert member_request(_tool_facts("decompile_function"), {"address": 0x401000}) is None

    def test_a_key_the_batch_answer_names_twice_runs(self) -> None:
        batch = (
            '{"0x1360bc0ae78": '
            + json.dumps(FIRST)
            + ', "0x1360bc0ae78": '
            + json.dumps(SECOND)
            + ', "0x1360bc08d90": '
            + json.dumps(SECOND)
            + "}"
        )
        tools, _recorder, calls = _loop(batch=batch)

        tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})

        assert _ran(calls) == ["batch_decompile", "decompile_function"]

    def test_a_counter_that_keeps_no_change_count_never_answers_from_the_ledger(self) -> None:
        for kept in ("missing", None, MagicMock()):
            counter = EvidenceCounter()
            if kept == "missing":
                del counter.changes
            else:
                counter.changes = kept  # type: ignore[assignment]
            tools, _recorder, calls = _loop(counter=counter)

            tools["batch_decompile"].invoke({"functions": "0x1360bc0ae78,0x1360bc08d90"})
            answers = [
                tools["decompile_function"].invoke({"address": address})
                for address in ("0x1360bc0ae78", "0x1360bc08d90", "0x1360bc08d90")
            ]

            assert _ran(calls) == ["batch_decompile"] + ["decompile_function"] * 3, kept
            assert not any("answered from the ledger" in answer for answer in answers), kept

    def test_a_bare_spelling_is_never_answered_from_a_0x_read(self) -> None:
        tools, _recorder, calls = _loop()

        tools["decompile_function"].invoke({"address": "0x1360bc0ae78"})
        tools["decompile_function"].invoke({"address": "1360bc0ae78"})

        assert _ran(calls) == ["decompile_function", "decompile_function"]


class _AnySingle(BaseModel):
    address: int | str = ""
    program: str | None = None


class _NoOp:
    def invoke(self, _args: dict[str, Any]) -> str:
        return ""


def _tool_facts(name: str) -> Any:
    return declared_facts_of(_tool(name, _Single, "", []))
