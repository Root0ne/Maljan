"""A paged or limited tool answer tells the agent how complete it is (X12).

Every tool answer the recorder hands a model carries one line of fixed platform
wording when the answer is known to be partial: the tool's own paging words
and counts, a full page under a bounding argument the call passed, or the cut
the platform made. An answer whose completeness cannot be read says nothing
new, and the reading is the one the run's coverage record takes of the same
answer (``analysis.coverage``).
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from langchain_core.tools import StructuredTool
from pydantic import BaseModel

from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.agents.mcp_client import MCPLangChainToolkit
from maljan.analysis import coverage
from maljan.schemas.answer_completeness import (
    COMPLETENESS_PREFIX,
    completeness_line,
    platform_cut,
    read_answer,
)
from maljan.schemas.evidence import LedgerEntry, parse_structured
from maljan.schemas.evidence_spill import EvidenceSpill

LISTING = "void FUN_00401000(void) {\n  int counter = 0;\n  return;\n}\n" * 400


class _Store:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(self, sha256: str, blob: bytes, content_type: str) -> str:
        self.objects[f"evidence/job/{sha256}"] = blob
        return f"evidence/job/{sha256}"


def _ghidra(limit: int) -> Any:
    from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

    client = GhidraHTTPClient.__new__(GhidraHTTPClient)
    client._max_output_chars = limit
    client._output_guardrail = None
    client._truncation_ledger = None
    client._context_budget = None
    return client


class _Paged(BaseModel):
    topic: str
    cursor: str | None = None
    limit: int | None = None


def _handed(
    answer: Any,
    args: dict[str, Any],
    *,
    schema: type[BaseModel] = _Paged,
    store: _Store | None = None,
    name: str = "search_things",
) -> tuple[str, LedgerEntry]:
    """What a model is handed for one call of a third-party tool, and its entry."""

    def run(**kwargs: Any) -> str:
        return answer() if callable(answer) else answer

    tool = StructuredTool.from_function(
        func=run, name=name, description="A third-party tool.", args_schema=schema
    )
    recorder = EvidenceRecorder(
        "analyst", spill=EvidenceSpill(store.put) if store is not None else None
    )
    (wrapped,) = record_tools([tool], recorder)
    handed = str(wrapped.invoke(args))
    (entry,) = recorder.entries
    return handed, entry


def _line(handed: str) -> str:
    """The completeness line in what the model was handed, or ``""``."""
    lines = [line for line in handed.splitlines() if line.startswith(COMPLETENESS_PREFIX)]
    assert len(lines) <= 1, "one line per answer"
    return lines[0] if lines else ""


class TestTheToolSaysItIsAPage:
    def test_a_page_with_has_more_true_says_more_exists(self) -> None:
        answer = json.dumps({"items": [{"id": 1}, {"id": 2}], "has_more": True})
        handed, _ = _handed(answer, {"topic": "x"})
        line = _line(handed)
        assert '("has_more")' in line
        assert "unknown, not absent" in line
        assert "read further with `cursor`, `limit`" in line

    def test_a_total_greater_than_the_rows_shown_names_both(self) -> None:
        answer = json.dumps({"results": [1, 2, 3], "total": 250})
        line = _line(_handed(answer, {"topic": "x"})[0])
        assert '"results" shows 3 of 250' in line

    def test_an_mcp_tool_with_a_cursor_is_told_where_the_next_page_starts(self) -> None:
        # The MCP paging shape: the answer names the next cursor, the call
        # passes it back. No tool name decides anything.
        answer = json.dumps({"resources": [{"uri": "a"}], "nextCursor": "eyJwIjoyfQ=="})
        handed, entry = _handed(answer, {"topic": "x"}, name="list_resources")
        line = _line(handed)
        assert '("nextCursor")' in line
        assert "`cursor`" in line
        assert "eyJwIjoyfQ" not in line, "the line quotes no value the server sent"
        assert line not in str(entry.output), "the ledger keeps what the tool said"

    def test_a_page_of_a_known_count_is_numbered(self) -> None:
        line = completeness_line({"page": 2, "pages": 5, "rows": [1]})
        assert "this is page 2 of 5" in line

    def test_a_page_with_no_count_says_the_count_is_missing(self) -> None:
        line = completeness_line({"page": 3, "rows": [1]})
        assert "does not say how many pages exist" in line

    def test_a_full_page_under_a_bounding_argument_says_more_may_exist(self) -> None:
        answer = json.dumps({"hits": [1, 2, 3, 4]})
        line = _line(_handed(answer, {"topic": "x", "limit": 4})[0])
        assert "as many rows as `limit` allowed (4)" in line
        assert _line(_handed(answer, {"topic": "x", "limit": 9})[0]) == ""

    def test_a_list_name_that_is_not_an_identifier_is_not_quoted(self) -> None:
        line = completeness_line({'ro"ws\n': [1], "total": 4})
        assert "a field shows 1 of 4" in line
        assert '"ro' not in line


class TestThePlatformsOwnCut:
    def test_a_byte_cut_with_spill_is_stated_with_its_size(self) -> None:
        client = _ghidra(4000)
        store = _Store()
        handed, entry = _handed(
            lambda: client._apply_output_guardrail(LISTING), {"topic": "x"}, store=store
        )
        assert platform_cut(entry) > 0
        assert entry.spilled, "the whole answer is kept beside the entry"
        line = _line(handed)
        assert f"the platform left out {platform_cut(entry):,} characters" in line
        assert "read further with `cursor`, `limit`" in line
        stamp = f"[{entry.id}]\n"
        assert len(handed) - len(stamp) <= 4000, "the answer and its line fit the limit"
        bare, _ = _handed(lambda: client._apply_output_guardrail(LISTING), {"topic": "x"})
        assert bare == handed, "what the model reads does not depend on the store"

    def test_a_shortened_document_is_stated_once(self) -> None:
        document = json.dumps({"rows": [{"i": i, "v": "v" * 30} for i in range(400)]})
        toolkit = MCPLangChainToolkit(None, max_output_chars=4000)
        handed, entry = _handed(
            lambda: toolkit._apply_output_guardrail(document, ("cursor", "limit")),
            {"topic": "x"},
        )
        assert platform_cut(entry) > 0
        assert "did not fit and was shortened" in handed
        assert _line(handed) == "", "the shortening sentence already says it"


class TestNothingNewIsSaid:
    @pytest.mark.parametrize(
        "answer",
        [
            {"items": [], "has_more": False, "next": None},
            {"items": [{"id": 9}], "nextCursor": None},
            {"page": 5, "pages": 5, "rows": []},
            # A total of runs scanned beside a page that says it is the last.
            {"strings": [1, 2], "total": 900, "truncated": False, "next_offset": None},
            {"results": [1, 2, 3], "total": 3},
        ],
    )
    def test_a_complete_last_page_carries_no_line(self, answer: dict[str, Any]) -> None:
        assert _line(_handed(json.dumps(answer), {"topic": "x"})[0]) == ""

    @pytest.mark.parametrize(
        "answer",
        ["the function returns zero", json.dumps({"name": "x", "value": 3}), "[1, 2]", "{"],
    )
    def test_an_answer_of_unknown_shape_carries_no_line(self, answer: str) -> None:
        assert _line(_handed(answer, {"topic": "x"})[0]) == ""

    def test_a_next_field_below_the_top_is_not_a_page(self) -> None:
        # A linked structure's ``next`` inside a row is data, not paging.
        answer = {"entries": [{"name": "a", "next": 4096}]}
        assert completeness_line(answer) == ""


# -- the same reading as the coverage record ---------------------------------

SAMPLE = "/jobs/j1/sample.exe"

PERSISTENCE = {"total": 5, "services": ["a", "b"], "tasks": [], "commands": ["x", "y", "z"]}

# (answer, call arguments, whether the line speaks of the structure)
AGREEMENT: list[tuple[Any, dict[str, Any], bool]] = [
    ({"items": [1, 2], "has_more": True}, {}, True),
    ({"results": [1, 2, 3], "total": 250}, {}, True),
    ({"resources": [1], "nextCursor": "abc"}, {}, True),
    ({"page": 2, "pages": 5, "rows": [1]}, {}, True),
    ({"page": 3, "rows": [1]}, {}, True),
    ({"dex_files": ["a"], "totals": {"dex_files": 9}}, {}, True),
    ({"services": [1, 2], "services_total": 4}, {}, True),
    ({"data": [1], "meta": {"cursor": "c"}, "links": {"next": "u"}}, {}, True),
    ({"items": [1], "pageInfo": {"hasNextPage": True}}, {}, True),
    ({"Contents": [1], "IsTruncated": True}, {}, True),
    ({"registry": [1, 2, 3, 4, 5], "total": 15}, {"offset": 0}, True),
    # Complete, unbound or unknown: no line, and not capped in the record.
    ({"items": [], "has_more": False, "next": None}, {}, False),
    ({"total": 3, "items": [1, 2, 3]}, {}, False),
    (PERSISTENCE, {}, False),
    ({"page": 1, "per_page": 50, "total": 12, "results": list(range(12))}, {}, False),
    ({"page": 0, "pages": 1, "rows": [1]}, {}, False),
    ({"page": 4, "pages": 5, "rows": [1]}, {}, False),
    ({"registry": [1, 2, 3, 4, 5], "total": 15}, {"offset": 10}, False),
    ({"rows": [1, 2, 3, 4, 5], "total": 15, "page_offset": 10}, {}, False),
    ({"data": [1], "links": {"next": None, "self": "u"}}, {}, False),
    ({"entries": [{"name": "a", "next": 4096, "total": 9, "refs": [1]}]}, {}, False),
    ({"name": "x", "value": 3}, {}, False),
]


@pytest.mark.parametrize(("answer", "args", "speaks"), AGREEMENT)
def test_the_line_and_the_coverage_record_agree(
    answer: Any, args: dict[str, Any], speaks: bool
) -> None:
    output = json.dumps(answer)
    entry = LedgerEntry(
        id="ev_0001",
        seq=1,
        agent="static",
        tool="search_things",
        server="third",
        source="mcp:third",
        args={"topic": "x", **args},
        facts={"v": 1, "kind": "string_extraction", "arguments": {"path": "path"}},
        output=output,
    )
    call = coverage._call(entry, coverage._Inputs(SAMPLE, "", {}), lambda _entry: False)
    line = completeness_line(parse_structured(output), args=entry.args, text_chars=len(output))
    assert bool(line) is speaks
    assert ("capped" in call.get("limits", ())) is speaks, "the record reads the same answer"
    if speaks:
        assert call["read"] != coverage.WHOLE


@pytest.mark.parametrize(("output", "cut"), [("the function returns zero", 1200), ("{}", 0)])
def test_the_platform_cut_is_one_number_for_both(output: str, cut: int) -> None:
    entry = LedgerEntry(
        id="ev_0001", seq=1, agent="static", tool="t", output=output, chars_dropped=cut
    )
    call = coverage._call(entry, coverage._Inputs(SAMPLE, "", {}), lambda _entry: False)
    line = completeness_line(parse_structured(output), cut=platform_cut(entry))
    assert ("cut" in call.get("limits", ())) is bool(cut)
    assert bool(line) is bool(cut)


class TestTheReview:
    """Each case the adversarial review raised, as the governing rule reads it."""

    def test_a_total_beside_several_lists_binds_to_none(self) -> None:
        assert completeness_line(PERSISTENCE) == ""
        assert not read_answer(PERSISTENCE).capped

    def test_a_total_named_for_its_list_binds_to_it(self) -> None:
        assert '"services" shows 2 of 4' in completeness_line(
            {"services": [1, 2], "commands": [1], "services_total": 4}
        )
        assert '"hits" shows 1 of 7' in completeness_line(
            {"hits": [1], "other": [1, 2], "total_hits": 7}
        )

    def test_a_page_whose_total_is_shown_is_complete(self) -> None:
        rest = {"page": 1, "per_page": 50, "total": 12, "results": list(range(12))}
        assert completeness_line(rest) == ""
        assert completeness_line({"page": 3, "offset": 10, "total": 15, "rows": [1] * 5}) == ""

    @pytest.mark.parametrize("page", [{"page": 0, "pages": 1}, {"page": 5, "pages": 5}])
    def test_a_last_page_by_any_count_is_complete(self, page: dict[str, int]) -> None:
        assert completeness_line({**page, "rows": [1]}) == ""

    def test_a_number_longer_than_its_answer_is_malformed(self) -> None:
        answer = {"rows": [1], "total": 10**40}
        reading = read_answer(answer, text_chars=20)
        assert reading.malformed
        assert not reading.capped
        assert completeness_line(answer, text_chars=20) == ""
        # The cut the platform made is still stated.
        assert "left out 9 characters" in completeness_line(answer, text_chars=20, cut=9)
        # Read against its own text, the same number is a number.
        text = json.dumps(answer)
        assert "shows 1 of" in completeness_line(answer, text_chars=len(text))

    def test_a_replayed_answer_states_its_first_cut_and_is_charged(self) -> None:
        from maljan.agents.evidence_recorder import earlier_chunk_answer

        charged: list[str] = []

        def charge(line: str) -> str:
            charged.append(line)
            return line

        said = earlier_chunk_answer(
            "decompile", "ev_0003", "void f(void) {", ("offset",), cut=1200, charge=charge
        )
        assert "the platform left out 1,200 characters" in said
        assert "read further with `offset`" in said
        assert charged
        assert charged[0] in said

    def test_a_read_back_answer_states_the_held_cut_and_its_tool_s_paging(self) -> None:
        from maljan.agents.tool_answer_clearing import read_evidence_tool

        client = _ghidra(4000)

        def run(**kwargs: Any) -> str:
            return str(client._apply_output_guardrail(LISTING))

        tool = StructuredTool.from_function(
            func=run, name="decompile_all", description="d", args_schema=_Paged
        )
        recorder = EvidenceRecorder("analyst")
        stored: dict[str, str] = {}
        reader = read_evidence_tool(stored.get)
        wrapped, wrapped_reader = record_tools([tool, reader], recorder)
        wrapped.invoke({"topic": "x"})
        (entry,) = recorder.entries
        stored[entry.id] = str(entry.output)
        line = _line(str(wrapped_reader.invoke({"evidence_id": entry.id})))
        assert f"the platform left out {platform_cut(entry):,} characters" in line
        assert "read further with `cursor`, `limit`" in line

    def test_a_shortened_document_with_its_own_paging_stays_inside_the_limit(self) -> None:
        rows = [{"i": i, "v": "v" * 30} for i in range(400)]
        document = json.dumps({"rows": rows, "meta": {"next_cursor": "c"}})
        toolkit = MCPLangChainToolkit(None, max_output_chars=4000)
        handed, entry = _handed(
            lambda: toolkit._apply_output_guardrail(document, ("cursor", "limit")),
            {"topic": "x"},
        )
        assert "did not fit and was shortened" in handed
        line = _line(handed)
        assert '("next_cursor")' in line
        assert "left out" not in line, "the cut is the shortening sentence's to say"
        assert len(handed) - len(f"[{entry.id}]\n") <= 4000

    def test_read_further_names_only_paging_arguments(self) -> None:
        paged = {"rows": [1], "has_more": True}
        assert completeness_line(paged, narrowing=("query", "pattern")).endswith(
            "this tool takes no argument that pages it."
        )
        line = completeness_line(paged, narrowing=("query", "offset", "limit"))
        assert line.endswith("read further with `offset`, `limit`.")
        nested = {"section": "x", "value": {"a": {"items": [1], "truncated": True}}}
        assert completeness_line(nested, narrowing=("offset", "limit")).endswith(
            "no argument of this tool pages that part."
        )

    @pytest.mark.parametrize(
        ("answer", "word"),
        [
            ({"data": [1], "meta": {"cursor": "c"}}, "cursor"),
            ({"data": [1], "links": {"next": "u"}}, "next"),
            ({"items": [1], "pageInfo": {"hasNextPage": True}}, "hasNextPage"),
            ({"Contents": [1], "IsTruncated": True}, "IsTruncated"),
            ({"result": {"rows": [1], "NextContinuationToken": "t"}}, "NextContinuationToken"),
        ],
    )
    def test_a_nested_paging_word_is_read(self, answer: dict[str, Any], word: str) -> None:
        assert f'("{word}")' in completeness_line(answer)

    def test_the_full_page_reading_needs_limit_and_one_list(self) -> None:
        two = {"strings": [1, 2, 3], "sections": [1, 2, 3, 4, 5]}
        assert completeness_line(two, bounds=("limit",), args={"limit": 5}) == ""
        one = {"strings": [1, 2, 3, 4, 5]}
        assert completeness_line(one, bounds=("limit",), args={}) == ""
        assert "`limit` allowed (5)" in completeness_line(one, bounds=("limit",), args={"limit": 5})

    def test_a_last_page_reached_by_offset_carries_no_line(self) -> None:
        page = {"registry": [1, 2, 3, 4, 5], "total": 15}
        assert completeness_line(page, args={"offset": 10}) == ""
        assert '"registry" shows 5 of 15' in completeness_line(page, args={"offset": 5})


def test_a_cursor_pages_and_a_limit_bounds() -> None:
    from maljan.agents.output_shortening import bounding_arguments, narrowing_arguments

    names = ("topic", "cursor", "query", "offset", "limit", "max_rows", "page_size", "k")
    assert "cursor" in narrowing_arguments(names)
    assert narrowing_arguments(("after_cursor",)) == ("after_cursor",)
    assert bounding_arguments(("cursor", "offset", "limit", "max_rows", "buffer_size", "k")) == (
        "limit",
        "max_rows",
        "k",
    )


@pytest.mark.parametrize(("limit", "kept_back"), [(4000, True), (200, False)])
def test_the_line_s_room_is_kept_back_only_while_the_answer_still_fits(
    limit: int, kept_back: bool
) -> None:
    """A limit too small for the answer and the line keeps the answer's place."""
    from maljan.agents.tool_fence import fence_lines_room
    from maljan.llm.context_window import answering_for
    from maljan.schemas.answer_completeness import cut_line_room

    text = "B" * 5000
    toolkit = MCPLangChainToolkit(None, max_output_chars=limit)
    with answering_for("analyst") as answer:
        kept = toolkit._apply_output_guardrail(text)
    assert answer.line_room is kept_back
    room = cut_line_room(len(text)) if kept_back else 0
    assert len(kept) == limit - fence_lines_room() - room
