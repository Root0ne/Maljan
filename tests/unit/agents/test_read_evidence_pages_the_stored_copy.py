"""``read_evidence`` pages through the full copy of an answer the job's store holds.

A call with no ``offset`` and no ``limit`` is the read it always was. With
either, the answer is read page by page by byte position from the stored full
copy where the entry references one, else from the stored answer, and every
page says which bytes it holds, from which copy, and where the next starts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pytest

from maljan.agents import tool_answer_clearing as tac
from maljan.agents.base_agent import _stored_answer_of, _stored_copy_of
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools
from maljan.schemas.evidence_spill import EvidenceSpill

WHOLE = "".join(f"row {index:03d} é\n" for index in range(40))


class _Store(EvidenceSpill):
    """A store that keeps what it is given and hands byte ranges back."""

    def __init__(self) -> None:
        super().__init__(self._keep)
        self.blobs: dict[str, bytes] = {}
        self.refuse_reads = False

    def _keep(self, sha256: str, blob: bytes, content_type: str) -> str:
        self.blobs[sha256] = blob
        return f"evidence/job/{sha256}"

    def read(self, sha256: str, offset: int = 0, length: int | None = None) -> bytes | None:
        if self.refuse_reads or sha256 not in self.blobs:
            return None
        blob = self.blobs[sha256]
        return blob[offset : offset + length] if length else blob[offset:]


def _recorder_with_a_cut_answer(
    store: EvidenceSpill | None, corpus: Any = None
) -> EvidenceRecorder:
    recorder = EvidenceRecorder("static", spill=store, corpus=corpus)
    recorder.record(
        tool="lookup",
        args={"n": 1},
        server=None,
        output=WHOLE[:100],
        cut=len(WHOLE) - 100,
        whole=WHOLE,
    )
    return recorder


def _tool(recorder: EvidenceRecorder) -> Any:
    return tac.read_evidence_tool(_stored_answer_of(recorder), None, _stored_copy_of(recorder))


def _pages(tool: Any, limit: int) -> tuple[str, int]:
    """Every page of ev_0001 read ``limit`` bytes at a time, joined, and how many there were."""
    offset, text, count = 0, "", 0
    while True:
        page = tool.invoke({"evidence_id": "ev_0001", "offset": offset, "limit": limit})
        head, _, body = page.partition("\n")
        text += body
        count += 1
        if "this is the end" in head:
            return text, count
        offset = int(head.rsplit("offset ", 1)[1].rstrip("]"))


class TestAReadWithoutPagingIsUnchanged:
    def test_it_answers_the_stored_output_as_before(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        assert _tool(recorder).invoke({"evidence_id": "ev_0001"}) == WHOLE[:100]

    def test_the_ledger_records_the_arguments_as_the_call_made_them(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        (read,) = record_tools([_tool(recorder)], recorder)
        read.invoke({"evidence_id": "ev_0001"})
        read.invoke({"evidence_id": "ev_0001", "offset": 5})

        assert recorder.entries[-2].args == {"evidence_id": "ev_0001"}
        assert recorder.entries[-1].args == {"evidence_id": "ev_0001", "offset": 5}

    def test_the_text_is_the_same_with_or_without_a_store(self) -> None:
        with_store = _tool(_recorder_with_a_cut_answer(_Store())).invoke({"evidence_id": "ev_0001"})
        without = _tool(_recorder_with_a_cut_answer(None)).invoke({"evidence_id": "ev_0001"})
        assert with_store == without


class TestPagingThroughTheStoredCopy:
    def test_the_pages_join_into_the_whole_answer_including_what_was_cut(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        text, count = _pages(_tool(recorder), 97)
        assert text == WHOLE
        assert count > 1

    def test_a_page_names_its_bytes_its_copy_and_where_the_next_starts(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        page = _tool(recorder).invoke({"evidence_id": "ev_0001", "offset": 0, "limit": 50})
        total = len(WHOLE.encode())
        assert page.startswith(
            f"[read_evidence: bytes 0-50 of {total} of the stored full copy of the answer; "
            "the next page starts at offset 50]\n"
        )

    def test_a_character_a_position_falls_inside_is_never_split(self) -> None:
        tool = _tool(_recorder_with_a_cut_answer(_Store()))
        # Every limit, so some page boundary falls inside the two-byte character.
        for limit in range(5, 40):
            text, _ = _pages(tool, limit)
            assert text == WHOLE, limit

    def test_an_offset_alone_reads_to_the_end(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        page = _tool(recorder).invoke({"evidence_id": "ev_0001", "offset": 22})
        assert page.endswith(WHOLE.encode()[22:].decode())
        assert "this is the end" in page.partition("\n")[0]

    def test_an_offset_past_the_end_says_so(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        page = _tool(recorder).invoke({"evidence_id": "ev_0001", "offset": 10_000})
        assert "is at or past the end" in page

    def test_the_stored_copy_is_named_by_its_digest(self) -> None:
        store = _Store()
        recorder = _recorder_with_a_cut_answer(store)
        (ref,) = recorder.entries[0].spilled
        assert ref["sha256"] == hashlib.sha256(WHOLE.encode()).hexdigest()
        assert store.blobs[ref["sha256"]] == WHOLE.encode()


class TestWhereThereIsNoStoredCopy:
    def test_a_run_without_a_store_pages_the_stored_answer_and_says_so(self) -> None:
        recorder = _recorder_with_a_cut_answer(None)
        page = _tool(recorder).invoke({"evidence_id": "ev_0001", "offset": 0, "limit": 30})
        head, _, body = page.partition("\n")
        assert "of the stored answer;" in head
        assert WHOLE.encode().startswith(body.encode()) and 28 <= len(body.encode()) <= 30

    def test_a_copy_that_cannot_be_read_falls_back_and_says_so(self) -> None:
        store = _Store()
        recorder = _recorder_with_a_cut_answer(store)
        store.refuse_reads = True
        page = _tool(recorder).invoke({"evidence_id": "ev_0001", "offset": 0, "limit": 30})
        assert "(the full copy could not be read)" in page.partition("\n")[0]

    def test_an_entry_that_kept_its_answer_whole_has_no_copy(self) -> None:
        recorder = EvidenceRecorder("static", spill=_Store())
        recorder.record(tool="lookup", args={}, server=None, output="short answer")
        page = _tool(recorder).invoke({"evidence_id": "ev_0001", "offset": 6})
        assert page.endswith("answer")
        assert "of the stored answer;" in page.partition("\n")[0]


class TestTheArgumentsAreChecked:
    def test_a_negative_offset_or_a_zero_limit_is_refused(self) -> None:
        tool = _tool(_recorder_with_a_cut_answer(_Store()))
        with pytest.raises(Exception, match="greater than|less than"):
            tool.invoke({"evidence_id": "ev_0001", "offset": -1})
        with pytest.raises(Exception, match="greater than|less than"):
            tool.invoke({"evidence_id": "ev_0001", "limit": 0})

    def test_an_unknown_id_is_still_the_same_failure(self) -> None:
        tool = _tool(_recorder_with_a_cut_answer(_Store()))
        answer = json.loads(tool.invoke({"evidence_id": "ev_0099", "offset": 5}))
        assert answer["error"]["code"] == "bad_argument"


class TestThroughTheRecorder:
    def test_a_page_is_filed_as_a_repeat_and_its_text_reaches_the_corpus(self) -> None:
        class _Corpus:
            def __init__(self) -> None:
                self.kept: dict[str, str] = {}

            def remember(self, entry_id: str, tool: str, text: str) -> None:
                self.kept[entry_id] = text

        corpus = _Corpus()
        recorder = _recorder_with_a_cut_answer(_Store(), corpus)
        (read,) = record_tools([_tool(recorder)], recorder)
        shown = read.invoke({"evidence_id": "ev_0001", "offset": 300, "limit": 40})
        assert shown.startswith("[ev_0001]\n")
        assert recorder.entries[-1].repeated_of == "ev_0001"
        assert any("@300+40" in key and "row" in text for key, text in corpus.kept.items())


MIXED = "aé€😀" * 30


class TestAPageAlwaysFitsTheRoom:
    def _tool(self, room: int, text: str = WHOLE * 4) -> Any:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        recorder = EvidenceRecorder("static", spill=_Store())
        recorder.record(
            tool="lookup", args={}, server=None, output=text[:50], cut=len(text) - 50, whole=text
        )
        sizer = MCPLangChainToolkit(None, max_output_chars=room)
        return tac.read_evidence_tool(_stored_answer_of(recorder), sizer, _stored_copy_of(recorder))

    def test_a_page_is_never_cut_by_the_guardrail_and_the_walk_is_exact(self) -> None:
        tool = self._tool(400)
        whole = (WHOLE * 4).encode()
        offset, got, pages = 0, b"", 0
        while True:
            page = tool.invoke({"evidence_id": "ev_0001", "offset": offset, "limit": 10**6})
            head, _, body = page.partition("\n")
            assert len(page) <= 400, len(page)
            first, last = (int(n) for n in head.split("bytes ")[1].split(" of ")[0].split("-"))
            assert first == offset and whole[first:last] == body.encode()
            got += body.encode()
            pages += 1
            if "this is the end" in head:
                assert last == len(whole)
                break
            assert last < len(whole)
            offset = last
        assert got == whole
        assert pages > 3

    def test_a_limit_above_the_room_is_held_to_the_room(self) -> None:
        tool = self._tool(400)
        page = tool.invoke({"evidence_id": "ev_0001", "offset": 0, "limit": 100_000})
        assert len(page) <= 400
        assert "the next page starts at offset" in page.partition("\n")[0]


class TestALimitSmallerThanACharacterStillAdvances:
    def test_a_walk_by_one_to_three_bytes_reaches_the_end(self) -> None:
        recorder = _recorder_with_a_cut_answer(None)
        recorder.entries[0].output = MIXED
        tool = _tool(recorder)
        for limit in (1, 2, 3):
            offset, text = 0, ""
            for _ in range(len(MIXED.encode()) + 2):
                page = tool.invoke({"evidence_id": "ev_0001", "offset": offset, "limit": limit})
                head, _, body = page.partition("\n")
                text += body
                if "this is the end" in head:
                    break
                nxt = int(head.rsplit("offset ", 1)[1].rstrip("]"))
                assert nxt > offset
                offset = nxt
            assert text == MIXED, limit


class TestAPageStatesOnlyItsOwnCut:
    def test_the_held_answers_cut_line_is_not_repeated_under_a_page(self) -> None:
        recorder = _recorder_with_a_cut_answer(_Store())
        (read,) = record_tools([_tool(recorder)], recorder)
        whole_read = read.invoke({"evidence_id": "ev_0001"})
        paged = read.invoke({"evidence_id": "ev_0001", "offset": 0, "limit": 50})
        assert "Completeness" in whole_read
        assert "Completeness" not in paged


class TestAPageGroundsTheCitedEntry:
    def test_the_corpus_joins_an_entry_with_the_pages_read_of_it(self) -> None:
        from maljan.agents.run_evidence_corpus import RunEvidenceCorpus

        corpus = RunEvidenceCorpus(1_000_000)
        recorder = _recorder_with_a_cut_answer(_Store(), corpus)
        (read,) = record_tools([_tool(recorder)], recorder)
        read.invoke({"evidence_id": "ev_0001", "offset": 300, "limit": 40})

        joined = corpus.text_of_entry("ev_0001")
        assert WHOLE[:100].lower() in joined
        assert "row 0" in corpus.pages_of("ev_0001")
        assert "ev_0001@" not in joined
        assert corpus.text_of_entry("ev_0002") == ""

    def test_a_value_only_on_a_page_is_in_the_text_of_the_cited_entry(self) -> None:
        from maljan.agents.run_evidence_corpus import RunEvidenceCorpus
        from maljan.pipeline.validation import EntryTexts

        marker = "uniquevalue-7f3a"
        text = WHOLE + marker + "\n" + WHOLE
        corpus = RunEvidenceCorpus(1_000_000)
        recorder = EvidenceRecorder("static", spill=_Store(), corpus=corpus)
        recorder.record(
            tool="lookup", args={}, server=None, output=text[:50], cut=len(text) - 50, whole=text
        )
        (read,) = record_tools([_tool(recorder)], recorder)
        at = text.encode().index(marker.encode())
        read.invoke({"evidence_id": "ev_0001", "offset": at - 5, "limit": 60})

        texts = EntryTexts.from_ledger(recorder.entries, corpus)

        assert marker in texts.texts["ev_0001"]
        assert marker not in EntryTexts.from_ledger(recorder.entries, None).texts["ev_0001"]
