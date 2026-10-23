"""Another run's ledger and item ids never reach this run in this run's form.

``ev_NNNN`` and sandbox item ids (``net:4``) are per-run sequence numbers. A
similar past case's summary is that run's claims with that run's ids, so its
``ev_0007`` named a real entry of this run that says something else: a judge
that copied it cited that entry, and every id check passed. Each id of a
stored case is now renamed (``foreign_ids_written_out``) wherever the case's
text reaches this run, in a form no id reader accepts. This run's own ids and
a case with no id are untouched, byte for byte.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from maljan.agents.judge_agent import JudgeAgent, closed_memory_cut, verdict_report_parts
from maljan.agents.tool_fence import quoted_value
from maljan.analysis.sandbox_sections import item_ids_in
from maljan.extractors.attribution import populate_similar_samples
from maljan.memory.long_term_memory import (
    FOREIGN_ENTRY_ID,
    FOREIGN_ITEM_ID,
    StoredCase,
    foreign_ids_written_out,
    foreign_quoted_value,
)
from maljan.pipeline.validation import _EVIDENCE_ID_RE
from maljan.schemas.evidence import ENTRY_ID_JOIN_RE, ENTRY_ID_RE, entry_ids_in
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.utils.marked_cut import marked_cut


def _no_id_of_this_run_s_shape(text: str) -> None:
    # Every reader: the bounded entry id, the unbounded one validation finds
    # in a citing field, the join an escape can bring, and an item id.
    assert not entry_ids_in(text)
    assert not ENTRY_ID_RE.search(text)
    assert not _EVIDENCE_ID_RE.search(text)
    assert not ENTRY_ID_JOIN_RE.search(text)
    assert not item_ids_in(text)


class TestTheRenaming:
    @pytest.mark.parametrize(
        "text",
        [
            "injects into explorer.exe [ev_0007]",
            "EV_0002 and Ev_12 and ev_0003,ev_0004",
            "prev_0007 dev_1",
            "beacons to net:4, spawns proc:1234.2 and proc:p3, reads (file:12)",
            "ev_0007net:4 net:4ev_0007 ev_ev_0001",
            "\x0ev_0003 \nnet:4",
        ],
    )
    def test_no_id_reader_finds_one_afterwards(self, text: str) -> None:
        out = foreign_ids_written_out(text)

        _no_id_of_this_run_s_shape(out)
        _no_id_of_this_run_s_shape(foreign_quoted_value(text))
        assert foreign_ids_written_out(out) == out

    def test_each_id_is_said_to_be_another_run_s(self) -> None:
        out = foreign_ids_written_out("[ev_0007] connects (net:4)")

        assert out == f"[{FOREIGN_ENTRY_ID}] connects ({FOREIGN_ITEM_ID})"

    @pytest.mark.parametrize(
        "text",
        ["", "T1055 T1547.001 RAT", "c2.example.net:443", "C:\\Users\\x\\file:3", "dev box"],
    )
    def test_a_text_with_no_id_comes_back_as_it_was(self, text: str) -> None:
        assert foreign_ids_written_out(text) == text
        assert foreign_quoted_value(text) == quoted_value(text)

    def test_linear_in_the_text(self) -> None:
        def timed(n: int) -> float:
            text = "ev_0007net:4 ev_" * n + "e" * n + "net:" * n
            started = time.perf_counter()
            foreign_ids_written_out(text)
            return time.perf_counter() - started

        timed(1_000)
        small, large = timed(20_000), timed(200_000)
        assert large < small * 40


def _case(summary: str, category: str = "RAT") -> SimpleNamespace:
    return SimpleNamespace(
        sample_id="cd" * 32,
        summary_text=summary,
        technique_ids=["T1055"],
        malware_category=category,
        owner=None,
    )


def _isr() -> AgentISR:
    return AgentISR(
        agent_id="static",
        domain="static",
        claims=[ClaimEvidence(claim="injects code", evidence_ref="ev_0007", confidence=0.8)],
    )


class TestTheJudgesSimilarCaseBlock:
    def test_a_past_case_s_id_never_reaches_the_judge_as_this_run_s(self) -> None:
        store = SimpleNamespace(
            retrieve=lambda *_a, **_k: [
                _case("[STATIC] injects into explorer.exe [ev_0007] net:4 \x0ev_0003", "ev_0001")
            ]
        )

        block = JudgeAgent._build_memory_context({"static": _isr()}, store, owner=None)

        _no_id_of_this_run_s_shape(block)
        assert FOREIGN_ENTRY_ID in block and FOREIGN_ITEM_ID in block
        assert "injects into explorer.exe" in block

    def test_a_window_cut_never_ends_one_of_its_texts_on_an_id(self) -> None:
        # ``net:44x`` and ``proc:12.5x`` are no ids; cut after their first
        # digit they would be, and the block is renamed after the cut too.
        store = SimpleNamespace(
            retrieve=lambda *_a, **_k: [_case("beacons net:44x then proc:12.5x", "net:44x")]
        )
        block = JudgeAgent._build_memory_context({"static": _isr()}, store, owner=None)

        for width in range(1, len(block) + 1):
            shown = closed_memory_cut(marked_cut(block, width), block)
            assert not item_ids_in(shown), width
            _no_id_of_this_run_s_shape(shown)

    def test_this_run_s_own_ids_are_untouched(self) -> None:
        parts = verdict_report_parts({"static": "injects code [ev_0007] (net:4)"}, None)

        assert "[ev_0007] (net:4)" in parts["static report"]

    def test_a_case_with_no_id_is_shown_as_it_was(self) -> None:
        summary, category = "[STATIC] injects into explorer.exe T1055", "RAT"
        store = SimpleNamespace(retrieve=lambda *_a, **_k: [_case(summary, category)])

        block = JudgeAgent._build_memory_context({"static": _isr()}, store, owner=None)

        assert f"sample_id: {'cd' * 32} (category: {quoted_value(category)})" in block
        assert "  Past techniques: T1055" in block
        assert f"  Behavioral summary: {quoted_value(summary)}" in block


class TestTheReportsSimilarSamples:
    def test_a_past_case_s_id_is_renamed_in_the_summary(self) -> None:
        case = StoredCase(
            sample_id="b" * 64,
            summary_text="[STATIC] injects [ev_0007] beacons net:4",
            technique_ids=["T1055"],
            malware_category="ev_0003",
            created_at=datetime.now(UTC),
        )
        store = SimpleNamespace(retrieve=lambda *_a, **_k: [case])
        report = {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "malware_category": "RAT",
            "attribution": {"similar_samples": []},
        }

        populate_similar_samples(report, store)

        (similar,) = report["attribution"]["similar_samples"]
        _no_id_of_this_run_s_shape(similar["summary"])
        _no_id_of_this_run_s_shape(similar["malware_category"])
        assert similar["malware_category"] == FOREIGN_ENTRY_ID
        assert similar["summary"] == (
            f"[STATIC] injects [{FOREIGN_ENTRY_ID}] beacons {FOREIGN_ITEM_ID}"
        )

    def test_the_summary_is_cut_before_it_is_renamed(self) -> None:
        # Cut first, an id the cut completes (``net:4`` of ``net:44x``) is
        # renamed; renamed first, it would survive.
        case = StoredCase(
            sample_id="b" * 64,
            # Cut at 239 characters and a mark: ``net:4`` and the mark.
            summary_text="x" * 233 + " net:44x",
            created_at=datetime.now(UTC),
        )
        store = SimpleNamespace(retrieve=lambda *_a, **_k: [case])
        report = {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "malware_category": "RAT",
            "attribution": {"similar_samples": []},
        }

        populate_similar_samples(report, store)

        (similar,) = report["attribution"]["similar_samples"]
        assert not item_ids_in(similar["summary"])
        assert similar["summary"].endswith(f" {FOREIGN_ITEM_ID}…")
