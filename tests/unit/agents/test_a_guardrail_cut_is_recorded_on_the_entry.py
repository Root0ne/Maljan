"""An answer the tool-output guardrail cut is recorded as cut, with what it lost.

The guardrail cut two decompilations to fit and the ledger kept the cut copies
marked ``truncated: false``, so the report's evidence bounds said nothing was
cut while thousands of characters of the listing were. The guardrail now tells
the call it is answering how many characters it dropped; the entry keeps what
the model read, is marked ``truncated`` and carries ``chars_dropped``, and the
run summary and §13 count it apart from an entry the byte budget trimmed.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from maljan.agents.base_agent import earlier_chunks_block
from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools, seeded_repeat_guard
from maljan.core.truncation_ledger import record_guardrail_outcome
from maljan.pipeline.nodes import evidence_summary
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry, apply_budget, holds_its_answer

LISTING = "void FUN_00401000(void) {\n  int counter = 0;\n  return;\n}\n" * 400


def _client(limit: int) -> Any:
    from maljan.agents.ghidra_http_client import GhidraHTTPClient

    client = GhidraHTTPClient.__new__(GhidraHTTPClient)
    client._max_output_chars = limit
    client._output_guardrail = None
    client._truncation_ledger = None
    client._context_budget = None
    return client


def _decompiler(answer: Any) -> StructuredTool:
    def decompile_function(address: str) -> str:
        """Decompile the function at an address."""
        return answer()

    return StructuredTool.from_function(func=decompile_function, name="decompile_function")


def _recorded(answer: Any) -> tuple[str, LedgerEntry]:
    recorder = EvidenceRecorder("reverser")
    (tool,) = record_tools([_decompiler(answer)], recorder)
    handed = tool.invoke({"address": "0x401000"})
    (entry,) = recorder.entries
    return str(handed), entry


class TestTheEntry:
    def test_a_hard_cut_is_truncated_with_the_characters_it_dropped(self) -> None:
        limit = 4000
        client = _client(limit)

        handed, entry = _recorded(lambda: client._apply_output_guardrail(LISTING))

        assert entry.truncated is True
        assert entry.chars_dropped == len(LISTING) - len(entry.output)
        assert entry.chars_dropped > 0
        assert entry.output in handed, "the entry keeps what the model read"

    def test_an_answer_that_fits_is_whole(self) -> None:
        client = _client(len(LISTING) + 10)

        _handed, entry = _recorded(lambda: client._apply_output_guardrail(LISTING))

        assert entry.truncated is False
        assert entry.chars_dropped == 0

    def test_a_shortened_or_summarised_answer_is_cut_and_a_compacted_one_is_not(self) -> None:
        def said(**outcome: Any) -> Any:
            def answer() -> str:
                record_guardrail_outcome(
                    None, chars_in=1000, chars_kept=300, over_limit=True, **outcome
                )
                return "kept"

            return answer

        for outcome in ({"shortened": True}, {"summarised": True}, {"hard_truncated": True}):
            _handed, entry = _recorded(said(**outcome))
            assert (entry.truncated, entry.chars_dropped) == (True, 700), outcome

        _handed, entry = _recorded(said(compacted=True))
        assert (entry.truncated, entry.chars_dropped) == (False, 0)


class TestACutEntryIsReadAsCut:
    def _cut(self) -> LedgerEntry:
        return LedgerEntry(
            id="ev_0004",
            tool="decompile_function",
            args={"address": "0x401000"},
            output="void FUN_00401000(void) {",
            truncated=True,
            chars_dropped=1200,
        )

    def test_it_holds_its_answer_until_the_budget_blanks_it(self) -> None:
        entry = self._cut()
        assert holds_its_answer(entry)

        apply_budget([entry], budget_bytes=1)

        assert not holds_its_answer(entry)

    def test_a_later_chunk_is_answered_from_it_and_not_told_to_ask_again(self) -> None:
        entry = self._cut()

        guard = seeded_repeat_guard([entry])
        block = earlier_chunks_block([entry])

        assert guard.recorded_answer("decompile_function", {"address": "0x401000"}) == (
            "ev_0004",
            entry.output,
        )
        assert "result not kept" not in block

    def test_the_summary_counts_cuts_apart_from_budget_trims(self) -> None:
        trimmed = LedgerEntry(id="ev_0005", tool="strings", output="", truncated=True)
        blanked_cut = self._cut().model_copy(update={"id": "ev_0006", "output": ""})

        summary = evidence_summary([self._cut(), trimmed, blanked_cut])

        assert summary["trimmed"] == 2
        assert (summary["cut"], summary["chars_dropped"]) == (2, 2400)

    def test_a_ledger_with_no_cut_keeps_its_summary_shape(self) -> None:
        summary = evidence_summary([LedgerEntry(id="ev_0001", tool="strings", output="x")])
        assert "cut" not in summary and "chars_dropped" not in summary


class TestTheEvidenceBounds:
    def _render(self, run_summary: dict[str, Any]) -> str:
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
            run_summary=run_summary,
        )
        return MarkdownRenderer().render(report)

    def test_the_line_counts_the_cut_answers(self) -> None:
        text = self._render(
            {
                "evidence": {
                    "entries": 5,
                    "ok": 5,
                    "failed": 0,
                    "trimmed": 0,
                    "cut": 2,
                    "chars_dropped": 5817,
                }
            }
        )

        assert (
            "**Evidence bounds:** 5 ledger entries, 5 ok, 0 failed, 0 trimmed to the budget, "
            "2 cut by the tool-output guardrail (5,817 characters dropped)." in text
        )

    def test_a_summary_older_than_the_count_reads_the_guardrail_s_own(self) -> None:
        text = self._render(
            {
                "evidence": {"entries": 5, "ok": 5, "failed": 0, "trimmed": 0},
                "truncation": {
                    "tool_output_hard_truncated": 2,
                    "tool_output_shortened": 1,
                    "tool_output_summarised": 0,
                    "tool_output_chars_dropped": 9000,
                },
            }
        )

        assert "3 cut by the tool-output guardrail (9,000 characters dropped)." in text

    def test_nothing_cut_reads_as_before(self) -> None:
        text = self._render({"evidence": {"entries": 5, "ok": 5, "failed": 0, "trimmed": 0}})

        assert (
            "**Evidence bounds:** 5 ledger entries, 5 ok, 0 failed, 0 trimmed to the budget."
            in text
        )
