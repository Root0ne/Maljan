"""An answer over the cap only because of its indentation is handed over whole.

A live run's ``elf_info`` came back indented at 8,628 characters against a cap
of 8,486. Written compactly it is 5,577 characters: the same document, every
value the same, well inside the cap. The shortener measured the compact size,
found nothing to cut, and handed the indented text back unchanged — which the
guardrail then cut as text, so the model got a prefix ending mid-document, the
ledger got ``structured: null``, and the report never saw the answer. The
second over-limit answer of that run, a ``strings`` of 8,442 characters against
7,334, went the same way and would also have fit whole written compactly.

Re-emitting whitespace changes no value, so it is not a shortening: the model
is handed the compact document, parseable, with no notice, and the ledger
counts it as its own outcome. Only a compact form that still does not fit is
shortened, and then the compact form is what is shortened.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.agents.output_shortening import BOOKKEEPING_KEY, shorten_json_document

COMPACT = (",", ":")
MARKER = "[OUTPUT TRUNCATED]"


def _elf_info() -> dict[str, Any]:
    """An ``elf_info``-shaped document the recorded sizes of the live one.

    8,628 characters written with an indent of two, 5,577 written compactly —
    the two numbers the run recorded — so the gap between them is the gap the
    live answer fell into.
    """
    document: dict[str, Any] = {
        "read_path": "/staging/sample",
        "format": "ELF64",
        "machine": "x86-64",
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "comment": "c" * 361,
        "sections": [
            {
                "name": f".s{i}",
                "type": "PROGBITS",
                "offset": 4096 + i,
                "size": 64 * i,
                "flags": "AX",
            }
            for i in range(46)
        ],
        "imports": [f"symbol_{i}" for i in range(140)],
    }
    for index in range(4):
        document[f"x{index}"] = index
    return document


def _strings() -> dict[str, Any]:
    """A ``strings``-shaped document: 8,442 characters indented, 6,602 compact."""
    return {
        "read_path": "/staging/sample",
        "strings": [{"offset": 77 + i, "text": f"row {i} " + "t" * 60} for i in range(70)],
        "total": 3876,
        "note": "n" * 129,
    }


def _indented(document: Any) -> str:
    return json.dumps(document, indent=2)


def _compact(document: Any) -> str:
    return json.dumps(document, ensure_ascii=False, separators=COMPACT)


class _Ledger:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def record_tool_output(self, **row: Any) -> None:
        self.rows.append(row)


def _toolkit(cap: int, ledger: Any) -> Any:
    from maljan.agents.mcp_client import MCPLangChainToolkit

    return MCPLangChainToolkit(max_output_chars=cap, truncation_ledger=ledger)


def _ghidra(cap: int, ledger: Any) -> Any:
    from maljan.agents.ghidra_http_client import GhidraHTTPClient

    client = GhidraHTTPClient.__new__(GhidraHTTPClient)
    client._max_output_chars = cap
    client._output_guardrail = None
    client._truncation_ledger = ledger
    client._context_budget = None
    return client


GUARDRAILS = pytest.mark.parametrize("guardrail", [_toolkit, _ghidra], ids=["mcp", "ghidra"])


class TestTheRecordedSizes:
    def test_the_fixtures_are_the_sizes_the_run_recorded(self) -> None:
        assert (len(_indented(_elf_info())), len(_compact(_elf_info()))) == (8628, 5577)
        assert len(_indented(_strings())) == 8442


class TestAnAnswerThatFitsCompactIsHandedOverWhole:
    @GUARDRAILS
    def test_the_elf_info_answer_reaches_the_model_whole_and_parseable(
        self, guardrail: Any
    ) -> None:
        ledger = _Ledger()

        kept = guardrail(8486, ledger)._apply_output_guardrail(_indented(_elf_info()))

        assert kept == _compact(_elf_info())
        assert json.loads(kept) == _elf_info(), "no value changed"
        assert MARKER not in kept
        assert BOOKKEEPING_KEY not in json.loads(kept), "nothing was left out, so nothing says so"
        row = ledger.rows[-1]
        assert row["compacted"] is True
        assert (row["shortened"], row["hard_truncated"], row["summarised"]) == (False,) * 3
        assert row["over_limit"] is True and row["limit"] == 8486

    @GUARDRAILS
    def test_the_strings_answer_does_too(self, guardrail: Any) -> None:
        ledger = _Ledger()

        kept = guardrail(7334, ledger)._apply_output_guardrail(_indented(_strings()))

        assert json.loads(kept) == _strings()
        assert ledger.rows[-1]["compacted"] is True

    def test_the_ledger_entry_carries_the_data_and_no_shortening_notice(self) -> None:
        from maljan.agents.evidence_recorder import EvidenceRecorder, shortened_notice

        kept = _toolkit(8486, None)._apply_output_guardrail(_indented(_elf_info()))
        entry = EvidenceRecorder("static").record(
            tool="elf_info", args={}, server="analysis", output=kept
        )

        assert entry.structured == _elf_info()
        assert shortened_notice(kept) == ""

    def test_the_run_counts_it_as_its_own_outcome(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        _toolkit(8486, ledger)._apply_output_guardrail(_indented(_elf_info()))
        snapshot = ledger.snapshot()

        assert snapshot["tool_output_compacted"] == 1
        assert (snapshot["tool_output_shortened"], snapshot["tool_output_hard_truncated"]) == (
            0,
            0,
        )
        summary = RunSummaryBuilder(0.0).set_truncation(snapshot).build()
        assert summary.to_dict()["truncation"]["tool_output_compacted"] == 1
        assert "| — handed over whole without its whitespace | 1 |" in summary.to_markdown()


class TestACompactFormThatStillDoesNotFitIsShortened:
    @GUARDRAILS
    def test_the_shortener_acts_on_the_compact_form(self, guardrail: Any) -> None:
        ledger = _Ledger()
        answer = _indented(_strings())
        assert len(_compact(_strings())) > 6000

        kept = guardrail(6000, ledger)._apply_output_guardrail(answer)

        parsed = json.loads(kept)
        assert kept == _compact(parsed), "the shortened document is written compactly"
        assert len(kept) <= 6000
        assert parsed[BOOKKEEPING_KEY]["/strings"]["kept"] > 0
        row = ledger.rows[-1]
        assert (row["shortened"], row["compacted"]) == (True, False)

    def test_writing_it_compactly_keeps_more_rows_than_writing_it_indented_would(self) -> None:
        answer = _indented(_strings())

        kept = json.loads(shorten_json_document(answer, 6000).text)

        # The indented form spends about a quarter of its characters on
        # whitespace; the compact form spends none, so more rows fit.
        rows_indented = 0
        while (
            len(_indented({**_strings(), "strings": _strings()["strings"][:rows_indented]})) < 6000
        ):
            rows_indented += 1
        assert len(kept["strings"]) > rows_indented


class TestTheShortenerSaysWhichItDid:
    def test_an_indented_document_that_fits_the_cap_compact_is_compacted(self) -> None:
        result = shorten_json_document(_indented(_elf_info()), 8200, cap=8486)

        assert (result.compacted, result.shortened) == (True, False)
        assert result.text == _compact(_elf_info())

    def test_the_cap_defaults_to_the_limit(self) -> None:
        assert shorten_json_document(_indented(_elf_info()), 5577).compacted is True
        assert shorten_json_document(_indented(_elf_info()), 5576).compacted is False

    def test_a_document_whose_meaning_would_change_is_not_compacted(self) -> None:
        duplicated = '{\n  "n": 1,\n  "n": 2,\n  "pad": "%s"\n}' % ("x" * 500)

        result = shorten_json_document(duplicated, 510)

        assert (result.compacted, result.text) == (False, duplicated)

    def test_a_bare_list_that_fits_compact_is_compacted_too(self) -> None:
        rows = [{"n": index} for index in range(300)]

        result = shorten_json_document(_indented(rows), len(_compact(rows)))

        assert result.compacted is True
        assert json.loads(result.text) == rows

    def test_an_escaped_lone_surrogate_stays_escaped(self) -> None:
        """Bytes a binary's strings decode badly arrive escaped, and stay so.

        Written back unescaped, a lone surrogate is a string no UTF-8 encoder
        accepts, and the answer would fail on its way to the model instead of
        reaching it.
        """
        document = {"read_path": "/staging/sample", "strings": ["ok \udc80 bytes"] * 200}

        result = shorten_json_document(_indented(document), len(_indented(document)) - 1)

        assert result.compacted is True
        assert result.text.encode("utf-8")
        assert json.loads(result.text) == document
