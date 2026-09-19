"""A tool answer too big for the prompt is shortened, not broken in half.

The guardrail cut a JSON answer as text, so an analyst's *largest* answers —
the ones that found the most — arrived at the model as a prefix ending
mid-array and at the ledger as prose with no ``structured`` at all. Everything
downstream reads ``structured``, so those calls contributed no evidence, no
corroboration and no artefacts to the report, and nothing said so.

What is shortened now is the document: elements come off the end of its
largest lists until it fits, no key is ever dropped, and the answer says in its
own vocabulary how many rows it is handing over.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.agents.output_shortening import shorten_json_document


def _strings_answer(rows: int, *, total: int = 3876) -> str:
    """The shape the analysis sidecar's ``strings`` returns over a carved file."""
    return json.dumps(
        {
            "read_path": "/staging/carved/body_0x364000",
            "strings": [
                {"offset": 77 + index, "enc": "ascii", "text": f"row number {index}"}
                for index in range(rows)
            ],
            "total": total,
            "truncated": False,
            "page_limit": 150,
            "next_offset": None,
        }
    )


class TestADocumentComesBackADocument:
    def test_a_long_answer_still_parses_and_keeps_every_key(self) -> None:
        answer = _strings_answer(300)

        shortened, was_shortened = shorten_json_document(answer, 4000)

        assert was_shortened
        parsed = json.loads(shortened)
        assert set(parsed) >= {
            "read_path",
            "strings",
            "total",
            "truncated",
            "page_limit",
            "next_offset",
        }
        assert len(shortened) <= 4000

    def test_the_file_that_was_read_survives_wherever_it_sits(self) -> None:
        """The key the front-placement in the sidecar was a stand-in for."""
        answer = json.dumps(
            {
                "strings": [{"text": f"row {index}"} for index in range(300)],
                "total": 3876,
                "read_path": "/staging/carved/body_0x364000",
            }
        )

        shortened, _ = shorten_json_document(answer, 2000)

        assert json.loads(shortened)["read_path"] == "/staging/carved/body_0x364000"

    def test_fewer_rows_come_back_and_they_are_the_first_ones_in_order(self) -> None:
        answer = _strings_answer(300)

        shortened, _ = shorten_json_document(answer, 4000)

        rows = json.loads(shortened)["strings"]
        assert 0 < len(rows) < 300
        assert [row["text"] for row in rows] == [f"row number {i}" for i in range(len(rows))]

    def test_the_answer_says_it_was_shortened(self) -> None:
        shortened, _ = shorten_json_document(_strings_answer(300), 4000)

        assert json.loads(shortened)["truncated"] is True

    def test_the_count_can_be_reconciled_against_the_total_the_tool_gave(self) -> None:
        shortened, _ = shorten_json_document(_strings_answer(300), 4000)

        parsed = json.loads(shortened)
        assert parsed["strings_returned"] == len(parsed["strings"])
        assert parsed["total"] == 3876

    def test_a_list_with_no_total_beside_it_says_what_was_left_out(self) -> None:
        answer = json.dumps({"rows": [{"n": index} for index in range(300)]})

        shortened, _ = shorten_json_document(answer, 1000)

        parsed = json.loads(shortened)
        assert parsed["rows_omitted"] == 300 - len(parsed["rows"])
        assert parsed["rows_omitted"] > 0

    def test_a_nested_list_is_counted_on_the_object_that_holds_it(self) -> None:
        answer = json.dumps(
            {
                "read_path": "/staging/x",
                "pe": {"sections": [{"name": f"s{index}"} for index in range(300)]},
            }
        )

        shortened, _ = shorten_json_document(answer, 1200)

        parsed = json.loads(shortened)
        assert parsed["read_path"] == "/staging/x"
        assert parsed["pe"]["sections_omitted"] == 300 - len(parsed["pe"]["sections"])

    def test_the_largest_list_is_the_one_that_gives(self) -> None:
        answer = json.dumps(
            {
                "imports": [{"n": f"import number {index}"} for index in range(400)],
                "exports": [{"n": f"export {index}"} for index in range(4)],
            }
        )

        shortened, _ = shorten_json_document(answer, 1500)

        parsed = json.loads(shortened)
        assert len(parsed["exports"]) == 4, "a short list is not touched while a long one fits"
        assert len(parsed["imports"]) < 400

    def test_it_keeps_as_much_as_the_limit_allows(self) -> None:
        """Halving would fit too, and would throw away rows nobody had to lose."""
        shortened, _ = shorten_json_document(_strings_answer(300), 4000)

        parsed = json.loads(shortened)
        one_more = dict(parsed)
        one_more["strings"] = parsed["strings"] + [
            {"offset": 77 + len(parsed["strings"]), "enc": "ascii", "text": "row number x"}
        ]
        assert len(json.dumps(one_more)) > 4000

    def test_the_same_answer_always_comes_back_the_same_way(self) -> None:
        answer = _strings_answer(300)

        first, _ = shorten_json_document(answer, 4000)
        second, _ = shorten_json_document(answer, 4000)

        assert first == second


class TestWhatIsLeftAlone:
    def test_an_answer_inside_the_limit_is_returned_untouched(self) -> None:
        answer = _strings_answer(2)

        shortened, was_shortened = shorten_json_document(answer, 4000)

        assert was_shortened is False
        assert shortened == answer

    def test_text_that_is_not_json_is_not_this_function_s_business(self) -> None:
        for text in ("a decompiled function, in C", "", "[OUTPUT TRUNCATED]", "null", "42"):
            assert shorten_json_document(text, 4) == (text, False)

    def test_a_bare_list_is_left_to_the_character_cut(self) -> None:
        """Nothing in a bare list can say how many rows are missing."""
        answer = json.dumps([{"n": index} for index in range(300)])

        assert shorten_json_document(answer, 100) == (answer, False)

    def test_a_document_whose_keys_alone_are_too_big_is_left_alone(self) -> None:
        answer = json.dumps({"read_path": "/staging/" + "x" * 500, "rows": [1, 2, 3]})

        shortened, was_shortened = shorten_json_document(answer, 100)

        assert was_shortened is False
        assert shortened == answer


class TestItFinishesOnSomethingBig:
    def test_a_five_megabyte_answer_is_shortened_in_bounded_time(self) -> None:
        import time

        answer = json.dumps(
            {
                "read_path": "/staging/x",
                "total": 200_000,
                "strings": [
                    {"text": f"row number {index} " + "y" * 20} for index in range(150_000)
                ],
            }
        )
        assert len(answer) > 5_000_000

        started = time.monotonic()
        shortened, was_shortened = shorten_json_document(answer, 6000)
        elapsed = time.monotonic() - started

        assert was_shortened
        assert len(shortened) <= 6000
        assert json.loads(shortened)["read_path"] == "/staging/x"
        assert elapsed < 10.0, f"took {elapsed:.1f}s"


class TestTheGuardrailUsesIt:
    class _Ledger:
        def __init__(self) -> None:
            self.rows: list[dict[str, Any]] = []

        def record_tool_output(self, **row: Any) -> None:
            self.rows.append(row)

    @staticmethod
    def _client(ledger: Any, limit: int = 4000) -> Any:
        from maljan.agents.mcp_client import MCPLangChainToolkit

        toolkit = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
        toolkit._max_output_chars = limit
        toolkit._output_guardrail = None
        toolkit._truncation_ledger = ledger
        return toolkit

    def test_a_large_json_answer_reaches_the_model_as_a_document(self) -> None:
        ledger = self._Ledger()

        kept = self._client(ledger)._apply_output_guardrail(_strings_answer(300))

        parsed = json.loads(kept)
        assert parsed["truncated"] is True
        assert parsed["read_path"] == "/staging/carved/body_0x364000"
        assert ledger.rows[-1]["shortened"] is True
        assert ledger.rows[-1]["hard_truncated"] is False

    def test_a_large_non_json_answer_is_cut_exactly_as_it_always_was(self) -> None:
        ledger = self._Ledger()
        text = "a decompiled function, in C. " * 500

        kept = self._client(ledger)._apply_output_guardrail(text)

        assert kept == text[:4000] + "\n\n[OUTPUT TRUNCATED]"
        assert ledger.rows[-1]["hard_truncated"] is True
        assert ledger.rows[-1]["shortened"] is False

    def test_an_answer_inside_the_limit_is_still_counted_and_not_touched(self) -> None:
        ledger = self._Ledger()
        answer = _strings_answer(2)

        assert self._client(ledger)._apply_output_guardrail(answer) == answer
        assert ledger.rows[-1]["over_limit"] is False

    def test_the_ghidra_client_does_the_same_thing(self) -> None:
        from maljan.agents.ghidra_http_client import GhidraHTTPClient

        ledger = self._Ledger()
        client = GhidraHTTPClient.__new__(GhidraHTTPClient)
        client._max_output_chars = 4000
        client._output_guardrail = None
        client._truncation_ledger = ledger

        kept = client._apply_output_guardrail(_strings_answer(300))

        assert json.loads(kept)["truncated"] is True
        assert ledger.rows[-1]["shortened"] is True


class TestWhatTheRecordThenHolds:
    """The consequence the whole change exists for, end to end.

    ``ev_0021`` of the recorded run is a ``strings`` call over a carved PE:
    successful, 59 ms, six thousand characters of output and ``structured:
    null``, because the answer was cut mid-array before the recorder saw it.
    Every reader of the record skips an entry with no ``structured``, so that
    call — the one that found the most — put nothing in the report. The rows
    it found are the sample's own content and are not written down here; what
    is reproduced is the answer's shape and its size against the same six
    thousand characters the run used.
    """

    LIMIT = 6000

    def _entry(self) -> Any:
        from maljan.agents.evidence_recorder import EvidenceRecorder
        from maljan.agents.mcp_client import MCPLangChainToolkit

        toolkit = MCPLangChainToolkit.__new__(MCPLangChainToolkit)
        toolkit._max_output_chars = self.LIMIT
        toolkit._output_guardrail = None
        toolkit._truncation_ledger = None

        recorder = EvidenceRecorder("static")
        return recorder.record(
            tool="strings",
            args={"carved_path": "/staging/carved/body_0x364000"},
            server="analysis",
            output=toolkit._apply_output_guardrail(_strings_answer(150)),
        )

    def test_the_entry_now_carries_the_data_and_not_only_prose(self) -> None:
        entry = self._entry()

        assert entry.ok
        assert isinstance(entry.structured, dict)
        assert entry.structured["read_path"] == "/staging/carved/body_0x364000"
        assert entry.structured["truncated"] is True
        assert entry.structured["strings_returned"] == len(entry.structured["strings"])

    def test_the_ledger_report_draws_a_section_from_it(self) -> None:
        from maljan.reporting.ledger_report import build_sections

        sections = build_sections([self._entry()])

        assert [section for section in sections if "string" in section.key.lower()], [
            section.key for section in sections
        ]
