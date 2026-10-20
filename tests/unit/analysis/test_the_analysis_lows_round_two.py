"""AUD-46 review round: counts read with their tool, decimal sizes, not-built blocks.

Every value is synthetic. The statements have the shape of four citations a
stored run placed on a count its answer states.
"""

from __future__ import annotations

from typing import Any

from maljan.analysis.evidence_roots import answer_facts, statement_values


def _places(structured: dict[str, Any], tool: str, statement: str) -> bool:
    facts = answer_facts(structured, tool)
    return facts.written_in(statement_values(statement), None)  # type: ignore[arg-type]


def test_a_l4_a_generic_count_key_is_read_with_the_tool_that_counted() -> None:
    assert _places({"total": 218, "strings": []}, "strings", "The file holds 218 strings.")
    assert _places(
        {"total": 9, "dropped": [{"name": "a"}]},
        "sandbox_dropped_files",
        "The sandbox recorded 9 dropped files.",
    )
    assert _places(
        {"total": 101, "results": [{"text": "a"}]},
        "decode_string_blobs",
        "Recovered 101 strings from the blobs.",
    )
    assert _places(
        {"total": 101, "results": [{"text": "a"}]},
        "decode_string_blobs",
        "decode_string_blobs found 101 candidate texts.",
    )
    assert not _places({"total": 218}, "strings", "It loads 218 modules.")


def test_a_l4_a_generic_count_key_is_read_with_the_list_of_that_length() -> None:
    structured = {"count": 2, "findings": [{"a": 1}, {"a": 2}]}
    assert _places(structured, "scan_tool", "There are 2 findings.")
    assert not _places(structured, "scan_tool", "There are 2 modules.")


def test_a_l4_short_field_words_and_joined_words_match() -> None:
    assert _places({"url_count": 4}, "t", "It contacts 4 URLs.")
    assert _places({"dll_total": 4}, "t", "It imports 4 DLLs.")
    assert _places({"decoded_strings": 3}, "t", "It_writes-3 strings.")
    assert not _places({"decoded_strings": 3}, "t", "It loads 3 modules.")


def test_a_l3_a_decimal_string_is_decimal_and_hex_needs_its_prefix() -> None:
    from maljan.analysis.evidence_roots import _measure

    assert _measure("4096") == 4096
    assert _measure("0x1000") == 4096
    assert _measure("1000") == 1000
    assert _measure("ff") is None
    assert _measure(True) is None


def test_a_l1_the_cli_fallback_does_not_recreate_a_zero_confidence(tmp_path: Any) -> None:
    from maljan.cli import _write_markdown_report

    summary = {
        "final_decision": "Malware",
        "elapsed_seconds": 1.0,
        "stix_object_count": 1,
        "negotiation": {"termination_reason": "unknown"},
        "agent_stats": [],
    }
    out = tmp_path / "r.md"

    _write_markdown_report({"run_summary": summary}, str(out))

    assert "Final confidence" not in out.read_text(encoding="utf-8")


def test_a_l1_the_inline_summary_says_not_recorded(capsys: Any) -> None:
    from maljan.cli import _print_run_summary_inline

    _print_run_summary_inline(
        {
            "final_decision": "Malware",
            "elapsed_seconds": 1.0,
            "stix_object_count": 1,
            "negotiation": {"termination_reason": "unknown"},
            "agent_stats": [],
        }
    )

    assert "Final confidence: not recorded" in capsys.readouterr().out


def test_a_l2_the_report_names_a_block_that_was_not_built() -> None:
    from maljan.analysis.disclosure import NOT_BUILT_UNREAD, not_built, not_built_line

    line = not_built_line("coverage", not_built(NOT_BUILT_UNREAD))
    assert line == f"The coverage block was not built: {NOT_BUILT_UNREAD}."
    assert not_built_line("coverage", {"v": 1}) == ""
    assert not_built_line("coverage", None) == ""


def test_a_l2_a_stopped_run_retries_a_block_that_was_not_built() -> None:
    from maljan.analysis.disclosure import NOT_BUILT_UNREAD, not_built
    from maljan.pipeline.stopped_run import _is_built

    assert _is_built({"v": 1}) is True
    assert _is_built(not_built(NOT_BUILT_UNREAD)) is False
    assert _is_built(None) is False
