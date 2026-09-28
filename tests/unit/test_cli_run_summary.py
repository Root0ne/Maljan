"""The terminal summary reads a corroboration row in either shape."""

from __future__ import annotations

import pytest

from maljan.cli import _print_run_summary_inline


def _summary(corroboration: dict) -> dict:
    return {
        "final_decision": "Malware",
        "elapsed_seconds": 1.0,
        "stix_object_count": 3,
        "negotiation": {},
        "agent_stats": [],
        "corroboration": corroboration,
    }


class TestCorroborationInTheTerminal:
    def test_the_current_rows_print_their_sources_not_their_keys(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _print_run_summary_inline(
            _summary(
                {
                    "T1055": {"asserted_by": ["capa"], "claimed_by": ["static", "dynamic"]},
                    "T1071": {"asserted_by": [], "claimed_by": ["static"]},
                }
            )
        )
        out = capsys.readouterr().out
        assert "2 technique(s) | 1 named by more than one source" in out
        assert "T1055          capa, static, dynamic" in out
        assert "T1071          static" in out
        assert "asserted_by" not in out

    def test_a_stored_flat_row_still_prints(self, capsys: pytest.CaptureFixture[str]) -> None:
        _print_run_summary_inline(_summary({"T1055": ["static", "dynamic"]}))
        out = capsys.readouterr().out
        assert "1 technique(s) | 1 named by more than one source" in out
        assert "T1055          static, dynamic" in out


class TestTheLegacySummaryNamesBothBundles:
    def test_the_exported_count_and_the_judge_s_are_both_written(self, tmp_path) -> None:
        from maljan.cli import _write_markdown_report

        summary = {
            **_summary({}),
            "file_hash": "e" * 64,
            "stix_object_count": 77,
            "judge_stix_object_count": 4,
        }
        path = tmp_path / "summary.md"
        _write_markdown_report({"run_summary": summary}, str(path))

        written = path.read_text(encoding="utf-8")
        assert "**STIX objects**: 77 (the judge's bundle: 4)" in written
