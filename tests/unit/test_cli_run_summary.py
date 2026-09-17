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
