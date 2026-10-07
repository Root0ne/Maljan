"""What the report's value checks print is defanged and escaped, and fails closed.

The marks after a kept sentence, the IOC table's state beside a table cell and
the messages of the stated-value and unpublished-value findings all carry
values from the sample and the IOC table's own words about them. Each is
written the way the report writes a network value — defanged — with
Markdown's own characters escaped, so a value can open no link, tag, code
span or table cell. A state that cannot be read is said to be unknown; the
raw value is never printed in its place.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import patch

import pytest

from maljan.pipeline.validation import record_flagged_statements, unpublished_value_violations
from maljan.reporting.models import (
    C2Channel,
    ConfigItem,
    ConsolidatedIOC,
    FileHashes,
    HostIdentifier,
    MalwareReport,
    SampleIdentity,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.markdown import STATE_UNKNOWN, TABLE_NOT_READ, MarkdownRenderer

ADDRESS = "198.51.100.7"
HOST = "relay.example.net"
# A refusal whose words carry a link, a tag, a code span, a cell break, a URL,
# a mailbox, an address and a host.
HOSTILE = (
    "no: see [x](http://evil.example.com/a) <script>`x`|y for op@mail.example.org "
    "at 203.0.113.5 and evil.example.com"
)


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        consolidated_iocs=[
            ConsolidatedIOC(
                type="IPv4", kind="ip", value=ADDRESS, source="sandbox", published=HOSTILE
            ),
            ConsolidatedIOC(
                type="Domain", kind="domain", value=HOST, source="sandbox", published=HOSTILE
            ),
        ],
        **over,
    )


def _clean(line: str) -> None:
    """No live network value and no Markdown the sample's text could open."""
    import re

    for live in ("http://", "evil.example.com", "op@mail", "203.0.113.5"):
        assert live not in line, (live, line)
    for opener in (r"\]\(", r"<script", r"`x"):
        assert not re.search(r"(?<!\\)" + opener, line), (opener, line)


class TestTheMarkAfterAKeptSentence:
    def test_the_label_is_defanged_and_escaped(self) -> None:
        sentence = f"It uses {ADDRESS} as C2."
        report = _report(
            technical_analysis=TechnicalAnalysis(
                command_and_control=TechnicalSubsection(title="Command and control", body=sentence)
            )
        )
        record_flagged_statements(
            report,
            unpublished_value_violations({"body": sentence}, lambda kind, value: HOSTILE),
        )

        text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if "not published by this run" in line)
        _clean(line.split("**[", 1)[1])
        assert "198[.]51[.]100[.]7" in line and "evil[.]example[.]com" in line


class TestTheStateBesideACell:
    def test_every_cell_s_state_is_defanged_escaped_and_keeps_the_table_whole(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[ConfigItem(key="Fallback", value=ADDRESS, how_obtained="decrypted")],
                host_identifiers=[HostIdentifier(kind="Address", value=ADDRESS)],
            ),
            c2_channels=[C2Channel(name="relay", endpoints=[HOST])],
        )

        # The table a cell's state reads is the one the report prints, rebuilt
        # by the publish rule, whose answers carry no such words: it is read
        # here as the hostile rows above, to see what a hostile answer becomes.
        with patch(
            "maljan.reporting.builder.build_consolidated_iocs",
            lambda built: list(built.consolidated_iocs),
        ):
            text = MarkdownRenderer().render(report)

        for start, cells in (("| Fallback", 4), ("| Address", 4), ("| relay", 6)):
            line = next(line for line in text.splitlines() if line.startswith(start))
            state = line.split("(no:", 1)[1]
            _clean(state)
            assert "evil[.]example[.]com" in state, line
            assert line.replace("\\|", "").count("|") == cells + 1, line

    def test_a_table_that_cannot_be_read_refuses_every_value(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[ConfigItem(key="Fallback", value=ADDRESS, how_obtained="decrypted")]
            )
        )
        with patch(
            "maljan.reporting.narrative_agent.published_answers",
            side_effect=RuntimeError("unreadable"),
        ):
            text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if line.startswith("| Fallback"))
        assert f"({TABLE_NOT_READ})" in line

    def test_a_failed_rebuild_is_logged_once_and_the_stored_state_is_printed(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[ConfigItem(key="Fallback", value=ADDRESS, how_obtained="decrypted")]
            )
        )
        with (
            caplog.at_level(logging.ERROR, logger="maljan"),
            patch(
                "maljan.reporting.builder.build_consolidated_iocs",
                side_effect=RuntimeError("unrebuildable"),
            ),
        ):
            text = MarkdownRenderer().render(report)

        assert len([r for r in caplog.records if r.exc_info]) == 1
        line = next(line for line in text.splitlines() if line.startswith("| Fallback"))
        assert "evil[.]example[.]com" in line

    def test_a_failed_rebuild_with_no_stored_row_refuses_every_cell_and_logs_once(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[ConfigItem(key="Fallback", value=ADDRESS, how_obtained="decrypted")]
            )
        )
        report.consolidated_iocs = []
        with (
            caplog.at_level(logging.ERROR, logger="maljan"),
            patch(
                "maljan.reporting.builder.build_consolidated_iocs",
                side_effect=RuntimeError("unrebuildable"),
            ),
        ):
            text = MarkdownRenderer().render(report)

        assert len([r for r in caplog.records if r.exc_info]) == 1
        line = next(line for line in text.splitlines() if line.startswith("| Fallback"))
        assert f"({TABLE_NOT_READ})" in line

    def test_a_lookup_that_fails_says_the_state_is_unknown(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[ConfigItem(key="Fallback", value=ADDRESS, how_obtained="decrypted")]
            )
        )
        with patch(
            "maljan.pipeline.validation._unstated_values", side_effect=RuntimeError("broken")
        ):
            text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if line.startswith("| Fallback"))
        assert f"({STATE_UNKNOWN})" in line

    def test_a_failed_lookup_leaves_a_cell_with_no_network_value_alone(self) -> None:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                configuration=[
                    ConfigItem(key="Mutex", value="Global\\M1", how_obtained="decrypted")
                ]
            )
        )
        with patch(
            "maljan.pipeline.validation._unstated_values", side_effect=RuntimeError("broken")
        ):
            text = MarkdownRenderer().render(report)

        line = next(line for line in text.splitlines() if line.startswith("| Mutex"))
        assert STATE_UNKNOWN not in line


class TestTheIdentifierCell:
    @staticmethod
    def _line(value: str) -> str:
        report = _report(
            technical_analysis=TechnicalAnalysis(
                host_identifiers=[HostIdentifier(kind="Domain", value=value)]
            )
        )
        text = MarkdownRenderer().render(report)
        return next(line for line in text.splitlines() if line.startswith("| Domain"))

    def test_a_host_shaped_value_is_defanged(self) -> None:
        line = self._line("c2.badsite.net")

        assert "c2[.]badsite[.]net" in line and "c2.badsite.net" not in line

    def test_a_backtick_in_the_value_cannot_close_the_code_span(self) -> None:
        line = self._line("pre` [y](http://inj.example/a) `post")

        # The fence is longer than any backtick run in the value, so the span
        # holds the whole value and no link is live.
        cell = line.split(" | ")[1]
        assert cell.startswith("`` ") and cell.endswith(" ``"), cell
        assert "http://" not in line and "hxxp://inj[.]example/a" in line


class TestTheFindingMessages:
    def test_both_value_findings_print_defanged_and_escaped_in_the_notes(self) -> None:
        rows = [
            {
                "agent": "composer:x",
                "code": code,
                "message": f"the text names {ADDRESS} ({HOSTILE})",
            }
            for code in ("report.unpublished_value", "report.value_not_in_cited_entry")
        ]
        report = _report(run_summary={"validation": {"retries": 1, "unresolved": rows}})

        text = MarkdownRenderer().render(report)

        lines = [line for line in text.splitlines() if "the text names" in line]
        assert len(lines) == 2
        for line in lines:
            _clean(line)
            assert "198[.]51[.]100[.]7" in line

    def test_a_finding_of_another_code_is_defanged_and_otherwise_as_written(self) -> None:
        message = "'evil.example.com' is not in ev_0001, which the text cites for it"
        rows = [{"agent": "composer:x", "code": "report.citation_wrong_entry", "message": message}]
        report = _report(run_summary={"validation": {"retries": 1, "unresolved": rows}})
        text = MarkdownRenderer().render(report)

        assert "'evil[.]example[.]com' is not in ev_0001, which the text cites for it" in text
        assert "evil.example.com" not in text
