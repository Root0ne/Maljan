"""One publish rule for every kind the platform mints, and one place a pattern is written.

The rule was applied on the network block's own rows and on the string rows
for domains and URLs — and not on the string rows for addresses, which fell
past every branch to a bare ``return True``. So the network block refused
``6.0.0.0``, a version number out of the strings table, and two sections later
the same address was exported as ``malicious-activity``. The one predicate was
one predicate on three of four paths.

It was also a predicate for the network kinds only, and every other kind the
string sweep produces — an e-mail address, a file name, a registry key, a
mutex — reached the bundle with no question asked at all: a Benign PuTTY run
exported ten SSH algorithm identifiers as ``malicious-activity`` e-mail
indicators, and a PE run exported a third party's address lifted from embedded
library source.

A pattern for any of those kinds is now written in exactly one function and
every minting path asks ``indicator_publish_reason`` before it is. The scan at
the bottom is what keeps that true: a second path that writes its own pattern
fails it.
"""

from __future__ import annotations

import ast
import json
import pathlib
from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.ledger_projection import network_from_ledger, static_from_ledger
from maljan.reporting.models import MalwareReport, StaticAnalysis, StringIOC
from maljan.reporting.renderers.stix_renderer import (
    NETWORK_KINDS,
    STRING_IOC_KINDS,
    ExtendedSTIXRenderer,
    indicator_pattern,
    indicator_publish_reason,
)
from maljan.schemas.evidence import build_entry

SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "maljan"

# The prefixes a STIX pattern this platform mints begins with: the four
# endpoints and every other kind the string sweep types a row as. The sample's
# own hash is deliberately not here — it is minted from the identity block the
# router established, not from a row anybody has to be asked about.
NETWORK_PREFIXES = (
    "[ipv4-addr:value",
    "[ipv6-addr:value",
    "[domain-name:value",
    "[url:value",
    "[email-addr:value",
    "[mutex:name",
    "[windows-registry-key:key",
    "[file:name",
)

# The one function that may write one. Everything else reads a pattern that
# already exists — the cap's banding, the grounding check, the dedupe's
# fingerprint — and a read is a literal with no value in it.
THE_ONE_BUILDER = "indicator_pattern"


def _entry(seq: int, tool: str, payload: dict[str, Any]) -> Any:
    return build_entry(
        entry_id=f"ev_{seq:04d}",
        seq=seq,
        agent="static",
        tool=tool,
        args={},
        server="analysis",
        output=json.dumps(payload),
    )


def _report(ledger: list[Any]) -> MalwareReport:
    report = MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.6,
        judge_assessment=None,
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=ledger,
    ).build_deterministic()
    report.network = network_from_ledger(ledger)
    report.static = static_from_ledger(ledger, {}) or StaticAnalysis()
    return report


def _patterns(bundle: Any) -> list[str]:
    return [
        str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    ]


class TestTheStringScanAsksTheSameRule:
    """The recorded ledger: a strings table with version numbers in it."""

    @staticmethod
    def _ledger() -> list[Any]:
        return [
            _entry(
                1,
                "iocs_from_file",
                {
                    "iocs": [
                        {"kind": "ip", "value": "6.0.0.0"},
                        {"kind": "ip", "value": "1.0.0.1"},
                        {"kind": "ip", "value": "185.99.133.7"},
                        {"kind": "domain", "value": "c2.example.com"},
                    ]
                },
            ),
            _entry(
                2,
                "sandbox_network",
                {
                    "hosts": [{"ip": "185.99.133.7"}, {"ip": "10.0.0.5"}],
                    "dns": [{"request": "c2.example.com"}],
                },
            ),
        ]

    def test_the_network_block_records_every_address_with_its_source(self) -> None:
        network = network_from_ledger(self._ledger())

        assert network is not None
        assert {(ip.address, ip.source) for ip in network.ips} == {
            ("185.99.133.7", "sandbox"),
            ("10.0.0.5", "sandbox"),
            ("6.0.0.0", "strings"),
            ("1.0.0.1", "strings"),
        }

    def test_a_version_number_is_not_exported_by_any_path(self) -> None:
        report = _report(self._ledger())
        assert any(ioc.kind == "ip" for ioc in report.static.interesting_strings), (
            "the string scan puts the addresses in interesting_strings, which is the "
            "path this is about"
        )

        patterns = _patterns(ExtendedSTIXRenderer().render(report))

        assert "[ipv4-addr:value = '6.0.0.0']" not in patterns
        assert "[ipv4-addr:value = '1.0.0.1']" not in patterns

    def test_what_the_sandbox_watched_is(self) -> None:
        report = _report(self._ledger())

        patterns = _patterns(ExtendedSTIXRenderer().render(report))

        assert "[ipv4-addr:value = '185.99.133.7']" in patterns
        assert "[ipv4-addr:value = '10.0.0.5']" in patterns
        assert "[domain-name:value = 'c2.example.com']" in patterns


class TestThePredicateAnswersEveryKind:
    def test_a_string_derived_endpoint_needs_a_second_source(self) -> None:
        for kind, value in (
            ("ip", "185.99.133.7"),
            ("domain", "c2.example.com"),
            ("url", "http://c2.example.com/gate"),
        ):
            assert indicator_publish_reason(kind, value, "strings") is None, kind

    def test_an_observed_endpoint_is_published(self) -> None:
        for kind, value in (
            ("ip", "185.99.133.7"),
            ("domain", "c2.example.com"),
            ("url", "http://c2.example.com/gate"),
        ):
            assert indicator_publish_reason(kind, value, "sandbox") == "sandbox", kind

    def test_a_host_that_could_not_exist_is_refused_whoever_saw_it(self) -> None:
        for kind, value in (
            ("ip", "127.0.0.1"),
            ("domain", "fileserver.corp.internal"),
            ("url", "http://localho"),
        ):
            assert indicator_publish_reason(kind, value, "sandbox") is None, kind

    def test_a_kind_it_does_not_know_publishes_nothing(self) -> None:
        assert indicator_publish_reason("pcap", "capture.pcap", "sandbox") is None
        assert indicator_pattern("pcap", "capture.pcap") is None

    def test_the_pattern_function_answers_every_kind_it_names(self) -> None:
        for kind in NETWORK_KINDS:
            assert indicator_pattern(kind, "8.8.8.8") is not None, kind

    def test_every_string_kind_has_an_answer(self) -> None:
        """A kind with no answer is a kind that falls past the rule."""
        for kind in STRING_IOC_KINDS:
            assert indicator_publish_reason(kind, "whatever", "strings") is None, kind

    def test_an_observed_artefact_of_any_kind_is_published(self) -> None:
        for kind, value in (
            ("email", "operator@example.org"),
            ("mutex", "Global\\Zararli"),
            ("registry", "HKLM\\Software\\Run\\x"),
            ("path", "C:\\Windows\\Temp\\dropper.exe"),
        ):
            assert indicator_publish_reason(kind, value, "sandbox") == "sandbox", kind

    def test_a_string_derived_artefact_needs_a_second_source(self) -> None:
        for kind, value in (
            ("email", "operator@example.org"),
            ("mutex", "Global\\Zararli"),
            ("registry", "HKLM\\Software\\Run\\x"),
            ("path", "C:\\Windows\\Temp\\dropper.exe"),
        ):
            assert indicator_publish_reason(kind, value, "strings") is None, kind
            assert (
                indicator_publish_reason(kind, value, "strings", corroborated_by="the sandbox")
                == "the sandbox"
            ), kind


def _docstrings(tree: ast.AST) -> set[int]:
    """The string constants that are prose rather than a value the code builds."""
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        first = next(iter(node.body), None)
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            found.add(id(first.value))
    return found


class TestOnlyOnePlaceWritesOne:
    """A fifth minting path is a fifth place the rule could be forgotten."""

    @staticmethod
    def _builds() -> list[tuple[str, str, int]]:
        """Every literal in the tree that *builds* a network pattern.

        A build carries a value: the literal has an assignment in it, or a
        substitution. A literal that is only a prefix — ``"[url:value"`` — is
        something reading a pattern somebody else wrote, which is not this
        rule's business. Neither is a docstring: a module that explains what a
        pattern looks like writes one out, and nothing is minted from prose.
        """
        found: list[tuple[str, str, int]] = []
        for path in sorted(SRC.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            functions = {
                node.lineno: node.name
                for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef)
            }
            prose = _docstrings(tree)
            for node in ast.walk(tree):
                if id(node) in prose:
                    continue
                if isinstance(node, ast.JoinedStr):
                    text = "".join(
                        part.value for part in node.values if isinstance(part, ast.Constant)
                    )
                    substitutes = any(isinstance(part, ast.FormattedValue) for part in node.values)
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    text, substitutes = node.value, False
                else:
                    continue
                if not any(prefix in text for prefix in NETWORK_PREFIXES):
                    continue
                if not (substitutes or "= '" in text):
                    continue
                owner = max((line for line in functions if line <= node.lineno), default=0)
                found.append((path.name, functions.get(owner, "<module>"), node.lineno))
        return found

    def test_the_scan_found_the_patterns_it_is_about(self) -> None:
        builds = self._builds()

        assert len(builds) >= len(NETWORK_KINDS), builds

    def test_every_one_of_them_is_in_the_one_builder(self) -> None:
        elsewhere = [row for row in self._builds() if row[1] != THE_ONE_BUILDER]

        assert not elsewhere, (
            "These build a STIX pattern this platform mints outside "
            f"``{THE_ONE_BUILDER}``, which means they did not have to ask "
            "``indicator_publish_reason`` first. Route them through it:\n  "
            + "\n  ".join(f"{name}:{line} in {owner}" for name, owner, line in elsewhere)
        )

    def test_the_scan_catches_a_new_path(self) -> None:
        """It passes trivially if the scan is broken, so prove it is not."""
        source = "def mint(value):\n    return f\"[ipv4-addr:value = '{value}']\"\n"
        tree = ast.parse(source)

        found = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.JoinedStr)
            and any(
                prefix in "".join(p.value for p in node.values if isinstance(p, ast.Constant))
                for prefix in NETWORK_PREFIXES
            )
        ]

        assert len(found) == 1


class TestTheStringRowsOfEveryKind:
    @staticmethod
    def _report_with(*iocs: StringIOC) -> MalwareReport:
        report = _report([])
        report.static = StaticAnalysis(interesting_strings=list(iocs))
        return report

    def test_an_uncorroborated_address_is_not_published(self) -> None:
        report = self._report_with(StringIOC(kind="ip", value="185.99.133.7", notes=""))

        assert not any("addr:value" in p for p in _patterns(ExtendedSTIXRenderer().render(report)))

    def test_an_uncorroborated_domain_is_not_published(self) -> None:
        report = self._report_with(StringIOC(kind="domain", value="c2.example.com", notes=""))

        assert not any("domain-name" in p for p in _patterns(ExtendedSTIXRenderer().render(report)))

    def test_an_uncorroborated_url_is_not_published(self) -> None:
        report = self._report_with(
            StringIOC(kind="url", value="http://c2.example.com/gate", notes="")
        )

        assert not any("url:value" in p for p in _patterns(ExtendedSTIXRenderer().render(report)))
