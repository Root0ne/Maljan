"""A live run's ledger, replayed offline through projection, table, export and drafts.

The entries are the shapes one paid run's ``evidence.json`` holds, trimmed, with
neutral values: a Sigma pass over the sandbox's events whose one match names no
technique, a sandbox network view listing a public resolver and one other
address that no process record ties to the sample, FLOSS's decoded strings
holding two C2 URLs, and a judge whose bundle carries those URLs and no domain.
That run published both addresses as indicators and drafted rules over them,
filed the Sigma rule's title as a Run key, and published neither URL's name.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.reporting.builder import MalwareReportBuilder, build_consolidated_iocs
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
from maljan.schemas.evidence import build_entry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle

RESOLVER = "9.9.9.9"
BACKGROUND = "185.199.108.153"
URLS = ("https://relay-alpha-7f3c.top/live/", "https://relay-beta-9d1e.com/live/")
HOSTS = ("relay-alpha-7f3c.top", "relay-beta-9d1e.com")
SIGMA_TITLE = "Utility Executed From An Unusual Drive"
SHA256 = "5" * 64


def _entry(number: int, agent: str, tool: str, payload: Any) -> Any:
    return build_entry(
        entry_id=f"ev_{number:04d}",
        seq=number,
        agent=agent,
        tool=tool,
        args={},
        server="pipeline" if agent == "pipeline" else None,
        output=json.dumps(payload),
        stage="triage_pack" if agent == "pipeline" else "analysis",
    )


def _ledger() -> list[Any]:
    command = f"rundll32.exe C:\\Users\\Admin\\AppData\\Local\\Temp\\{SHA256}.dll,#1"
    return [
        _entry(
            9,
            "pipeline",
            "sigma_match_sandbox",
            {
                "matches": [
                    {
                        "rule": "r-ordinal",
                        "title": "Call By Ordinal Through A Proxy Utility",
                        "level": "medium",
                        "tags": ["attack.stealth", "attack.t1218.011"],
                        "matched_fields": {
                            "Image": "C:\\Windows\\system32\\rundll32.exe",
                            "CommandLine": command,
                        },
                    },
                    {
                        "rule": "r-drive",
                        "title": SIGMA_TITLE,
                        "level": "medium",
                        "tags": ["attack.stealth"],
                        "matched_fields": {"Image": "C:\\Windows\\system32\\rundll32.exe"},
                    },
                ],
                "rule_count": 4000,
                "event_count": 2,
            },
        ),
        _entry(
            12,
            "pipeline",
            "sandbox_processes",
            {
                "processes": [
                    {
                        "pid": 83,
                        "ppid": 56,
                        "name": "C:\\Windows\\system32\\rundll32.exe",
                        "command_line": command,
                        "call_count": 0,
                    }
                ],
                "total": 1,
            },
        ),
        # The view as the run recorded it: no row says which process made the
        # flows, and the resolver is marked as one.
        _entry(
            13,
            "pipeline",
            "sandbox_network",
            {
                "dns": [],
                "hosts": [{"ip": RESOLVER, "public_resolver": True}, {"ip": BACKGROUND}],
                "http": [],
                "tcp": [{"dst": BACKGROUND, "dport": 80}],
                "udp": [{"dst": RESOLVER, "dport": 53, "public_resolver": True}],
            },
        ),
        _entry(
            19,
            "pipeline",
            "floss",
            {
                "strings": [
                    {"kind": "decoded", "string": URLS[0], "function_rva": "0xae78"},
                    {"kind": "decoded", "string": URLS[1], "function_rva": "0xae78"},
                ],
                "counts": {"decoded": 2, "stack": 0, "tight": 0},
                "total": 2,
            },
        ),
    ]


def _judge_bundle() -> dict[str, Any]:
    return {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333220{n}",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
            }
            for n, url in enumerate(URLS)
        ],
    }


def _isrs() -> dict[str, AgentISR]:
    return {
        "network": AgentISR(
            agent_id="network",
            domain="network",
            claims=[
                ClaimEvidence(
                    claim=f"The sample embeds two HTTPS C2 check-in endpoints, {URLS[0]} and "
                    f"{URLS[1]}.",
                    evidence_ref="ev_0019",
                    confidence=0.8,
                )
            ],
        )
    }


@pytest.fixture(scope="module")
def report() -> MalwareReport:
    stix_output = _judge_bundle()
    built = MalwareReportBuilder(
        file_hash=SHA256,
        file_name=f"{SHA256}.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports=_isrs(),
        stix_output=stix_output,
        run_summary={},
        discussion_history=[],
        final_decision="Malware",
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        sample_platform="windows",
        sample_file_type="pe",
        evidence_ledger=_ledger(),
    ).build_deterministic()
    bundle = ExtendedSTIXRenderer().render(built, base_bundle=Bundle.model_validate(stix_output))
    built.stix_bundle_extended = bundle.model_dump(mode="json", exclude_none=True)
    built.consolidated_iocs = build_consolidated_iocs(built)
    return MalwareReportBuilder.attach_detection_signatures(built)


def _row(report: MalwareReport, value: str) -> Any:
    return next(row for row in report.consolidated_iocs if row.value == value)


def _patterns(report: MalwareReport) -> list[str]:
    objects = (report.stix_bundle_extended or {}).get("objects") or []
    return [str(o.get("pattern") or "") for o in objects if o.get("type") == "indicator"]


class TestTheBackgroundAddresses:
    def test_the_table_carries_each_with_the_reason_it_is_not_published(
        self, report: MalwareReport
    ) -> None:
        resolver = _row(report, RESOLVER)
        other = _row(report, BACKGROUND)

        assert str(resolver.published).startswith("no: the sandbox report does not say")
        assert "public DNS resolver" in str(resolver.published)
        assert str(resolver.published).endswith("and no model named it")
        assert "public DNS resolver" in str(resolver.context)
        assert str(other.published).startswith("no:")

    def test_the_export_carries_neither(self, report: MalwareReport) -> None:
        patterns = " ".join(_patterns(report))

        assert RESOLVER not in patterns and BACKGROUND not in patterns

    def test_no_draft_matches_on_either(self, report: MalwareReport) -> None:
        for rule in report.detection_signatures:
            assert RESOLVER not in rule.body, rule.kind
            assert BACKGROUND not in rule.body, rule.kind


class TestTheSigmaTitle:
    def test_it_is_no_persistence_row(self, report: MalwareReport) -> None:
        assert all(SIGMA_TITLE not in mech.target for mech in report.persistence)

    def test_it_is_no_indicator_row(self, report: MalwareReport) -> None:
        assert all(SIGMA_TITLE != row.value for row in report.consolidated_iocs)


class TestThePublishedURLsCarryTheirNames:
    def test_the_urls_are_published(self, report: MalwareReport) -> None:
        for url in URLS:
            assert _row(report, url).published == "yes"

    def test_each_host_is_a_published_domain_row(self, report: MalwareReport) -> None:
        for host in HOSTS:
            row = _row(report, host)
            assert row.kind == "domain"
            assert row.published == "yes"

    def test_the_export_carries_each_host(self, report: MalwareReport) -> None:
        patterns = _patterns(report)

        for host in HOSTS:
            assert f"[domain-name:value = '{host}']" in patterns
