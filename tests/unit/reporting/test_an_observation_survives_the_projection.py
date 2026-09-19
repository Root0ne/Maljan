"""What somebody watched reaches the report, whatever the export does with it.

A name a private network gives its own machines is not published — that is an
export decision and a right one. It was made at the projection instead, so a
sandbox-observed ``fileserver.corp.internal`` never reached
``report.network.domains`` at all: erased from the report as well as from the
bundle, with nothing recorded, while the URL carrying the same host survived
the projection and was refused at the export with a row beside it. A DNS
resolution with no request behind it left nothing anywhere, and an analyst
reading a lateral-movement case could not see which internal host the sample
resolved.

The projection keeps what somebody observed. The export refuses it and says so.
A name only the string sweep produced is unchanged: a run of bytes that happens
to end in ``.local`` is not an observation of anything, and it is held back
without a row.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.ledger_projection import network_from_ledger
from maljan.reporting.models import MalwareReport, NetworkIOCs
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_ENDPOINT_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.evidence import build_entry

INTERNAL = "fileserver.corp.internal"
REAL = "c2.evil.example.com"


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


def _sandbox_ledger() -> list[Any]:
    return [
        _entry(
            1,
            "sandbox_network",
            {
                "dns": [{"request": INTERNAL}, {"request": REAL}],
                "http": [{"host": INTERNAL, "uri": "/share"}],
                "hosts": [{"ip": "10.0.0.5"}],
            },
        )
    ]


def _report(network: NetworkIOCs | None) -> MalwareReport:
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
        evidence_ledger=[],
    ).build_deterministic()
    report.network = network
    return report


def _patterns(bundle: Any) -> list[str]:
    return [
        str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    ]


class TestTheProjectionKeepsWhatSomebodyWatched:
    def test_a_private_use_name_the_sandbox_resolved_is_in_the_report(self) -> None:
        network = network_from_ledger(_sandbox_ledger())

        assert network is not None
        assert {(d.fqdn, d.source) for d in network.domains} == {
            (INTERNAL, "sandbox"),
            (REAL, "sandbox"),
        }

    def test_a_reserved_name_the_sandbox_resolved_is_too(self) -> None:
        for name in ("printer.local", "wpad.test", "host.invalid"):
            network = network_from_ledger(
                [_entry(1, "sandbox_network", {"dns": [{"request": name}]})]
            )
            assert network is not None, name
            assert [d.fqdn for d in network.domains] == [name], name

    def test_an_analyst_artefact_is_kept_the_same_way(self) -> None:
        from maljan.schemas.isr_models import AgentISR, Artifact

        isr = AgentISR(
            agent_id="network",
            domain="network",
            artifacts=[
                Artifact(
                    kind="endpoints",
                    columns=["kind", "value"],
                    rows=[["domain", INTERNAL]],
                )
            ],
        )

        network = network_from_ledger([], {"network": isr})

        assert network is not None
        assert [(d.fqdn, d.source) for d in network.domains] == [(INTERNAL, "analyst")]

    def test_a_name_only_the_string_sweep_produced_is_unchanged(self) -> None:
        """A run of bytes ending in ``.local`` is not an observation of anything."""
        network = network_from_ledger(
            [
                _entry(
                    1,
                    "iocs_from_file",
                    {"iocs": [{"kind": "domain", "value": "printer.local"}]},
                )
            ]
        )

        assert network is None


class TestTheExportRefusesItAndSaysSo:
    def test_the_name_is_not_in_the_bundle(self) -> None:
        report = _report(network_from_ledger(_sandbox_ledger()))

        patterns = _patterns(ExtendedSTIXRenderer().render(report))

        assert f"[domain-name:value = '{INTERNAL}']" not in patterns
        assert f"[domain-name:value = '{REAL}']" in patterns

    def test_the_decline_is_recorded_with_a_true_reason(self) -> None:
        renderer = ExtendedSTIXRenderer()

        renderer.render(_report(network_from_ledger(_sandbox_ledger())))

        rows = dict(renderer.declined)
        assert UNPUBLISHABLE_ENDPOINT_CODE in rows
        assert INTERNAL in rows[UNPUBLISHABLE_ENDPOINT_CODE]
        assert "does not resolve outside the analysed network" in rows[UNPUBLISHABLE_ENDPOINT_CODE]

    def test_the_url_on_the_same_host_is_recorded_as_it_was(self) -> None:
        renderer = ExtendedSTIXRenderer()

        renderer.render(_report(network_from_ledger(_sandbox_ledger())))

        assert UNPUBLISHABLE_ENDPOINT_CODE in dict(renderer.declined)

    def test_a_string_derived_name_is_held_back_without_a_row(self) -> None:
        from maljan.reporting.models import NetworkDomain

        renderer = ExtendedSTIXRenderer()

        renderer.render(
            _report(NetworkIOCs(domains=[NetworkDomain(fqdn=INTERNAL, source="strings")]))
        )

        assert renderer.declined == []
