"""A report no format recognises reaches the run unread, and reads as a built-in once accepted.

Two invented report shapes (``tests/fixtures/sandbox/unread_nested_report.json``,
one block holding everything several levels down, and
``unread_flat_report.json``, a flat list of top-level blocks) stand for the
exports of sandboxes no reader was written for.

* Accepted unread (``"unread"`` in ``sandbox.upload.allowed_formats``), the
  report reaches the run as raw ``report.<block>`` channels the dynamic
  analyst reads, and no observed fact is drawn from it: no process, no flow,
  no DNS name, every section unavailable.
* The proposal read from its shape, once accepted as written, recognises it
  and reads its processes, flows, DNS questions and dropped files as a
  built-in reader's are read: through the pack's sections and the report's
  dynamic and network blocks to the Markdown report. The REST provider reads
  the same body alike when its ``report.format`` names the accepted format.
* Without the opt-in, an unread row is refused in words.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from maljan.core.config import Settings
from maljan.core.report_proposals import propose_format
from maljan.providers.errors import ProviderError
from maljan.providers.sandbox.upload import UploadSandboxProvider
from maljan.schemas.sandbox_document import sandbox_document

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "sandbox"

# Per fixture: the processes, a flow, the DNS name and its address, a dropped
# file's name, and a raw block the analyst reads unread.
CASES: dict[str, dict[str, Any]] = {
    "unread_nested_report.json": {
        "processes": [(2148, 1012), (2290, 2148)],
        "process_name": "invoice-q3.exe",
        "tcp": ("203.0.113.10", 443),
        "udp": ("198.51.100.7", 53),
        "dns": ("relay-q1.example", "203.0.113.10"),
        "dropped": "helper.dll",
        "kept_channel": "report.analysis_report",
        "raw_block": "report.analysis_report",
    },
    "unread_flat_report.json": {
        "processes": [(1, 0), (2, 1)],
        "process_name": "setup-r2.exe",
        "tcp": ("203.0.113.77", 8080),
        "udp": ("198.51.100.53", 53),
        "dns": ("beacon-r2.example", "203.0.113.77"),
        "dropped": "s.txt",
        "kept_channel": "report.vti",
        "raw_block": "report.process_list",
    },
}


def _blob(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def _payload(name: str) -> dict[str, Any]:
    return json.loads(_blob(name))


def _settings(allowed: list[str], formats: list[dict[str, Any]] | None = None) -> Settings:
    sandbox = {
        "provider": "upload",
        "upload": {"allowed_formats": allowed},
        "report_formats": formats or [],
    }
    return Settings(_env_file=None, sandbox=sandbox)  # type: ignore[call-arg]


def _accepted(name: str) -> dict[str, Any]:
    proposal = propose_format(_payload(name))
    assert "declaration" in proposal, proposal.get("failed")
    # The console sends the accepted declaration as JSON.
    return json.loads(json.dumps(proposal["declaration"]))


def _provider(cfg: Settings, name: str, recorded: str) -> UploadSandboxProvider:
    provider = UploadSandboxProvider.from_settings(cfg)
    provider.set_pending_blob(_blob(name), report_format=recorded)
    return provider


def _pack(document: dict[str, Any], normalised: Any, tmp_path: Path) -> Any:
    from maljan.agents.evidence_recorder import EvidenceRecorder
    from maljan.pipeline.triage_pack import PIPELINE, run_pack
    from maljan.schemas.evidence import EvidenceCounter
    from tests.unit.pipeline.test_triage_pack import _inputs, _write
    from tests.unit.tools.test_binary import _pe

    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    path = _write(tmp_path, "s.exe", _pe())
    return run_pack(
        recorder,
        _inputs(path, "pe", sandbox_report=document, sandbox_normalised_by=normalised),
    )


@pytest.mark.parametrize("name", sorted(CASES))
class TestUnread:
    def test_it_reaches_the_run_as_raw_blocks_and_no_observed_fact(
        self, name: str, tmp_path: Path
    ) -> None:
        from maljan.providers.sandbox_tools import sandbox_channels
        from maljan.reporting.ledger_projection import network_from_sandbox_report

        case = CASES[name]
        run = _provider(_settings(["unread"]), name, "unread").fetch("uploaded")
        assert run.report.source_format == "unread"
        document = sandbox_document(run.report)
        assert case["raw_block"] in document["channels"]
        assert document["behavior"]["processes"] == []
        assert all(document["network"][kind] == [] for kind in ("tcp", "udp", "dns"))
        assert document["dropped"] == []
        assert {"processes", "network", "signatures"} & set(document["unavailable"])
        # The analyst reads the blocks raw; the dynamic analyst's channels hold them.
        listed = json.dumps(
            [sandbox_channels(document, channel) for channel in document["channels"]],
            default=str,
        )
        assert case["dns"][0] in listed
        assert case["process_name"] in listed
        # No fact is drawn: no domain is projected from it.
        projected = network_from_sandbox_report(document)
        assert projected is None or projected.domains == []
        result = _pack(document, ("upload", "unread", ""), tmp_path)
        index = {e.tool: e for e in result.entries}["sandbox_sections"].structured["sections"]
        assert "items" not in index["processes"]
        assert index["channels"]["items"] >= 1

    def test_without_the_opt_in_an_unread_row_is_refused_in_words(self, name: str) -> None:
        with pytest.raises(ProviderError, match="unread"):
            _provider(_settings(["cape2", "cuckoo", "triage"]), name, "unread")


@pytest.mark.parametrize("name", sorted(CASES))
class TestAccepted:
    def _read(self, name: str) -> tuple[Any, dict[str, Any], str]:
        declaration = _accepted(name)
        cfg = _settings([declaration["name"]], [declaration])
        provider = _provider(cfg, name, declaration["name"])
        run = provider.fetch("uploaded")
        return run, sandbox_document(run.report), declaration["name"]

    def test_the_accepted_declaration_reads_it_as_a_built_in_does(self, name: str) -> None:
        from maljan.reporting.ledger_projection import network_from_sandbox_report

        case = CASES[name]
        _run, document, _format = self._read(name)
        processes = document["behavior"]["processes"]
        assert [(p["pid"], p["ppid"]) for p in processes] == case["processes"]
        assert case["process_name"] in processes[0]["process_name"]
        assert [(r["dst"], r["dport"]) for r in document["network"]["tcp"]] == [case["tcp"]]
        assert [(r["dst"], r["dport"]) for r in document["network"]["udp"]] == [case["udp"]]
        domains = network_from_sandbox_report(document).domains
        assert [(d.fqdn, d.resolved_ips) for d in domains] == [(case["dns"][0], [case["dns"][1]])]
        assert case["dropped"] in document["dropped"][0]["name"]
        # What no path reads is still kept for the analyst, raw.
        assert case["kept_channel"] in document["channels"]

    def test_it_reaches_the_pack_the_report_and_the_markdown(
        self, name: str, tmp_path: Path
    ) -> None:
        from maljan.reporting.ledger_projection import dynamic_from_ledger
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        case = CASES[name]
        run, document, fmt = self._read(name)
        result = _pack(document, ("upload", run.report.source_format, ""), tmp_path)
        by_tool = {entry.tool: entry for entry in result.entries}
        index = by_tool["sandbox_sections"].structured["sections"]
        assert index["processes"]["items"] == len(case["processes"])
        assert index["network"]["items"] >= 3
        assert {"sandbox_processes", "sandbox_network"} <= set(by_tool)
        dynamic = dynamic_from_ledger(result.entries)
        assert dynamic is not None
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="c" * 64)), dynamic=dynamic
        )
        assert case["process_name"] in MarkdownRenderer().render(report)

    def test_the_rest_provider_reads_the_body_alike(self, name: str) -> None:
        from maljan.providers.sandbox.rest import RestSandboxProvider

        _run, uploaded, fmt = self._read(name)
        declaration = _accepted(name)
        cfg = _settings([fmt], [declaration])
        cfg.sandbox.provider = "rest"
        cfg.sandbox.rest.base_url = "https://xyz.example/api"
        cfg.sandbox.rest.report.format = fmt
        provider = RestSandboxProvider.from_settings(cfg)
        provider._http = httpx.Client(
            base_url="https://xyz.example/api",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, content=_blob(name))),
        )
        assert provider.capabilities.report_format == "generic"
        fetched = sandbox_document(provider.fetch("T-1").report)
        for key in ("behavior", "network", "dropped", "channels"):
            assert fetched[key] == uploaded[key]


def test_a_format_mapping_its_reader_cannot_read_is_refused_in_words() -> None:
    declaration = {**_accepted("unread_flat_report.json"), "reader": "cape2"}
    cfg = _settings([declaration["name"]], [declaration])
    with pytest.raises(ProviderError, match="reads no mapping"):
        _provider(cfg, "unread_flat_report.json", declaration["name"])
