"""The sandbox shape test never takes a tool or a block whose evidence fits another kind better.

A name and a type are what function, section, rule and classification lists
hold, and a digest, a name and a size what every archive or resource listing
holds. Such rows read as DNS questions or dropped files only with evidence of
their own, and a tool's other kind signals (its words, its roles, its answer)
come first. The proposals for the shipped sidecars' tools, the undeclared-server
fixtures and static tool shapes are pinned to what dev proposed
(``tests/fixtures/golden/declaration_proposals_on_dev.json``, captured on dev
before the shape test existed).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from maljan.core.declaration_proposals import propose_tool
from maljan.core.report_proposals import propose_format
from maljan.core.report_shapes import row_shape

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = ROOT / "tests" / "fixtures" / "golden" / "declaration_proposals_on_dev.json"
FIXTURES = ROOT / "tests" / "fixtures" / "sandbox"

_CASES: list[dict[str, Any]] = json.loads(GOLDEN.read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize(
    "case",
    _CASES,
    ids=[f"{c['origin']}:{c['definition']['name']}" for c in _CASES],
)
def test_every_proposal_is_dev_s(case: dict[str, Any]) -> None:
    proposal = propose_tool(case["definition"], answer=case.get("answer"))
    held = None if proposal is None else json.loads(json.dumps(proposal.as_dict()))
    assert held == case["proposal"]


def test_the_golden_holds_the_shipped_sidecars_and_the_static_shapes() -> None:
    origins = {case["origin"] for case in _CASES}
    assert {"analysis sidecar", "knowledge sidecar", "G10b fixture"} <= origins
    named = {case["definition"]["name"] for case in _CASES}
    assert {
        "decompile_function",
        "list_functions",
        "yara_scan",
        "pe_sections",
        "extract_archive",
    } <= named
    # The re-review's listings that only resemble a run's rows.
    assert {
        "dns_lookup",
        "passive_dns",
        "domain_report",
        "whois",
        "list_interfaces",
        "hosts_entries",
        "extract_config",
        "list_created_files",
        "pslist",
        "parse_pcap",
    } <= named


def _tool(name: str, rows: str, keys: list[str], description: str = "") -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "outputSchema": {
            "type": "object",
            "properties": {
                rows: {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {key: {"type": "string"} for key in keys},
                    },
                }
            },
        },
    }


@pytest.mark.parametrize(
    ("name", "keys", "kind"),
    [
        ("decompile_function", ["name", "type", "code"], "decompile"),
        ("list_functions", ["name", "address", "type"], None),
        ("yara_scan", ["name", "type", "techniques", "description"], None),
        ("pe_sections", ["name", "type", "entropy"], None),
        ("extract_archive", ["name", "sha256", "size"], None),
    ],
)
def test_a_static_tool_is_proposed_as_dev_proposed_it(
    name: str, keys: list[str], kind: str | None
) -> None:
    proposal = propose_tool(_tool(name, "items", keys))
    assert proposal is not None
    assert proposal.facts.get("kind") == kind


def test_another_kind_signal_comes_before_the_sandbox_shape() -> None:
    # Rows that would pass the DNS test, from a tool its words name a decompiler.
    proposal = propose_tool(
        _tool("show", "dns", ["request", "type", "answers"], "Decompiles the function.")
    )
    assert proposal is not None
    assert proposal.facts.get("kind") == "decompile"


def test_a_sandbox_tool_s_own_evidence_still_names_its_kind() -> None:
    dns = propose_tool(_tool("run_lookups", "dns", ["name", "type"]), sandbox_source=True)
    assert dns is not None and dns.facts.get("kind") == "sandbox_network"
    dropped = propose_tool(
        _tool("run_dropped", "items", ["name", "sha256", "size"]), sandbox_source=True
    )
    assert dropped is not None and dropped.facts.get("kind") == "sandbox_dropped_files"


def test_only_a_server_declared_a_sandbox_source_is_read_by_the_shape_test() -> None:
    tool = _tool("get_processes", "processes", ["pid", "ppid", "name", "command_line"])
    held = propose_tool(tool, sandbox_source=True)
    assert held is not None and held.facts.get("kind") == "sandbox_processes"
    plain = propose_tool(tool)
    assert plain is not None and plain.facts.get("kind") is None


class TestDnsNeedsDnsEvidence:
    @pytest.mark.parametrize(
        "list_name", ["classification", "functions", "sections", "rules", "items"]
    )
    def test_a_name_and_a_type_are_no_dns_question(self, list_name: str) -> None:
        assert row_shape(list_name, ["name", "type"]) is None

    @pytest.mark.parametrize(
        ("keys", "extra"),
        [
            (["name", "type", "answers"], {}),
            (["qname", "qtype"], {}),
            (["name", "rrtype"], {}),
            (["name", "type"], {"record_types": True}),
        ],
    )
    def test_dns_evidence_of_its_own_reads_as_dns(
        self, keys: list[str], extra: dict[str, Any]
    ) -> None:
        shape = row_shape("items", keys, **extra)
        assert shape is not None
        assert shape.kind == "dns"

    def test_a_dns_named_list_reads_as_dns(self) -> None:
        shape = row_shape("dns_lookups", ["name", "type"])
        assert shape is not None and shape.kind == "dns"

    @pytest.mark.parametrize("list_name", ["files", "resources", "members", "extracted"])
    def test_a_digest_name_and_size_are_no_dropped_file(self, list_name: str) -> None:
        assert row_shape(list_name, ["name", "sha256", "size"]) is None

    def test_a_classification_never_takes_the_dns_mapping_from_a_real_dns_list(self) -> None:
        payload = json.loads((FIXTURES / "unread_flat_report.json").read_text())
        payload["classification"] = [{"name": "Trojan.Generic", "type": "family"}]
        mapping = propose_format(payload)["declaration"]["mapping"]
        assert mapping["dns"] == "$['dns_lookups'][*]"

    def test_record_types_seen_in_an_upload_read_a_name_and_type_list_as_dns(self) -> None:
        payload = {
            "info": {"run": 1},
            "names": [{"name": "a.example", "type": "A"}, {"name": "b.example", "type": "AAAA"}],
            "classes": [{"name": "Trojan.Generic", "type": "family"}],
        }
        mapping = propose_format(payload)["declaration"]["mapping"]
        assert mapping["dns"] == "$['names'][*]"

    @pytest.mark.parametrize(
        ("list_name", "keys"),
        [
            ("config", ["domain", "ips"]),
            ("c2", ["domain", "ips", "port"]),
            ("interfaces", ["name", "addresses", "mtu"]),
            ("interfaces", ["name", "addresses", "dns_servers"]),
            ("entries", ["hostname", "addresses"]),
            ("name_servers", ["hostname", "ips"]),
            ("records", ["hostname", "resolved"]),
        ],
    )
    def test_a_name_with_its_addresses_is_no_dns_question(
        self, list_name: str, keys: list[str]
    ) -> None:
        assert row_shape(list_name, keys) is None

    def test_type_values_that_are_no_record_types_outweigh_a_dns_name(self) -> None:
        assert row_shape("dns_lookups_summary", ["name", "type"], record_types=False) is None
        low = row_shape("dns_lookups_summary", ["name", "type"])
        assert low is not None and low.confidence == "low"


_REAL_DNS: dict[str, Any] = {
    "analysis": {"task_id": 7, "sha256": "a" * 64},
    "network": {
        "dns": [{"request": "real-r1.example", "type": "A", "answers": ["198.51.100.8"]}],
        "flows": [{"dst": "198.51.100.8", "dport": 443, "protocol": "tcp"}],
    },
    "behavior": {"processes": [{"pid": 1, "ppid": 0, "name": "a.exe", "command_line": "a.exe"}]},
}


@pytest.mark.parametrize(
    "decoy",
    [
        {"config": [{"domain": "bad-r1.example", "ips": ["192.0.2.4"]}]},
        {"host": {"interfaces": [{"name": "eth0", "addresses": ["10.0.0.5"]}]}},
        {"a_static": {"imports": [{"name": "x", "type": "A"}, {"name": "y", "type": "A"}]}},
        {"aa": [{"query": "q.example", "type": "A"}]},
    ],
    ids=["config", "interfaces", "imports-typed-A", "weaker-dns-list"],
)
def test_a_decoy_list_never_takes_the_dns_mapping_from_the_real_dns_list(
    decoy: dict[str, Any],
) -> None:
    proposal = propose_format({**_REAL_DNS, **decoy})
    mapping = proposal["declaration"]["mapping"]
    assert mapping["dns"] == "$['network']['dns'][*]"
    assert not any(key.startswith("dns.") for key in mapping.get("field_names", {}))
    assert proposal["fields"]["mapping.dns"]["confidence"] == "high"


def test_a_report_with_no_dns_list_proposes_no_dns_from_a_decoy() -> None:
    report = {k: v for k, v in _REAL_DNS.items() if k != "network"}
    report["extracted"] = {"c2": [{"hostname": "bad-r1.example", "ips": ["192.0.2.4"]}]}
    report["classes"] = [{"name": "dns_query_suspicious", "type": "signature"}]
    assert "dns" not in propose_format(report)["declaration"]["mapping"]


@pytest.mark.parametrize(
    ("name", "argument", "rows", "keys"),
    [
        ("dns_lookup", "domain", "records", ["name", "type", "ttl", "data"]),
        ("passive_dns", "domain", "resolutions", ["hostname", "ip_address", "last_seen"]),
        ("domain_report", "domain", "resolutions", ["hostname", "ips", "date"]),
        ("ip_flows", "ip", "flows", ["dst", "dport"]),
        ("url_report", "url", "dns", ["request", "type", "answers"]),
    ],
)
def test_a_tool_asked_about_a_subject_is_no_run_even_on_a_sandbox_source(
    name: str, argument: str, rows: str, keys: list[str]
) -> None:
    tool = _tool(name, rows, keys)
    tool["inputSchema"] = {
        "type": "object",
        "properties": {argument: {"type": "string"}},
        "required": [argument],
    }
    proposal = propose_tool(tool, sandbox_source=True)
    assert proposal is not None
    assert not str(proposal.facts.get("kind", "")).startswith("sandbox_")
