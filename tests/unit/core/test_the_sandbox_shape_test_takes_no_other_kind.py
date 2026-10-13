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


# The re-review's lists whose question is spelled ``request`` or ``query``
# but that are no DNS questions: an HTTP request log, WMI, LDAP, registry and
# database queries, and an import table whose types read ``A``.
_NO_DNS: dict[str, Any] = {
    "analysis": {"task_id": 7, "sha256": "a" * 64},
    "behavior": {"processes": [{"pid": 1, "ppid": 0, "name": "a.exe", "command_line": "a.exe"}]},
}
_HTTP = {"http": [{"request": "GET /x HTTP/1.1", "host": "a.example", "port": 80, "method": "GET"}]}


def _with(base: dict[str, Any], block: str, extra: dict[str, Any]) -> dict[str, Any]:
    report = json.loads(json.dumps(base))
    report.setdefault(block, {}).update(json.loads(json.dumps(extra)))
    return report


class TestARequestOrQueryKeyIsNoDnsEvidenceAlone:
    @pytest.mark.parametrize(
        ("block", "extra"),
        [
            ("network", _HTTP),
            ("network", {**_HTTP, "domains": [{"domain": "a.example", "ip": "192.0.2.1"}]}),
            ("behavior", {"wmi_queries": [{"query": "SELECT * FROM Win32_Process", "ns": "x"}]}),
            ("behavior", {"ldap": [{"query": "(objectClass=user)", "base": "dc=x"}]}),
            ("behavior", {"registry_queries": [{"query": "HKLM\\Software\\X", "result": "ok"}]}),
            ("db", {"queries": [{"query": "select 1", "duration": 3}]}),
            ("static", {"imports": [{"name": "CreateFileA", "type": "A"}]}),
        ],
        ids=["http", "http-and-domains", "wmi", "ldap", "registry", "sql", "imports-typed-A"],
    )
    def test_no_such_list_takes_the_dns_mapping(self, block: str, extra: dict[str, Any]) -> None:
        proposal = propose_format(_with(_NO_DNS, block, extra))
        assert "mapping.dns" not in proposal["fields"]
        assert "dns" not in proposal["declaration"]["mapping"]

    @pytest.mark.parametrize(
        ("dns", "confidence"),
        [
            ([{"hostname": "a.example", "ip": "192.0.2.1"}], "low"),
            ([{"request": "a.example", "type": "A", "answers": ["192.0.2.1"]}], "high"),
        ],
        ids=["hostname-ip", "request-type-answers"],
    )
    def test_a_real_dns_list_keeps_the_dns_mapping_beside_an_http_log(
        self, dns: list[dict[str, Any]], confidence: str
    ) -> None:
        proposal = propose_format(_with(_NO_DNS, "network", {**_HTTP, "dns": dns}))
        assert proposal["declaration"]["mapping"]["dns"] == "$['network']['dns'][*]"
        assert proposal["fields"]["mapping.dns"]["confidence"] == confidence

    def test_host_name_questions_under_a_generic_key_read_as_dns(self) -> None:
        report = _with(_NO_DNS, "net", {"lookups_x": [{"query": "a.example"}, {"query": "wpad"}]})
        proposal = propose_format(report)
        assert proposal["declaration"]["mapping"]["dns"] == "$['net']['lookups_x'][*]"
        assert proposal["fields"]["mapping.dns"]["confidence"] == "medium"

    def test_a_generic_spelling_with_one_signal_is_never_high(self) -> None:
        one = row_shape("items", ["request"], host_names={"request": True})
        assert one is not None and one.kind == "dns" and one.confidence == "medium"
        typed = row_shape("items", ["request", "type"], record_types=True)
        assert typed is not None and typed.confidence == "medium"
        two = row_shape(
            "items", ["request", "type", "answers"], record_types=True, host_names={"request": True}
        )
        assert two is not None and two.confidence == "high"

    @pytest.mark.parametrize(
        ("keys", "extra"),
        [
            (["request"], {}),
            (["query", "answers", "score"], {}),
            (["query", "duration", "rows"], {}),
            (["request", "host", "port", "method"], {"host_names": {"request": True}}),
            (["query", "namespace"], {"host_names": {"query": False}}),
        ],
    )
    def test_a_generic_spelling_without_a_second_signal_is_no_dns(
        self, keys: list[str], extra: dict[str, Any]
    ) -> None:
        assert row_shape(["queries", "query_log"], keys, **extra) is None

    def test_a_dns_only_key_outweighs_values_that_are_no_host_names(self) -> None:
        shape = row_shape("items", ["qname", "qtype"], host_names={"qname": False})
        assert shape is not None and shape.kind == "dns"


@pytest.mark.parametrize(
    ("name", "rows", "keys", "description"),
    [
        ("query_log", "queries", ["query", "duration", "rows"], ""),
        ("search_kb", "results", ["query", "answers", "score"], ""),
        ("dns_settings", "servers", ["name", "address", "port"], "Configured DNS servers."),
    ],
)
def test_a_sandbox_server_s_query_and_settings_tools_are_no_run_network(
    name: str, rows: str, keys: list[str], description: str
) -> None:
    tool = _tool(name, rows, keys, description)
    tool["inputSchema"] = {"type": "object", "properties": {}}
    proposal = propose_tool(tool, sandbox_source=True)
    assert proposal is not None
    assert not str(proposal.facts.get("kind", "")).startswith("sandbox_")


@pytest.mark.parametrize(
    ("answer", "kind"),
    [
        ({"items": [{"query": "how?", "answers": ["like so"]}]}, None),
        ({"imports": [{"name": "CreateFileA", "type": "A"}]}, None),
        ({"dns": [{"request": "a.example"}, {"request": "b.example"}]}, "sandbox_network"),
        (
            {"rows": [{"query": "a.example", "type": "A"}, {"query": "b.example", "type": "MX"}]},
            "sandbox_network",
        ),
    ],
    ids=["kb-answers", "imports-typed-A", "dns-sparse", "typed-generic"],
)
def test_a_probe_answer_s_values_are_read_by_the_shape_test(
    answer: dict[str, Any], kind: str | None
) -> None:
    tool = {"name": "task_rows", "inputSchema": {"type": "object", "properties": {}}}
    proposal = propose_tool(tool, answer=answer, sandbox_source=True)
    assert proposal is not None
    assert proposal.facts.get("kind") == kind


def test_a_second_list_read_as_the_same_slot_is_named_in_the_notes() -> None:
    report = _with(
        _NO_DNS,
        "network",
        {
            "dns": {
                "udp": [{"request": "a.example", "type": "A", "answers": ["192.0.2.1"]}],
                "tcp": [{"request": "b.example", "type": "A"}],
            }
        },
    )
    proposal = propose_format(report)
    assert proposal["declaration"]["mapping"]["dns"] == "$['network']['dns']['udp'][*]"
    notes = [note for note in proposal.get("notes", []) if note.startswith("mapping.dns")]
    assert len(notes) == 1
    assert "$['network']['dns']['tcp'][*]" in notes[0]


def test_one_list_per_slot_says_nothing() -> None:
    assert "notes" not in propose_format(_REAL_DNS)


class TestAServerWithoutTheSandboxRoleIsToldOfIt:
    _PROCS = _tool("get_processes", "processes", ["pid", "ppid", "name", "command_line"])

    def test_run_shaped_rows_give_the_hint_and_no_kind(self) -> None:
        from maljan.core.declaration_proposals import propose

        out = propose([self._PROCS])
        assert out["tools"]["get_processes"]["facts"].get("kind") is None
        assert len(out["notes"]) == 1
        assert "get_processes" in out["notes"][0]
        assert "roles: [sandbox]" in out["notes"][0]
        # The hint is the server's, never a field of the tool's proposal.
        assert out["notes"][0] not in out["tools"]["get_processes"].get("notes", [])

    def test_a_sandbox_source_gets_the_kind_and_no_hint(self) -> None:
        from maljan.core.declaration_proposals import propose

        out = propose([self._PROCS], sandbox_source=True)
        assert out["tools"]["get_processes"]["facts"]["kind"] == "sandbox_processes"
        assert "notes" not in out

    def test_a_server_whose_rows_read_like_no_run_gets_no_hint(self) -> None:
        from maljan.core.declaration_proposals import propose

        out = propose([_tool("list_functions", "items", ["name", "address", "type"])])
        assert "notes" not in out
