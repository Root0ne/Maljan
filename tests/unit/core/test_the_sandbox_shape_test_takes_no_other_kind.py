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
    dns = propose_tool(_tool("run_lookups", "dns", ["name", "type"]))
    assert dns is not None and dns.facts.get("kind") == "sandbox_network"
    dropped = propose_tool(_tool("run_dropped", "items", ["name", "sha256", "size"]))
    assert dropped is not None and dropped.facts.get("kind") == "sandbox_dropped_files"


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
