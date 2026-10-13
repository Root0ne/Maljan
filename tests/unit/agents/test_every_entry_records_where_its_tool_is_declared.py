"""Every ledger entry records where its tool's declaration lives, when it is written.

The read API resolves an entry by its recorded source alone
(``core.tool_declarations``), so the source is written where it is known: a
registry server's tool by its key, a provider's or the sandbox report's tool by
what it was stamped with when it was attached, the triage pack by its own
source and the evidence-only provider by its own. An entry written before
sources were recorded dumps exactly as it did.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from langchain_core.tools import StructuredTool

from maljan.agents.delegation import TEAM_SERVER
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.prompt_fragments import (
    DECLARED_SOURCE_METADATA_KEY,
    PROVIDER_FAMILY,
    stamp_source,
)
from maljan.agents.tool_pinning import SERVER_METADATA_KEY, declared_source_of
from maljan.providers.base import StaticEvidenceBundle
from maljan.providers.static.capa_yara import ledger_entries
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry, build_entry


def _tool(name: str = "decompile_function", metadata: dict[str, Any] | None = None) -> Any:
    return StructuredTool.from_function(
        func=lambda address="": "ok", name=name, description="d", metadata=metadata or {}
    )


def test_a_registry_tool_records_its_servers_source() -> None:
    assert declared_source_of(_tool(metadata={SERVER_METADATA_KEY: "analysis"})) == "mcp:analysis"


def test_a_team_ask_tool_and_an_unstamped_tool_record_none() -> None:
    assert declared_source_of(_tool(metadata={SERVER_METADATA_KEY: TEAM_SERVER})) is None
    assert declared_source_of(_tool()) is None


def test_a_providers_tool_records_the_source_it_was_stamped_with() -> None:
    (stamped,) = stamp_source([_tool()], PROVIDER_FAMILY, declared="provider:ghidra")
    assert stamped.metadata[DECLARED_SOURCE_METADATA_KEY] == "provider:ghidra"
    assert declared_source_of(stamped) == "provider:ghidra"
    (plain,) = stamp_source([_tool()], PROVIDER_FAMILY)
    assert declared_source_of(plain) is None


def test_the_recorder_writes_the_source_it_is_given() -> None:
    recorder = EvidenceRecorder("static", counter=EvidenceCounter())
    entry = recorder.record(
        tool="load_program", args={}, server=None, output="ok", source="provider:ghidra"
    )
    assert entry.source == "provider:ghidra"
    assert entry.model_dump()["source"] == "provider:ghidra"


def test_a_recorded_tool_call_writes_the_tools_source() -> None:
    from maljan.agents.evidence_recorder import record_tools

    recorder = EvidenceRecorder("static", counter=EvidenceCounter())
    (stamped,) = stamp_source([_tool()], PROVIDER_FAMILY, declared="provider:r2")
    registry = _tool("strings", metadata={SERVER_METADATA_KEY: "analysis"})
    for tool in record_tools([stamped, registry], recorder):
        tool.invoke({"address": "0x1"})
    assert [(e.tool, e.source) for e in recorder.entries] == [
        ("decompile_function", "provider:r2"),
        ("strings", "mcp:analysis"),
    ]


def test_an_entry_with_no_source_dumps_as_it_always_did() -> None:
    entry = build_entry(
        entry_id="ev_0001", seq=1, agent="a", tool="t", args={}, server=None, output=""
    )
    assert "source" not in entry.model_dump()
    assert "source" not in entry.model_dump(mode="json")
    assert LedgerEntry.model_validate(entry.model_dump()).source is None


def test_the_ledger_entrys_schema_names_the_source() -> None:
    for mode in ("validation", "serialization"):
        schema = LedgerEntry.model_json_schema(mode=mode)  # type: ignore[arg-type]
        assert "source" in schema["properties"]
        assert "tool" in schema["properties"]


def test_the_evidence_providers_entries_record_its_source() -> None:
    bundle = StaticEvidenceBundle(
        capa_rules=[{"rule": "r", "addresses": []}], yara_matches=[{"rule": "y"}]
    )
    entries = ledger_entries(bundle, EvidenceCounter())
    assert entries and all(e.source == "provider:capa_yara" for e in entries)


def test_the_probe_only_sandbox_entry_records_the_sandbox_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maljan.reporting import ledger_projection

    seen: list[Any] = []
    monkeypatch.setattr(
        ledger_projection, "network_from_ledger", lambda entries: seen.extend(entries)
    )
    ledger_projection.network_from_sandbox_report({"network": {"dns": []}})
    assert [(e.tool, e.source) for e in seen] == [("sandbox_network", "sandbox")]


def test_every_triage_pack_entry_records_the_packs_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maljan.pipeline.triage_pack import PIPELINE, run_pack
    from maljan.tools import rules
    from tests.unit.pipeline.test_triage_pack import _inputs, _write
    from tests.unit.tools.test_binary import _pe

    monkeypatch.setattr(
        rules, "capa", lambda path, **_: {"capabilities": [], "meta": {"backend": "fake"}}
    )
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    result = run_pack(recorder, _inputs(_write(tmp_path, "s.exe", _pe()), "pe"))
    assert result.entries
    assert {entry.source for entry in result.entries} == {"pack"}
