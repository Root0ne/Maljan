"""Any sandbox's JSON, described by JSONPath, becomes a SandboxReport."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import RestMappingConfig
from maljan.extractors.dynamic_extractor import build_dynamic_behavior
from maljan.extractors.network_extractor import build_network_iocs
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.errors import ProviderConfigurationError
from maljan.providers.sandbox.rest_mapping import (
    CHANNELS,
    MAX_ROWS_PER_CHANNEL,
    apply_mapping,
    compile_mapping,
)

GOLDEN = Path(__file__).resolve().parents[2] / "fixtures" / "golden" / "rest_mapping"

XYZ_MAPPING = RestMappingConfig(
    target_sha256="$.sample.hashes.sha256",
    processes="$.run.processes[*]",
    calls="$.run.processes[*].syscalls[*]",
    signatures="$.detections[*]",
    dns="$.net.lookups[*]",
    tcp="$.net.streams[*]",
    dropped_files="$.artifacts[*]",
    registry="$.run.registry[*]",
    field_names={
        "processes.command_line": "cmdline",
        "processes.name": "image",
        "calls.api": "syscall",
        "signatures.severity": "score",
        "signatures.ttps": "attack",
        "dns.request": "qname",
        "tcp.dst": "peer",
        "tcp.dport": "peer_port",
        "dropped_files.name": "filename",
    },
)


def test_a_bad_path_names_the_channel_it_came_from():
    with pytest.raises(ProviderConfigurationError) as exc:
        compile_mapping(RestMappingConfig(processes="$[["))
    assert "processes" in str(exc.value)


def test_an_unmapped_channel_is_reported_as_unavailable():
    compiled = compile_mapping(RestMappingConfig(processes="$.p[*]"))
    result = apply_mapping(compiled, {"p": [{"pid": 1}]}, provider="rest", task_id="t")
    assert "processes" not in result.report.unavailable
    assert set(result.report.unavailable) == set(CHANNELS) - {"processes"}


def test_rows_missing_a_required_field_are_dropped_and_counted():
    compiled = compile_mapping(RestMappingConfig(processes="$.p[*]"))
    result = apply_mapping(
        compiled, {"p": [{"pid": 4}, {"nope": 1}, "not a row"]}, provider="rest", task_id="t"
    )
    stats = result.stats["processes"]
    assert (stats.matched, stats.kept, stats.dropped) == (3, 1, 2)
    assert [p.pid for p in result.report.processes] == [4]


def test_a_channel_is_capped_and_the_cap_is_visible_in_the_stats():
    compiled = compile_mapping(RestMappingConfig(registry="$.r[*]"))
    payload = {"r": [f"HKLM\\k{i}" for i in range(MAX_ROWS_PER_CHANNEL + 10)]}
    result = apply_mapping(compiled, payload, provider="rest", task_id="t")
    assert len(result.report.registry) == MAX_ROWS_PER_CHANNEL
    assert result.stats["registry"].matched == MAX_ROWS_PER_CHANNEL + 10


def test_field_names_rename_per_channel_without_touching_the_others():
    compiled = compile_mapping(
        RestMappingConfig(processes="$.p[*]", field_names={"processes.command_line": "cmdline"})
    )
    result = apply_mapping(
        compiled,
        {"p": [{"pid": 1, "cmdline": "x.exe /q", "command_line": "ignored"}]},
        provider="rest",
        task_id="t",
    )
    assert result.report.processes[0].command_line == "x.exe /q"


def test_the_stats_carry_at_most_three_sample_rows():
    compiled = compile_mapping(RestMappingConfig(registry="$.r[*]"))
    result = apply_mapping(compiled, {"r": ["a", "b", "c", "d"]}, provider="rest", task_id="t")
    assert result.stats["registry"].sample_rows == ["a", "b", "c"]


def test_calls_are_attached_to_their_process_and_counted_into_apistats():
    compiled = compile_mapping(RestMappingConfig(processes="$.p[*]", calls="$.p[*].c[*]"))
    payload = {
        "p": [
            {"pid": 7, "c": [{"pid": 7, "api": "WriteProcessMemory"}, {"pid": 7, "api": "Sleep"}]},
            {"pid": 8, "c": [{"pid": 9, "api": "Orphan"}]},
        ]
    }
    result = apply_mapping(compiled, payload, provider="rest", task_id="t")
    assert [c["api"] for c in result.report.processes[0].calls] == [
        "WriteProcessMemory",
        "Sleep",
    ]
    assert result.report.apistats["7"] == {"WriteProcessMemory": 1, "Sleep": 1}
    assert result.stats["calls"].dropped == 1, "a call for a process nobody declared is dropped"


def test_the_xyz_golden_maps_exactly_as_recorded():
    """A synthetic sandbox nobody has ever integrated, mapped from settings alone."""
    payload = json.loads((GOLDEN / "xyz_report.json").read_text(encoding="utf-8"))
    expected = json.loads((GOLDEN / "xyz_mapped.json").read_text(encoding="utf-8"))
    compiled = compile_mapping(XYZ_MAPPING)
    result = apply_mapping(compiled, payload, provider="rest", task_id="xyz-1")
    assert result.report.model_dump(mode="json") == expected


def _dump(model):
    return None if model is None else model.model_dump(mode="json")


def test_the_xyz_golden_renders_through_the_existing_consumers():
    """The mapped report is not just a shape; the downstream extractors read it."""
    payload = json.loads((GOLDEN / "xyz_report.json").read_text(encoding="utf-8"))
    compiled = compile_mapping(XYZ_MAPPING)
    result = apply_mapping(compiled, payload, provider="rest", task_id="xyz-1")
    cape_shaped = to_cape_shaped_dict(result.report)

    expected_dynamic = json.loads(
        (GOLDEN / "xyz_dynamic_behavior.json").read_text(encoding="utf-8")
    )
    expected_network = json.loads((GOLDEN / "xyz_network_iocs.json").read_text(encoding="utf-8"))
    assert _dump(build_dynamic_behavior(cape_shaped)) == expected_dynamic
    assert _dump(build_network_iocs(cape_shaped)) == expected_network
