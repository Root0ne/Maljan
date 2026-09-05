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
    # generic_events/screenshots have no RestMappingConfig field at all, so
    # they are always unavailable; apistats is derived from calls, which is
    # unmapped here too, so it joins them.
    assert set(result.report.unavailable) == (set(CHANNELS) - {"processes"}) | {
        "generic_events",
        "screenshots",
        "apistats",
    }


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
    payload = {"r": [f"HKLM\\k{i}" for i in range(MAX_ROWS_PER_CHANNEL + 1)]}
    result = apply_mapping(compiled, payload, provider="rest", task_id="t")
    assert len(result.report.registry) == MAX_ROWS_PER_CHANNEL
    stats = result.stats["registry"]
    assert stats.matched == MAX_ROWS_PER_CHANNEL
    assert stats.truncated is True


def test_a_channel_under_the_cap_is_not_marked_truncated():
    compiled = compile_mapping(RestMappingConfig(registry="$.r[*]"))
    result = apply_mapping(compiled, {"r": ["a", "b"]}, provider="rest", task_id="t")
    assert result.stats["registry"].truncated is False


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


def test_field_names_renames_also_apply_to_the_http_channel():
    """Regression (F12): ``_coerce`` built ``row`` from ``_FIELDS`` (no
    ``http`` entry, so ``{}``) and then overwrote it wholesale with
    ``dict(raw)``, so a configured ``field_names["http.host"]`` never took
    effect and the preview showed the same numbers either way."""
    compiled = compile_mapping(
        RestMappingConfig(http="$.h[*]", field_names={"http.host": "hostname"})
    )
    result = apply_mapping(
        compiled,
        {"h": [{"hostname": "evil.example", "uri": "/beacon"}]},
        provider="rest",
        task_id="t",
    )
    assert result.report.network.http[0]["host"] == "evil.example"
    # Passthrough is preserved: the raw field survives alongside the rename.
    assert result.report.network.http[0]["hostname"] == "evil.example"
    assert result.report.network.http[0]["uri"] == "/beacon"


def test_select_returns_rows_alongside_stats_without_smuggling_them_in():
    """Regression (F15): ``_select`` used to hand back rows through
    ``object.__setattr__(stats, "_rows", kept)`` on a ``frozen=True``
    dataclass -- an undeclared field a stats-only rebuild elsewhere could
    silently drop. It returns ``(stats, rows)`` instead."""
    from maljan.providers.sandbox.rest_mapping import ChannelStats, _select

    compiled = compile_mapping(RestMappingConfig(processes="$.p[*]"))
    stats, rows = _select(compiled, "processes", {"p": [{"pid": 1}, {"pid": 2}]})
    assert isinstance(stats, ChannelStats)
    assert stats.kept == 2
    assert [r["pid"] for r in rows] == [1, 2]
    assert not hasattr(stats, "_rows")


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


def test_target_sha256_normalises_uppercase_hex():
    compiled = compile_mapping(RestMappingConfig(target_sha256="$.h"))
    result = apply_mapping(
        compiled,
        {"h": "B1946AC92492D2347C6235B4D2611184B1946AC92492D2347C6235B4D2611184"},
        provider="rest",
        task_id="t",
    )
    assert (
        result.report.target.sha256
        == "b1946ac92492d2347c6235b4d2611184b1946ac92492d2347c6235b4d2611184"
    )
    assert "target_sha256" not in result.stats


def test_a_prefixed_or_garbage_sha256_is_dropped_with_a_reason():
    compiled = compile_mapping(RestMappingConfig(target_sha256="$.h"))
    result = apply_mapping(compiled, {"h": "0xdeadbeef"}, provider="rest", task_id="t")
    assert result.report.target.sha256 == ""
    stats = result.stats["target_sha256"]
    assert stats.dropped == 1
    assert "0xdeadbeef" in stats.error


def test_a_missing_sha256_leaves_no_stats_entry_at_all():
    compiled = compile_mapping(RestMappingConfig(target_sha256="$.absent"))
    result = apply_mapping(compiled, {}, provider="rest", task_id="t")
    assert result.report.target.sha256 == ""
    assert "target_sha256" not in result.stats


def test_every_consumer_channel_is_populated_or_named_unavailable():
    """The same rule the Triage adapter's own invariant test enforces, over
    the same channel list, so a future edit here cannot reopen the silent
    gap that test guards against for Triage."""
    payload = json.loads((GOLDEN / "xyz_report.json").read_text(encoding="utf-8"))
    compiled = compile_mapping(XYZ_MAPPING)
    result = apply_mapping(compiled, payload, provider="rest", task_id="xyz-1")
    report = result.report
    unavailable = set(report.unavailable)
    channels: list[tuple[str, object]] = [
        ("apistats", report.apistats),
        ("calls", [c for p in report.processes for c in p.calls]),
        ("generic_events", report.generic_events),
        ("registry", report.registry),
        ("screenshots", report.screenshots),
        ("processes", report.processes),
        ("signatures", report.signatures),
        ("dns", report.network.dns),
        ("http", report.network.http),
        ("tcp", report.network.tcp),
        ("udp", report.network.udp),
        ("hosts", report.network.hosts),
        ("domains", report.network.domains),
        ("dropped_files", report.dropped_files),
    ]
    for name, value in channels:
        assert bool(value) or name in unavailable, (
            f"{name!r} is empty and not named in `unavailable`: "
            "a rendered report would read like a clean sample for it"
        )


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
    # The fixture's DNS/TCP rows use routable, non-RFC-reserved values on
    # purpose: a documentation-range IP or a *.example domain is filtered by
    # the real extractor's own suspicion/emittable rules, and a golden built
    # from one would pin `null` and prove nothing about the mapped rows
    # actually surviving into a real IOC table.
    assert expected_network is not None
    assert expected_network["domains"], "the golden must carry at least one real DNS row"
    assert expected_network["ips"], "the golden must carry at least one real TCP/IP row"
