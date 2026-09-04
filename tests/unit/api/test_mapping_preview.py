"""The one place a mapping's errors are shown before a job is submitted."""

from __future__ import annotations

from app.services.mapping_preview import PREVIEW_MAX_BYTES, preview_mapping


def test_a_channel_reports_matched_kept_and_dropped():
    out = preview_mapping({"p": [{"pid": 1}, {"nope": 2}]}, {"processes": "$.p[*]"})
    assert out["channels"]["processes"]["matched"] == 2
    assert out["channels"]["processes"]["kept"] == 1
    assert out["channels"]["processes"]["dropped"] == 1
    assert len(out["channels"]["processes"]["sample_rows"]) == 1


def test_the_target_hash_is_shown_as_a_value_not_a_row():
    out = preview_mapping({"t": {"h": "abc"}}, {"target_sha256": "$.t.h"})
    assert out["target_sha256"] == "abc"


def test_a_bad_path_reports_on_its_own_channel_and_leaves_the_others_alone():
    out = preview_mapping({"p": [{"pid": 1}]}, {"processes": "$.p[*]", "dns": "$[["})
    assert out["channels"]["dns"]["error"]
    assert "dns" in out["channels"]["dns"]["error"]
    assert out["channels"]["processes"]["kept"] == 1


def test_an_unmapped_channel_is_reported_as_zero_rather_than_missing():
    out = preview_mapping({}, {})
    assert out["channels"]["http"] == {
        "matched": 0,
        "kept": 0,
        "dropped": 0,
        "truncated": False,
        "sample_rows": [],
        "error": None,
    }


def test_the_cap_is_four_mebibytes():
    assert PREVIEW_MAX_BYTES == 4 * 1024 * 1024


def test_the_rest_probe_is_registered_and_reads_the_rest_settings():
    from app.services.settings_probes import _INPUTS, PROBES

    assert "rest" in PROBES
    assert "core.sandbox.rest.base_url" in _INPUTS["rest"]
    assert "core.sandbox.rest.auth.token" in _INPUTS["rest"]


def test_a_good_mapping_over_the_xyz_fixture_matches_task_10s_golden():
    """The preview and the real mapping run the same compiler, so their
    counts agree on the fixture Task 10 already pinned exactly."""
    import json as _json
    from pathlib import Path

    from maljan.core.config import RestMappingConfig
    from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping

    golden = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "golden" / "rest_mapping"
    payload = _json.loads((golden / "xyz_report.json").read_text(encoding="utf-8"))

    field_names = {
        "processes.command_line": "cmdline",
        "processes.name": "image",
        "calls.api": "syscall",
        "signatures.severity": "score",
        "signatures.ttps": "attack",
        "dns.request": "qname",
        "tcp.dst": "peer",
    }
    mapping = {
        "target_sha256": "$.sample.hashes.sha256",
        "processes": "$.run.processes[*]",
        "calls": "$.run.processes[*].syscalls[*]",
        "signatures": "$.detections[*]",
        "dns": "$.net.lookups[*]",
        "tcp": "$.net.streams[*]",
        "dropped_files": "$.artifacts[*]",
        "registry": "$.run.registry[*]",
        "field_names": field_names,
    }

    xyz_config = RestMappingConfig(
        **{k: v for k, v in mapping.items() if k != "field_names"}, field_names=field_names
    )
    expected = apply_mapping(compile_mapping(xyz_config), payload, provider="rest", task_id="xyz-1")

    out = preview_mapping(payload, mapping)

    # "calls" is included: the preview now maps every compiled channel
    # together in one ``apply_mapping`` call, the same call a job would make,
    # so a call's attachment to its process — and the orphan count that
    # attachment produces — matches Task 10's golden exactly, not just the
    # unattached "matched" figure.
    for channel in ("processes", "calls", "signatures", "dns", "tcp", "dropped_files", "registry"):
        assert out["channels"][channel]["matched"] == expected.stats[channel].matched
        assert out["channels"][channel]["kept"] == expected.stats[channel].kept
        assert out["channels"][channel]["dropped"] == expected.stats[channel].dropped
    assert out["target_sha256"] == expected.report.target.sha256
