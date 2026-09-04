"""The CAPE provider is the existing client behind the provider contract."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.core.config import Settings
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

ROOT = Path(__file__).resolve().parents[3]


class _FakeClient:
    def __init__(self, report):
        self.report = report
        self.submitted: list[str] = []
        self.waited: list[tuple[str, int, int]] = []

    def submit(self, sample_path):
        self.submitted.append(str(sample_path))
        return "42"

    def wait_for_completion(self, task_id, timeout_seconds=300, poll_interval_seconds=10):
        self.waited.append((task_id, timeout_seconds, poll_interval_seconds))
        return "reported"

    def fetch_report(self, task_id):
        from maljan.loaders.sandbox_client import SubmissionResult

        target = self.report.get("target", {})
        # Mirrors the fixed CAPEv2Client.fetch_report: real CAPE reports nest
        # sample identity under target.file.*, never flat on target (confirmed
        # against all 97 reports under data/cape_reports/); the flat read stays
        # as a fallback for a report that genuinely has it flat.
        file_block = target.get("file") if isinstance(target.get("file"), dict) else {}
        return SubmissionResult(
            task_id=task_id,
            sample_sha256=file_block.get("sha256") or target.get("sha256", ""),
            sample_name=file_block.get("name") or target.get("name", ""),
            status="reported",
            report=self.report,
        )

    def fetch_pcap(self, task_id, dest_dir):
        return None


@pytest.fixture
def raw_report():
    path = sorted((ROOT / "data" / "cape_reports").glob("*.json"))[0]
    return json.loads(path.read_text(encoding="utf-8"))


def test_capabilities(raw_report):
    # provides_tools tracks the CAPE MCP toggle, which — like every other MCP
    # server in this config (ghidra, r2, generic) — defaults to disabled; it
    # is set explicitly here so this test exercises the "enabled" branch
    # rather than asserting a truthy value against a config that defaults
    # false.
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.mcp.enabled = True
    caps = CAPE2SandboxProvider.from_settings(cfg).capabilities
    assert caps.can_submit and caps.can_poll and caps.can_fetch_report and caps.can_fetch_pcap
    assert caps.provides_tools and caps.report_format == "cape2"
    assert caps.degrade_on_failure is True
    assert caps.accepts_uploaded_report is False


def test_fetch_keeps_the_raw_report_by_identity(raw_report):
    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    provider._client = _FakeClient(raw_report)
    run = provider.fetch("42")
    assert run.raw is raw_report
    assert to_cape_shaped_dict(run.report) is raw_report
    assert run.report.source_format == "cape2"
    # Real CAPE reports nest sample identity under target.file.sha256, not a
    # flat target.sha256 (empirically confirmed against data/cape_reports/;
    # target's only keys there are "category" and "file") — see the report's
    # write-up of the cape2_client.py fetch_report fix.
    assert run.sample_sha256 == raw_report["target"]["file"]["sha256"]


def test_the_configured_timeout_and_interval_reach_the_client(raw_report):
    cfg = Settings(_env_file=None)
    cfg.sandbox.cape2.timeout_seconds = 1200
    cfg.sandbox.cape2.poll_interval_seconds = 15
    provider = CAPE2SandboxProvider.from_settings(cfg)
    client = _FakeClient(raw_report)
    provider._client = client
    provider.wait_for_completion("42")
    assert client.waited == [("42", 1200, 15)]


def test_the_essential_tool_names_match_the_golden():
    golden = json.loads(
        (ROOT / "tests" / "fixtures" / "golden" / "allowlists.json").read_text(encoding="utf-8")
    )
    assert sorted(CAPE2SandboxProvider.CAPE_ESSENTIAL_TOOLS) == golden["cape_essential_tools"]


def test_notable_apis_survives_the_identity_short_circuit_for_persistence_extractor():
    """Carried finding: ``persistence_extractor`` reads ``behavior.notable_apis``
    straight off the raw sandbox dict for Linux LD_PRELOAD detection. Neither
    ``SandboxReport`` nor ``to_cape_shaped_dict``'s full render names that key —
    but this provider never takes the full-render path with a real report:
    ``fetch()`` always sets ``raw`` to the client's untouched dict and
    ``source_format="cape2"``, so ``to_cape_shaped_dict`` always short-circuits
    to ``raw`` by identity, carrying whatever ``behavior.notable_apis`` the
    sandbox emitted through byte-for-byte. Proved end to end against
    ``persistence_extractor`` rather than merely asserted in prose.
    """
    from maljan.extractors.persistence_extractor import build_persistence_list

    raw = {
        "target": {"sha256": "e" * 64, "name": "mirai"},
        "behavior": {
            "notable_apis": [{"api": "setenv", "arguments": "LD_PRELOAD=/tmp/x.so"}],
        },
    }
    provider = CAPE2SandboxProvider.from_settings(Settings(_env_file=None))
    provider._client = _FakeClient(raw)
    run = provider.fetch("1")

    rendered = to_cape_shaped_dict(run.report)
    assert rendered is raw

    mechanisms = build_persistence_list(rendered, sample_platform="linux")
    assert any(m.kind == "ld_preload" for m in mechanisms)
