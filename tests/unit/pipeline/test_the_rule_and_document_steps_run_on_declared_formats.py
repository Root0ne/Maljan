"""The rule and document servers' pack steps run on the routed format, and are off without a server.

YARA-X's step matches the operator's rule files against every sample, right
after the shipped YARA scan; oletools' steps read an Office container (its
macros, its DDE links) or an RTF (its embedded objects, its DDE links), and
webcrack's rewrites a JavaScript file or an HTA's or WSF's script blocks, each
by the format the router gave the sample, never by a tool's name. A step whose
server is not configured, switched off, or does not offer the tool is off: no
call, no entry, and the reason on the pack's result, so a deployment without
the servers (every stored run) runs the pack as it was. Nothing here reaches a
server: the node's call is stood in for.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.composition import servers_a_job_calls
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core import config as config_module
from maljan.core.config import Settings
from maljan.core.declared_reading import builtin_tools
from maljan.core.pack_steps import (
    OFFICE_FORMATS,
    RTF_FORMATS,
    SCRIPT_FORMATS,
    default_steps,
    effective_steps,
    shipped_step,
    steps_on_servers,
)
from maljan.core.settings_overrides import build_settings
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    ServerAnswer,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter

SERVERS = ("yarax", "oletools", "webcrack")
# Each step, its server, and the routed formats it runs on (empty: every one).
STEPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "ole_vba": ("oletools", OFFICE_FORMATS),
    "office_dde": ("oletools", (*OFFICE_FORMATS, *RTF_FORMATS)),
    "rtf_objects": ("oletools", RTF_FORMATS),
    "js_deobfuscate": ("webcrack", SCRIPT_FORMATS),
    "yarax_scan": ("yarax", ()),
}
# Formats each step must not run on, beside the ones it does.
OTHER_FORMATS = ("pe", "elf", "pdf", "zip", "ps1", "vbs", "unknown")


def _launch(key: str) -> dict[str, Any]:
    """How the server ``key`` ships started or reached, as an operator's stored entry holds it.

    A stored entry is held whole: one pointed where the server ships keeps the
    trust in what the server declares of its tools (T-418).
    """
    shipped = Settings(_env_file=None).mcp.servers[key]
    return shipped.model_dump(mode="json", include={"transport", "url", "command", "args", "cwd"})


def _settings(*on: str) -> Settings:
    """The shipped settings with the servers in ``on`` switched on."""
    servers = {key: {**_launch(key), "enabled": True} for key in on}
    return build_settings({"mcp.servers": servers}) if servers else Settings(_env_file=None)


@pytest.fixture
def in_force(monkeypatch: pytest.MonkeyPatch) -> Any:
    def use(settings: Settings) -> Settings:
        monkeypatch.setattr(config_module, "_settings_instance", settings)
        return settings

    return use


class _Calls:
    """The node's call, standing in: each server step answered from a table."""

    def __init__(self, answers: dict[str, Any] | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[str] = []

    def __call__(self, step: Any, values: Any, left: float | None) -> ServerAnswer:
        self.asked.append(step.id)
        return ServerAnswer(
            tool=step.called,
            args={"path": values.get("sample_path", "")},
            server=step.server,
            output=json.dumps(self.answers.get(step.id, {"tool": step.called})),
            started_at=time.time(),
        )


def _pack(tmp_path: Path, settings: Settings, calls: Any, file_type: str) -> Any:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"not a format the pack reads\n")
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=str(sample),
        sha256="a" * 64,
        file_type=file_type,
        strings_head=10,
        capa=CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
        # Only these servers' steps: the platform's own are not what is asked.
        steps=tuple(s for s in effective_steps() if s.id in STEPS),
        servers=settings.mcp.servers,
    )
    return run_pack(recorder, inputs, server_step=calls)


class TestOffWithoutTheirServer:
    def test_the_shipped_settings_run_the_pack_as_it_was(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings())
        calls = _Calls()
        for file_type in ("ole2", "rtf", "js", "pe"):
            result = _pack(tmp_path, settings, calls, file_type)
            assert result.entries == [] and result.failed == []
            assert result.steps_off == {
                step: f"{server} is switched off" for step, (server, _f) in STEPS.items()
            }
        assert calls.asked == []
        assert not set(SERVERS) & servers_a_job_calls(Settings(_env_file=None))

    def test_settings_without_the_servers_are_never_refused_for_them(self) -> None:
        held = Settings(_env_file=None)
        for key in SERVERS:
            del held.mcp.servers[key]
        for step_id in STEPS:
            step = shipped_step(step_id)
            assert step is not None and held.pack_step_problem(step) == ""
        off = steps_on_servers(effective_steps(), held.mcp.servers)[1]
        assert {step: off[step] for step in STEPS} == {
            step: f"no tool server is configured as {server}"
            for step, (server, _f) in STEPS.items()
        }

    def test_a_server_not_offering_the_tool_leaves_its_step_off(self) -> None:
        held = build_settings(
            {"mcp.servers": {"oletools": {"enabled": True, "tools": ["ole_indicators"]}}}
        )
        _kept, off = steps_on_servers(effective_steps(), held.mcp.servers)
        for step in ("ole_vba", "office_dde", "rtf_objects"):
            assert off[step] == f"{step} is not among the tools oletools offers"

    def test_a_switched_on_server_is_one_the_job_calls(self) -> None:
        assert set(SERVERS) <= servers_a_job_calls(_settings(*SERVERS))


class TestTheyRunOnTheRoutedFormat:
    @pytest.mark.parametrize(
        "file_type", sorted({*OFFICE_FORMATS, *RTF_FORMATS, *SCRIPT_FORMATS, *OTHER_FORMATS})
    )
    def test_each_step_runs_on_its_formats_alone(
        self, tmp_path: Path, in_force: Any, file_type: str
    ) -> None:
        settings = in_force(_settings(*SERVERS))
        calls = _Calls()
        result = _pack(tmp_path, settings, calls, file_type)
        want = [
            step for step, (_s, formats) in STEPS.items() if not formats or file_type in formats
        ]
        assert sorted(calls.asked) == sorted(want)
        assert sorted(e.tool for e in result.entries) == sorted(want)
        assert result.failed == [] and result.steps_off == {}

    def test_the_yara_x_step_follows_the_shipped_yara_scan(self) -> None:
        ids = [step.id for step in default_steps()]
        assert ids.index("yarax_scan") == ids.index("yara_scan") + 1
        documents = ["ole_vba", "office_dde", "rtf_objects", "js_deobfuscate"]
        at = ids.index("go_symbols") + 1
        assert ids[at : at + len(documents)] == documents

    def test_a_yara_x_match_counts_as_a_signature_rule_hit(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("yarax"))
        rows = [
            {"rule": "agent_loader", "meta": {}, "tags": [], "strings": []},
            {"rule": "agent_config", "meta": {}, "tags": [], "strings": []},
        ]
        calls = _Calls({"yarax_scan": {"tool": "yarax_scan", "matches": rows, "match_count": 2}})
        result = _pack(tmp_path, settings, calls, "pe")
        (entry,) = result.entries
        assert entry.ok and entry.server == "yarax"
        assert result.facts.hits.get("signature_rules") == 2

    def test_each_steps_formats_are_its_tools_declared_formats(self) -> None:
        for step_id, (server, formats) in STEPS.items():
            step = shipped_step(step_id)
            assert step is not None and (step.server, step.called) == (server, step_id)
            assert step.formats == formats and not step.when
            declared = builtin_tools(server)[step.called]
            assert tuple(declared.routed_formats) == formats, step_id


class TestAnOverlayOnAShippedServerStep:
    def test_the_shipped_yara_renderer_is_refused_on_the_yara_x_step(self) -> None:
        with pytest.raises(ValueError, match="renderer 'signature_rules'"):
            Settings(
                _env_file=None,
                triage={"steps": [{"id": "yarax_scan", "renderer": "signature_rules"}]},
            )

    def test_a_format_overlay_is_kept_and_another_tool_is_an_operators_step(self) -> None:
        (step,) = [
            s for s in effective_steps([{"id": "rtf_objects", "formats": ["rtf", "ole2"]}])
            if s.id == "rtf_objects"
        ]  # fmt: skip
        assert step.formats == ("rtf", "ole2") and step.server == "oletools"
        (other,) = [
            s for s in effective_steps([{"id": "ole_vba", "server": "oletools", "tool": "nope"}])
            if s.id == "ole_vba"
        ]  # fmt: skip
        held = Settings(_env_file=None)
        held.mcp.servers["oletools"].tools = ["ole_vba"]
        assert held.pack_step_problem(other) == (
            "triage step 'ole_vba': 'nope' is not allowed on server 'oletools'"
        )
        assert steps_on_servers([other], held.mcp.servers) == ((other,), {})
