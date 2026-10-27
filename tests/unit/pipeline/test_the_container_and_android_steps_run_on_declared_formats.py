"""The container and Android servers' pack steps run where declared, and are off without a server.

unblob's step extracts every sample (it finds a chunk of a format it knows by
the chunk's own bytes, whatever the router called the file) and declares the
answer's file paths as its ``outputs``, so each file it wrote is taken into the
job's artefact store for a later step to read; JADX's step lists an Android
package's or dex file's classes, by the format the router gave the sample. A
step whose server is not configured, switched off, or does not offer the tool
is off: no call, no entry, and the reason on the pack's result, so a
deployment without the servers (every stored run) runs the pack as it was.
Nothing here reaches a server: the node's call is stood in for.
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
    ANDROID_FORMATS,
    EXTRACTED_FILES,
    default_steps,
    effective_steps,
    shipped_step,
    steps_on_servers,
)
from maljan.core.settings_overrides import build_settings
from maljan.pipeline.artefacts import written_names
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    ServerAnswer,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter

SERVERS = ("unblob", "jadx")
# Each step, its server, and the routed formats it runs on (empty: every one).
STEPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "container_extract": ("unblob", ()),
    "android_classes": ("jadx", ANDROID_FORMATS),
}
FORMATS = ("apk", "dex", "pe", "elf", "zip", "img", "vhd", "lnk", "jar", "unknown")


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
        for file_type in ("apk", "img", "pe"):
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
            {"mcp.servers": {"unblob": {"enabled": True, "tools": ["container_scan"]}}}
        )
        _kept, off = steps_on_servers(effective_steps(), held.mcp.servers)
        assert off["container_extract"] == "container_extract is not among the tools unblob offers"

    def test_a_switched_on_server_is_one_the_job_calls(self) -> None:
        assert set(SERVERS) <= servers_a_job_calls(_settings(*SERVERS))


class TestTheyRunWhereDeclared:
    @pytest.mark.parametrize("file_type", FORMATS)
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

    def test_they_follow_the_document_steps(self) -> None:
        ids = [step.id for step in default_steps()]
        at = ids.index("js_deobfuscate") + 1
        assert ids[at : at + 2] == ["container_extract", "android_classes"]

    def test_each_steps_formats_are_its_tools_declared_formats(self) -> None:
        for step_id, (server, formats) in STEPS.items():
            step = shipped_step(step_id)
            assert step is not None and (step.server, step.called) == (server, step_id)
            assert step.formats == formats and not step.when
            declared = builtin_tools(server)[step.called]
            assert tuple(declared.routed_formats) == formats, step_id

    def test_the_extraction_hands_each_file_it_wrote_to_the_artefact_store(self) -> None:
        step = shipped_step("container_extract")
        assert step is not None and step.outputs == EXTRACTED_FILES
        answer = {
            "tool": "container_extract",
            "files": [
                {"path": "r1/s.bin_extract/a.bin", "name": "s.bin_extract/a.bin"},
                {"path": "r1/s.bin_extract/etc/b", "name": "s.bin_extract/etc/b"},
            ],
            "links": [{"name": "s.bin_extract/l", "target": "/etc/passwd"}],
        }
        # The regular files' paths, never a link's.
        assert written_names(answer, step.outputs) == [
            "r1/s.bin_extract/a.bin",
            "r1/s.bin_extract/etc/b",
        ]
        assert shipped_step("android_classes").outputs == ""  # type: ignore[union-attr]
