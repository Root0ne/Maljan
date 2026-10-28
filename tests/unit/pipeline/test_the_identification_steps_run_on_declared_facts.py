"""The identification servers' pack steps run on declared facts, and are off without a server.

Detect It Easy's step runs on any sample; ILSpy's lists a .NET assembly's
types only where Detect It Easy's answer names the .NET library, and GoReSym's
recovers a Go binary's functions only where it names the Go compiler: each a
condition on a value the tool declares (``ToolFacts.values``), never on a
tool's name. A step whose server is not configured, switched off, or does not
offer the tool is off: no call, no entry, and the reason on the pack's result,
so a deployment without the servers (every stored run) runs the pack as it
was. Nothing here reaches a server: the node's call is stood in for.
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
    DOTNET_RUNTIMES,
    GO_COMPILERS,
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

IDENTIFIERS = ("die", "ilspy", "goresym")
STEPS = {"die": "die_scan", "ilspy": "dotnet_types", "goresym": "go_symbols"}


def _launch(key: str) -> dict[str, Any]:
    """How the server ``key`` ships started or reached, as an operator's stored entry holds it.

    A stored entry is held whole: one pointed where the server ships keeps the
    trust in what the server declares of its tools (T-418).
    """
    shipped = Settings(_env_file=None).mcp.servers[key]
    return shipped.model_dump(mode="json", include={"transport", "url", "command", "args", "cwd"})


def _settings(*on: str, **blocks: Any) -> Settings:
    """The shipped settings with the identification servers in ``on`` switched on."""
    servers = {key: {**_launch(key), "enabled": True, **blocks.get(key, {})} for key in on}
    return build_settings({"mcp.servers": servers}) if servers else Settings(_env_file=None)


@pytest.fixture
def in_force(monkeypatch: pytest.MonkeyPatch) -> Any:
    def use(settings: Settings) -> Settings:
        monkeypatch.setattr(config_module, "_settings_instance", settings)
        return settings

    return use


class _Calls:
    """The node's call, standing in: each server step answered from a table."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def __call__(self, step: Any, values: Any, left: float | None) -> ServerAnswer:
        self.asked.append(step.id)
        return ServerAnswer(
            tool=step.called,
            args={"path": values.get("sample_path", "")},
            server=step.server,
            output=json.dumps(self.answers.get(step.id, {})),
            started_at=time.time(),
        )


def _detected(*names: str) -> dict[str, Any]:
    rows = [{"file_type": "PE32", "type": "Library", "name": name} for name in names]
    return {"tool": "die_scan", "file_types": ["PE32"], "detections": rows}


def _pack(tmp_path: Path, settings: Settings, calls: Any, file_type: str = "pe") -> Any:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"not a format the pack reads\n")
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    inputs = PackInputs(
        sample_path=str(sample),
        sha256="a" * 64,
        file_type=file_type,
        strings_head=10,
        capa=CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
        # Only the identification steps: the platform's own are not what is asked.
        steps=tuple(s for s in effective_steps() if s.id in STEPS.values()),
        servers=settings.mcp.servers,
    )
    return run_pack(recorder, inputs, server_step=calls)


def _entry(result: Any, tool: str) -> Any:
    (entry,) = [e for e in result.entries if e.tool == tool]
    return entry


class TestOffWithoutTheirServer:
    def test_the_shipped_settings_run_the_pack_as_it_was(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings())
        calls = _Calls({})
        result = _pack(tmp_path, settings, calls)
        assert result.entries == [] and calls.asked == [] and result.failed == []
        assert result.steps_off == {
            "die_scan": "die is switched off",
            "dotnet_types": "ilspy is switched off",
            "go_symbols": "goresym is switched off",
        }

    def test_a_run_that_calls_no_server_leaves_them_off(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        inputs = PackInputs(
            sample_path=str(sample),
            sha256="a" * 64,
            file_type="pe",
            strings_head=10,
            capa=CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
            steps=tuple(s for s in effective_steps() if s.id in STEPS.values()),
        )
        result = run_pack(recorder, inputs)
        assert result.entries == []
        assert set(result.steps_off.values()) == {"this run calls no tool server"}

    def test_a_server_not_configured_or_not_offering_the_tool_is_off_too(self) -> None:
        steps = effective_steps()
        held = _settings("die", "ilspy", ilspy={"tools": ["dotnet_resources"]})
        servers = {k: v for k, v in held.mcp.servers.items() if k != "goresym"}
        kept, off = steps_on_servers(steps, servers)
        # The identification steps' own; the other servers' steps are held in
        # test_the_rule_and_document_steps_run_on_declared_formats.py.
        off = {step: why for step, why in off.items() if step in STEPS.values()}
        assert off == {
            "dotnet_types": "dotnet_types is not among the tools ilspy offers",
            "go_symbols": "no tool server is configured as goresym",
        }
        assert "die_scan" in {s.id for s in kept}
        # Every step of the platform's own is kept as it is.
        assert [s.id for s in kept if s.builtin] == [s.id for s in steps if s.builtin]

    def test_settings_without_the_servers_are_never_refused_for_them(self) -> None:
        # A step of the shipped list never makes settings that lack its server invalid.
        held = Settings(_env_file=None)
        for key in IDENTIFIERS:
            del held.mcp.servers[key]
        for step_id in STEPS.values():
            step = shipped_step(step_id)
            assert step is not None and held.pack_step_problem(step) == ""
        off = steps_on_servers(effective_steps(), held.mcp.servers)[1]
        assert set(STEPS.values()) <= set(off)
        assert not set(IDENTIFIERS) & servers_a_job_calls(Settings(_env_file=None))

    def test_an_operators_step_on_an_absent_server_is_still_refused(self) -> None:
        # Only the shipped steps are off without their server; an operator's
        # own step naming a server that is not there is refused as before.
        with pytest.raises(ValueError, match="unknown mcp server 'nowhere'"):
            Settings(
                _env_file=None,
                triage={"steps": [{"id": "mine", "server": "nowhere", "tool": "die_scan"}]},
            )

    def test_a_switched_on_server_is_one_the_job_calls(self) -> None:
        assert {"die", "goresym"} <= servers_a_job_calls(_settings("die", "goresym"))


class TestTheyRunOnDeclaredFacts:
    @pytest.mark.parametrize("runtime", DOTNET_RUNTIMES)
    def test_ilspy_lists_types_where_detect_it_easy_names_dotnet(
        self, tmp_path: Path, in_force: Any, runtime: str
    ) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        calls = _Calls({"die_scan": _detected("Microsoft Linker", runtime)})
        result = _pack(tmp_path, settings, calls)
        assert calls.asked == ["die_scan", "dotnet_types"]
        assert _entry(result, "dotnet_types").ok
        go = _entry(result, "go_symbols")
        assert go.ok is False and go.error == (
            "not run: it runs when die_scan's name is 'Go', and die_scan's answer holds no "
            "such value"
        )
        assert result.failed == [] and result.steps_off == {}

    @pytest.mark.parametrize("file_type", ["pe", "elf", "mach-o"])
    def test_goresym_recovers_symbols_where_detect_it_easy_names_go(
        self, tmp_path: Path, in_force: Any, file_type: str
    ) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        calls = _Calls({"die_scan": _detected(*GO_COMPILERS)})
        result = _pack(tmp_path, settings, calls, file_type=file_type)
        assert "go_symbols" in calls.asked and _entry(result, "go_symbols").ok
        assert "dotnet_types" not in calls.asked

    def test_neither_runs_on_a_native_binary_nor_on_another_format(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        calls = _Calls({"die_scan": _detected("GCC", "UPX")})
        result = _pack(tmp_path, settings, calls)
        assert calls.asked == ["die_scan"]
        for tool in ("dotnet_types", "go_symbols"):
            assert _entry(result, tool).error.startswith("not run: it runs when die_scan's name")
        # A .NET name on a sample routed as an ELF: the .NET step is for PE only.
        calls = _Calls({"die_scan": _detected(".NET Core")})
        result = _pack(tmp_path, settings, calls, file_type="elf")
        assert calls.asked == ["die_scan"]
        assert not [e for e in result.entries if e.tool == "dotnet_types"]

    def test_a_decompiler_without_its_identifier_says_why_it_did_not_run(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("ilspy"))
        calls = _Calls({})
        result = _pack(tmp_path, settings, calls)
        assert calls.asked == []
        assert _entry(result, "dotnet_types").error == (
            "not run: it runs when die_scan's name is '.NET Framework' or '.NET Core', and "
            "die_scan did not run"
        )
        assert result.steps_off == {
            "die_scan": "die is switched off",
            "go_symbols": "goresym is switched off",
        }
        assert result.failed == []

    def test_the_conditions_name_a_declared_value_not_a_tool(self) -> None:
        die = builtin_tools("die")["die_scan"]
        for step_id in ("dotnet_types", "go_symbols"):
            step = shipped_step(step_id)
            assert step is not None
            (condition,) = step.when
            assert condition.step == "die_scan" and condition.value in die.values


class TestAnOverlayOnAShippedServerStep:
    def test_a_renderer_its_tool_cannot_feed_is_refused(self) -> None:
        with pytest.raises(ValueError, match="renderer 'capability_rules'"):
            Settings(
                _env_file=None,
                triage={"steps": [{"id": "die_scan", "renderer": "capability_rules"}]},
            )

    def test_another_tool_is_checked_as_an_operators_step_never_left_off(self) -> None:
        (step,) = [
            s for s in effective_steps([{"id": "die_scan", "server": "die", "tool": "not_offered"}])
            if s.id == "die_scan"
        ]  # fmt: skip
        assert (step.server, step.called) == ("die", "not_offered")
        held = Settings(_env_file=None)
        held.mcp.servers["die"].tools = ["die_scan"]
        assert held.pack_step_problem(step) == (
            "triage step 'die_scan': 'not_offered' is not allowed on server 'die'"
        )
        # Not one of the shipped steps any more: never off, recorded as it runs.
        assert steps_on_servers([step], held.mcp.servers) == ((step,), {})
        del held.mcp.servers["die"]
        assert "unknown mcp server 'die'" in held.pack_step_problem(step)
