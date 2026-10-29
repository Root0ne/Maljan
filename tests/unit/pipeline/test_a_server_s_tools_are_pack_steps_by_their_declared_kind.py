"""A server's tools are the pack's steps by what their declarations say, never by a name.

The shipped list holds only the platform's own steps. Every server configured
gives a step for each tool whose declaration in force says it answers one of
the pack's server-step kinds about the whole file, is read-only, takes the
file by its path, and runs nothing of the sample and sends nothing of it out
(``core.pack_steps.server_steps``). The step runs on the routed formats the
tool declares, writes the files it declares it writes, and, for a tool that
reads one code runtime alone, runs where an identification answer names that
runtime. A server with other names whose tools say the same gets the same
steps; a tool that would send the sample anywhere, or does not say, is never
a step the pack takes on its own. A step whose server is switched off, or does
not offer the tool, is off, with why, and a deployment with no such server
(every stored run) runs the pack as it was. Nothing here reaches a server: the
node's call is stood in for.
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
from maljan.core.config import MCPServerConfig, Settings
from maljan.core.declared_reading import builtin_tools
from maljan.core.pack_steps import (
    IDENTIFICATION_KIND,
    RUNTIME_VALUE,
    SERVER_STEP_KINDS,
    SERVER_STEPS_AFTER,
    check_steps,
    default_steps,
    effective_steps,
    runs_as_a_step,
    server_step_ids,
    server_steps,
    steps_left_out,
    steps_on_servers,
)
from maljan.core.settings_overrides import build_settings
from maljan.core.tool_declarations import ToolFacts
from maljan.pipeline.artefacts import written_names
from maljan.pipeline.triage_pack import (
    PIPELINE,
    CapaSettings,
    PackInputs,
    ServerAnswer,
    run_pack,
)
from maljan.schemas.evidence import EvidenceCounter

# The platform's own servers whose tools answer a server-step kind.
SERVERS = ("die", "ilspy", "goresym", "yarax", "oletools", "webcrack", "unblob", "jadx")
# Each step their tools give, its server, and the routed formats it runs on
# (empty: every one), in the order the pack runs them.
STEPS: dict[str, tuple[str, tuple[str, ...]]] = {
    "die_scan": ("die", ()),
    "dotnet_types": ("ilspy", ("pe",)),
    "go_symbols": ("goresym", ("pe", "elf", "mach-o")),
    "go_types": ("goresym", ("pe", "elf", "mach-o")),
    "office_dde": ("oletools", ("ole2", "ooxml", "rtf")),
    "ole_vba": ("oletools", ("ole2", "ooxml")),
    "rtf_objects": ("oletools", ("rtf",)),
    "js_deobfuscate": ("webcrack", ("js", "hta", "wsf")),
    "container_extract": ("unblob", ()),
    "android_classes": ("jadx", ("apk", "dex")),
    "yarax_scan": ("yarax", ()),
}
# The steps that read one code runtime, and the runtime each reads.
RUNTIME_STEPS = {"dotnet_types": "dotnet", "go_symbols": "go", "go_types": "go"}
FORMATS = (
    "pe", "elf", "mach-o", "ole2", "ooxml", "rtf", "js", "hta", "wsf", "apk", "dex", "zip",
    "pdf", "unknown",
)  # fmt: skip


def _launch(key: str) -> dict[str, Any]:
    """How the server ``key`` ships started or reached, as an operator's stored entry holds it."""
    shipped = Settings(_env_file=None).mcp.servers[key]
    return shipped.model_dump(mode="json", include={"transport", "url", "command", "args", "cwd"})


def _settings(*on: str, **blocks: Any) -> Settings:
    """The shipped settings with the servers in ``on`` switched on."""
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

    def __init__(self, answers: dict[str, Any] | None = None) -> None:
        self.answers = answers or {}
        self.asked: list[str] = []

    def __call__(self, step: Any, values: Any, left: float | None) -> ServerAnswer:
        self.asked.append(step.called)
        return ServerAnswer(
            tool=step.called,
            args={"path": values.get("sample_path", "")},
            server=step.server,
            output=json.dumps(self.answers.get(step.called, {"tool": step.called})),
            started_at=time.time(),
        )


def _identified(*runtimes: str) -> dict[str, Any]:
    """An identification answer whose rows name ``runtimes``, as Detect It Easy's server does."""
    rows = [{"file_type": "PE32", "type": "Library", "name": "x", "runtime": r} for r in runtimes]
    return {"detections": rows}


def _server_steps_only(settings: Settings) -> tuple[Any, ...]:
    """The run's steps of the servers' tools alone: the platform's own are not what is asked."""
    steps, _off = steps_on_servers(effective_steps(), settings.mcp.servers)
    return tuple(step for step in steps if step.server)


def _pack(
    tmp_path: Path, settings: Settings, calls: Any, file_type: str = "pe", **over: Any
) -> Any:
    sample = tmp_path / "s.bin"
    sample.write_bytes(b"not a format the pack reads\n")
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    values: dict[str, Any] = {
        "sample_path": str(sample),
        "sha256": "a" * 64,
        "file_type": file_type,
        "strings_head": 10,
        "capa": CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
        "steps": (),
        "servers": settings.mcp.servers,
    }
    values.update(over)
    return run_pack(recorder, PackInputs(**values), server_step=calls)


def _entry(result: Any, tool: str) -> Any:
    (entry,) = [e for e in result.entries if e.tool == tool]
    return entry


class TestTheStepsAreReadFromTheDeclarations:
    def test_the_shipped_list_names_no_server_and_no_servers_tool(self) -> None:
        assert all(not step.server for step in default_steps())
        assert not {step.called for step in default_steps()} & set(STEPS)

    def test_every_server_on_gives_its_steps_in_order(self, in_force: Any) -> None:
        settings = in_force(_settings(*SERVERS))
        steps, off = steps_on_servers(effective_steps(), settings.mcp.servers)
        assert off == {}
        ids = [step.id for step in steps]
        # After the format readers, the identification step first; YARA-X right
        # after the platform's own scan of the same kind.
        at = ids.index(SERVER_STEPS_AFTER) + 1
        assert ids[at : at + 10] == [s for s in STEPS if s != "yarax_scan"]
        assert ids[ids.index("yara_scan") + 1] == "yarax_scan"
        # Every step of the platform's own is kept, in its order.
        assert [s.id for s in steps if not s.server] == [s.id for s in effective_steps()]

    def test_each_step_is_its_tools_declaration(self, in_force: Any) -> None:
        settings = in_force(_settings(*SERVERS))
        for step in _server_steps_only(settings):
            server, formats = STEPS[step.id]
            declared = builtin_tools(server)[step.called]
            assert (step.server, step.called) == (server, step.id)
            assert step.formats == formats == tuple(declared.routed_formats), step.id
            assert declared.kind in SERVER_STEP_KINDS and runs_as_a_step(declared)
            assert step.outputs == declared.outputs
            assert not step.renderer and not step.kind
            # Its tool's display name and its kind's words.
            assert (
                step.display_name
                == f"{declared.display_name} · " + (SERVER_STEP_KINDS[declared.kind])
            )

    def test_the_runtime_steps_run_on_the_identification_steps_runtime_value(
        self, in_force: Any
    ) -> None:
        settings = in_force(_settings(*SERVERS))
        die = builtin_tools("die")["die_scan"]
        assert die.kind == IDENTIFICATION_KIND and RUNTIME_VALUE in die.values
        for step in _server_steps_only(settings):
            if step.id in RUNTIME_STEPS:
                (condition,) = step.when
                assert (condition.step, condition.value) == ("die_scan", RUNTIME_VALUE)
                assert condition.equals == (RUNTIME_STEPS[step.id],)
            else:
                assert step.when == (), step.id

    def test_the_extraction_hands_each_file_it_wrote_to_the_artefact_store(
        self, in_force: Any
    ) -> None:
        settings = in_force(_settings("unblob"))
        (step,) = [s for s in _server_steps_only(settings) if s.id == "container_extract"]
        answer = {
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


class TestOffWithoutTheirServer:
    def test_the_shipped_settings_run_the_pack_as_it_was(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings())
        calls = _Calls()
        for file_type in ("pe", "ole2", "apk", "js"):
            result = _pack(tmp_path, settings, calls, file_type)
            assert result.entries == [] and result.failed == []
            assert result.steps_off == {
                step: f"{server} is switched off" for step, (server, _f) in STEPS.items()
            }
        assert calls.asked == []
        assert not set(SERVERS) & servers_a_job_calls(Settings(_env_file=None))

    def test_a_run_that_calls_no_server_has_no_server_steps(self, tmp_path: Path) -> None:
        sample = tmp_path / "s.bin"
        sample.write_bytes(b"x")
        recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
        inputs = PackInputs(
            sample_path=str(sample),
            sha256="a" * 64,
            file_type="pe",
            strings_head=10,
            capa=CapaSettings(rules_dir="r", signatures_dir="s", timeout_s=7),
            steps=(),
        )
        result = run_pack(recorder, inputs)
        assert result.entries == [] and result.steps_off == {}

    def test_a_server_not_configured_or_not_offering_the_tool_is_off_too(self) -> None:
        held = _settings("die", "ilspy", ilspy={"tools": ["dotnet_resources"]})
        servers = {k: v for k, v in held.mcp.servers.items() if k != "goresym"}
        steps, off = steps_on_servers(effective_steps(), servers)
        assert off["dotnet_types"] == "dotnet_types is not among the tools ilspy offers"
        assert not {"go_symbols", "go_types"} & {*off, *(s.id for s in steps)}
        assert "die_scan" in {s.id for s in steps}

    def test_a_runtime_step_without_an_identification_step_is_off_with_why(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("ilspy"))
        calls = _Calls()
        result = _pack(tmp_path, settings, calls)
        assert calls.asked == [] and result.entries == [] and result.failed == []
        assert result.steps_off["dotnet_types"] == (
            "it reads dotnet code, and no step of an identification tool names a file's runtime"
        )

    def test_settings_without_the_servers_are_never_refused_for_them(self) -> None:
        held = Settings(_env_file=None)
        for key in SERVERS:
            del held.mcp.servers[key]
        steps, off = steps_on_servers(effective_steps(), held.mcp.servers)
        assert not {s.server for s in steps if s.server} & set(SERVERS)
        assert not set(STEPS) & set(off)
        assert all(held.pack_step_problem(step) == "" for step in steps)

    def test_a_switched_on_server_is_one_the_job_calls(self) -> None:
        assert set(SERVERS) <= servers_a_job_calls(_settings(*SERVERS))


class TestTheyRunWhereDeclared:
    @pytest.mark.parametrize("file_type", FORMATS)
    def test_each_step_runs_on_its_formats_alone(
        self, tmp_path: Path, in_force: Any, file_type: str
    ) -> None:
        settings = in_force(_settings(*SERVERS))
        calls = _Calls({"die_scan": _identified("dotnet", "go")})
        result = _pack(tmp_path, settings, calls, file_type)
        want = [s for s, (_k, formats) in STEPS.items() if not formats or file_type in formats]
        assert sorted(calls.asked) == sorted(want)
        assert sorted(e.tool for e in result.entries) == sorted(want)
        assert result.failed == [] and result.steps_off == {}

    def test_ilspy_lists_types_where_the_identification_names_dotnet(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        calls = _Calls({"die_scan": _identified("dotnet")})
        result = _pack(tmp_path, settings, calls)
        assert calls.asked == ["die_scan", "dotnet_types"]
        assert _entry(result, "dotnet_types").ok
        go = _entry(result, "go_symbols")
        assert go.ok is False and go.error == (
            "not run: it runs when die_scan's runtime is 'go', and die_scan's answer holds no "
            "such value"
        )
        assert result.failed == [] and not set(RUNTIME_STEPS) & set(result.steps_off)

    @pytest.mark.parametrize("file_type", ["pe", "elf", "mach-o"])
    def test_goresym_reads_a_go_binary(self, tmp_path: Path, in_force: Any, file_type: str) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        calls = _Calls({"die_scan": _identified("go")})
        _pack(tmp_path, settings, calls, file_type)
        assert calls.asked == ["die_scan", "go_symbols", "go_types"]

    def test_neither_runs_on_a_native_binary_nor_dotnet_on_another_format(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        calls = _Calls({"die_scan": _identified()})
        result = _pack(tmp_path, settings, calls)
        assert calls.asked == ["die_scan"]
        for tool in RUNTIME_STEPS:
            assert _entry(result, tool).error.startswith("not run: it runs when die_scan's runtime")
        calls = _Calls({"die_scan": _identified("dotnet")})
        result = _pack(tmp_path, settings, calls, "elf")
        assert calls.asked == ["die_scan"]
        assert not [e for e in result.entries if e.tool == "dotnet_types"]

    def test_the_detect_it_easy_server_names_the_runtime_of_its_detections(self) -> None:
        import importlib.util

        root = Path(__file__).resolve().parents[3]
        spec = importlib.util.spec_from_file_location(
            "die_mcp", root / "services/die-mcp/server.py"
        )
        assert spec is not None and spec.loader is not None
        die = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(die)
        names = [".NET Framework", ".NET Core", "Go", "GCC", "UPX"]
        document = {"detects": [{"filetype": "PE32", "values": [{"name": n} for n in names]}]}
        _types, rows = die.detections(document)
        assert [row.get("runtime") for row in rows] == ["dotnet", "dotnet", "go", None, None]

    def test_a_yara_x_match_counts_as_a_signature_rule_hit(
        self, tmp_path: Path, in_force: Any
    ) -> None:
        settings = in_force(_settings("yarax"))
        rows = [
            {"rule": "agent_loader", "meta": {}, "tags": [], "strings": []},
            {"rule": "agent_config", "meta": {}, "tags": [], "strings": []},
        ]
        calls = _Calls({"yarax_scan": {"tool": "yarax_scan", "matches": rows, "match_count": 2}})
        result = _pack(tmp_path, settings, calls)
        (entry,) = result.entries
        assert entry.ok and entry.server == "yarax"
        assert entry.pack_step == {"v": 1, "id": "yarax_scan", "label": "YARA-X · rule matches"}
        assert result.facts.hits.get("signature_rules") == 2


# A server never seen before, under names of its own: what each of its tools
# declares is what the platform's own servers declare of theirs.
def _renamed() -> dict[str, Any]:
    die = builtin_tools("die")["die_scan"]
    ilspy = builtin_tools("ilspy")["dotnet_types"]
    yarax = builtin_tools("yarax")["yarax_scan"]
    facts = {
        "what_is_it": die.model_dump(mode="json", exclude_defaults=True),
        "managed.types": ilspy.model_dump(mode="json", exclude_defaults=True),
        "MatchRules": yarax.model_dump(mode="json", exclude_defaults=True),
    }
    return {"command": "acme-kit", "enabled": True, "tool_facts": facts}


class TestAServerWithOtherNamesGetsTheSameSteps:
    @pytest.fixture
    def renamed(self, monkeypatch: pytest.MonkeyPatch) -> Settings:
        held = Settings(_env_file=None)
        held.mcp.servers["acme"] = MCPServerConfig.model_validate(_renamed())
        monkeypatch.setattr(config_module, "_settings_instance", held)
        return held

    def test_its_steps_are_placed_and_conditioned_as_the_built_ins_are(
        self, renamed: Settings
    ) -> None:
        steps, off = steps_on_servers(effective_steps(), {"acme": renamed.mcp.servers["acme"]})
        assert off == {}
        ours = [(s.id, s.called, s.formats, s.when) for s in steps if s.server == "acme"]
        assert [(i, c, f) for i, c, f, _w in ours] == [
            ("what_is_it", "what_is_it", ()),
            ("managed_types", "managed.types", ("pe",)),
            ("matchrules", "MatchRules", ()),
        ]
        (condition,) = ours[1][3]
        assert condition.model_dump() == {
            "step": "what_is_it",
            "value": RUNTIME_VALUE,
            "equals": ("dotnet",),
        }
        ids = [s.id for s in steps]
        assert ids.index("what_is_it") == ids.index(SERVER_STEPS_AFTER) + 1
        assert ids.index("matchrules") == ids.index("yara_scan") + 1

    def test_it_runs_as_the_built_ins_run(self, tmp_path: Path, renamed: Settings) -> None:
        # The server's steps alone: the identification step first, then its
        # tools by name.
        calls = _Calls({"what_is_it": _identified("dotnet")})
        result = _pack(tmp_path, renamed, calls)
        assert calls.asked == ["what_is_it", "MatchRules", "managed.types"]
        assert [e.server for e in result.entries] == ["acme"] * 3
        assert [e.pack_step["id"] for e in result.entries] == [
            "what_is_it",
            "matchrules",
            "managed_types",
        ]
        calls = _Calls({"what_is_it": _identified("go")})
        result = _pack(tmp_path, renamed, calls)
        assert calls.asked == ["what_is_it", "MatchRules"]
        assert _entry(result, "managed.types").error.startswith(
            "not run: it runs when what_is_it's runtime is 'dotnet'"
        )

    def test_two_servers_with_one_tool_name_each_get_a_step(self) -> None:
        held = Settings(_env_file=None)
        for key in ("one", "two"):
            held.mcp.servers[key] = MCPServerConfig.model_validate(_renamed())
        found, _off = server_steps(effective_steps(), held.mcp.servers)
        assert [s.id for s in found if s.called == "MatchRules"] == [
            "matchrules",
            "two_matchrules",
        ]

    def test_a_tool_named_as_a_shipped_step_never_takes_its_id(self) -> None:
        # Switched off, the shipped step's id is still the shipped step's.
        held = Settings(_env_file=None)
        facts = builtin_tools("yarax")["yarax_scan"].model_dump(mode="json", exclude_defaults=True)
        block = {"command": "acme-kit", "enabled": True, "tool_facts": {"capa": facts}}
        held.mcp.servers["acme"] = MCPServerConfig.model_validate(block)
        declared = effective_steps([{"id": "capa", "enabled": False}])
        found, _off = server_steps(declared, {"acme": held.mcp.servers["acme"]})
        assert [(s.id, s.called) for s in found] == [("acme_capa", "capa")]


# Declarations of the pack's server-step kinds that the pack never calls on its
# own: each would send the sample, or run it, or does not say.
_LOCAL = {"executes": "no", "network": False, "third_party": "no"}
_BASE = {"kind": "signature_rules", "read_only": True, "arguments": {"path": "path"}}
NOT_A_STEP: dict[str, dict[str, Any]] = {
    "discloses": {**_BASE, "effects": _LOCAL, "discloses_sample": True},
    "sends_bytes": {**_BASE, "effects": {**_LOCAL, "network": True, "third_party": "bytes"}},
    "sends_hash": {**_BASE, "effects": {**_LOCAL, "network": True, "third_party": "hash"}},
    "reaches_out": {**_BASE, "effects": {**_LOCAL, "network": True}},
    "on_refresh": {**_BASE, "effects": {**_LOCAL, "network": "on_refresh"}},
    "runs_it": {**_BASE, "effects": {**_LOCAL, "executes": "sandbox"}},
    "emulates": {**_BASE, "effects": {**_LOCAL, "executes": "emulation"}},
    "says_nothing": dict(_BASE),
    "network_unsaid": {**_BASE, "effects": {"executes": "no", "third_party": "no"}},
    "third_party_unsaid": {**_BASE, "effects": {"executes": "no", "network": False}},
    "writes": {**_BASE, "read_only": False, "effects": _LOCAL},
    "no_path": {**_BASE, "arguments": {"hash": "sha256"}, "effects": _LOCAL},
    "other_kind": {**_BASE, "kind": "decompile", "effects": _LOCAL},
}


class TestAToolThatWouldSendTheSampleIsNeverAStepOfItsOwn:
    @pytest.mark.parametrize("tool", sorted(NOT_A_STEP))
    def test_its_declaration_is_never_read_as_a_step(self, tool: str) -> None:
        assert not runs_as_a_step(ToolFacts.model_validate(NOT_A_STEP[tool]))
        assert runs_as_a_step(ToolFacts.model_validate({**_BASE, "effects": _LOCAL}))

    def test_a_server_of_such_tools_gives_no_step(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        held = Settings(_env_file=None)
        block = {"command": "leaky", "enabled": True, "tool_facts": NOT_A_STEP}
        held.mcp.servers["leaky"] = MCPServerConfig.model_validate(block)
        monkeypatch.setattr(config_module, "_settings_instance", held)
        assert server_steps(effective_steps(), {"leaky": held.mcp.servers["leaky"]}) == ([], {})
        calls = _Calls()
        result = _pack(tmp_path, held, calls)
        assert calls.asked == [] and result.entries == []

    def test_the_operator_may_still_name_one_as_a_step(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        held = Settings(_env_file=None)
        block = {"command": "leaky", "enabled": True, "tool_facts": NOT_A_STEP}
        held.mcp.servers["leaky"] = MCPServerConfig.model_validate(block)
        monkeypatch.setattr(config_module, "_settings_instance", held)
        mine = effective_steps([{"id": "mine", "server": "leaky", "tool": "sends_bytes"}])
        calls = _Calls()
        _pack(tmp_path, held, calls, steps=tuple(s for s in mine if s.server))
        assert calls.asked == ["sends_bytes"]


class TestADeclarationOverAServersStep:
    def test_switched_off_it_drops_the_step(self, in_force: Any) -> None:
        settings = in_force(_settings("die", "ilspy"))
        declared = effective_steps([{"id": "die_scan", "enabled": False}])
        steps, off = steps_on_servers(declared, settings.mcp.servers)
        assert not {"die_scan", "dotnet_types"} & {s.id for s in steps}
        # Nothing then names the runtime the .NET step reads; the step switched
        # off is not said to be off for a reason of the run's.
        assert "die_scan" not in off
        assert off["dotnet_types"] == (
            "it reads dotnet code, and no step of an identification tool names a file's runtime"
        )

    def test_its_fields_are_laid_over_the_step_and_after_places_it(self, in_force: Any) -> None:
        settings = in_force(_settings("oletools"))
        declared = effective_steps(
            [{"id": "rtf_objects", "formats": ["rtf", "ole2"], "after": "strings"}]
        )
        steps, _off = steps_on_servers(declared, settings.mcp.servers)
        ids = [s.id for s in steps]
        (step,) = [s for s in steps if s.id == "rtf_objects"]
        assert step.formats == ("rtf", "ole2") and step.server == "oletools"
        assert ids.index("rtf_objects") == ids.index("strings") + 1

    def test_one_with_no_such_step_is_left_out(self) -> None:
        declared = effective_steps([{"id": "nothing_here", "enabled": False}])
        assert "nothing_here" in {s.id for s in declared}
        steps, off = steps_on_servers(declared, Settings(_env_file=None).mcp.servers)
        assert "nothing_here" not in {s.id for s in steps} | set(off)
        assert steps_on_servers(declared, None)[0] == tuple(
            s for s in declared if s.id != "nothing_here"
        )

    def test_a_renderer_its_tool_cannot_feed_is_refused(self) -> None:
        with pytest.raises(ValueError, match="renderer 'signature_rules'"):
            Settings(
                _env_file=None,
                triage={"steps": [{"id": "yarax_scan", "renderer": "signature_rules"}]},
            )

    def test_another_tool_on_the_server_is_an_operators_step(self, in_force: Any) -> None:
        (step,) = [
            s for s in effective_steps([{"id": "ole_vba", "server": "oletools", "tool": "nope"}])
            if s.id == "ole_vba"
        ]  # fmt: skip
        held = Settings(_env_file=None)
        held.mcp.servers["oletools"].tools = ["ole_vba"]
        assert held.pack_step_problem(step) == (
            "triage step 'ole_vba': 'nope' is not allowed on server 'oletools'"
        )
        # The operator's step calls the server's tool by its own id; the
        # server's own step of that tool is not added beside it.
        settings = in_force(_settings("oletools"))
        mine = effective_steps([{"id": "macros", "server": "oletools", "tool": "ole_vba"}])
        steps, _off = steps_on_servers(mine, settings.mcp.servers)
        assert [s.id for s in steps if s.called == "ole_vba"] == ["macros"]


class TestAnOperatorsStepOfTheSameTool:
    def test_it_is_the_servers_step_under_its_own_id_and_fields(self, in_force: Any) -> None:
        settings = in_force(_settings("die", "ilspy", "goresym"))
        mine = {"id": "die_scan", "server": "die", "tool": "die_scan", "display_name": "Mine"}
        steps, off = steps_on_servers(effective_steps([mine]), settings.mcp.servers)
        ours = {s.id: s for s in steps if s.server in ("die", "ilspy", "goresym")}
        assert ours["die_scan"].display_name == "Mine"
        assert not set(RUNTIME_STEPS) & set(off)
        for step_id in RUNTIME_STEPS:
            assert [c.step for c in ours[step_id].when] == ["die_scan"]
        ids = [s.id for s in steps]
        # Placed by its kind, as the server's own step is, never twice.
        assert ids.index("die_scan") == ids.index(SERVER_STEPS_AFTER) + 1
        assert ids.count("die_scan") == 1

    def test_under_another_id_the_runtime_steps_run_on_that_id(self, in_force: Any) -> None:
        settings = in_force(_settings("die", "ilspy"))
        mine = {"id": "ident", "server": "die", "tool": "die_scan"}
        steps, _off = steps_on_servers(effective_steps([mine]), settings.mcp.servers)
        (dotnet,) = [s for s in steps if s.id == "dotnet_types"]
        assert [c.step for c in dotnet.when] == ["ident"]
        assert "die_scan" not in {s.id for s in steps}


class TestANameOfAServersStep:
    def test_a_stored_list_keeps_it_and_the_run_places_it(self, in_force: Any) -> None:
        settings = in_force(_settings("die"))
        later = {"id": "after_die", "server": "analysis", "tool": "strings", "after": "die_scan"}
        kept, left = steps_left_out([later])
        assert left == [] and [s.id for s in kept] == ["after_die"]
        steps, _off = steps_on_servers(effective_steps(kept), settings.mcp.servers)
        ids = [s.id for s in steps]
        assert ids.index("after_die") == ids.index("die_scan") + 1
        # A step placed after a step no server of the run gives stays last.
        lost = {"id": "lost", "server": "analysis", "tool": "strings", "after": "jadx_thing"}
        steps, _off = steps_on_servers(effective_steps([lost]), settings.mcp.servers)
        assert steps[-1].id == "lost"

    def test_a_condition_on_no_step_of_the_run_says_so(self, tmp_path: Path, in_force: Any) -> None:
        settings = in_force(_settings())
        mine = {
            "id": "mine",
            "server": "analysis",
            "tool": "strings",
            "when": [{"step": "die_scan", "value": "runtime", "equals": ["go"]}],
        }
        steps = tuple(s for s in effective_steps([mine]) if s.server)
        result = _pack(tmp_path, settings, _Calls(), steps=steps)
        assert _entry(result, "strings").error == (
            "not run: it runs when die_scan's runtime is 'go', and die_scan is no step of this run"
        )

    def test_a_save_knows_the_configured_servers_steps(self) -> None:
        # Every shipped server is configured (switched off), its tools kept.
        steps = [
            {"id": "go_types", "enabled": False},
            {"id": "rtf_objects", "after": "ole_vba"},
            {"id": "mine", "server": "analysis", "tool": "strings", "after": "die_scan"},
        ]
        held = Settings(_env_file=None, triage={"steps": steps})
        assert [s.id for s in held.triage.steps] == [s["id"] for s in steps]
        with pytest.raises(ValueError, match="no configured server's tool gives a step"):
            Settings(_env_file=None, triage={"steps": [{"id": "die_scna", "enabled": False}]})
        with pytest.raises(ValueError, match="which no step is"):
            Settings(
                _env_file=None,
                triage={"steps": [{"id": "m", "server": "analysis", "tool": "x", "after": "no"}]},
            )

    def test_a_save_is_held_to_it_and_a_stored_read_is_not(self) -> None:
        from maljan.core.settings_overrides import build_settings, pack_step_refusals

        typo = {"triage.steps": [{"id": "die_scna", "enabled": False}]}
        assert "die_scna" in str(pack_step_refusals(typo, {}))
        known = {"triage.steps": [{"id": "die_scan", "enabled": False}]}
        assert pack_step_refusals(known, {}) == {}
        # A stored list read keeps the name, for the run to resolve.
        assert [s.id for s in build_settings(typo).triage.steps] == ["die_scna"]

    def test_at_run_a_declaration_over_no_servers_step_is_off(self, in_force: Any) -> None:
        settings = in_force(_settings("die"))
        declared = effective_steps([{"id": "die_scna", "formats": ["pe"]}])
        _steps, off = steps_on_servers(declared, settings.mcp.servers)
        assert off["die_scna"] == "no server of this run gives a step die_scna"


class TestNoToolNameDecides:
    def test_a_tool_named_as_a_platforms_own_tool_is_a_step(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        held = Settings(_env_file=None)
        facts = builtin_tools("yarax")["yarax_scan"].model_dump(mode="json", exclude_defaults=True)
        held.mcp.servers["acme"] = MCPServerConfig.model_validate(
            {"command": "acme-kit", "enabled": True, "tool_facts": {"yara_scan": facts}}
        )
        monkeypatch.setattr(config_module, "_settings_instance", held)
        found, _off = server_steps(effective_steps(), {"acme": held.mcp.servers["acme"]})
        assert [(s.id, s.called) for s in found] == [("acme_yara_scan", "yara_scan")]


# What a server declares of its own tools under ``_meta``, kept as a listing
# keeps it: one tool of a server-step kind, read-only, closed.
SERVED = {
    "scan_it": {
        "kind": "signature_rules",
        "read_only": True,
        "arguments": {"path": "path"},
        "rows": "/matches/*",
        "effects": {"executes": "no", "network": False, "third_party": "no"},
    }
}
STDIO = {"transport": "stdio", "command": "/bin/true", "args": [], "enabled": True}


def _served(key: str, block: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> Settings:
    from maljan.core import served_declarations
    from maljan.core.tool_declarations import launch_identity

    held = build_settings({"mcp.servers": {key: block}})
    monkeypatch.setattr(config_module, "_settings_instance", held)
    launch = launch_identity(held.mcp.servers[key])
    served_declarations.install_persisted(((f"mcp:{key}", launch, SERVED),))
    return held


class TestWhatAServerDeclaresOfItself:
    def test_a_trusted_servers_declaration_gives_its_step(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        held = _served("kit", {**STDIO, "trusts_served_declaration": True}, monkeypatch)
        found, off = server_steps(effective_steps(), {"kit": held.mcp.servers["kit"]})
        assert [s.called for s in found] == ["scan_it"] and off == {}

    def test_an_untrusted_servers_claim_gives_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        held = _served("kit", dict(STDIO), monkeypatch)
        assert server_steps(effective_steps(), {"kit": held.mcp.servers["kit"]}) == ([], {})

    def test_a_trusted_server_not_listed_yet_is_off_with_why(self) -> None:
        block = {**STDIO, "trusts_served_declaration": True}
        held = build_settings({"mcp.servers": {"kit": block}})
        _found, off = server_steps(effective_steps(), {"kit": held.mcp.servers["kit"]})
        assert off == {"kit": "kit has not been listed, so its tools are not known"}

    def test_a_declaration_kept_by_another_release_is_not_kept(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core import served_declarations, tool_declarations
        from maljan.core.tool_declarations import launch_identity

        held = _served("kit", {**STDIO, "trusts_served_declaration": True}, monkeypatch)
        block = held.mcp.servers["kit"]
        before = launch_identity(block)
        assert served_declarations.kept("mcp:kit", before)
        monkeypatch.setattr(tool_declarations, "KEPT_DECLARATIONS_RELEASE", "another")
        after = launch_identity(block)
        assert after != before and not served_declarations.kept("mcp:kit", after)
        # A block that does not trust its server keeps by its launch alone.
        plain = MCPServerConfig.model_validate(dict(STDIO))
        first = launch_identity(plain)
        monkeypatch.setattr(tool_declarations, "KEPT_DECLARATIONS_RELEASE", "yet another")
        assert launch_identity(plain) == first


class TestAServerOnAnotherHost:
    def test_with_no_mount_of_the_samples_its_steps_are_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        held = Settings(_env_file=None)
        facts = builtin_tools("yarax")["yarax_scan"].model_dump(mode="json", exclude_defaults=True)
        block = {
            "transport": "streamable-http",
            "url": "http://far.invalid/mcp",
            "enabled": True,
            "tool_facts": {"scan_it": facts},
        }
        held.mcp.servers["far"] = MCPServerConfig.model_validate(block)
        monkeypatch.setattr(config_module, "_settings_instance", held)
        found, off = server_steps(effective_steps(), {"far": held.mcp.servers["far"]})
        assert found == [] and off == {"far": "the sample would be sent to far"}
        # Mounting the samples, it is read where the worker put them.
        mounted = MCPServerConfig.model_validate({**block, "sample_mount": "/data/samples"})
        found, off = server_steps(effective_steps(), {"far": mounted})
        assert [s.called for s in found] == ["scan_it"] and off == {}
        # An operator may still name its tool as a step of their own.
        mine = effective_steps([{"id": "mine", "server": "far", "tool": "scan_it"}])
        steps, _off = steps_on_servers(mine, {"far": held.mcp.servers["far"]})
        assert [s.id for s in steps if s.server] == ["mine"]

    def test_a_server_off_as_a_whole_names_no_step(self) -> None:
        block = {**STDIO, "trusts_served_declaration": True}
        held = build_settings({"mcp.servers": {"kit": block}})
        assert server_step_ids(effective_steps(), {"kit": held.mcp.servers["kit"]}) == frozenset()


# A step of the operator's that runs on Detect It Easy's answer, placed before
# the identification step runs.
EARLY = {
    "id": "m",
    "server": "oletools",
    "tool": "rtf_objects",
    "after": "archive_list",
    "when": [{"step": "die_scan", "value": "name", "equals": ["x"]}],
}


class TestTheRunsOrder:
    def test_a_save_refuses_a_step_on_a_servers_step_that_comes_after_it(
        self, in_force: Any
    ) -> None:
        settings = in_force(_settings("die", "oletools"))
        with pytest.raises(ValueError, match="runs on what 'die_scan' answers, which does not"):
            check_steps([EARLY], settings.mcp.servers)
        # Nor where a declaration moves the identification step past it.
        moved = {**EARLY, "after": "die_scan"}
        later = [{"id": "die_scan", "after": "strings"}, {**moved, "after": "archive_list"}]
        with pytest.raises(ValueError, match="which does not come before it"):
            check_steps(later, settings.mcp.servers)
        reading = {"id": "r", "server": "oletools", "tool": "ole_vba", "reads": "container_extract"}
        with pytest.raises(ValueError, match="reads the files 'container_extract' writes"):
            check_steps([{**reading, "after": "archive_list"}], _settings("unblob").mcp.servers)
        # Placed after it, it is saved.
        assert check_steps([{**EARLY, "after": "die_scan"}], settings.mcp.servers)

    def test_at_run_the_step_says_it_runs_after_it(self, tmp_path: Path, in_force: Any) -> None:
        settings = in_force(_settings("die", "oletools"))
        steps = effective_steps([EARLY])
        result = _pack(tmp_path, settings, _Calls(), "rtf", steps=steps)
        errors = [e.error for e in result.entries if e.tool == "rtf_objects"]
        assert errors == [
            "not run: it runs when die_scan's name is 'x', and die_scan runs after it"
        ]

    def test_a_chain_placed_after_a_moved_step_moves_with_it(self, in_force: Any) -> None:
        settings = in_force(_settings("die", "oletools"))
        chain = [
            {"id": "w", "server": "oletools", "tool": "rtf_objects", "after": "die_scan"},
            {"id": "x", "server": "oletools", "tool": "ole_vba", "after": "w"},
            {"id": "y", "server": "oletools", "tool": "office_dde", "after": "x"},
        ]
        steps, _off = steps_on_servers(effective_steps(chain), settings.mcp.servers)
        ids = [s.id for s in steps]
        at = ids.index("die_scan")
        assert ids[at : at + 4] == ["die_scan", "w", "x", "y"]
