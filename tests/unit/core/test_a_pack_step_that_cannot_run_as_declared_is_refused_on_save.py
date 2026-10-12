"""A triage pack step list is refused where it is saved when the pack could not run it as declared.

* A step on a server ``mcp.servers`` does not hold, or naming a tool outside
  that server's allow-list, is refused as an agent's reference is, in the same
  words; so is removing a server a step uses.
* A scheduling field the pack could not honour is refused, never saved and
  ignored: a start beside the pack for a step that runs only in turn, steps to
  run beside for one that starts after none, a peak nothing reads, a step that
  starts after or beside itself.
* A renderer is refused on a step whose answer it cannot read.
* An argument template is checked and filled at any depth.
* A dump of the settings reads back to the same steps.
* Every format a shipped step runs for is a name the router gives.
"""

from __future__ import annotations

import gc
import time
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.core.config import Settings, TriageConfig
from maljan.core.pack_steps import (
    PackStep,
    check_steps,
    default_steps,
    effective_steps,
    placeholder_values,
)
from maljan.extractors import sample_identity

SERVER = {"command": "invented-inventory", "enabled": True}


def _settings(**over: Any) -> Settings:
    return Settings(_env_file=None, **over)


def _refused(steps: list[dict[str, Any]]) -> str:
    with pytest.raises(ValueError) as caught:
        check_steps(steps)
    return str(caught.value)


class TestAServerStepIsCheckedAsAnAgentsReferenceIs:
    def test_an_unknown_server_is_refused(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _settings(triage={"steps": [{"id": "x", "server": "nope", "tool": "t"}]})
        assert "triage step 'x' references unknown mcp server 'nope'" in str(caught.value)

    def test_a_tool_outside_the_allow_list_is_refused(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _settings(
                mcp={"servers": {"inv": {**SERVER, "tools": ["count"]}}},
                triage={"steps": [{"id": "x", "server": "inv", "tool": "other"}]},
            )
        assert "triage step 'x': 'other' is not allowed on server 'inv'" in str(caught.value)

    def test_the_agent_check_says_the_same_words(self) -> None:
        with pytest.raises(ValidationError) as caught:
            _settings(
                agents={
                    "definitions": {
                        "helper": {
                            "role": "static",
                            "tools": [{"kind": "mcp", "server": "nope", "name": "t"}],
                        }
                    }
                }
            )
        assert "'helper' references unknown mcp server 'nope'" in str(caught.value)

    def test_an_allowed_tool_or_a_server_with_no_list_is_saved(self) -> None:
        for tools in (["count"], None):
            held = _settings(
                mcp={"servers": {"inv": {**SERVER, "tools": tools}}},
                triage={"steps": [{"id": "x", "server": "inv", "tool": "count"}]},
            )
            assert [s.id for s in held.triage.steps] == ["x"]

    def test_removing_a_server_a_step_uses_is_refused(self) -> None:
        held = _settings(
            mcp={"servers": {"inv": SERVER}},
            triage={"steps": [{"id": "x", "server": "inv", "tool": "count"}]},
        )
        dumped = held.model_dump(mode="json")
        dumped["mcp"]["servers"].pop("inv")
        with pytest.raises(ValidationError, match="references unknown mcp server 'inv'"):
            Settings(_env_file=None, **dumped)

    def test_a_dropped_step_needs_no_server(self) -> None:
        held = _settings(triage={"steps": [{"id": "capa", "enabled": False}]})
        assert held.triage.steps[0].enabled is False


class TestASchedulingFieldThePackCouldNotHonourIsRefused:
    def test_a_start_beside_the_pack_on_a_step_that_runs_in_turn(self) -> None:
        for field_name, value in (("starts_after", "identify_file"), ("beside", ["floss"])):
            said = _refused([{"id": "capa", field_name: value}])
            assert "step 'capa' runs in-process in turn and cannot start beside the pack" in said
            assert "only floss can" in said

    def test_a_step_that_starts_after_or_beside_itself(self) -> None:
        said = _refused(
            [{"id": "x", "server": "s", "tool": "t", "starts_after": "x", "beside": ["x"]}]
        )
        assert "step 'x' starts after itself" in said and "step 'x' runs beside itself" in said

    def test_steps_to_run_beside_with_no_start(self) -> None:
        said = _refused([{"id": "x", "server": "s", "tool": "t", "beside": ["capa"]}])
        assert "names steps to run beside but starts after none" in said

    def test_a_peak_nothing_reads(self) -> None:
        said = _refused([{"id": "x", "server": "s", "tool": "t", "peak_mb": 10}])
        assert "step 'x' declares peak_mb" in said
        assert "step 'yara_scan' declares peak_mb" in _refused([{"id": "yara_scan", "peak_mb": 5}])

    def test_what_the_pack_honours_is_saved(self) -> None:
        steps = check_steps(
            [
                # capa's peak sizes FLOSS beside it while capa is not yet measured.
                {"id": "capa", "peak_mb": 900},
                {"id": "floss", "peak_mb": 2048, "beside": ["capa", "yara_scan"]},
                {"id": "x", "server": "s", "tool": "t", "starts_after": "hashes", "peak_mb": 10},
                {"id": "y", "server": "s", "tool": "t", "starts_after": "x", "beside": ["x"]},
            ]
        )
        assert [s.id for s in steps] == ["capa", "floss", "x", "y"]

    def test_the_shipped_list_is_saved_as_it_is(self) -> None:
        assert check_steps([s.model_dump() for s in default_steps()]) != []


class TestARendererIsRefusedWhereItCannotRead:
    def test_on_a_server_tool(self) -> None:
        said = _refused([{"id": "x", "server": "s", "tool": "t", "renderer": "pe_header"}])
        assert "renderer 'pe_header' reads only the answer of pe_info" in said
        assert "leave renderer empty for the generic line" in said

    def test_on_another_of_the_platform_s_own_steps(self) -> None:
        assert "renderer 'pe_header'" in _refused([{"id": "capa", "renderer": "pe_header"}])

    def test_a_renderer_that_reads_declared_facts_is_saved_on_any_tool(self) -> None:
        (step,) = check_steps(
            [{"id": "capa", "server": "s", "tool": "t", "renderer": "capability_rules"}]
        )
        assert step.renderer == "capability_rules"


class TestAnArgumentTemplateAtAnyDepth:
    VALUES = {"sample_path": "/s.exe", "sha256": "b" * 64, "file_type": "pe"}

    def test_an_unknown_placeholder_is_refused_however_deep(self) -> None:
        for arguments in (
            {"p": {"q": "{evil}"}},
            {"p": [{"q": ["x", "{evil}"]}]},
        ):
            with pytest.raises(ValidationError, match=r"argument 'p' names \{evil\}"):
                PackStep(id="x", server="s", tool="t", arguments=arguments)

    def test_every_string_is_filled_however_deep_and_once(self) -> None:
        template = {
            "target": {"file": "{sample_path}", "tags": ["{file_type}", 3, None]},
            "hash": "{sha256}",
            "n": 4,
        }
        filled = placeholder_values(template, {**self.VALUES, "file_type": "{sha256}"})
        assert filled == {
            "target": {"file": "/s.exe", "tags": ["{sha256}", 3, None]},
            "hash": "b" * 64,
            "n": 4,
        }
        assert template["target"]["file"] == "{sample_path}", "the template is left as declared"

    def test_ten_times_the_depth_takes_about_ten_times_as_long(self) -> None:
        def deep(n: int) -> dict[str, Any]:
            held: Any = "{sample_path}"
            for _ in range(n):
                held = {"inner": [held]}
            return {"p": held}

        def seconds(n: int) -> float:
            template = deep(n)
            gc.collect()
            began = time.perf_counter()
            PackStep(id="x", server="s", tool="t", arguments=template)
            placeholder_values(template, self.VALUES)
            return time.perf_counter() - began

        seconds(2_000)
        low = min(seconds(2_000) for _ in range(2))
        high = min(seconds(20_000) for _ in range(2))
        print("deep template:", round(low, 4), round(high, 4))
        assert high < low * 20


class TestADumpReadsBackToTheSameSteps:
    DECLARED = [
        {"id": "capa", "budget_seconds": 100},
        {"id": "floss", "enabled": False},
        {"id": "x", "server": "inv", "tool": "count", "after": "hashes", "arguments": {"f": "1"}},
    ]

    def test_a_step_dumps_what_it_was_given(self) -> None:
        dumped = TriageConfig(steps=self.DECLARED).model_dump(mode="json")["steps"]
        assert dumped == [{**self.DECLARED[0], "budget_seconds": 100.0}, *self.DECLARED[1:]]

    def test_the_settings_dump_reads_back_to_the_same_merged_steps(self) -> None:
        held = _settings(mcp={"servers": {"inv": SERVER}}, triage={"steps": self.DECLARED})
        for mode in ("json", "python"):
            again = Settings(_env_file=None, **held.model_dump(mode=mode))
            assert effective_steps(again.triage.steps) == effective_steps(held.triage.steps)
        capa = next(s for s in effective_steps(again.triage.steps) if s.id == "capa")
        assert (capa.renderer, capa.display_name, capa.budget_seconds) == (
            "capability_rules",
            "capa",
            100,
        )


def test_every_shipped_format_is_a_name_the_router_gives() -> None:
    routed = {
        *sample_identity.PLATFORM_BY_FILE_TYPE,
        *sample_identity.ARCHIVE_FILE_TYPES,
        *sample_identity.DOCUMENT_FILE_TYPES,
        *sample_identity.SCRIPT_FILE_TYPES,
    }
    for step in default_steps():
        assert set(step.formats) <= routed, (step.id, set(step.formats) - routed)
    constants = next(s for s in default_steps() if s.id == "find_crypto_constants")
    assert "mach-o" in constants.formats
