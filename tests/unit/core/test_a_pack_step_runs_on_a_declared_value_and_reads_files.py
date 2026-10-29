"""A pack step declares, as data, the value it runs on and the files it reads and writes.

``when`` names a value an earlier step's tool declares and the texts it must
be; ``outputs`` the path of a server step's answer that names the files its
tool wrote; ``reads`` an earlier step with ``outputs``, which the step then
runs once per file for. Each is checked where the list is saved, so a list
that cannot run as declared never reaches a run, and a stored step that names
a step left out goes with it.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from maljan.core.config import Settings, TriageConfig
from maljan.core.pack_steps import (
    ARGUMENT_PLACEHOLDERS,
    FILE_PLACEHOLDERS,
    PackStep,
    effective_steps,
    step_vocabulary,
    steps_left_out,
    template_placeholders,
)

UNPACK = {"id": "unpack", "server": "carver", "tool": "extract", "outputs": "/files/*/path"}
SCAN = {"id": "scan", "server": "scanner", "tool": "scan", "reads": "unpack"}
DECOMPILE = {
    "id": "decompile",
    "server": "decompiler",
    "tool": "decompile",
    "when": [{"step": "identify", "value": "runtime", "equals": [".NET", "Mono"]}],
}
IDENTIFY = {"id": "identify", "server": "identifier", "tool": "detect"}


def _step(steps: list[dict[str, Any]], step_id: str) -> PackStep:
    return next(step for step in effective_steps(steps) if step.id == step_id)


class TestWhatAStepMayDeclare:
    def test_a_condition_outputs_and_reads_are_held_as_declared(self) -> None:
        steps = [IDENTIFY, DECOMPILE, UNPACK, SCAN]
        decompile = _step(steps, "decompile")
        (condition,) = decompile.when
        assert (condition.step, condition.value, condition.equals) == (
            "identify",
            "runtime",
            (".NET", "Mono"),
        )
        assert _step(steps, "unpack").outputs == "/files/*/path"
        assert _step(steps, "scan").reads == "unpack"

    def test_a_step_dumps_only_what_it_set(self) -> None:
        dumped = _step([IDENTIFY, DECOMPILE], "decompile").model_dump(mode="json")
        assert dumped == {**DECOMPILE, "when": [dict(DECOMPILE["when"][0])]}
        assert "outputs" not in dumped and "reads" not in dumped

    def test_the_file_placeholders_are_served_with_what_each_stands_for(self) -> None:
        served = {term["name"]: term["meaning"] for term in step_vocabulary()["placeholders"]}
        for name in (*FILE_PLACEHOLDERS, "artefact_sha256"):
            assert served[name] == ARGUMENT_PLACEHOLDERS[name]
        fields = [field["name"] for field in step_vocabulary()["fields"]]
        assert {"when", "outputs", "reads"} <= set(fields)

    def test_a_template_s_placeholders_are_read_at_any_depth(self) -> None:
        template = {"a": "{capture_path}", "b": [{"c": "x {artefact_path} {sha256}"}]}
        assert template_placeholders(template) == {"capture_path", "artefact_path", "sha256"}

    def test_a_condition_names_the_shipped_scan_by_its_old_name_as_the_new(self) -> None:
        step = PackStep.model_validate(
            {
                "id": "x",
                "server": "s",
                "tool": "t",
                "when": [
                    {"step": "find_anti_analysis_techniques", "value": "rule", "equals": ["a"]}
                ],
            }
        )
        assert step.when[0].step == "anti_analysis_scan"


class TestAListThatCannotRunIsRefused:
    @pytest.mark.parametrize(
        ("steps", "said"),
        [
            (
                [{"id": "x", "server": "s", "tool": "t", "arguments": {"f": "{artefact_path}"}}],
                "only a step that reads",
            ),
            ([SCAN, UNPACK], "which does not come before it"),
            ([{**UNPACK, "outputs": ""}, SCAN], "declares no outputs"),
            ([UNPACK, {**SCAN, "starts_after": "unpack"}], "starts_after would be ignored"),
            ([DECOMPILE, IDENTIFY], "which does not come before it"),
            ([{"id": "strings", "outputs": "/x"}], "passes no file between servers"),
            ([{"id": "strings", "reads": "hashes"}], "passes no file between servers"),
            ([{**UNPACK, "outputs": "files"}], "must start with '/'"),
            (
                [{**DECOMPILE, "when": [{"step": "identify", "value": "runtime", "equals": []}]}],
                "at least 1 item",
            ),
            (
                [{**DECOMPILE, "when": [{"step": "identify", "value": "Run", "equals": ["a"]}]}],
                "not the name of a declared value",
            ),
            (
                [
                    {
                        **DECOMPILE,
                        "when": [{"step": "identify", "value": "r", "equals": ["a"], "x": 1}],
                    }
                ],
                "Extra inputs",
            ),
        ],
    )
    def test_where_it_is_saved(self, steps: list[dict[str, Any]], said: str) -> None:
        with pytest.raises(ValidationError, match=said):
            TriageConfig(steps=steps)

    @pytest.mark.parametrize(
        ("steps", "said"),
        [
            ([UNPACK, {**SCAN, "reads": "nowhere"}], "reads 'nowhere', which no step is"),
            ([DECOMPILE], "runs when 'identify', which no step is"),
        ],
    )
    def test_a_name_of_no_step_is_refused_where_the_servers_are_known(
        self, steps: list[dict[str, Any]], said: str
    ) -> None:
        # Alone, the list cannot know the servers' own steps: the name is kept
        # for the run, which says it is no step of the run.
        assert TriageConfig(steps=steps).steps
        servers = {step["server"]: {"command": "x"} for step in steps}
        with pytest.raises(ValidationError, match=said):
            Settings(_env_file=None, mcp={"servers": servers}, triage={"steps": steps})

    def test_a_condition_on_a_shipped_step_is_one_of_the_platform_s_own_steps_too(self) -> None:
        step = _step(
            [{"id": "floss", "when": [{"step": "pe_info", "value": "packer", "equals": ["UPX"]}]}],
            "floss",
        )
        assert step.builtin and step.when[0].step == "pe_info"


class TestAStoredStepNamingOneLeftOutGoesWithIt:
    def test_the_reader_and_the_one_it_runs_on_go_with_their_source(self) -> None:
        stored = [
            {**UNPACK, "renderer": "pe_header"},
            SCAN,
            IDENTIFY,
            {**DECOMPILE, "when": [{"step": "unpack", "value": "kind", "equals": ["pe"]}]},
        ]
        kept, left = steps_left_out(stored)
        assert [step.id for step in kept] == ["identify"]
        reasons = {entry.name: entry.reason for entry in left}
        assert reasons["scan"] == "step 'scan' names step 'unpack', which is left out"
        assert reasons["decompile"] == "step 'decompile' names step 'unpack', which is left out"
