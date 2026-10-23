"""The pack's anti-analysis scan step is ``anti_analysis_scan``; its old name is still read.

The step was recorded under Ghidra's tool name (``find_anti_analysis_techniques``)
whichever static provider made the scan. A stored run's entries keep the name
they were recorded under, and an operator's ``triage.steps`` may name the step
by its old id, so both read as the step it became.
"""

from __future__ import annotations

from maljan.analysis.anti_analysis import SCAN_RENDERER, SCAN_TOOL
from maljan.core import pack_steps
from maljan.core.pack_steps import (
    LEGACY_STEP_NAMES,
    PackStep,
    effective_steps,
    shipped_renderer,
    shipped_step,
    written_for,
)

OLD = "find_anti_analysis_techniques"
NEW = "anti_analysis_scan"


def test_the_shipped_step_and_the_name_it_records_under_are_the_new_one() -> None:
    assert SCAN_TOOL == NEW
    assert LEGACY_STEP_NAMES == {OLD: NEW}
    ids = [step.id for step in pack_steps.default_steps()]
    assert NEW in ids and OLD not in ids


def test_an_entry_stored_under_the_old_name_is_read_as_the_step() -> None:
    assert written_for(SCAN_RENDERER, OLD)
    assert written_for(SCAN_RENDERER, NEW)
    assert shipped_renderer(OLD) == SCAN_RENDERER
    assert shipped_step(OLD) is shipped_step(NEW)


def test_a_declaration_under_the_old_id_is_laid_over_the_shipped_step() -> None:
    steps = {s.id: s for s in effective_steps([{"id": OLD, "display_name": "scan"}])}
    assert OLD not in steps
    assert steps[NEW].display_name == "scan"
    assert steps[NEW].renderer == SCAN_RENDERER


def test_a_declaration_under_the_old_id_can_switch_the_step_off() -> None:
    assert NEW not in {s.id for s in effective_steps([{"id": OLD, "enabled": False}])}


def test_a_step_placed_after_the_old_id_is_placed_after_the_new_one() -> None:
    steps = effective_steps([{"id": "mine", "tool": "x", "server": "s", "after": OLD}])
    ids = [s.id for s in steps]
    assert ids[ids.index(NEW) + 1] == "mine"


def test_a_server_step_keeps_the_tool_name_it_calls() -> None:
    step = PackStep.model_validate({"id": "ghidra_scan", "tool": OLD, "server": "ghidra"})
    assert step.tool == OLD, "a server's own tool is not renamed"
    own = PackStep.model_validate({"id": NEW, "tool": OLD})
    assert own.tool == NEW


def test_the_old_name_stays_declared_with_the_same_kind() -> None:
    from maljan.core.builtin_declarations import _PACK_TOOLS

    assert _PACK_TOOLS[OLD] == _PACK_TOOLS[NEW]
    assert _PACK_TOOLS[NEW]["kind"] == "anti_analysis_scan"
