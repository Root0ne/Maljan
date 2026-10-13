"""The anti-analysis pass is recorded under the name its shipped pack step declares, one source."""

from __future__ import annotations

from maljan.analysis.anti_analysis import SCAN_RENDERER, SCAN_TOOL
from maljan.core.pack_steps import default_steps


def test_the_pass_is_named_by_the_shipped_step_of_its_renderer() -> None:
    (step,) = [step for step in default_steps() if step.renderer == SCAN_RENDERER]
    assert SCAN_TOOL == step.called


def test_the_pack_dispatches_the_pass_under_that_name() -> None:
    from maljan.pipeline import triage_pack

    assert SCAN_TOOL in triage_pack._BUILTIN_STEPS
