"""Which of the platform's own pack steps take a wall clock comes from their shipped declaration.

* The shipped steps that honour ``budget_seconds`` say so on their own
  declaration (``wall_clock``); the set is the one the in-process code honours.
* A declaration cannot set ``wall_clock``; it gives ``budget_seconds`` instead.
* ``wall_clock`` is never dumped, so a saved list reads back unchanged.
* A clock on a step whose in-process code honours none is refused, naming the
  steps that do, read from the declarations.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.core.pack_steps import PackStep, check_steps, default_steps, effective_steps


def test_the_shipped_steps_with_a_clock_are_the_ones_the_in_process_code_honours() -> None:
    clocked = {step.id for step in default_steps() if step.wall_clock}
    assert clocked == {"capa", "floss", "yara_scan"}


def test_a_declaration_cannot_say_a_step_takes_a_clock() -> None:
    with pytest.raises(ValidationError, match="wall_clock"):
        PackStep.model_validate({"id": "strings", "wall_clock": True})
    with pytest.raises(ValueError, match="wall_clock"):
        check_steps([{"id": "strings", "wall_clock": True}])


def test_the_mark_is_never_dumped() -> None:
    for step in default_steps():
        assert "wall_clock" not in step.model_dump()
    laid = effective_steps([{"id": "capa", "budget_seconds": 5}])
    capa = next(step for step in laid if step.id == "capa")
    assert capa.wall_clock and capa.budget_seconds == 5
    assert "wall_clock" not in capa.model_dump()


def test_a_clock_on_a_step_without_one_is_refused_naming_the_declared_ones() -> None:
    with pytest.raises(ValueError, match="budget_seconds applies to capa, floss, yara_scan"):
        check_steps([{"id": "strings", "budget_seconds": 5}])
    assert check_steps([{"id": "floss", "budget_seconds": 5}])


def test_a_step_on_a_server_takes_a_clock_whatever_its_id() -> None:
    steps = check_steps(
        [{"id": "strings", "server": "inventory", "tool": "list_strings", "budget_seconds": 5}]
    )
    assert steps[0].budget_seconds == 5
