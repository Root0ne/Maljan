"""The pack's state keeps its own keys whatever its steps are named.

``pipeline.conditions.pack_state`` is the one place the triage pack's state is
written: its facts and counts, then how each step that may run beside the pack
ran, under the step's id. A step named as one of the state's own keys runs as
any other: its schedule is held apart under ``HELD_SCHEDULES``, a key no step
id can take, instead of replacing that key, and the run summary states it there
beside the counts. A run with no such step writes what it always wrote, and no
step id is refused for its name.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import ValidationError

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import Settings
from maljan.core.pack_steps import PackStep, default_steps, effective_steps, step_vocabulary
from maljan.core.settings_overrides import pack_steps_left_out
from maljan.pipeline.conditions import (
    HELD_SCHEDULES,
    PACK_LEFT_OUT,
    TriageFacts,
    pack_state,
    pack_state_keys,
)
from maljan.pipeline.triage_pack import PackResult

SERVER = {"command": "invented-rules", "enabled": True}


def _state(schedules: dict[str, str], facts: TriageFacts | None = None) -> dict[str, Any]:
    return pack_state(
        facts or TriageFacts(),
        entries=3,
        failed=1,
        duration_ms=7,
        degradation_reasons=["one failed"],
        schedules=schedules,
    )


def _summary_triage(state: dict[str, Any]) -> dict[str, Any]:
    return RunSummaryBuilder(start_time=0.0).set_triage(state).build().to_dict()["triage"]


def test_a_run_with_no_such_step_writes_what_it_always_wrote() -> None:
    facts = TriageFacts(has_signature=True, yara_hits=2, rule_hits=2, hits={"signature_rules": 2})
    state = _state({"inventory": "beside other_step", "decoder": "in turn"}, facts)
    written = {
        **facts.to_dict(),
        "entries": 3,
        "failed": 1,
        "duration_ms": 7,
        "degradation_reasons": ["one failed"],
        "inventory": "beside other_step",
        "decoder": "in turn",
    }
    assert json.dumps(state) == json.dumps(written)
    assert json.dumps(PackResult(schedules={"inventory": "in turn"}).to_state()) == json.dumps(
        {
            **TriageFacts().to_dict(),
            "entries": 0,
            "failed": 0,
            "duration_ms": 0,
            "degradation_reasons": [],
            "inventory": "in turn",
        }
    )


def test_a_schedule_under_one_of_its_keys_is_held_apart_and_the_rest_keep_their_order() -> None:
    state = _state(
        {
            "first": "in turn",
            "entries": "beside other_step",
            "has_signature": "in turn: no room",
            "last": "beside the pack",
        },
        TriageFacts(has_signature=True),
    )
    assert (state["entries"], state["has_signature"]) == (3, True)
    assert state[HELD_SCHEDULES] == {
        "entries": "beside other_step",
        "has_signature": "in turn: no room",
    }
    assert list(state)[-3:] == ["first", "last", HELD_SCHEDULES]


def test_the_left_out_record_keeps_its_key_too() -> None:
    state = _state({PACK_LEFT_OUT: "in turn"})
    assert PACK_LEFT_OUT not in state
    assert state[HELD_SCHEDULES] == {PACK_LEFT_OUT: "in turn"}


def test_no_step_id_can_take_the_key_schedules_are_held_under() -> None:
    with pytest.raises(ValidationError):
        PackStep(id=HELD_SCHEDULES)
    assert {HELD_SCHEDULES, PACK_LEFT_OUT} <= pack_state_keys()


def test_the_state_s_keys_are_read_off_the_state_itself() -> None:
    assert frozenset(PackResult().to_state()) <= pack_state_keys()
    assert {"entries", "failed", "duration_ms", "degradation_reasons"} <= pack_state_keys()
    served = step_vocabulary()["state_keys"]
    assert served == sorted(name for name in pack_state_keys() if name != HELD_SCHEDULES)
    assert not {step.id for step in default_steps()} & set(served)


def test_a_step_so_named_is_saved_and_read_as_any_other() -> None:
    steps = [
        {"id": "entries", "server": "rules", "tool": "match", "starts_after": "signing_info"},
        {"id": "yara_hits", "server": "rules", "tool": "match"},
    ]
    for name in step_vocabulary()["state_keys"]:
        PackStep.model_validate({**steps[0], "id": name})
    settings = Settings(_env_file=None, mcp={"servers": {"rules": SERVER}}, triage={"steps": steps})
    assert {"entries", "yara_hits"} <= {step.id for step in effective_steps(settings.triage.steps)}
    assert pack_steps_left_out({"mcp.servers": {"rules": SERVER}, "triage.steps": steps}) == {}


def test_the_run_summary_states_a_held_schedule_beside_the_counts() -> None:
    state = PackResult(schedules={"entries": "beside other_step"}).to_state()
    assert _summary_triage(state) == {
        "entries": 0,
        "failed": 0,
        "duration_ms": 0,
        HELD_SCHEDULES: {"entries": "beside other_step"},
    }


def test_a_summary_with_nothing_held_is_what_it_always_was() -> None:
    state = PackResult(schedules={"scan_beside": "beside other_step"}).to_state()
    assert _summary_triage(state) == {
        "entries": 0,
        "failed": 0,
        "duration_ms": 0,
        "scan_beside": "beside other_step",
    }
