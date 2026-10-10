"""A whole analysis against the rehearsal's stub model passes the written checklist, on both wires.

The real pipeline — the default profile, the triage pack, the repository's own
tool sidecars over stdio, the mock sandbox, every model call through the
settings a deployment sets — runs in this process against the loopback stub
(``scripts/rehearsal``), once per scenario and per wire (the Anthropic
Messages API and the OpenAI-compatible chat completions API). Each run must
pass every check of ``scripts/rehearsal/checklist.py`` but the ones
``KNOWN_DEFECTS`` names, and fail those with the detail pinned there: a defect
fixed, or the same check failing for another reason, is a test that says so.
The rounds and retries two further defects cost are pinned the same way. Two
normal runs must be identical, and no run may leave a process-wide setting
behind.

Skipped where what an in-process run needs is absent: the web server packages
the stub is served with (``starlette``, ``uvicorn``), the ``mcp`` package the
tool sidecars speak, or a loopback port to bind. No Docker, no network beyond
127.0.0.1, no model cost.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("starlette", reason="the stub model is served with starlette")
pytest.importorskip("uvicorn", reason="the stub model is served with uvicorn")
pytest.importorskip("mcp", reason="the tool sidecars speak the mcp package's protocol")

from scripts.rehearsal.checklist import check_run, compare, observations, signature  # noqa: E402
from scripts.rehearsal.inprocess import Rehearsal, rehearse  # noqa: E402
from scripts.rehearsal.roles import SCENARIOS  # noqa: E402


def _loopback_binds() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not _loopback_binds(), reason="no loopback port to bind the stub on"),
]

# A deadline every rehearsal but ``deadline_hit`` finishes far inside.
JOB_DEADLINE_S = 600.0
WIRES = ("openai", "anthropic")

# The checks each scenario fails today, each with the exact detail it fails
# with and the product defect behind it (``tests/fixtures/rehearsal/
# known_defects.json``). A pin matches only its whole detail: the same check
# failing for one more reason is a new failure, and a defect fixed is a test
# asking to strike its rows.
PINS_FILE = Path(__file__).resolve().parents[1] / "fixtures" / "rehearsal" / "known_defects.json"
_PINNED = json.loads(PINS_FILE.read_text(encoding="utf-8"))
KNOWN_DEFECTS: dict[tuple[str, str], dict[str, str]] = {}
for _row in _PINNED["pins"]:
    KNOWN_DEFECTS.setdefault((_row["scenario"], _row["wire"]), {})[_row["check"]] = _row["detail"]
# The numbers a run must show exactly: any defect's own (the same file's
# ``observations``) and the clean ones. A mediator answer cut at its cap is
# not mediated, and the answers in force go to the judge after one round. A
# clean debate takes 2 rounds and ends in consensus, also when every first
# revision answer was empty, and no revision draws a citation retry.
_CLEAN_DEBATE = {
    "negotiation_rounds": 2,
    "termination_reason": "consensus",
    "isr.ungrounded_technique": None,
}
PINNED_OBSERVATIONS: dict[tuple[str, str], dict[str, object]] = {
    ("cut_at_cap", "openai"): {"negotiation_rounds": 1, "termination_reason": "not_mediated"},
    ("cut_at_cap", "anthropic"): {"negotiation_rounds": 1, "termination_reason": "not_mediated"},
    ("normal", "openai"): dict(_CLEAN_DEBATE),
    ("normal", "anthropic"): dict(_CLEAN_DEBATE),
    ("empty_answer", "openai"): dict(_CLEAN_DEBATE),
    ("empty_answer", "anthropic"): dict(_CLEAN_DEBATE),
}
for _row in _PINNED["observations"]:
    PINNED_OBSERVATIONS.setdefault((_row["scenario"], _row["wire"]), {})[_row["observation"]] = (
        _row["value"]
    )


@pytest.fixture(autouse=True)
def no_process_wide_setting_outlives_a_run() -> Iterator[None]:
    """Every run puts back the settings singleton and the sidecars' sample roots."""
    from maljan.core import config
    from maljan.tools.roots import SAMPLE_ROOTS_ENV

    settings, roots = config._settings_instance, os.environ.get(SAMPLE_ROOTS_ENV)
    yield
    assert config._settings_instance is settings
    assert os.environ.get(SAMPLE_ROOTS_ENV) == roots


@pytest.mark.parametrize("wire", WIRES)
@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_every_check_passes_but_a_known_defect(tmp_path: Path, scenario: str, wire: str) -> None:
    rehearsal = Rehearsal(
        scenario=scenario,
        provider=wire,
        work_dir=tmp_path / scenario,
        job_timeout_s=None if scenario == "deadline_hit" else JOB_DEADLINE_S,
        slow_seconds=0.2 if scenario == "slow_model" else None,
        loop_steps=8 if scenario == "long_loop" else None,
    )
    record = asyncio.run(rehearse(rehearsal))
    failed = {c.name: c.detail for c in check_run(record) if not c.ok}
    known = KNOWN_DEFECTS.get((scenario, wire), {})
    for name, pinned in known.items():
        assert name in failed, (
            f"known defect {scenario}/{wire} '{name}' no longer reproduces: strike it from "
            f"{PINS_FILE.name}"
        )
        assert failed[name] == pinned, (
            f"'{name}' fails with a detail the pin does not hold: {failed[name]}"
        )
    unexpected = {name: detail for name, detail in failed.items() if name not in known}
    assert unexpected == {}
    observed = observations(record)
    for key, value in PINNED_OBSERVATIONS.get((scenario, wire), {}).items():
        found = observed["validation_codes"].get(key) if "." in key else observed.get(key)
        assert found == value, (
            f"pinned {key} for {scenario}/{wire} moved from {value} to {found}: if a defect was "
            "fixed, strike the pin; if it grew, the defect is worse"
        )


@pytest.mark.parametrize("wire", WIRES)
def test_two_normal_runs_are_identical(tmp_path: Path, wire: str) -> None:
    signatures = []
    for index in range(2):
        rehearsal = Rehearsal(scenario="normal", provider=wire, work_dir=tmp_path / f"run{index}")
        record = asyncio.run(rehearse(rehearsal))
        signatures.append(signature(record, check_run(record)))
    assert compare(signatures) == []


@pytest.mark.parametrize("wire", WIRES)
def test_a_deadline_aimed_at_the_report_stage_lands_there(tmp_path: Path, wire: str) -> None:
    """The in-process deadline stops the run inside the report stage, every time.

    Against the stack the same aim stops the worker inside its report node,
    whose stopped run must keep its run summary, its usage and a partial report.
    """
    rehearsal = Rehearsal(
        scenario="deadline_hit", provider=wire, deadline_in="report", work_dir=tmp_path / "dl"
    )
    record = asyncio.run(rehearse(rehearsal))
    failed = {c.name: c.detail for c in check_run(record) if not c.ok}
    assert failed == {}
    held = [e for e in record.stub_log if e.get("waiting")]
    assert held and held[-1]["role"] in ("composer", "narrative")


# The all-tools team an operator imports (``docs/examples/profiles/all-tools.json``):
# custom agents beside the built-in ones, a triage analyst and a reverser in
# stages of their own. The Qu1cksc0pe server it names is not in the
# repository, so the repository's analysis sidecar answers under its name.
ALL_TOOLS = Path(__file__).resolve().parents[2] / "docs/examples/profiles/all-tools.json"


def _all_tools_team() -> dict[str, object]:
    from maljan.core.settings_overrides import build_settings

    values = json.loads(ALL_TOOLS.read_text(encoding="utf-8"))["values"]
    analysis = build_settings({}).mcp.servers["analysis"].model_dump(mode="json")
    analysis.pop("auth_token", None)
    return {
        "agents.definitions": values["core.agents.definitions"],
        "agents.profiles": values["core.agents.profiles"],
        "agents.profile": "all_tools",
        "mcp.servers": {"qu1cksc0pe": analysis},
    }


@pytest.mark.parametrize("wire", WIRES)
def test_a_custom_team_passes_every_check(tmp_path: Path, wire: str) -> None:
    """Every check reads the custom team from the job's own roster and passes.

    Three of the team's analysts answer alike, so the debate flags their
    agreement and runs a later revision round: each revision restates the
    answer in force, and the report's labels number the claims of that answer.
    """
    rehearsal = Rehearsal(
        scenario="normal",
        provider=wire,
        work_dir=tmp_path / "team",
        job_timeout_s=JOB_DEADLINE_S,
        extra=_all_tools_team(),
    )
    record = asyncio.run(rehearse(rehearsal))
    failed = {c.name: c.detail for c in check_run(record) if not c.ok}
    assert failed == {}
    custom = {"all_tools_static_r2", "all_tools_qu1cksc0pe", "all_tools_reverser_ghidra"}
    assert custom <= set(record.agent_models)
    assert custom | {"triage"} <= set(record.claims_in_force)
    assert custom | {"triage"} <= set(record.run_summary["generation"]["output_caps"])
    assert record.required_stages["reversing"] == ["all_tools_reverser_ghidra"]
    assert observations(record)["negotiation_rounds"] > 2
