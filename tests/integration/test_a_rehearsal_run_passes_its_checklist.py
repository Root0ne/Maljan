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
# The numbers a run must show exactly. The defects' own (the same file's
# ``observations``) and two clean ones: a mediator answer cut at its cap is
# not mediated, and the answers in force go to the judge after one round.
PINNED_OBSERVATIONS: dict[tuple[str, str], dict[str, object]] = {
    ("cut_at_cap", "openai"): {"negotiation_rounds": 1, "termination_reason": "not_mediated"},
    ("cut_at_cap", "anthropic"): {"negotiation_rounds": 1, "termination_reason": "not_mediated"},
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
