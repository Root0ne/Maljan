"""Every benchmark run is submitted without an earlier run's memory of its sample (T-414).

A series runs one sample again and again; a run shown the previous run's
technique list scores partly that run. The config the benchmark submits a job
with carries ``ignore_earlier_runs``, which an option of the caller's never
turns off; only an explicit choice keeps the earlier runs, and the score then
has to say so. The scoring tools read each scored run's stored run summary
and name every run that neither says it started without earlier runs nor
states, in its score, that it used them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.benchmark import earlier_runs
from scripts.benchmark.jobs import IGNORE_EARLIER_RUNS, ISOLATED_MEMORY, SWITCHES, job_config
from scripts.benchmark.run import main
from scripts.benchmark.scores import read_key_score

from app.schemas.job import JobCreateRequest, _KnownJobConfig


def test_the_options_are_the_ones_the_submit_schema_knows() -> None:
    assert SWITCHES == (IGNORE_EARLIER_RUNS, ISOLATED_MEMORY)
    assert set(SWITCHES) <= set(_KnownJobConfig.model_fields)
    body = JobCreateRequest(
        sample_id="00000000-0000-0000-0000-000000000001", config=job_config({"profile": "x"})
    )
    assert body.config == {"profile": "x", "ignore_earlier_runs": True, "isolated_memory": True}


@pytest.mark.parametrize(
    "options",
    [
        None,
        {},
        {"profile": "all_tools"},
        {"ignore_earlier_runs": False},
        {"isolated_memory": False},
        {"ignore_earlier_runs": False, "isolated_memory": False, "profile": "p"},
    ],
)
def test_every_run_s_config_sets_both_switches(options: dict | None) -> None:
    config = job_config(options)
    assert config[IGNORE_EARLIER_RUNS] is True
    assert config[ISOLATED_MEMORY] is True
    assert {k: v for k, v in config.items() if k not in SWITCHES} == {
        k: v for k, v in (options or {}).items() if k not in SWITCHES
    }


def test_only_an_explicit_choice_keeps_the_earlier_runs() -> None:
    # A job with memory of its own reads no earlier run either: both go.
    assert job_config(
        {"profile": "p", "ignore_earlier_runs": True, "isolated_memory": True}, earlier_runs=True
    ) == {"profile": "p"}


def test_the_options_handed_in_are_not_changed() -> None:
    options = {"profile": "p"}
    job_config(options)
    assert options == {"profile": "p"}


def test_the_command_line_prints_the_config(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["job-config", "--profile", "all_tools"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "profile": "all_tools",
        "ignore_earlier_runs": True,
        "isolated_memory": True,
    }
    assert main(["job-config"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "ignore_earlier_runs": True,
        "isolated_memory": True,
    }
    assert main(["job-config", "--with-earlier-runs"]) == 0
    assert json.loads(capsys.readouterr().out) == {}


# ---------------------------------------------------------------------------
# A scored run whose earlier runs are not ruled out is named
# ---------------------------------------------------------------------------


def _scored(
    tmp_path: Path, name: str, *, summary: Any = None, stated: bool = False, fresh: bool = False
) -> Path:
    from tests.unit.scripts.test_the_benchmark_tells_own_analysis_from_lookup import _stored_run

    path = _stored_run(tmp_path / name)
    if stated:
        path.write_text(
            path.read_text(encoding="utf-8") + "\n**Earlier runs:** used (the run before it)\n",
            encoding="utf-8",
        )
    if fresh:
        path.write_text(
            path.read_text(encoding="utf-8") + "\n**Memory:** fresh account (an empty store)\n",
            encoding="utf-8",
        )
    if summary is not None:
        (path.parent / earlier_runs.SUMMARY_FILE).write_text(json.dumps(summary), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("summary", "stated", "status"),
    [
        ({"earlier_runs_ignored": True, "isolated_memory": True}, False, earlier_runs.OFF),
        # Ignoring the sample's earlier runs alone leaves the series' other cases readable.
        ({"earlier_runs_ignored": True}, False, earlier_runs.NOT_RULED_OUT),
        ({"isolated_memory": True}, False, earlier_runs.NOT_RULED_OUT),
        ({"final_decision": "Malware"}, True, earlier_runs.STATED),
        ({"final_decision": "Malware"}, False, earlier_runs.NOT_RULED_OUT),
        # No stored summary says nothing of earlier runs.
        (None, False, earlier_runs.NOT_RULED_OUT),
        # A truthy value that is not ``true`` is not the record.
        (
            {"earlier_runs_ignored": "yes", "isolated_memory": True},
            False,
            earlier_runs.NOT_RULED_OUT,
        ),
        (
            {"earlier_runs_ignored": True, "isolated_memory": "yes"},
            False,
            earlier_runs.NOT_RULED_OUT,
        ),
    ],
)
def test_a_key_score_reads_the_run_summary_beside_it(
    tmp_path: Path, summary: Any, stated: bool, status: str
) -> None:
    run = read_key_score(_scored(tmp_path, "run", summary=summary, stated=stated))
    assert run.earlier_runs == status


@pytest.mark.parametrize(
    ("summary", "missing"),
    [
        ({"earlier_runs_ignored": True}, "does not say isolated_memory"),
        ({"isolated_memory": True}, "does not say earlier_runs_ignored"),
        ({"final_decision": "Malware"}, "does not say earlier_runs_ignored or isolated_memory"),
    ],
)
def test_the_note_names_the_switch_the_summary_does_not_say(
    tmp_path: Path, summary: Any, missing: str
) -> None:
    run = read_key_score(_scored(tmp_path, "run", summary=summary))
    assert run.earlier_runs == earlier_runs.NOT_RULED_OUT
    assert missing in run.earlier_runs_note


def test_a_stated_fresh_account_stands_in_for_isolated_memory(tmp_path: Path) -> None:
    run = read_key_score(
        _scored(tmp_path, "run", summary={"earlier_runs_ignored": True}, fresh=True)
    )
    assert run.earlier_runs == earlier_runs.OFF
    assert "fresh account" in run.earlier_runs_note


def test_a_stated_fresh_account_never_stands_in_for_ignoring_earlier_runs(tmp_path: Path) -> None:
    run = read_key_score(_scored(tmp_path, "run", summary={"isolated_memory": False}, fresh=True))
    assert run.earlier_runs == earlier_runs.NOT_RULED_OUT


def test_the_summary_is_read_from_the_stored_report_when_alone(tmp_path: Path) -> None:
    path = _scored(tmp_path, "run")
    (path.parent / earlier_runs.REPORT_BY_JOB_FILE).write_text(
        json.dumps({"run_summary": {"earlier_runs_ignored": True, "isolated_memory": True}}),
        encoding="utf-8",
    )
    assert read_key_score(path).earlier_runs == earlier_runs.OFF


def test_score_and_gate_name_a_run_not_ruled_out_first_and_in_the_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clean = _scored(
        tmp_path, "clean", summary={"earlier_runs_ignored": True, "isolated_memory": True}
    )
    leaky = _scored(tmp_path, "leaky", summary={"final_decision": "Malware"})
    out = tmp_path / "out.json"

    assert main(["score", str(clean), "--json", str(out)]) == 0
    assert earlier_runs.FLAG not in capsys.readouterr().out
    assert json.loads(out.read_text())["runs"][0]["earlier_runs_not_ruled_out"] == {}

    assert main(["score", str(leaky), "--json", str(out)]) == 0
    text = capsys.readouterr().out
    assert text.splitlines()[1].startswith(f"{earlier_runs.FLAG}: leaky: ")
    assert set(json.loads(out.read_text())["runs"][0]["earlier_runs_not_ruled_out"]) == {"leaky"}

    # Flagged, not gated: the gate's outcome is the verdicts'.
    assert main(["gate", "--baseline", str(clean), "--candidate", str(leaky)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "known-answer gate: PASS"
    assert lines[1].startswith(f"{earlier_runs.FLAG}: leaky: ")
