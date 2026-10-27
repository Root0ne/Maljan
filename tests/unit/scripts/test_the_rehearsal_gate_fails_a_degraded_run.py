"""The zero-cost gate fails a run that carries a degradation reason (T-329).

A rehearsal whose run went on without a tool passed, and the paid run after it
said ``DEGRADED RUN``. Each reason is printed and the exit code is non-zero,
unless the operator names the reason as expected.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.rehearsal import run
from scripts.rehearsal.checklist import Check, RunRecord
from scripts.rehearsal.run import degradation_name, degradations_not_allowed, write_results

CAPA = (
    "server.analysis.capa_unavailable(capa is not installed (No module named 'capa')); "
    "install capa on the host that runs this server: uv sync --extra capa"
)


@pytest.fixture(autouse=True)
def every_check_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """What is judged here is the degradation rule alone, not the checklist."""
    monkeypatch.setattr(run, "check_run", lambda record: [Check("job completed", True, "")])


def _record(*reasons: str, in_report: tuple[str, ...] = ()) -> RunRecord:
    return RunRecord(
        scenario="normal",
        job_status="completed",
        run_summary={"degradation_reasons": list(reasons), "degraded_mode": bool(reasons)},
        malware_report={"degradation_reasons": list(in_report)},
    )


def test_a_clean_run_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert write_results([_record()], tmp_path) == 0
    result: dict[str, Any] = json.loads((tmp_path / "normal-run1.json").read_text())
    assert result["passed"] is True and result["degradations_not_allowed"] == []
    assert "run 1: PASS" in capsys.readouterr().out


def test_a_degraded_run_fails_and_prints_each_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert write_results([_record("triage.capa_failed", CAPA)], tmp_path) == 1
    shown = capsys.readouterr().out
    assert "run 1: FAIL" in shown
    assert "  DEGRADED triage.capa_failed" in shown
    assert f"  DEGRADED {CAPA}" in shown
    result = json.loads((tmp_path / "normal-run1.json").read_text())
    assert result["passed"] is False
    assert result["degradations_not_allowed"] == ["triage.capa_failed", CAPA]
    assert json.loads((tmp_path / "summary.json").read_text())["passed"] is False


def test_a_reason_only_the_report_carries_fails_too(tmp_path: Path) -> None:
    assert write_results([_record(in_report=("analyst failures: network",))], tmp_path) == 1


def test_named_reasons_are_allowed_and_only_those(tmp_path: Path) -> None:
    record = _record("triage.capa_failed", CAPA)
    allowed = ["triage.capa_failed", "server.analysis.capa_unavailable"]
    assert write_results([record], tmp_path, allowed) == 0
    assert write_results([record], tmp_path, ["triage.capa_failed"]) == 1
    assert degradations_not_allowed(record, ["triage.capa_failed"]) == [CAPA]


def test_a_reason_both_places_carry_is_named_once() -> None:
    assert degradations_not_allowed(_record(CAPA, in_report=(CAPA,))) == [CAPA]


def test_a_reasons_name_is_its_words_before_the_parenthesis() -> None:
    assert degradation_name(CAPA) == "server.analysis.capa_unavailable"
    assert degradation_name("triage.capa_failed") == "triage.capa_failed"
    assert degradation_name("verdict fell back; the judge did not answer") == "verdict fell back"


def test_the_flag_reaches_the_gate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, Any] = {}
    monkeypatch.setattr(run, "run_in_process", lambda args: [_record(CAPA)])

    def written(records: list[RunRecord], out: Path, allowed: Any = ()) -> int:
        seen["allowed"] = list(allowed)
        return 0

    monkeypatch.setattr(run, "write_results", written)
    argv = ["--in-process", "--out", str(tmp_path)]
    argv += ["--allow-degradation", "server.analysis.capa_unavailable"]
    assert run.main(argv) == 0
    assert seen["allowed"] == ["server.analysis.capa_unavailable"]


# A reason the cut_at_cap fault leaves, as a measured run worded it.
CUT = (
    "report section 'payloads' is not written: its answer was cut at 262144 tokens with no "
    "text written (the model's reasoning took the whole allowance), and a second call would "
    "have 262144 tokens, no more room; the limit was its output budget of 262144 tokens"
)
# The note a run the worker's job timeout stopped keeps (``stop_note``).
TIMED_OUT = (
    "Stopped by the job timeout (40 s, core.job_timeout) 41 s into the run, in the report "
    "stage. The report kept is partial: it holds what the run produced before it stopped, "
    "and nothing the run would have done after it."
)


def _scenario(scenario: str, *reasons: str) -> RunRecord:
    record = _record(*reasons)
    record.scenario = scenario
    return record


def test_a_fault_scenario_passes_on_the_reason_it_declares(tmp_path: Path) -> None:
    assert write_results([_scenario("cut_at_cap", CUT)], tmp_path) == 0
    assert write_results([_scenario("deadline_hit", TIMED_OUT)], tmp_path) == 0


def test_a_fault_scenario_fails_on_a_reason_it_does_not_declare(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert write_results([_scenario("cut_at_cap", CUT, CAPA)], tmp_path) == 1
    assert f"  DEGRADED {CAPA}" in capsys.readouterr().out
    # Another fault's reason is not this one's.
    assert degradations_not_allowed(_scenario("deadline_hit", CUT)) == [CUT]
    assert degradations_not_allowed(_scenario("empty_answer", CUT)) == [CUT]


def test_the_normal_scenario_may_carry_no_reason_at_all(tmp_path: Path) -> None:
    assert write_results([_scenario("normal", CUT)], tmp_path) == 1
    assert write_results([_scenario("normal", TIMED_OUT)], tmp_path) == 1


def test_the_operator_flag_still_allows_a_named_reason_beside_the_declared(
    tmp_path: Path,
) -> None:
    record = _scenario("cut_at_cap", CUT, CAPA)
    assert write_results([record], tmp_path, ["server.analysis.capa_unavailable"]) == 0


def test_a_declared_names_placeholders_match_only_their_kind() -> None:
    from scripts.rehearsal.run import name_matches

    assert name_matches("{n} rule match carry", "12 rule match carry")
    assert not name_matches("{n} rule match carry", "many rule match carry")
    assert name_matches("section '{section}' gone", "section 'cli_flags' gone")
    assert not name_matches("section '{section}' gone", "section 'cli flags' gone")
    assert not name_matches("triage.capa_failed", "triage.capa_failed and more")


def test_every_declared_scenario_is_a_fault_scenario() -> None:
    from scripts.rehearsal.roles import SCENARIO_DEGRADATIONS, SCENARIOS

    assert set(SCENARIO_DEGRADATIONS) <= set(SCENARIOS) - {"normal"}


# T-338: what the operator's configuration left out, in the words its producers write.
UNSET = (
    "server.threatintel.check_hash_unavailable(VIRUSTOTAL_API_KEY is not configured); "
    "set the credential or setting this tool needs in Settings and run the probe again"
)


def _withheld() -> str:
    from maljan.providers.sample_open import UNCOVERED, withheld_unpinned

    return withheld_unpinned("remote http://localhost:8089 (backend 1)", "open_project", UNCOVERED)


def test_an_operator_choice_fails_nothing_and_is_named(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    record = _record()
    record.run_summary["operator_choices"] = [UNSET]
    assert write_results([record], tmp_path) == 0
    shown = capsys.readouterr().out
    assert "run 1: PASS" in shown
    assert f"  NOT CONFIGURED OR WITHHELD BY CHOICE {UNSET}" in shown
    result = json.loads((tmp_path / "normal-run1.json").read_text())
    assert result["operator_choices"] == [UNSET]


def test_a_record_that_lists_a_choice_among_its_reasons_is_read_as_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A record written before the choices were listed apart is gated as a current one.

    A withheld tool's sentence says what it is. An unset key's sentence with
    no manifest code behind it is a loss, and the gate fails on it.
    """
    withheld = _withheld()
    assert degradations_not_allowed(_record(withheld, UNSET, CAPA)) == [UNSET, CAPA]
    assert write_results([_record(withheld)], tmp_path) == 0
    shown = capsys.readouterr().out
    assert f"  NOT CONFIGURED OR WITHHELD BY CHOICE {withheld}" in shown
    assert "DEGRADED" not in shown
