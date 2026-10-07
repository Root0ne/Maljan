"""Report text stating persistence the sandbox did not record is asked about once.

The Persistence section printed "no persistence observed" under its own prose
saying the sample persists through two mechanisms, and an execution-flow step
marked observed stated the same persistence: nothing put the contradiction to
the report model. When the sandbox watched the registry and the files and
recorded no persistence, the section's prose stating persistence with no word
that it was not observed, and each observed step stating it, are asked once.
What the model answers stands.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.validation import (
    FLOW_VOICE_CODE,
    KEPT_WITH_A_FINDING,
    PERSISTENCE_NOT_OBSERVED_CODE,
    persistence_not_observed_violations,
)
from maljan.reporting.evidence_bundles import sandbox_saw_no_persistence
from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    MalwareReport,
    PersistenceMechanism,
    SampleIdentity,
)

STATES = "The program persists through a logon task it registers at first run [ev_0004]."


def _report(**over: Any) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        **over,
    )


class TestTheFact:
    def test_a_sandbox_that_watched_and_recorded_none_saw_none(self) -> None:
        assert sandbox_saw_no_persistence(_report(dynamic=DynamicBehavior()))

    def test_no_sandbox_is_no_fact(self) -> None:
        assert not sandbox_saw_no_persistence(_report())

    def test_a_sandbox_blind_to_the_registry_is_no_fact(self) -> None:
        report = _report(dynamic=DynamicBehavior(unavailable=["registry"]))

        assert not sandbox_saw_no_persistence(report)

    def test_a_recorded_mechanism_is_no_fact(self) -> None:
        report = _report(
            dynamic=DynamicBehavior(),
            persistence=[PersistenceMechanism(kind="scheduled_task", target="updater")],
        )

        assert not sandbox_saw_no_persistence(report)


class TestTheSection:
    def test_prose_stating_persistence_is_asked_once(self) -> None:
        (found,) = persistence_not_observed_violations(
            {"body": f"{STATES} It also persists by a second route."},
            True,
            section="persistence_detail",
        )

        assert found.code == PERSISTENCE_NOT_OBSERVED_CODE
        assert '"The program persists through a logon' in found.message
        assert "no persistence observed" in found.message

    def test_prose_saying_it_was_not_observed_is_not_asked(self) -> None:
        body = f"{STATES} The task was not observed in this run's sandbox."

        assert (
            persistence_not_observed_violations({"body": body}, True, section="persistence_detail")
            == []
        )

    def test_prose_stating_absence_is_not_asked(self) -> None:
        body = "The file holds no persistence mechanism [ev_0004]."

        assert (
            persistence_not_observed_violations({"body": body}, True, section="persistence_detail")
            == []
        )

    def test_without_the_fact_nothing_is_asked(self) -> None:
        assert (
            persistence_not_observed_violations(
                {"body": STATES}, False, section="persistence_detail"
            )
            == []
        )

    def test_a_kept_answer_ships_with_the_finding(self) -> None:
        assert PERSISTENCE_NOT_OBSERVED_CODE in KEPT_WITH_A_FINDING


class TestTheFlow:
    def _steps(self, voice: str) -> dict[str, Any]:
        return {
            "steps": [
                {"order": 1, "action": "Decodes its strings.", "voice": "observed"},
                {"order": 2, "action": STATES, "voice": voice, "evidence_refs": ["ev_0014"]},
            ]
        }

    def test_an_observed_step_stating_persistence_is_asked(self) -> None:
        (found,) = persistence_not_observed_violations(
            self._steps("observed"), True, section="execution_flow"
        )

        assert found.code == FLOW_VOICE_CODE
        assert found.path == "steps.1.voice"
        assert found.message.startswith("step 2 is marked observed and states persistence")

    def test_an_assessed_step_is_not_asked(self) -> None:
        assert (
            persistence_not_observed_violations(
                self._steps("assessed"), True, section="execution_flow"
            )
            == []
        )
