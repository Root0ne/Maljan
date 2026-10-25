"""The completed event's facts are read under the key each surface serves them.

``GET /jobs/{id}/events`` serves an event as ``{"type", "data", "ts"}``; a
stored run's ``events.json`` is the table's rows, with ``payload``. The
checker reads the verdict, the confidence and the report id from either, so a
live job whose completed event carries them is clean, and one whose event says
otherwise is a defect on the events surface.
"""

from __future__ import annotations

from typing import Any

from scripts.audit import surfaces

from tests.unit.scripts._surfaces_run import clean_run, clean_spec, defects


def _served(run: dict[str, Any]) -> dict[str, Any]:
    run["events"] = [
        {"type": e["type"], "data": e["payload"], "ts": "2026-10-25T00:00:00+00:00"}
        for e in run["events"]
    ]
    return run


def test_a_served_completed_event_agrees() -> None:
    result = surfaces.audit(_served(clean_run()), clean_spec())

    assert defects(result) == []
    assert result["checked"]["identity"] > 0


def test_a_served_completed_event_that_disagrees_is_named() -> None:
    run = _served(clean_run())
    run["events"][-1]["data"].update(verdict="Benign", confidence=0.5, report_id="other")

    result = surfaces.audit(run, clean_spec())

    assert sorted(defects(result)) == [
        ("differs", "confidence", "events"),
        ("differs", "identity", "events"),
        ("differs", "verdict", "events"),
    ]
