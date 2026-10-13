"""Whether a stored report had its task reports is read from the provider's own declaration.

A report that does not say what its reader read was taken to have had task
reports when its provider id was one a reader held in a table of ids. The
provider now declares it (``SandboxProvider.FETCHES_TASK_REPORTS``), so any
provider that fetches them is read the same way and an id no provider is
registered under is read as an overview alone.
"""

from __future__ import annotations

import pytest

from maljan.providers import registry
from maljan.providers.base import SandboxProvider
from maljan.providers.sandbox.readers import fetches_task_reports, report_reader
from maljan.schemas.sandbox_report import TRIAGE_NORMALISER_FILLS, TRIAGE_OVERVIEW_FILLS


def test_the_shipped_provider_that_fetches_them_says_so() -> None:
    assert fetches_task_reports("triage") is True
    for other in ("upload", "cape2", "mock", "rest"):
        assert fetches_task_reports(other) is False


def test_an_unregistered_id_reads_as_an_overview_alone() -> None:
    reader = report_reader("triage")
    assert reader is not None
    reading = reader.reading("", "a-provider-since-removed")
    assert reading.fills == TRIAGE_OVERVIEW_FILLS
    assert reading.partial


def test_any_provider_that_declares_it_is_read_as_having_had_them(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Fetching(SandboxProvider):
        FETCHES_TASK_REPORTS = True

    registry.discover_providers()
    monkeypatch.setitem(registry._SANDBOX_REGISTRY, "another-cloud", _Fetching)
    reader = report_reader("triage")
    assert reader is not None
    assert reader.reading("", "another-cloud").fills == TRIAGE_NORMALISER_FILLS
    # What the report says it read always decides.
    assert reader.reading("overview", "another-cloud").fills == TRIAGE_OVERVIEW_FILLS
