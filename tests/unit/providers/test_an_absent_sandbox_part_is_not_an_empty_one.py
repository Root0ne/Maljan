"""A part the sandbox report does not hold reads as absent, not as empty.

``{"processes": [], "total": 0}`` says the sandbox watched and saw no process;
for a report with no process list at all it said something nobody observed.
An absent part is named as absent, and a present empty part still answers its
empty list.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.providers.sandbox_tools import (
    NETWORK_VIEW_KINDS,
    sandbox_api_calls,
    sandbox_dropped_files,
    sandbox_mutexes,
    sandbox_network,
    sandbox_processes,
    sandbox_registry_ops,
    sandbox_services_and_tasks,
    sandbox_signatures,
)

_OTHER = {"target": {"file": {"sha256": "a" * 64}}, "cti": {"x": 1}}

VIEWS = [
    (sandbox_processes, "processes", {"behavior": {"processes": []}}),
    (sandbox_signatures, "signatures", {"signatures": []}),
    (sandbox_dropped_files, "dropped", {"dropped": []}),
]


@pytest.mark.parametrize(("view", "key", "_empty"), VIEWS)
def test_an_absent_part_is_named_absent(view: Any, key: str, _empty: Any) -> None:
    answer = view(dict(_OTHER))
    assert answer.get("absent")
    assert key not in answer
    assert "total" not in answer


@pytest.mark.parametrize(("view", "key", "empty"), VIEWS)
def test_a_present_empty_part_is_still_empty(view: Any, key: str, empty: Any) -> None:
    answer = view({**_OTHER, **empty})
    assert answer[key] == []
    assert answer["total"] == 0
    assert "absent" not in answer


def test_an_absent_network_section_is_not_no_network_activity() -> None:
    answer = sandbox_network(dict(_OTHER))
    assert answer.get("absent") == ["network"]
    for kind in ("dns", "hosts", "http", "tcp", "udp"):
        assert kind not in answer


def test_a_network_kind_the_report_lacks_is_named_absent() -> None:
    answer = sandbox_network({**_OTHER, "network": {"dns": [], "http": []}})
    assert answer["dns"] == [] and answer["http"] == []
    assert "network.tcp" in answer["absent"]
    assert "network.dns" not in answer["absent"]


def test_a_full_network_section_names_nothing_absent() -> None:
    answer = sandbox_network({**_OTHER, "network": {k: [] for k in NETWORK_VIEW_KINDS}})
    assert "absent" not in answer


# --- Parts a reader lays out empty and names in the report's ``unavailable`` list.


def _laid_out(*unavailable: str) -> dict[str, Any]:
    """A neutral document from a reader whose sandbox could not give ``unavailable``."""
    from maljan.schemas.sandbox_document import sandbox_document
    from maljan.schemas.sandbox_report import SandboxReport

    return sandbox_document(
        SandboxReport(provider="rest", source_format="rest", unavailable=list(unavailable))
    )


@pytest.mark.parametrize(
    ("view", "part"),
    [
        (sandbox_processes, "processes"),
        (sandbox_signatures, "signatures"),
        (sandbox_dropped_files, "dropped_files"),
    ],
)
def test_a_part_named_unavailable_is_absent_though_laid_out_empty(view: Any, part: str) -> None:
    assert view(_laid_out(part))["absent"] == [part]


def test_a_network_kind_named_unavailable_is_absent_by_either_name() -> None:
    answer = sandbox_network(_laid_out("dns", "network.http"))
    assert answer["absent"] == ["network.dns", "network.http"]
    assert "dns" not in answer and "http" not in answer
    assert answer["tcp"] == []


def test_network_named_unavailable_is_the_whole_section_absent() -> None:
    assert sandbox_network(_laid_out("network"))["absent"] == ["network"]


def test_a_laid_out_report_naming_nothing_unavailable_still_answers_empty() -> None:
    document = _laid_out()
    assert sandbox_processes(document) == {"processes": [], "total": 0}
    assert "absent" not in sandbox_network(document)


# --- The views that read several sources: absent only when none is held.

MULTI = [
    (sandbox_registry_ops, ["registry", "calls"]),
    (sandbox_api_calls, ["apistats", "calls"]),
    (sandbox_mutexes, ["summary.mutexes", "calls"]),
    (
        sandbox_services_and_tasks,
        [
            "summary.created_services",
            "summary.started_services",
            "summary.executed_commands",
            "calls",
        ],
    ),
]


@pytest.mark.parametrize(("view", "sources"), MULTI)
def test_a_view_with_none_of_its_sources_names_them_absent(view: Any, sources: list[str]) -> None:
    assert view(dict(_OTHER))["absent"] == sources


@pytest.mark.parametrize(("view", "_sources"), MULTI)
def test_one_held_source_is_enough_for_an_answer(view: Any, _sources: list[str]) -> None:
    report = {**_OTHER, "behavior": {"processes": [{"pid": 4, "calls": []}]}}
    assert "absent" not in view(report)


def test_a_sandbox_without_call_logs_answers_api_calls_and_registry_absent() -> None:
    """Triage names ``apistats``, ``calls`` and ``registry`` unavailable."""
    document = _laid_out("apistats", "calls", "registry")
    assert sandbox_api_calls(document)["absent"] == ["apistats", "calls"]
    assert sandbox_registry_ops(document)["absent"] == ["registry", "calls"]
    # Its summary's mutex list is laid out and not named: held, so answered.
    assert sandbox_mutexes(document) == {"mutexes": [], "total": 0}


# --- Parts the job's reader declares it never fills (``Reading.fills``).


def _read_by(provider: str, source_format: str, *unavailable: str) -> tuple[dict, tuple]:
    """A laid-out document and the ``normalised_by`` of the reader that made it."""
    from maljan.schemas.sandbox_document import sandbox_document
    from maljan.schemas.sandbox_report import SandboxReport, reader_of, section_id

    report = SandboxReport(
        provider=provider,
        source_format=source_format,
        unavailable=sorted({section_id(name) for name in unavailable}),
    )
    return sandbox_document(report), reader_of(report)


def test_a_rest_mapping_never_fills_tls_icmp_or_the_summary() -> None:
    """The reviewer's p4: every channel mapped but ``calls``."""
    document, by = _read_by("rest", "generic", "calls", "apistats", "generic_events", "screenshots")
    network = sandbox_network(document, normalised_by=by)
    assert {"network.tls", "network.icmp"} <= set(network["absent"])
    assert "tls" not in network and "icmp" not in network
    assert network["dns"] == []  # filled by the mapping, and empty
    assert sandbox_mutexes(document, normalised_by=by)["absent"] == ["summary.mutexes", "calls"]
    assert "absent" in sandbox_services_and_tasks(document, normalised_by=by)
    assert sandbox_api_calls(document, normalised_by=by)["absent"] == ["apistats", "calls"]


def test_triage_reads_absent_what_its_reader_never_fills() -> None:
    from maljan.providers.sandbox.triage import TriageSandboxProvider
    from maljan.schemas.sandbox_report import TRIAGE_NORMALISER_FILLS

    document, by = _read_by("triage", "triage", *TriageSandboxProvider.UNAVAILABLE)
    for view in (sandbox_mutexes, sandbox_registry_ops, sandbox_services_and_tasks):
        answer = view(document, normalised_by=by)
        held = [s for s in answer.get("absent", []) if s in TRIAGE_NORMALISER_FILLS]
        assert "absent" in answer and not held


def test_a_part_the_reader_fills_and_found_empty_stays_empty() -> None:
    document, by = _read_by("rest", "generic")
    assert sandbox_processes(document, normalised_by=by) == {"processes": [], "total": 0}
    assert sandbox_signatures(document, normalised_by=by) == {"signatures": [], "total": 0}


def test_the_cape_reader_is_unaffected_by_its_declaration() -> None:
    """CAPE's reader fills every list field: naming it changes no answer."""
    from maljan.providers.sandbox.readers import required_reader
    from maljan.schemas.sandbox_document import sandbox_document
    from maljan.schemas.sandbox_report import reader_of
    from tests.unit.providers._cape_fixture import first_cape_report

    report = required_reader("cape2").read(first_cape_report(), provider="cape2", task_id="1")
    document, by = sandbox_document(report), reader_of(report)
    for view in (
        sandbox_processes,
        sandbox_network,
        sandbox_signatures,
        sandbox_dropped_files,
        sandbox_registry_ops,
        sandbox_api_calls,
        sandbox_mutexes,
        sandbox_services_and_tasks,
    ):
        assert view(document, normalised_by=by) == view(document)
