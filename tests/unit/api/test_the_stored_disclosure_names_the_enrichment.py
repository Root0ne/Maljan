"""The stored run's disclosure block names the enrichment that follows it, then what it asked.

Two stages, one record. When the worker stores a report with enrichment on,
the record names the follow-up job and what it may reach (RDAP, which needs no
key, and every configured source), in the run summary and in the report
payload every served rendering is made from, and never says that nothing left.
The enrichment job then adds what it asked to both. A run whose record was not
built stores why, so it is told apart from a run stored before the block.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.worker.analysis_worker import _report_inputs, enrichment_plan
from maljan.analysis.disclosure import (
    ENRICHMENT_SOURCES_UNREAD,
    NOT_BUILT_NO_SUMMARY,
    NOT_BUILT_REPORTING_OFF,
    NOT_BUILT_UNREAD,
    disclosure_lines,
    disclosure_record,
    rdap_row,
)
from maljan.core.config import Settings
from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer


def _key(*parts: str) -> str:
    """A credential-shaped value built at run time."""
    return "-".join(parts)


def _local_record() -> dict[str, Any]:
    record = disclosure_record(
        {
            "llm.provider": "openai",
            "llm.openai.base_url": "http://127.0.0.1:8080/v1",
            "memory.backend": "memory",
        },
        tokens={
            "llm_calls": 1,
            "per_agent": {
                "judge": {"llm_calls": 1, "models": {"openai/q @ http://127.0.0.1:8080": 1}}
            },
        },
        agents=["judge"],
        runtimes={"http://127.0.0.1:8080": "llama.cpp /props"},
    )
    assert record["nothing_left"] is True
    return record


def _payload(record: dict[str, Any]) -> dict[str, Any]:
    return MalwareReport.model_validate(
        {
            "identity": {"hashes": {"sha256": "a" * 64}},
            "verdict": "Malware",
            "run_summary": {"final_decision": "Malware", "disclosure": record},
            "generated_at": "2026-09-01T00:00:00Z",
        }
    ).model_dump(mode="json")


def _state(record: dict[str, Any] | None) -> dict[str, Any]:
    summary = {"final_decision": "Malware"}
    if record is not None:
        summary["disclosure"] = record
    return {
        "run_summary": summary,
        "malware_report": _payload(record) if record is not None else None,
    }


def _served(payload: dict[str, Any]) -> str:
    return MarkdownRenderer().render(MalwareReport.model_validate(payload))


def _inputs(state: dict[str, Any], settings: Settings | None = None, **over: Any) -> dict:
    _bundle, summary = _report_inputs(
        state,
        core_settings=settings or Settings(_env_file=None),
        override_keys=(),
        hash_mismatch_reason=None,
        **over,
    )
    return summary


# ---------------------------------------------------------------------------
# The worker's stage: the follow-up job, named
# ---------------------------------------------------------------------------


def test_a_queued_enrichment_is_named_in_the_summary_and_the_served_report() -> None:
    state = _state(_local_record())

    summary = _inputs(state, enrichment=[rdap_row()])

    for record in (summary["disclosure"], state["malware_report"]["run_summary"]["disclosure"]):
        assert record["nothing_left"] is False
        assert record["enrichment"]["state"] == "queued"
        assert [row["source"] for row in record["enrichment"]["may_reach"]] == ["rdap"]
        assert "rdap.arin.net" in record["addressed"]
    served = _served(state["malware_report"])
    assert "Nothing left this machine" not in served
    assert (
        "Enrichment: a follow-up job queued after this report may send the report's public "
        "domains and addresses to RDAP (ip) at `rdap.arin.net`"
    ) in served


def test_no_enrichment_queued_leaves_the_record_as_the_run_closed_it() -> None:
    record = _local_record()
    state = _state(record)

    summary = _inputs(state)

    assert summary["disclosure"] == record
    assert state["malware_report"]["run_summary"]["disclosure"] == record


@pytest.mark.parametrize(
    ("state", "reporting", "reason"),
    [
        ({"run_summary": {"final_decision": "Malware"}}, False, NOT_BUILT_REPORTING_OFF),
        ({"run_summary": None}, True, NOT_BUILT_NO_SUMMARY),
        ({"run_summary": {"final_decision": "Malware"}}, True, NOT_BUILT_UNREAD),
    ],
)
def test_a_run_whose_record_was_not_built_stores_why(
    state: dict[str, Any], reporting: bool, reason: str
) -> None:
    settings = Settings.model_validate({"reporting": {"enabled": reporting}})

    summary = _inputs(state, settings, enrichment=[rdap_row()])

    assert summary["disclosure"] == {"not_built": reason}
    assert disclosure_lines(summary["disclosure"]) == []


@pytest.mark.asyncio
async def test_the_plan_is_none_while_enrichment_is_off() -> None:
    with patch("app.worker.analysis_worker.runtime_config.get", AsyncMock(return_value=False)):
        assert await enrichment_plan(Settings(_env_file=None)) is None


@pytest.mark.asyncio
async def test_the_plan_names_rdap_and_every_configured_source() -> None:
    stored = {"abuseipdb": {"enabled": False}}
    values = {"enrichment_enabled": True, "enrichment_sources": stored}

    with (
        patch(
            "app.worker.analysis_worker.runtime_config.get",
            AsyncMock(side_effect=lambda name: values[name]),
        ),
        patch(
            "app.services.enrichment_sources.read_setting_secret",
            AsyncMock(return_value=_key("vt", "k")),
        ),
    ):
        plan = await enrichment_plan(Settings(_env_file=None))

    assert plan is not None
    assert [(row["source"], row["hosts"], row["kinds"]) for row in plan] == [
        ("rdap", ["rdap.arin.net"], ["ip"]),
        ("virustotal", ["www.virustotal.com"], ["domain", "ip"]),
    ]


@pytest.mark.asyncio
async def test_a_plan_that_cannot_be_read_still_says_the_sources_may_be_asked() -> None:
    values = {"enrichment_enabled": True}

    with (
        patch(
            "app.worker.analysis_worker.runtime_config.get",
            AsyncMock(side_effect=lambda name: values[name]),
        ),
    ):
        plan = await enrichment_plan(Settings(_env_file=None))

    assert plan is not None
    assert plan[0]["source"] == "rdap"
    assert (plan[1]["source"], plan[1]["why"]) == ("", ENRICHMENT_SOURCES_UNREAD)


@pytest.mark.asyncio
async def test_the_reach_places_a_server_source_by_its_servers_block() -> None:
    from types import SimpleNamespace

    from app.services.enrichment_sources import enrichment_reach

    stored = {
        "virustotal": {"enabled": False},
        "abuseipdb": {"enabled": False},
        "intel": {
            "kinds": ["domain"],
            "server": "far",
            "tool": "lookup",
            "arguments": {"domain": "name"},
            "record": [{"name": "malicious", "path": "/malicious", "read": "count"}],
        },
    }
    servers = {
        "far": SimpleNamespace(
            enabled=True, transport="streamable-http", url="https://intel.example.org/mcp"
        )
    }

    reach = await enrichment_reach(stored, AsyncMock(return_value=""), servers)

    assert [(row["source"], row["server"], row["hosts"], row["where"]) for row in reach] == [
        ("rdap", "", ["rdap.arin.net"], "remote"),
        ("intel", "far", ["intel.example.org"], "remote"),
    ]


# ---------------------------------------------------------------------------
# The enrichment job's stage: what it asked, added
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_enrichment_job_adds_what_it_asked_to_the_stored_record() -> None:
    from app.worker.enrich_worker import enrich_threat_intel

    queued = _inputs(state := _state(_local_record()), enrichment=[rdap_row()])
    report = MagicMock()
    report.id = uuid.uuid4()
    report.job_id = uuid.uuid4()
    report.malware_report = {
        **state["malware_report"],
        "network": {"domains": [], "ips": [{"address": "1.2.3.4"}]},
    }
    report.run_summary = queued

    async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        settle = await kwargs["on_ask"]("rdap", "rdap.arin.net", "ip", "")
        settle(True)
        return payload

    db = MagicMock()
    db.get = AsyncMock(return_value=report)
    db.commit = AsyncMock()
    session = AsyncMock()
    session.__aenter__.return_value = db
    session.__aexit__.return_value = None
    values = {"enrichment_enabled": True, "enrichment_max_lookups": 25, "enrichment_sources": {}}
    with (
        patch("maljan.enrichment.enrich_malware_report", new=AsyncMock(side_effect=_lookups)),
        patch(
            "app.worker.enrich_worker.runtime_config.get",
            AsyncMock(side_effect=lambda name: values[name]),
        ),
        patch("app.worker.enrich_worker.runtime_config.get_secret", AsyncMock(return_value="")),
        patch("app.worker.enrich_worker._get_memory_store", AsyncMock(return_value=None)),
    ):
        result = await enrich_threat_intel(
            {"redis": AsyncMock(), "db_session": MagicMock(return_value=session)}, str(report.id)
        )

    assert result["status"] == "ok"
    for record in (
        report.run_summary["disclosure"],
        report.malware_report["run_summary"]["disclosure"],
    ):
        assert record["enrichment"]["state"] == "done"
        assert record["enrichment"]["asked"] == [
            {
                "source": "rdap",
                "host": "rdap.arin.net",
                "where": "remote",
                "kinds": {"ip": 1},
                "failed": 0,
                "why": "",
            }
        ]
        assert record["nothing_left"] is False
    assert (
        "Enrichment: the follow-up job asked `rdap.arin.net` (outside this machine) about ip 1 "
        "(RDAP)."
    ) in _served(report.malware_report)


def test_a_report_stored_before_the_block_is_left_as_it_was() -> None:
    from app.worker.enrich_worker import disclosed_enrichment

    payload = {"run_summary": {"final_decision": "Malware"}, "network": {}}
    asked = [{"source": "rdap", "host": "rdap.arin.net", "kinds": {"ip": 1}, "why": ""}]

    updated, column = disclosed_enrichment(payload, {"final_decision": "Malware"}, asked)

    assert updated == payload
    assert column is None


# ---------------------------------------------------------------------------
# An enrichment on demand that fails or is stopped part-way
# ---------------------------------------------------------------------------


def _row_built_with_enrichment_off() -> Any:
    """A stored report whose record says nothing left: built while enrichment was off."""
    record = _local_record()
    row = MagicMock()
    row.id = uuid.uuid4()
    row.job_id = uuid.uuid4()
    row.malware_report = {
        **_payload(record),
        "network": {"domains": [{"fqdn": "evil.example.com"}], "ips": [{"address": "1.2.3.4"}]},
    }
    row.run_summary = {"final_decision": "Malware", "disclosure": record}
    return row


async def _enrich_on_demand(row: Any, lookups: Any) -> dict[str, Any]:
    from app.worker.enrich_worker import enrich_threat_intel

    db = MagicMock()
    db.get = AsyncMock(return_value=row)
    db.commit = AsyncMock()
    session = AsyncMock()
    session.__aenter__.return_value = db
    session.__aexit__.return_value = None
    values = {"enrichment_enabled": True, "enrichment_max_lookups": 25, "enrichment_sources": {}}
    with (
        patch("maljan.enrichment.enrich_malware_report", new=AsyncMock(side_effect=lookups)),
        patch(
            "app.worker.enrich_worker.runtime_config.get",
            AsyncMock(side_effect=lambda name: values[name]),
        ),
        patch("app.worker.enrich_worker.runtime_config.get_secret", AsyncMock(return_value="")),
        patch("app.worker.enrich_worker._get_memory_store", AsyncMock(return_value=None)),
    ):
        return await enrich_threat_intel(
            {"redis": AsyncMock(), "db_session": MagicMock(return_value=session)}, str(row.id)
        )


def _records(row: Any) -> list[dict[str, Any]]:
    return [row.run_summary["disclosure"], row.malware_report["run_summary"]["disclosure"]]


@pytest.mark.asyncio
async def test_nothing_is_cleared_before_the_first_question_goes_out() -> None:
    row = _row_built_with_enrichment_off()
    assert all(record["nothing_left"] for record in _records(row))
    seen: list[list[Any]] = []

    async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        settle = await kwargs["on_ask"]("rdap", "rdap.arin.net", "ip", "")
        # The question is about to be sent: what the stored report says now.
        seen.append([(r["nothing_left"], r["enrichment"]["state"]) for r in _records(row)])
        settle(True)
        return payload

    await _enrich_on_demand(row, _lookups)

    assert seen == [[(False, "running"), (False, "running")]]


@pytest.mark.asyncio
async def test_a_job_that_fails_part_way_leaves_what_it_asked() -> None:
    row = _row_built_with_enrichment_off()

    async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        (await kwargs["on_ask"]("rdap", "rdap.arin.net", "ip", ""))(True)
        await kwargs["on_ask"]("intel", "api.intel.example", "domain", "")
        raise RuntimeError("the source closed the connection")

    result = await _enrich_on_demand(row, _lookups)

    assert result["status"] == "error"
    for record in _records(row):
        assert record["nothing_left"] is False
        assert record["enrichment"]["state"] == "stopped"
        assert [(r["source"], r["kinds"], r["failed"]) for r in record["enrichment"]["asked"]] == [
            ("intel", {"domain": 1}, 1),
            ("rdap", {"ip": 1}, 0),
        ]
    served = _served(row.malware_report)
    assert "Nothing left this machine" not in served
    assert "Enrichment: the follow-up job stopped part-way after asking" in served


@pytest.mark.asyncio
async def test_a_job_stopped_by_its_timeout_leaves_what_it_asked() -> None:
    import asyncio

    row = _row_built_with_enrichment_off()

    async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        await kwargs["on_ask"]("rdap", "rdap.arin.net", "ip", "")
        raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await _enrich_on_demand(row, _lookups)

    for record in _records(row):
        assert record["nothing_left"] is False
        assert record["enrichment"]["state"] == "stopped"
        assert [(r["source"], r["failed"]) for r in record["enrichment"]["asked"]] == [("rdap", 1)]


@pytest.mark.asyncio
async def test_a_job_that_asked_nothing_before_failing_leaves_the_record_as_it_was() -> None:
    row = _row_built_with_enrichment_off()
    before = [dict(record) for record in _records(row)]

    async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("no source configured")

    await _enrich_on_demand(row, _lookups)

    assert _records(row) == before
