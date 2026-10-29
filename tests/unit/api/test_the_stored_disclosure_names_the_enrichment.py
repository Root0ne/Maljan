"""The stored run's disclosure block names the enrichment that follows it, then what it asked.

Two stages, one record. When the worker stores a report with enrichment on,
the record names the follow-up job and what it may reach (RDAP, which needs no
key, and every configured source), in the run summary and in the report
payload every served rendering is made from, and never says that nothing left.
The enrichment job then adds what it asked to both. A run whose record was not
built stores why, so it is told apart from a run stored before the block.
"""

from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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
    values = {
        "enrichment_enabled": True,
        "enrichment_sources": stored,
        "enrichment_reputation_servers": False,
    }

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
    values = {
        "enrichment_enabled": True,
        "enrichment_max_lookups": 25,
        "enrichment_sources": {},
        "enrichment_reputation_servers": False,
    }
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
        "(RDAP, the ARIN bootstrap alone: a referral to a regional registry is not followed)."
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
    values = {
        "enrichment_enabled": True,
        "enrichment_max_lookups": 25,
        "enrichment_sources": {},
        "enrichment_reputation_servers": False,
    }
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


@pytest.mark.asyncio
async def test_two_enrichments_of_one_report_at_once_lose_no_row() -> None:
    """Each write re-reads the row under its lock and merges; neither run's rows are lost."""
    import asyncio

    from app.worker.enrich_worker import enrich_threat_intel

    row = _row_built_with_enrichment_off()
    held = asyncio.Lock()

    class _Session:
        """One session over the shared row; ``get(..., with_for_update=True)`` holds the lock."""

        def __init__(self) -> None:
            self.locked = False

        async def __aenter__(self) -> Any:
            return self

        async def __aexit__(self, *exc: Any) -> bool:
            self._release()
            return False

        def _release(self) -> None:
            if self.locked:
                self.locked = False
                held.release()

        async def get(self, _model: Any, _key: Any, **kwargs: Any) -> Any:
            if kwargs.get("with_for_update"):
                await held.acquire()
                self.locked = True
                await asyncio.sleep(0)
            # A row read anew, as the database would hand it back.
            fresh = MagicMock()
            fresh.id, fresh.job_id = row.id, row.job_id
            fresh.malware_report = dict(row.malware_report)
            fresh.run_summary = dict(row.run_summary)
            self.fresh = fresh
            return fresh

        async def commit(self) -> None:
            row.malware_report = self.fresh.malware_report
            row.run_summary = self.fresh.run_summary
            await asyncio.sleep(0)
            self._release()

    gate = asyncio.Event()

    def _lookups_for(source: str, host: str, address: str) -> Any:
        async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            (await kwargs["on_ask"](source, host, "ip", ""))(True)
            await gate.wait()
            enriched = {**payload, "network": dict(payload["network"])}
            enriched["network"]["ips"] = [
                {**ip, "reputation": {"source": source}} if ip["address"] == address else ip
                for ip in payload["network"]["ips"]
            ]
            return enriched

        return _lookups

    row.malware_report["network"]["ips"] = [{"address": "1.2.3.4"}, {"address": "5.6.7.8"}]
    values = {
        "enrichment_enabled": True,
        "enrichment_max_lookups": 25,
        "enrichment_sources": {},
        "enrichment_reputation_servers": False,
    }
    runs = iter(
        [
            _lookups_for("rdap", "rdap.arin.net", "1.2.3.4"),
            _lookups_for("intel", "api.intel.example", "5.6.7.8"),
        ]
    )

    async def _either(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return await next(runs)(payload, **kwargs)

    async def _open_gate() -> None:
        await asyncio.sleep(0.05)
        gate.set()

    ctx = {"redis": AsyncMock(), "db_session": _Session}
    with (
        patch("maljan.enrichment.enrich_malware_report", new=AsyncMock(side_effect=_either)),
        patch(
            "app.worker.enrich_worker.runtime_config.get",
            AsyncMock(side_effect=lambda name: values[name]),
        ),
        patch("app.worker.enrich_worker.runtime_config.get_secret", AsyncMock(return_value="")),
        patch("app.worker.enrich_worker._get_memory_store", AsyncMock(return_value=None)),
    ):
        results = await asyncio.gather(
            enrich_threat_intel(ctx, str(row.id)),
            enrich_threat_intel(ctx, str(row.id)),
            _open_gate(),
        )

    assert [r["status"] for r in results[:2]] == ["ok", "ok"]
    for record in _records(row):
        assert sorted(r["source"] for r in record["enrichment"]["asked"]) == ["intel", "rdap"]
    reputations = {
        ip["address"]: ip.get("reputation") for ip in row.malware_report["network"]["ips"]
    }
    assert reputations == {"1.2.3.4": {"source": "rdap"}, "5.6.7.8": {"source": "intel"}}


@pytest.mark.asyncio
async def test_a_disclosure_entry_written_during_the_lookups_survives_the_write() -> None:
    """The job's snapshot is taken before its lookups; the write merges into the row as locked."""
    from maljan.analysis.disclosure import with_enrichment_asked

    row = _row_built_with_enrichment_off()
    other = {"source": "misp", "host": "misp.example.org", "kinds": {"domain": 1}, "why": ""}

    async def _lookups(payload: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        (await kwargs["on_ask"]("rdap", "rdap.arin.net", "ip", ""))(True)
        # Another writer adds a disclosure entry after the snapshot was taken.
        row.run_summary = {
            **row.run_summary,
            "disclosure": with_enrichment_asked(row.run_summary["disclosure"], [other]),
        }
        stored = row.malware_report["run_summary"]
        row.malware_report = {
            **row.malware_report,
            "run_summary": {
                **stored,
                "disclosure": with_enrichment_asked(stored["disclosure"], [other]),
            },
        }
        return payload

    result = await _enrich_on_demand(row, _lookups)

    assert result["status"] == "ok"
    for record in _records(row):
        assert sorted(r["source"] for r in record["enrichment"]["asked"]) == ["misp", "rdap"]


@pytest.mark.asyncio
async def test_a_sandbox_context_shell_takes_the_live_record_as_dev_stores_it() -> None:
    """An older report's reputation holds sandbox context and no source; the live record wins."""
    from app.worker.enrich_worker import enrichment_laid_over
    from maljan.enrichment.declared import ReadySource, effective_sources
    from maljan.enrichment.orchestrator import enrich_malware_report

    shell = {"hostname": "c2.example.com", "contacted_ports": [443]}
    before = {"network": {"domains": [], "ips": [{"address": "1.2.3.4", "reputation": shell}]}}
    source = effective_sources({"virustotal": {"rate_limit_seconds": 0.0}})["virustotal"]
    ready = ReadySource(key="virustotal", source=source, credential="-".join(("vt", "k")))

    def _answer(request: httpx.Request) -> httpx.Response:
        stats = {"malicious": 9, "suspicious": 0}
        return httpx.Response(200, json={"data": {"attributes": {"last_analysis_stats": stats}}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(_answer)) as http:
        with patch("maljan.enrichment.orchestrator.WhoisClient") as whois:
            whois.return_value.asn_lookup = AsyncMock(return_value=None)
            whois.return_value.geoip = MagicMock(return_value=None)
            enriched = await enrich_malware_report(
                json.loads(json.dumps(before)), sources=[ready], http_client=http
            )
    # Dev wrote the enriched copy whole: its row is the outcome to match.
    (dev_row,) = enriched["network"]["ips"]
    assert dev_row["reputation"]["source"] == "virustotal"

    # Meanwhile another writer added an entry to the stored row's record.
    stored = json.loads(json.dumps(before))
    stored["run_summary"] = {"disclosure": {"models": [], "kept": "concurrent"}}
    merged = enrichment_laid_over(stored, enriched)

    (row,) = merged["network"]["ips"]
    assert row == dev_row
    assert row["reputation"]["hostname"] == "c2.example.com"
    assert merged["run_summary"]["disclosure"]["kept"] == "concurrent"


def test_a_successful_stored_record_is_kept_over_the_live_one() -> None:
    from app.worker.enrich_worker import enrichment_laid_over

    kept = {"source": "abuseipdb", "abuse_confidence": 80}
    stored = {"network": {"ips": [{"address": "1.2.3.4", "reputation": kept, "asn": "AS1 X"}]}}
    live = {"source": "virustotal", "malicious": 9}
    enriched = {
        "network": {
            "ips": [{"address": "1.2.3.4", "reputation": live, "asn": "AS2 Y", "geo": "US"}]
        }
    }

    (row,) = enrichment_laid_over(stored, enriched)["network"]["ips"]

    assert (row["reputation"], row["asn"], row["geo"]) == (kept, "AS1 X", "US")


def test_the_last_enrichments_unasked_rows_replace_an_earlier_statement() -> None:
    from app.worker.enrich_worker import enrichment_laid_over

    old = [{"kind": "ip", "value": "1.2.3.4", "questions": ["reputation"], "cap": 1}]
    new = [{"kind": "domain", "value": "a.example", "questions": ["reputation"], "cap": 1}]
    stored = {"enrichment_not_asked": old}

    merged = enrichment_laid_over(stored, {"enrichment_not_asked": new})
    assert merged["enrichment_not_asked"] == new
    assert "enrichment_not_asked" not in enrichment_laid_over(stored, {})


def test_the_unasked_questions_are_read_against_the_laid_over_row() -> None:
    from app.worker.enrich_worker import enrichment_laid_over

    stored = {
        "network": {
            "ips": [
                {"address": "1.1.1.1", "reputation": {"source": "x"}, "asn": "AS1 X"},
                {"address": "2.2.2.2"},
            ],
            "domains": [{"fqdn": "a.example", "reputation": {"source": "y"}}],
        }
    }
    unasked = [
        {"kind": "ip", "value": "1.1.1.1", "questions": ["reputation", "asn", "geo"], "cap": 1},
        {"kind": "ip", "value": "2.2.2.2", "questions": ["reputation", "asn"], "cap": 1},
        {"kind": "domain", "value": "a.example", "questions": ["reputation"], "cap": 1},
    ]
    enriched = {"network": stored["network"], "enrichment_not_asked": unasked}

    rows = enrichment_laid_over(stored, enriched)["enrichment_not_asked"]

    assert [(r["value"], r["questions"]) for r in rows] == [
        ("1.1.1.1", ["geo"]),
        ("2.2.2.2", ["reputation", "asn"]),
    ]
