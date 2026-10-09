"""The rehearsal runner submits the sample, waits for the job and reads it back like the console.

The API is answered in this process (``httpx.MockTransport``), so what is held
here is the runner's side of the contract: the calls it makes and in which
order, the record it builds from the stored report, the settings
``--configure`` writes (probed before they are saved, since a save naming an
unprobed model is refused), and the exit code a failed check gives.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from scripts.rehearsal.checklist import RunRecord
from scripts.rehearsal.run import StackClient, record_from_stack, stack_settings, write_results

JOB = "11111111-1111-1111-1111-111111111111"
REPORT = "22222222-2222-2222-2222-222222222222"


def _api(seen: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1")
        seen.append(f"{request.method} {path}")
        if path == "/auth/login":
            return httpx.Response(200, json={"access_token": "t", "token_type": "bearer"})
        if path == "/samples/upload":
            return httpx.Response(201, json={"id": "33333333-3333-3333-3333-333333333333"})
        if path == "/jobs" and request.method == "POST":
            return httpx.Response(201, json={"id": JOB, "status": "queued"})
        if path == f"/jobs/{JOB}":
            return httpx.Response(200, json={"id": JOB, "status": "completed"})
        if path == f"/jobs/{JOB}/events":
            events = [
                {"seq": 1, "type": "stage_started", "data": {"stage": "analysis"}},
                {"seq": 2, "type": "stage_finished", "data": {"stage": "analysis"}},
            ]
            return httpx.Response(200, json={"events": events, "count": 2})
        if path == f"/reports/job/{JOB}":
            return httpx.Response(
                200,
                json={
                    "id": REPORT,
                    "verdict": "Malware",
                    "run_summary": {"verdict_reading": "stated"},
                    "malware_report": {"executive_summary": "s"},
                    "stix_bundle": {"type": "bundle", "objects": [{"type": "malware"}]},
                    "agent_findings": [
                        {"agent_name": "static", "claims": [{"claim": "It talks HTTP."}]}
                    ],
                },
            )
        if path == f"/reports/{REPORT}/markdown":
            return httpx.Response(200, text="# Report\nMalware\n")
        if path == f"/reports/{REPORT}/stix":
            assert request.url.params.get("source") == "judge"
            return httpx.Response(
                200, json={"kept": True, "bundle": {"type": "bundle", "objects": [{}]}}
            )
        return httpx.Response(404, json={"detail": "no such route"})

    return httpx.MockTransport(handler)


def test_submits_waits_and_reads_the_job_back() -> None:
    seen: list[str] = []
    client = StackClient("http://api", transport=_api(seen))
    try:
        client.login("operator@example.org", "pw")
        sample_id = client.upload("sample_1.exe", b"MZ")
        job_id = client.submit(sample_id)
        job = client.wait(job_id, timeout_s=5, poll_s=0)
        record = record_from_stack(client, job_id, job, "normal", [], {}, {}, 1.0)
    finally:
        client.close()
    assert seen[:3] == ["POST /auth/login", "POST /samples/upload", "POST /jobs"]
    assert seen[3] == f"GET /jobs/{JOB}"
    assert record.job_status == "completed"
    assert record.verdict == "Malware"
    assert record.claims_in_force == {"static": ["It talks HTTP."]}
    assert record.stix_bundle == {"type": "bundle", "objects": [{}]}
    assert record.stix_extended["objects"] == [{"type": "malware"}]
    assert record.markdown.startswith("# Report")
    assert [e["type"] for e in record.events] == ["stage_started", "stage_finished"]
    assert record.events[0]["stage"] == "analysis"


def test_configure_points_the_chosen_provider_at_the_stub() -> None:
    openai = stack_settings("openai", "http://127.0.0.1:8765", "high", 9000)
    assert openai["core.llm.openai.base_url"] == "http://127.0.0.1:8765/v1"
    assert openai["core.sandbox.provider"] == "mock"
    anthropic = stack_settings("anthropic", "http://127.0.0.1:8765", "high", 9000)
    assert anthropic["core.llm.anthropic.base_url"] == "http://127.0.0.1:8765"
    assert anthropic["core.llm.anthropic.effort"] == "high"
    assert "base_url" not in anthropic["core.llm.agents"]["judge"]


def test_results_are_written_and_a_failed_check_exits_non_zero(tmp_path: Path) -> None:
    record = RunRecord(scenario="normal", job_status="failed", job_error="boom")
    code = write_results([record], tmp_path)
    assert code == 1
    result = json.loads((tmp_path / "normal-run1.json").read_text())
    assert result["passed"] is False
    assert "job completed" in (tmp_path / "normal-run1.md").read_text()
    summary: dict[str, Any] = json.loads((tmp_path / "summary.json").read_text())
    assert summary == {"runs": 1, "passed": False, "identical": True, "differences": []}
