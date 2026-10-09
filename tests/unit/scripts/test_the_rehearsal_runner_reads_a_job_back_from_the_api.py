"""The rehearsal runner rehearses the operator's own configuration and puts every setting back.

The API is answered in this process (``httpx.MockTransport``), so what is held
here is the runner's side of the contract: the calls it makes and in which
order, the record it builds from the stored report and the job's events, the
fewest changes the gate makes (only the endpoints, plus the ``auto`` settings
a loopback address would resolve differently), the expectations it reads from
the stack's own settings, the snapshot it saves before any change and puts
back afterwards — after a failure and an interrupt too — and that a failed
connection test changes nothing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from scripts.rehearsal.checklist import RunRecord
from scripts.rehearsal.run import (
    SettingsGuard,
    StackClient,
    describe_changes,
    gate_changes,
    gate_expected,
    harness_changes,
    profile_stages,
    record_from_stack,
    restore_snapshot,
    third_party_off,
    write_results,
)

JOB = "11111111-1111-1111-1111-111111111111"
REPORT = "22222222-2222-2222-2222-222222222222"
STUB = "http://127.0.0.1:41234"


def _values(**overrides: Any) -> dict[str, dict[str, Any]]:
    base = {
        "core.llm.provider": {"value": "openai", "source": "ui"},
        "core.llm.openai.base_url": {"value": "https://api.deepseek.com", "source": "ui"},
        "core.llm.openai.compat": {"value": "auto", "source": "default"},
        "core.llm.openai.expert_model": {"value": "deepseek-v4-flash", "source": "ui"},
        "core.llm.openai.judge_model": {"value": "deepseek-v4-flash", "source": "ui"},
        "core.llm.openai.reasoning_effort": {"value": "high", "source": "ui"},
        "core.llm.openai.api_key": {"value": None, "is_set": True, "source": "ui"},
        "core.llm.parallel_analysts": {"value": "auto", "source": "default"},
        "core.llm.judge_max_tokens": {"value": 9000, "source": "ui"},
        "core.llm.agents": {
            "value": {
                "judge": {
                    "provider": "openai",
                    "model": "deepseek-v4-pro",
                    "base_url": "https://api.deepseek.com",
                    "effort": "max",
                    "fallbacks": [
                        {
                            "provider": "openai",
                            "model": "deepseek-v4-flash",
                            "base_url": "https://x.example",
                        }
                    ],
                }
            },
            "source": "ui",
        },
    }
    base.update(overrides)
    return base


class TestTheGateChangesOnlyTheEndpoints:
    def test_every_openai_endpoint_and_the_auto_settings_it_would_resolve_differently(self) -> None:
        changes = gate_changes(_values(), STUB)
        assert changes["core.llm.openai.base_url"] == f"{STUB}/v1"
        assert changes["core.llm.openai.compat"] == "standard"
        assert changes["core.llm.parallel_analysts"] == "true"
        judge = changes["core.llm.agents"]["judge"]
        assert judge["base_url"] == f"{STUB}/v1"
        assert judge["fallbacks"][0]["base_url"] == f"{STUB}/v1"
        assert judge["model"] == "deepseek-v4-pro" and judge["effort"] == "max"
        assert not any(key.endswith("api_key") or key.endswith("_model") for key in changes)

    def test_the_anthropic_base_url_alone_on_the_anthropic_wire(self) -> None:
        values = _values(
            **{
                "core.llm.provider": {"value": "anthropic", "source": "ui"},
                "core.llm.agents": {"value": {}, "source": "default"},
            }
        )
        assert gate_changes(values, STUB) == {
            "core.llm.anthropic.base_url": STUB,
            "core.llm.max_spend_usd_per_job": 1_000_000.0,
        }

    @pytest.mark.parametrize("provider", ["gemini", "ollama"])
    def test_a_provider_the_stub_cannot_stand_in_for_is_refused(self, provider: str) -> None:
        values = _values(**{"core.llm.provider": {"value": provider, "source": "ui"}})
        with pytest.raises(SystemExit, match="cannot stand in"):
            gate_changes(values, STUB)

    def test_expects_the_operator_s_own_models_and_efforts(self) -> None:
        values = _values()
        expected = gate_expected(values, gate_changes(values, STUB))
        assert expected["model.static"] == "deepseek-v4-flash"
        assert expected["model.judge"] == "deepseek-v4-pro"
        assert expected["effort.judge"] == "max"
        assert expected["effort.static"] == "high"
        assert expected["max_tokens.judge"] == 9000
        assert expected["settings.llm.openai.base_url"] == f"{STUB}/v1"
        assert expected["settings.llm.openai.expert_model"] == "deepseek-v4-flash"

    def test_no_third_party_is_reached_and_no_token_is_touched(self) -> None:
        values = _values(
            **{
                "core.sandbox.provider": {"value": "triage", "source": "ui"},
                "api.enrichment_enabled": {"value": True, "source": "default"},
                "core.mcp.servers": {
                    "value": {
                        "analysis": {"enabled": True, "transport": "stdio"},
                        "threatintel": {
                            "enabled": True,
                            "transport": "stdio",
                            "env_allow": ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"],
                        },
                        "virustotal": {
                            "enabled": True,
                            "transport": "streamable-http",
                            "url": "https://www.virustotal.com/mcp",
                            "token": "**********",
                        },
                        "local": {
                            "enabled": True,
                            "transport": "sse",
                            "url": "http://127.0.0.1:9100/sse",
                        },
                    },
                    "source": "ui",
                },
            }
        )
        changes = third_party_off(values)
        assert changes["core.sandbox.provider"] == "mock"
        assert changes["api.enrichment_enabled"] is False
        servers = changes["core.mcp.servers"]
        assert servers["analysis"]["enabled"] and servers["local"]["enabled"]
        assert servers["threatintel"]["enabled"] and servers["threatintel"]["env_allow"] == []
        assert not servers["virustotal"]["enabled"]
        assert servers["virustotal"]["token"] == "**********"
        assert "core.mcp.servers" in gate_changes(values, STUB)
        described = describe_changes(values, changes)
        assert described["servers_disabled"] == ["virustotal"]
        assert described["servers_with_keys_withheld"] == ["threatintel"]
        assert described["settings"]["core.sandbox.provider"] == {
            "before": "triage",
            "rehearsed": "mock",
        }

    def test_the_harness_mode_touches_no_key_and_keeps_the_stack_s_tools(self) -> None:
        changes = harness_changes("openai", STUB)
        assert changes["core.sandbox.provider"] == "mock"
        assert not any(key.endswith("api_key") for key in changes)
        assert "core.static.provider" not in changes and "core.memory.backend" not in changes


def test_the_profile_s_stages_are_read_from_the_stack_s_settings() -> None:
    stages = profile_stages(_values())
    assert list(stages) == ["triage_pack", "analysis", "debate", "verdict", "report"]
    assert stages["analysis"] == ["static", "dynamic", "network"]


def test_the_gate_sets_a_ceiling_only_where_none_is_set() -> None:
    assert gate_changes(_values(), STUB)["core.llm.max_spend_usd_per_job"] == 1_000_000.0
    held = _values(**{"core.llm.max_spend_usd_per_job": {"value": 50.0, "source": "ui"}})
    assert "core.llm.max_spend_usd_per_job" not in gate_changes(held, STUB)


class _Api:
    """A stack answered in this process, recording every call and holding its settings."""

    def __init__(self, values: dict[str, dict[str, Any]], probe_ok: bool = True) -> None:
        self.values = values
        self.probe_ok = probe_ok
        self.seen: list[str] = []
        self.status = "completed"
        self.active: dict[str, list[str]] = {}

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api/v1")
        self.seen.append(f"{request.method} {path}")
        is_json = "json" in request.headers.get("content-type", "")
        body = json.loads(request.content) if request.content and is_json else {}
        if path == "/auth/login":
            return httpx.Response(200, json={"access_token": "t"})
        if path == "/settings" and request.method == "GET":
            return httpx.Response(200, json={"values": self.values})
        if path == "/settings" and request.method == "PATCH":
            for key, value in body["changes"].items():
                self.values[key] = {"value": value, "source": "ui"}
            return httpx.Response(200, json={"applied": sorted(body["changes"]), "applies": {}})
        if path.startswith("/settings/") and request.method == "DELETE":
            self.values.pop(path.removeprefix("/settings/"), None)
            return httpx.Response(200, json={"reset": [path]})
        if path == "/settings/test/llm":
            return httpx.Response(200, json={"ok": self.probe_ok, "latency_ms": 1, "detail": "x"})
        if path == "/samples/upload":
            return httpx.Response(201, json={"id": "33333333-3333-3333-3333-333333333333"})
        if path == "/jobs" and request.method == "GET":
            wanted = request.url.params.get("status")
            items = [{"id": j, "status": wanted} for j in self.active.get(wanted, [])]
            return httpx.Response(200, json={"items": items, "total": len(items)})
        if path == "/jobs" and request.method == "POST":
            return httpx.Response(201, json={"id": JOB, "status": "queued"})
        if path == f"/jobs/{JOB}" and request.method == "DELETE":
            self.status = "cancelled"
            return httpx.Response(204)
        if path == f"/jobs/{JOB}":
            return httpx.Response(200, json={"id": JOB, "status": self.status})
        if path == f"/jobs/{JOB}/events":
            events = [
                {"seq": 1, "type": "stage_started", "data": {"stage": "analysis"}},
                {
                    "seq": 2,
                    "type": "agent_message",
                    "data": {
                        "speaker": "static",
                        "role": "analyst",
                        "claims": [{"claim": "It talks HTTP."}],
                    },
                },
                {"seq": 3, "type": "stage_finished", "data": {"stage": "analysis"}},
            ]
            return httpx.Response(200, json={"events": events, "count": 3})
        if path == f"/reports/job/{JOB}":
            return httpx.Response(
                200,
                json={
                    "id": REPORT,
                    "verdict": "Malware",
                    "run_summary": {"verdict_reading": "stated"},
                    "malware_report": {},
                    "stix_bundle": {"type": "bundle", "objects": [{"type": "malware"}]},
                    "agent_findings": [
                        {"agent_name": "static", "claims": [{"claim": "It talks HTTP."}]}
                    ],
                },
            )
        if path == f"/reports/{REPORT}/markdown":
            return httpx.Response(200, text="# Report\nMalware\n")
        if path == f"/reports/{REPORT}/stix":
            return httpx.Response(
                200, json={"kept": True, "bundle": {"type": "bundle", "objects": [{}]}}
            )
        return httpx.Response(404, json={"detail": "no such route"})


def _client(api: _Api) -> StackClient:
    return StackClient("http://api", transport=httpx.MockTransport(api.handler))


def test_submits_waits_and_reads_the_job_back_from_its_events() -> None:
    api = _Api(_values())
    client = _client(api)
    try:
        client.login("operator@example.org", "pw")
        job_id = client.submit(client.upload("sample_1.exe", b"MZ"))
        job = client.wait(job_id, timeout_s=5, poll_s=0)
        record = record_from_stack(client, job_id, job, "normal", [], {}, {}, 1.0, api="openai")
    finally:
        client.close()
    assert api.seen[:3] == ["POST /auth/login", "POST /samples/upload", "POST /jobs"]
    assert record.job_status == "completed" and record.verdict == "Malware"
    assert record.claims_in_force == {"static": ["It talks HTTP."]}
    assert record.stix_bundle == {"type": "bundle", "objects": [{}]}
    assert record.markdown.startswith("# Report")


def test_a_job_still_running_when_the_wait_runs_out_is_cancelled() -> None:
    api = _Api(_values())
    api.status = "running"
    client = _client(api)
    try:
        job = client.wait(JOB, timeout_s=0, poll_s=0)
    finally:
        client.close()
    assert f"DELETE /jobs/{JOB}" in api.seen
    assert job["status"] == "cancelled" and "cancelled the job" in job["error_message"]


class TestTheSnapshot:
    def test_is_saved_before_the_change_and_puts_every_key_back(self, tmp_path: Path) -> None:
        values = _values()
        api = _Api(json.loads(json.dumps(values)))
        client = _client(api)
        guard = SettingsGuard(client, tmp_path / "settings-snapshot.json")
        changes = gate_changes(values, STUB)
        guard.keep(values, list(changes))
        assert json.loads(guard.snapshot.read_text())["core.llm.openai.base_url"]["value"] == (
            "https://api.deepseek.com"
        )
        client.save(changes)
        assert guard.restore() == []
        client.close()
        assert api.values["core.llm.openai.base_url"]["value"] == "https://api.deepseek.com"
        assert api.values["core.llm.agents"] == values["core.llm.agents"]
        # A key the operator had left at its default goes back to its default.
        assert "core.llm.openai.compat" not in api.values
        assert "core.llm.parallel_analysts" not in api.values
        assert not guard.snapshot.exists()

    def test_restore_from_a_saved_file_puts_back_what_a_crash_left(self) -> None:
        api = _Api({"core.llm.openai.base_url": {"value": f"{STUB}/v1", "source": "ui"}})
        client = _client(api)
        saved = {"core.llm.openai.base_url": {"value": "https://api.deepseek.com", "source": "ui"}}
        assert restore_snapshot(client, saved) == []
        client.close()
        assert api.values["core.llm.openai.base_url"]["value"] == "https://api.deepseek.com"


def _args(tmp_path: Path, **extra: Any) -> Any:
    from types import SimpleNamespace

    base = {
        "login_env": "REHEARSAL_LOGIN",
        "configure": "gate",
        "stub_url": "",
        "stub_port": 0,
        "scenario": "normal",
        "loop_steps": None,
        "slow_seconds": None,
        "first_token_seconds": 0.0,
        "tokens_per_second": 0.0,
        "window": None,
        "slots": 1,
        "api": "http://api",
        "out": str(tmp_path),
        "expect": [],
        "provider": "openai",
        "email": "operator@example.org",
        "repeat": 1,
        "timeout": 5.0,
        "job_timeout": None,
        "stub_host": "127.0.0.1",
        "redis_url": "",
    }
    base.update(extra)
    return SimpleNamespace(**base)


def _run_with(api: _Api, args: Any, monkeypatch: pytest.MonkeyPatch, fail_on: str = "") -> Any:
    from scripts.rehearsal import run

    monkeypatch.setenv("REHEARSAL_LOGIN", "pw")
    monkeypatch.setattr(run, "StackClient", lambda _api: _client(api))
    if fail_on:
        original = _Api.handler

        def failing(self: _Api, request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith(fail_on):
                raise KeyboardInterrupt
            return original(self, request)

        monkeypatch.setattr(_Api, "handler", failing)
    return run.run_against_stack(args)


def test_a_failed_connection_test_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _Api(_values(), probe_ok=False)
    with pytest.raises(SystemExit, match="connection test failed"):
        _run_with(api, _args(tmp_path), monkeypatch)
    assert not any(call.startswith("PATCH") for call in api.seen)
    assert not any(call.startswith("POST /jobs") for call in api.seen)


def test_an_interrupt_mid_run_still_puts_the_settings_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    values = _values()
    api = _Api(json.loads(json.dumps(values)))
    with pytest.raises(KeyboardInterrupt):
        _run_with(api, _args(tmp_path), monkeypatch, fail_on="/samples/upload")
    assert api.values["core.llm.openai.base_url"]["value"] == "https://api.deepseek.com"
    assert api.values["core.llm.agents"] == values["core.llm.agents"]
    assert not (tmp_path / "settings-snapshot.json").exists()


def test_results_are_written_and_a_failed_check_exits_non_zero(tmp_path: Path) -> None:
    record = RunRecord(scenario="normal", job_status="failed", job_error="boom")
    assert write_results([record], tmp_path) == 1
    result = json.loads((tmp_path / "normal-run1.json").read_text())
    assert result["passed"] is False
    assert "job completed" in (tmp_path / "normal-run1.md").read_text()
    summary: dict[str, Any] = json.loads((tmp_path / "summary.json").read_text())
    assert summary == {"runs": 1, "passed": False, "identical": True, "differences": []}
    assert write_results([], tmp_path) == 1


def test_the_gate_refuses_to_start_while_a_job_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _Api(_values())
    api.active = {"running": ["44444444-4444-4444-4444-444444444444"]}
    with pytest.raises(SystemExit, match="queued or running"):
        _run_with(api, _args(tmp_path), monkeypatch)
    assert not any(c.startswith("PATCH") or c.startswith("POST /settings") for c in api.seen)


def test_without_configure_the_connection_test_is_still_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = _Api(_values())
    records = _run_with(api, _args(tmp_path, configure=None, stub_port=8765), monkeypatch)
    assert "POST /settings/test/llm" in api.seen
    assert records[0].probe["ok"] is True
    assert list(records[0].required_stages)[0] == "triage_pack"
