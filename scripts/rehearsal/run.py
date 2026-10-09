"""Rehearse an analysis at zero cost, and check it against the written checklist.

**The gate** — the operator's own paid configuration, against the running
stack, with only the model endpoints pointed at the loopback stub this script
starts::

    REHEARSAL_LOGIN=... python scripts/rehearsal/run.py \\
        --api http://127.0.0.1:8000 --email operator@example.org \\
        --configure gate --scenario normal --repeat 3

``--configure gate`` reads the stack's settings (``GET /settings``) and saves
them to ``<out>/settings-snapshot.json``. It then changes only what must
change for the calls to reach the stub: the OpenAI base URL (and every
per-agent OpenAI endpoint) or the Anthropic base URL. Where an ``auto``
setting would resolve differently against a loopback address than against
the paid endpoint, it is pinned to what it resolves to for the paid endpoint:
``llm.openai.compat`` to ``standard``, ``llm.parallel_analysts`` to ``true``.
Nothing may reach a third party: the sandbox becomes the mock, enrichment is
off and tool servers that answer from outside this machine are disabled.
Models, efforts, caps, timeouts, agents and keys stay as the operator set
them, and the checklist expects exactly them in force. The connection test
runs before anything is saved, and a failed one stops the rehearsal. Every
change is put back when the rehearsal ends — on success, on failure and on
Ctrl-C or SIGTERM — and ``--restore <snapshot>`` puts back a snapshot left by
a run that could not.

``--configure harness`` rehearses the harness's own fixed models and settings
instead (the in-process ones), with the same snapshot and restore. Without
``--configure`` nothing on the stack is changed and ``--expect key=value``
names what to find in force; a run with nothing to compare fails.

Without the stack, the same pipeline inside this process (``--in-process``;
``scripts/rehearsal/inprocess.py`` says how its setup differs from a paid
run)::

    python scripts/rehearsal/run.py --in-process --scenario normal --repeat 3

Each run submits the synthetic sample (``scripts/rehearsal/sample.py``), waits
for the job (and cancels it when the wait runs out), collects the job, the
stored report, its run summary, its STIX bundles and markdown and the job's
events, and checks them (``scripts/rehearsal/checklist.py``). One JSON and one
markdown file per run, and a summary comparing the runs of a ``--repeat``. The
exit code is non-zero when any check of any run fails or repeated runs differ.

The account's sign-in is read from the environment variable named by
``--login-env``; it is never taken on the command line or printed.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.rehearsal.checklist import (  # noqa: E402
    RunRecord,
    as_json,
    as_markdown,
    check_run,
    compare,
    signature,
)
from scripts.rehearsal.roles import SCENARIOS, Brain  # noqa: E402
from scripts.rehearsal.sample import sample_bytes  # noqa: E402
from scripts.rehearsal.stub_model import Pace, StubServer, StubState  # noqa: E402

TERMINAL = {"completed", "failed", "cancelled", "canceled"}
ACTIVE = ("pending", "queued", "running")
SNAPSHOT_NAME = "settings-snapshot.json"
# Providers the stub cannot stand in for: a rehearsal that would send one of
# their calls to the real service is refused rather than run.
UNREACHABLE_PROVIDERS = {"gemini", "ollama"}


def _parse_expect(pairs: list[str]) -> dict[str, Any]:
    expected: dict[str, Any] = {}
    for pair in pairs:
        key, _, raw = pair.partition("=")
        try:
            expected[key.strip()] = json.loads(raw)
        except ValueError:
            expected[key.strip()] = raw
    return expected


class StackClient:
    """The few API calls a rehearsal makes, with one bearer token."""

    def __init__(self, api: str, timeout: float = 60.0, transport: Any = None) -> None:
        import httpx

        self._http = httpx.Client(
            base_url=api.rstrip("/") + "/api/v1", timeout=timeout, transport=transport
        )

    def close(self) -> None:
        self._http.close()

    def login(self, email: str, password: str) -> None:
        answer = self._http.post("/auth/login", json={"email": email, "password": password})
        answer.raise_for_status()
        self._http.headers["Authorization"] = f"Bearer {answer.json()['access_token']}"

    def values(self) -> dict[str, dict[str, Any]]:
        """Every setting as the stack holds it: value (secrets masked) and source."""
        answer = self._http.get("/settings")
        answer.raise_for_status()
        return dict(answer.json().get("values") or {})

    def save(self, changes: dict[str, Any]) -> list[str]:
        answer = self._http.patch("/settings", json={"changes": changes})
        if answer.status_code >= 400:
            raise RuntimeError(f"the settings were refused: {answer.text[:500]}")
        return list(answer.json().get("applied") or [])

    def reset(self, key: str) -> None:
        answer = self._http.delete(f"/settings/{key}")
        if answer.status_code >= 400 and answer.status_code != 404:
            raise RuntimeError(f"{key} could not be reset: {answer.text[:300]}")

    def probe_models(self, staged: dict[str, Any]) -> dict[str, Any]:
        """The connection test over ``staged`` values, which files a probe row per model.

        Run before the values are saved: a save that names a model no probe
        has reached is refused, as a job naming one is.
        """
        answer = self._http.post("/settings/test/llm", json={"values": staged}, timeout=330)
        answer.raise_for_status()
        return dict(answer.json())

    def upload(self, name: str, data: bytes) -> str:
        answer = self._http.post(
            "/samples/upload", files={"file": (name, data, "application/octet-stream")}
        )
        answer.raise_for_status()
        return str(answer.json()["id"])

    def submit(self, sample_id: str) -> str:
        answer = self._http.post("/jobs", json={"sample_id": sample_id})
        if answer.status_code >= 400:
            raise RuntimeError(f"the job was refused: {answer.text[:500]}")
        return str(answer.json()["id"])

    def cancel(self, job_id: str) -> None:
        self._http.delete(f"/jobs/{job_id}")

    def active_jobs(self) -> list[str]:
        """The ids of this account's jobs that are queued or running."""
        found: list[str] = []
        for status in ACTIVE:
            answer = self._http.get("/jobs", params={"status": status, "page_size": 100})
            answer.raise_for_status()
            found += [str(j.get("id")) for j in answer.json().get("items") or []]
        return found

    def job(self, job_id: str) -> dict[str, Any]:
        answer = self._http.get(f"/jobs/{job_id}")
        answer.raise_for_status()
        return dict(answer.json())

    def wait(self, job_id: str, timeout_s: float, poll_s: float = 5.0) -> dict[str, Any]:
        """The job once it ends; a job still running when the wait runs out is cancelled."""
        deadline = time.monotonic() + timeout_s
        while True:
            job = self.job(job_id)
            if str(job.get("status")) in TERMINAL:
                return job
            if time.monotonic() > deadline:
                self.cancel(job_id)
                job = self.job(job_id)
                job["error_message"] = (
                    f"the rehearsal stopped waiting after {timeout_s:.0f}s and cancelled the job"
                )
                return job
            time.sleep(poll_s)

    def events(self, job_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        since: int | None = None
        while True:
            params: dict[str, Any] = {"limit": 1000}
            if since is not None:
                params["since"] = since
            answer = self._http.get(f"/jobs/{job_id}/events", params=params)
            answer.raise_for_status()
            page = answer.json().get("events") or []
            out.extend(page)
            seqs = [e.get("seq") for e in page if isinstance(e.get("seq"), int)]
            if len(page) < 1000 or not seqs:
                return out
            since = max(seqs)

    def report(self, job_id: str) -> dict[str, Any] | None:
        answer = self._http.get(f"/reports/job/{job_id}")
        if answer.status_code == 404:
            return None
        answer.raise_for_status()
        return dict(answer.json())

    def markdown(self, report_id: str) -> str:
        answer = self._http.get(f"/reports/{report_id}/markdown")
        return answer.text if answer.status_code == 200 else ""

    def judge_bundle(self, report_id: str) -> dict[str, Any]:
        answer = self._http.get(f"/reports/{report_id}/stix", params={"source": "judge"})
        if answer.status_code != 200:
            return {}
        bundle = answer.json().get("bundle")
        return bundle if isinstance(bundle, dict) else {}


# ---------------------------------------------------------------- configuration


def _value(values: dict[str, dict[str, Any]], key: str, default: Any = None) -> Any:
    row = values.get(key) or {}
    return row.get("value", default) if isinstance(row, dict) else default


def _entries(agents: dict[str, Any]) -> list[dict[str, Any]]:
    """Every model entry of ``llm.agents``: each agent's own and each of its fallbacks."""
    out: list[dict[str, Any]] = []
    for entry in agents.values():
        if isinstance(entry, dict):
            out.append(entry)
            out.extend(f for f in entry.get("fallbacks") or [] if isinstance(f, dict))
    return out


def gate_changes(values: dict[str, dict[str, Any]], stub_root: str) -> dict[str, Any]:
    """The fewest changes that send the operator's own configuration's calls to the stub.

    Refused when a provider in use is one the stub cannot stand in for.
    """
    from maljan.llm.openai_provider import is_local_endpoint

    provider = str(_value(values, "core.llm.provider", "openai"))
    agents = copy.deepcopy(_value(values, "core.llm.agents", {}) or {})
    providers = {provider} | {str(e.get("provider")) for e in _entries(agents)}
    unreachable = sorted(providers & UNREACHABLE_PROVIDERS)
    if unreachable:
        raise SystemExit(
            f"the configuration calls {', '.join(unreachable)}, which the stub cannot stand in "
            "for; a rehearsal would reach the real service"
        )
    changes: dict[str, Any] = {}
    if "anthropic" in providers:
        changes["core.llm.anthropic.base_url"] = stub_root
    if "openai" in providers:
        paid = _value(values, "core.llm.openai.base_url")
        changes["core.llm.openai.base_url"] = f"{stub_root}/v1"
        if str(
            _value(values, "core.llm.openai.compat", "auto")
        ) == "auto" and not is_local_endpoint(paid):
            changes["core.llm.openai.compat"] = "standard"
        moved = False
        for entry in _entries(agents):
            if entry.get("provider") == "openai" and entry.get("base_url"):
                entry["base_url"] = f"{stub_root}/v1"
                moved = True
        if moved:
            changes["core.llm.agents"] = agents
        if str(_value(values, "core.llm.parallel_analysts", "auto")) == "auto" and not (
            is_local_endpoint(paid)
        ):
            changes["core.llm.parallel_analysts"] = "true"
    if _value(values, "core.llm.max_spend_usd_per_job") is None:
        # A ceiling no rehearsal reaches, so the run summary carries the spend
        # the checklist prices the usage against.
        changes["core.llm.max_spend_usd_per_job"] = 1_000_000.0
    changes.update(third_party_off(values))
    return changes


def third_party_off(values: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """What keeps a rehearsal from reaching any third party beside the model.

    The sandbox becomes the mock and the threat-intel enrichment is switched
    off. The threat-intel sidecar stays, with the reputation keys withheld from
    its environment (it then answers from its own offline data), so its tool
    definitions still ride every request; it is disabled only where a token is
    written into its own environment map. Every tool server that answers from
    outside this machine (VirusTotal, any HTTP server not on loopback) is
    disabled, and its tool definitions are then missing from the rehearsed
    requests. The server map comes back masked and goes back masked; a masked
    token in a PATCH means "unchanged", so no token is lost.
    """
    from maljan.llm.openai_provider import is_local_endpoint

    changes: dict[str, Any] = {}
    if str(_value(values, "core.sandbox.provider", "mock")) != "mock":
        changes["core.sandbox.provider"] = "mock"
    if _value(values, "api.enrichment_enabled", False):
        changes["api.enrichment_enabled"] = False
    servers = copy.deepcopy(_value(values, "core.mcp.servers", {}) or {})
    moved = False
    for key, server in servers.items():
        if not isinstance(server, dict) or not server.get("enabled", True):
            continue
        remote = str(server.get("transport") or "stdio") != "stdio" and not is_local_endpoint(
            server.get("url")
        )
        if key == "threatintel" and not server.get("env"):
            if server.get("env_allow"):
                server["env_allow"] = []
                moved = True
            continue
        if key in ("virustotal", "threatintel") or remote:
            server["enabled"] = False
            moved = True
    if moved:
        changes["core.mcp.servers"] = servers
    return changes


def describe_changes(values: dict[str, dict[str, Any]], changes: dict[str, Any]) -> dict[str, Any]:
    """Every setting the rehearsal changed, before and during it, and every server it took away."""
    servers_before = _value(values, "core.mcp.servers", {}) or {}
    servers_during = changes.get("core.mcp.servers") or servers_before
    disabled = sorted(
        key
        for key, server in servers_during.items()
        if isinstance(server, dict)
        and not server.get("enabled", True)
        and (servers_before.get(key) or {}).get("enabled", True)
    )
    keys_withheld = sorted(
        key
        for key, server in servers_during.items()
        if isinstance(server, dict)
        and server.get("enabled", True)
        and (servers_before.get(key) or {}).get("env_allow")
        and not server.get("env_allow")
    )
    return {
        "settings": {
            key: {"before": _value(values, key), "rehearsed": value}
            for key, value in changes.items()
            if key != "core.mcp.servers"
        },
        "servers_disabled": disabled,
        "servers_with_keys_withheld": keys_withheld,
    }


def gate_expected(values: dict[str, dict[str, Any]], changes: dict[str, Any]) -> dict[str, Any]:
    """What the run must have in force: the operator's own models, efforts, caps and limits."""
    provider = str(_value(values, "core.llm.provider", "openai"))
    agents = _value(values, "core.llm.agents", {}) or {}
    expert = _value(values, f"core.llm.{provider}.expert_model")
    effort_key = "effort" if provider == "anthropic" else "reasoning_effort"
    effort = str(_value(values, f"core.llm.{provider}.{effort_key}", "") or "")
    expected: dict[str, Any] = {}

    def own(agent: str) -> tuple[Any, Any]:
        entry = agents.get(agent) if isinstance(agents, dict) else None
        if isinstance(entry, dict) and entry.get("model"):
            return entry.get("model"), entry.get("effort") or effort
        return expert, effort

    # The mediator reads its own ``llm.agents.mediator`` entry and, with none,
    # the expert model; a judge entry does not move it.
    for group in ("static", "judge", "reporter", "mediator"):
        model, its_effort = own(group)
        if model:
            expected[f"model.{group}"] = model
        expected[f"effort.{group}"] = its_effort
    cap = _value(values, "core.llm.judge_max_tokens", 0)
    if cap:
        expected["max_tokens.judge"] = cap
    for key in ("react_agent_max_steps", "react_agent_timeout"):
        if _value(values, f"core.{key}") is not None:
            expected["max_steps" if key.endswith("steps") else "timeout_s"] = _value(
                values, f"core.{key}"
            )
    for key in (
        "llm.provider",
        f"llm.{provider}.expert_model",
        f"llm.{provider}.judge_model",
        "llm.judge_max_tokens",
        "llm.expert_max_tokens",
        "llm.max_spend_usd_per_job",
    ):
        expected[f"settings.{key}"] = changes.get(f"core.{key}", _value(values, f"core.{key}"))
    for key, value in changes.items():
        if not key.startswith("core.") or key == "core.mcp.servers":
            # Not in the run summary's settings snapshot (API settings, the server map).
            continue
        name = key.removeprefix("core.")
        if name == "llm.agents" and isinstance(value, dict):
            # The run summary's settings snapshot holds an agent entry field by field.
            for agent, entry in value.items():
                for field in ("provider", "model", "base_url", "effort"):
                    if isinstance(entry, dict) and field in entry:
                        expected[f"settings.llm.agents.{agent}.{field}"] = entry[field]
            continue
        expected[f"settings.{name}"] = value
    return expected


def profile_stages(values: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """The stages of the profile the stack's settings name, each with its agents; empty unknown.

    Read from the settings in force, built the way the worker builds a job's,
    never from what the run reports about itself. A masked secret is left out:
    it plays no part in the profile.
    """
    from maljan.agents.composition import active_profile
    from maljan.core.settings_overrides import build_settings

    core = {
        key.removeprefix("core."): row.get("value")
        for key, row in values.items()
        if key.startswith("core.")
        and isinstance(row, dict)
        and row.get("value") is not None
        and row.get("value") != "**********"
    }
    try:
        profile = active_profile(build_settings(core))
    except Exception:  # noqa: BLE001 — stages nobody can read are not required silently
        return {}
    return {str(stage.key): [str(a) for a in stage.agents] for stage in profile.stages}


def harness_changes(provider: str, stub_root: str) -> dict[str, Any]:
    """The harness's own fixed settings (the in-process ones) on the stack, sandbox the mock."""
    from scripts.rehearsal.inprocess import Rehearsal, settings_for

    fixed = settings_for(Rehearsal(provider=provider), stub_root)
    changes = {f"core.{key}": value for key, value in fixed.items()}
    # The stack keeps its own static provider, memory and keys: only the sandbox
    # is the mock, and no secret is touched (a masked value cannot be put back).
    for key in ("core.static.provider", "core.memory.backend"):
        changes.pop(key, None)
    for key in [k for k in changes if k.endswith(".api_key")]:
        changes.pop(key)
    return changes


class SettingsGuard:
    """The stack's settings before the rehearsal, saved to a file and put back afterwards."""

    def __init__(self, client: StackClient, snapshot: Path) -> None:
        self.client = client
        self.snapshot = snapshot
        self.saved: dict[str, dict[str, Any]] = {}

    def keep(self, values: dict[str, dict[str, Any]], keys: list[str]) -> None:
        self.saved = {
            key: {
                "source": (values.get(key) or {}).get("source", "default"),
                "value": (values.get(key) or {}).get("value"),
            }
            for key in keys
        }
        self.snapshot.parent.mkdir(parents=True, exist_ok=True)
        self.snapshot.write_text(json.dumps(self.saved, indent=1, default=str), encoding="utf-8")

    def restore(self) -> list[str]:
        """Put every kept key back; answer what could not be (the snapshot stays for it)."""
        failed = restore_snapshot(self.client, self.saved)
        if not failed:
            self.snapshot.unlink(missing_ok=True)
        return failed


def restore_snapshot(client: StackClient, saved: dict[str, dict[str, Any]]) -> list[str]:
    """Each key back to its value, or to its default where the operator had set none."""
    failed: list[str] = []
    overridden = {k: v["value"] for k, v in saved.items() if v.get("source") == "ui"}
    if overridden:
        try:
            client.save(overridden)
        except Exception as exc:  # noqa: BLE001 — every key is tried, every failure said
            failed.append(f"{', '.join(sorted(overridden))}: {exc}")
    for key, row in saved.items():
        if row.get("source") != "ui":
            try:
                client.reset(key)
            except Exception as exc:  # noqa: BLE001
                failed.append(f"{key}: {exc}")
    return failed


def queued_elsewhere(redis_url: str) -> int:
    """How many jobs the stack's queue holds or runs, every account's, read from its Redis.

    The API lists only the caller's own jobs; the arq queue and its in-progress
    keys are the whole stack's.
    """
    import redis

    client = redis.Redis.from_url(redis_url, socket_timeout=5)
    try:
        waiting = int(client.zcard("arq:queue") or 0)
        running = sum(1 for _ in client.scan_iter("arq:in-progress:*"))
    finally:
        client.close()
    return waiting + running


def refuse_while_jobs_run(client: StackClient, redis_url: str) -> None:
    """Refuse to point the stack at the stub while any job could pick the stub's endpoints up."""
    mine = client.active_jobs()
    if mine:
        raise SystemExit(
            f"{len(mine)} job(s) of this account are queued or running; a rehearsal would "
            "change the endpoints under them"
        )
    if redis_url:
        others = queued_elsewhere(redis_url)
        if others:
            raise SystemExit(
                f"the stack's queue holds or runs {others} job(s); a rehearsal would change "
                "the endpoints under them"
            )
    else:
        print(
            "only this account's jobs were checked; name --redis-url to check every account's",
            flush=True,
        )


def _sigterm_is_interrupt() -> None:
    def handler(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, handler)


# ------------------------------------------------------------------------ runs


def _normal_event(event: dict[str, Any]) -> dict[str, Any]:
    data = event.get("data")
    return {"type": event.get("type"), **(data if isinstance(data, dict) else {})}


def record_from_stack(
    client: StackClient,
    job_id: str,
    job: dict[str, Any],
    scenario: str,
    stub_log: list[dict[str, Any]],
    expected: dict[str, Any],
    scenario_params: dict[str, Any],
    elapsed: float,
    *,
    api: str = "",
    probe: dict[str, Any] | None = None,
    required_stages: dict[str, list[str]] | None = None,
    gate: dict[str, Any] | None = None,
) -> RunRecord:
    """A run's record, read back from the API the way the console reads it."""
    from scripts.rehearsal.inprocess import claims_from_events, empty_evidence_sections

    report = client.report(job_id) or {}
    report_id = str(report.get("id") or "")
    events = [_normal_event(e) for e in client.events(job_id)]
    malware_report = dict(report.get("malware_report") or {})
    rows = {
        str(f.get("agent_name")): [c for c in f.get("claims") or [] if isinstance(c, dict)]
        for f in report.get("agent_findings") or []
    }
    empty: list[str] | None = None
    if malware_report:
        try:
            empty = empty_evidence_sections(malware_report, rows)
        except Exception:  # noqa: BLE001 — sections nothing can vouch for are not excused
            empty = None
    return RunRecord(
        scenario=scenario,
        api=api,
        job_status=str(job.get("status") or ""),
        job_error=str(job.get("error_message") or ""),
        verdict=str(report.get("verdict") or ""),
        run_summary=dict(report.get("run_summary") or {}),
        malware_report=malware_report,
        markdown=client.markdown(report_id) if report_id else "",
        stix_bundle=client.judge_bundle(report_id) if report_id else {},
        stix_extended=dict(report.get("stix_bundle") or {}),
        claims_in_force=claims_from_events(events),
        events=events,
        stub_log=stub_log,
        expected=expected,
        empty_evidence_sections=empty,
        required_stages=dict(required_stages or {}),
        gate=dict(gate or {}),
        probe=dict(probe or {}),
        scenario_params=scenario_params,
        elapsed_s=elapsed,
    )


def _stub_log(stub_url: str | None, server: StubServer | None) -> list[dict[str, Any]]:
    if server is not None:
        return list(server.state.log)
    if stub_url:
        import httpx

        return list(httpx.get(f"{stub_url.rstrip('/')}/_stub/log", timeout=10).json())
    return []


def _reset_stub(stub_url: str | None, server: StubServer | None) -> None:
    if server is not None:
        with server.state.lock:
            server.state.log.clear()
        server.state.brain.reset()
    elif stub_url:
        import httpx

        httpx.post(f"{stub_url.rstrip('/')}/_stub/reset", timeout=10).raise_for_status()


def _job_timeout(args: argparse.Namespace, values: dict[str, dict[str, Any]]) -> float | None:
    if args.job_timeout:
        return float(args.job_timeout)
    for key, row in values.items():
        if "job_timeout" in key and isinstance(row, dict) and row.get("value"):
            return float(row["value"])
    return None


def run_against_stack(args: argparse.Namespace) -> list[RunRecord]:
    password = os.environ.get(args.login_env, "")
    if not password:
        raise SystemExit(f"{args.login_env} is empty: it holds the account's sign-in")
    if not args.configure and not args.stub_url and not args.stub_port:
        raise SystemExit("without --configure the stack must already call a stub: name --stub-port")
    _sigterm_is_interrupt()
    brain = Brain(
        scenario=args.scenario, loop_steps=args.loop_steps, slow_seconds=args.slow_seconds
    )
    server: StubServer | None = None
    if not args.stub_url:
        state = StubState(
            brain=brain,
            pace=Pace(args.first_token_seconds, args.tokens_per_second),
            window=args.window,
            slots=args.slots,
        )
        server = StubServer(state, args.stub_port, host=args.stub_host).start()
    stub_root = args.stub_url.rstrip("/") if args.stub_url else server.root  # type: ignore[union-attr]
    client = StackClient(args.api)
    guard = SettingsGuard(client, Path(args.out) / SNAPSHOT_NAME)
    records: list[RunRecord] = []
    probe: dict[str, Any] = {}
    gate: dict[str, Any] = {}
    try:
        client.login(args.email, password)
        values = client.values()
        expected = _parse_expect(args.expect)
        if args.configure:
            refuse_while_jobs_run(client, args.redis_url)
            if args.configure == "gate":
                changes = gate_changes(values, stub_root)
                expected = {**gate_expected(values, changes), **expected}
            else:
                from scripts.rehearsal.inprocess import Rehearsal, expected_for

                changes = {**harness_changes(args.provider, stub_root), **third_party_off(values)}
                expected = {**expected_for(Rehearsal(provider=args.provider)), **expected}
            answer = client.probe_models(changes)
            probe = {"ok": bool(answer.get("ok")), "detail": str(answer.get("detail") or "")}
            print(f"connection test: {'passed' if probe['ok'] else 'failed'}", flush=True)
            if not probe["ok"]:
                raise SystemExit(
                    f"the connection test failed, nothing was changed: {probe['detail']}"
                )
            if server is not None:
                # The stub answers the models the run will name, and 404s any other.
                server.state.served.extend(
                    str(v) for k, v in expected.items() if k.startswith("model.") and v
                )
            gate = describe_changes(values, changes)
            guard.keep(values, list(changes))
            applied = client.save(changes)
            print(f"pointed {len(applied)} setting(s) at the stub: {', '.join(sorted(applied))}")
        params = {
            "loop_steps": brain.loop_steps,
            "slow_seconds": brain.slow_seconds,
            "job_timeout_s": _job_timeout(args, values),
        }
        if not args.configure:
            # The connection test over the stack's stored settings, as the console's button asks it.
            answer = client.probe_models({})
            probe = {"ok": bool(answer.get("ok")), "detail": str(answer.get("detail") or "")}
        stages = profile_stages(values)
        api = str(_value(values, "core.llm.provider", args.provider))
        for _ in range(args.repeat):
            _reset_stub(args.stub_url, server)
            started = time.monotonic()
            sample_id = client.upload("sample_1.exe", sample_bytes())
            job_id = client.submit(sample_id)
            print(f"job {job_id} submitted", flush=True)
            job = client.wait(job_id, args.timeout)
            elapsed = time.monotonic() - started
            records.append(
                record_from_stack(
                    client,
                    job_id,
                    job,
                    args.scenario,
                    _stub_log(args.stub_url, server),
                    expected,
                    params,
                    elapsed,
                    api=api,
                    probe=probe,
                    required_stages=stages,
                    gate=gate,
                )
            )
    finally:
        if guard.saved:
            failed = guard.restore()
            if failed:
                print(
                    f"settings NOT restored ({'; '.join(failed)}); run --restore {guard.snapshot}",
                    flush=True,
                )
            else:
                print(f"restored {len(guard.saved)} setting(s)", flush=True)
        client.close()
        if server is not None:
            server.stop()
    return records


def run_restore(args: argparse.Namespace) -> int:
    password = os.environ.get(args.login_env, "")
    if not password:
        raise SystemExit(f"{args.login_env} is empty: it holds the account's sign-in")
    saved = json.loads(Path(args.restore).read_text(encoding="utf-8"))
    client = StackClient(args.api)
    try:
        client.login(args.email, password)
        failed = restore_snapshot(client, saved)
    finally:
        client.close()
    if failed:
        print("not restored: " + "; ".join(failed))
        return 1
    Path(args.restore).unlink(missing_ok=True)
    print(f"restored {len(saved)} setting(s)")
    return 0


def run_in_process(args: argparse.Namespace) -> list[RunRecord]:
    from scripts.rehearsal.inprocess import Rehearsal, rehearse

    records = []
    for index in range(args.repeat):
        rehearsal = Rehearsal(
            scenario=args.scenario,
            provider=args.provider,
            work_dir=Path(args.out) / f"work-{index + 1}",
            tokens_per_second=args.tokens_per_second,
            first_token_seconds=args.first_token_seconds,
            loop_steps=args.loop_steps,
            slow_seconds=args.slow_seconds,
            job_timeout_s=args.job_timeout or None,
            chars_per_token=args.chars_per_token,
        )
        records.append(asyncio.run(rehearse(rehearsal)))
    return records


def write_results(records: list[RunRecord], out: Path) -> int:
    """Each run's JSON and markdown, the comparison, and the exit code."""
    out.mkdir(parents=True, exist_ok=True)
    signatures = []
    failed = False
    for index, record in enumerate(records, 1):
        checks = check_run(record)
        failed = failed or not all(c.ok for c in checks)
        stem = f"{record.scenario}-run{index}"
        (out / f"{stem}.json").write_text(
            json.dumps(as_json(record, checks), indent=1, default=str), encoding="utf-8"
        )
        (out / f"{stem}.md").write_text(as_markdown(record, checks), encoding="utf-8")
        signatures.append(signature(record, checks))
        status = "PASS" if all(c.ok for c in checks) else "FAIL"
        print(f"run {index}: {status} ({record.elapsed_s:.1f}s, verdict {record.verdict})")
        for check in checks:
            if not check.ok:
                print(f"  FAIL {check.name}: {check.detail}")
    differences = compare(signatures)
    summary = {
        "runs": len(records),
        "passed": not failed,
        "identical": not differences,
        "differences": differences,
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    if len(records) > 1:
        listed = "\n  ".join(differences)
        print("runs identical" if not differences else f"runs differ:\n  {listed}")
    return 1 if failed or differences or not records else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scenario", default="normal", choices=sorted(SCENARIOS))
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--out", default="rehearsal-results")
    parser.add_argument("--in-process", action="store_true", help="no stack: run in this process")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--email", default="")
    parser.add_argument("--login-env", default="REHEARSAL_LOGIN")
    parser.add_argument("--stub-url", default="", help="a stub already running; else one starts")
    parser.add_argument("--stub-port", type=int, default=0, help="0 takes a free port")
    parser.add_argument(
        "--stub-host",
        default="127.0.0.1",
        help="the address the stub binds: loopback, or the Docker bridge gateway a containerised "
        "worker reaches the host on (172.17.0.0 to 172.31.255.255)",
    )
    parser.add_argument(
        "--redis-url",
        default=os.environ.get("REDIS_URL", ""),
        help="the stack's Redis, to check every account's jobs before the gate starts",
    )
    parser.add_argument(
        "--configure",
        choices=["gate", "harness"],
        default=None,
        help="point the stack at the stub (gate: the operator's own configuration), then restore",
    )
    parser.add_argument("--restore", default="", help="put back a settings snapshot and exit")
    parser.add_argument("--provider", default="openai", choices=["openai", "anthropic"])
    parser.add_argument("--expect", action="append", default=[], help="key=value in force")
    parser.add_argument("--tokens-per-second", type=float, default=0.0)
    parser.add_argument("--first-token-seconds", type=float, default=0.0)
    parser.add_argument("--window", type=int, default=None)
    parser.add_argument("--slots", type=int, default=1)
    parser.add_argument("--chars-per-token", type=int, default=4)
    parser.add_argument("--loop-steps", type=int, default=None)
    parser.add_argument("--slow-seconds", type=float, default=None)
    parser.add_argument("--timeout", type=float, default=3600.0, help="seconds to wait per job")
    parser.add_argument(
        "--job-timeout",
        type=float,
        default=None,
        help="the worker's job timeout, when the settings do not carry one",
    )
    args = parser.parse_args(argv)
    if args.restore:
        if not args.email:
            parser.error("--email is required to restore")
        return run_restore(args)
    if args.repeat < 1:
        parser.error("--repeat is at least 1")
    print(f"scenario {args.scenario}: {SCENARIOS[args.scenario]}", flush=True)
    if args.in_process:
        records = run_in_process(args)
    else:
        if not args.email:
            parser.error("--email is required against the stack")
        records = run_against_stack(args)
    return write_results(records, Path(args.out))


if __name__ == "__main__":
    raise SystemExit(main())
