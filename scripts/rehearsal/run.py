"""Rehearse an analysis at zero cost, and check it against the written checklist.

Against the locally running stack (API + worker, mock sandbox), with every
model call going to the loopback stub model this script starts (or one already
running, ``--stub-url``)::

    REHEARSAL_PASSWORD=... python scripts/rehearsal/run.py \\
        --api http://127.0.0.1:8000 --email operator@example.org \\
        --scenario normal --repeat 3 --out rehearsal-results

Without the stack, the same pipeline inside this process (``--in-process``)::

    python scripts/rehearsal/run.py --in-process --scenario normal --repeat 3

Each run submits the synthetic sample (``scripts/rehearsal/sample.py``), waits
for the job, collects the job, the stored report, its run summary, its STIX
bundles and markdown and the job's events, and checks them
(``scripts/rehearsal/checklist.py``). One JSON and one markdown file per run,
and a summary comparing the runs of a ``--repeat``. The exit code is non-zero
when any check of any run fails or when repeated runs differ.

The stack must already send its model calls to the stub. ``--configure`` does
it through the settings API — the OpenAI base URL (or, with ``--provider
anthropic``, the Anthropic base URL), the models, the effort and the caps the
checklist then expects in force — and runs the connection test so the probe
gate admits the job; it prints every key it changed. Without it nothing on the
stack is changed, and ``--expect key=value`` names what to find in force.

The password is read from the environment variable named by
``--password-env``; it is never taken on the command line or printed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
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
from scripts.rehearsal.stub_model import ModelFacts, Pace, StubServer, StubState  # noqa: E402

TERMINAL = {"completed", "failed", "cancelled", "canceled"}


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

    def configure(self, changes: dict[str, Any]) -> list[str]:
        answer = self._http.patch("/settings", json={"changes": changes})
        if answer.status_code >= 400:
            raise RuntimeError(f"the settings were refused: {answer.text[:500]}")
        return list(answer.json().get("applied") or [])

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

    def job(self, job_id: str) -> dict[str, Any]:
        answer = self._http.get(f"/jobs/{job_id}")
        answer.raise_for_status()
        return dict(answer.json())

    def wait(self, job_id: str, timeout_s: float, poll_s: float = 5.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_s
        while True:
            job = self.job(job_id)
            if str(job.get("status")) in TERMINAL or time.monotonic() > deadline:
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


def stack_settings(provider: str, stub_root: str, effort: str, judge_max_tokens: int) -> dict:
    """The settings ``--configure`` writes: the stub's address, the models, effort and caps."""
    from scripts.rehearsal.inprocess import API_KEY, EXPERT_MODEL, JUDGE_MODEL

    changes: dict[str, Any] = {
        "core.llm.provider": provider,
        "core.llm.judge_max_tokens": judge_max_tokens,
        "core.sandbox.provider": "mock",
    }
    if provider == "anthropic":
        changes.update(
            {
                "core.llm.anthropic.base_url": stub_root,
                "core.llm.anthropic.api_key": API_KEY,
                "core.llm.anthropic.expert_model": EXPERT_MODEL,
                "core.llm.anthropic.judge_model": EXPERT_MODEL,
                "core.llm.anthropic.effort": effort,
                "core.llm.agents": {"judge": {"provider": "anthropic", "model": JUDGE_MODEL}},
            }
        )
    else:
        changes.update(
            {
                "core.llm.openai.base_url": f"{stub_root}/v1",
                "core.llm.openai.api_key": API_KEY,
                "core.llm.openai.expert_model": EXPERT_MODEL,
                "core.llm.openai.judge_model": EXPERT_MODEL,
                "core.llm.openai.reasoning_effort": effort,
                "core.llm.agents": {
                    "judge": {
                        "provider": "openai",
                        "model": JUDGE_MODEL,
                        "base_url": f"{stub_root}/v1",
                    }
                },
            }
        )
    return changes


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
) -> RunRecord:
    """A run's record, read back from the API the way the console reads it."""
    report = client.report(job_id) or {}
    report_id = str(report.get("id") or "")
    claims: dict[str, list[str]] = {}
    for finding in report.get("agent_findings") or []:
        texts = [
            str(c.get("claim"))
            for c in finding.get("claims") or []
            if isinstance(c, dict) and c.get("claim")
        ]
        claims[str(finding.get("agent_name"))] = texts
    return RunRecord(
        scenario=scenario,
        job_status=str(job.get("status") or ""),
        job_error=str(job.get("error_message") or ""),
        verdict=str(report.get("verdict") or ""),
        run_summary=dict(report.get("run_summary") or {}),
        malware_report=dict(report.get("malware_report") or {}),
        markdown=client.markdown(report_id) if report_id else "",
        stix_bundle=client.judge_bundle(report_id) if report_id else {},
        stix_extended=dict(report.get("stix_bundle") or {}),
        claims_in_force=claims,
        events=[_normal_event(e) for e in client.events(job_id)],
        stub_log=stub_log,
        expected=expected,
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


def run_against_stack(args: argparse.Namespace) -> list[RunRecord]:
    password = os.environ.get(args.password_env, "")
    if not password:
        raise SystemExit(f"set the account's password in the environment as {args.password_env}")
    brain = Brain(
        scenario=args.scenario,
        loop_steps=args.loop_steps,
        slow_seconds=args.slow_seconds,
    )
    server: StubServer | None = None
    if not args.stub_url:
        state = StubState(
            brain=brain,
            pace=Pace(args.first_token_seconds, args.tokens_per_second),
            facts=ModelFacts(window=args.window, slots=args.slots),
        )
        server = StubServer(state, args.stub_port).start()
    stub_root = args.stub_url.rstrip("/") if args.stub_url else server.root  # type: ignore[union-attr]
    client = StackClient(args.api)
    records: list[RunRecord] = []
    try:
        client.login(args.email, password)
        expected = _parse_expect(args.expect)
        if args.configure:
            changes = stack_settings(args.provider, stub_root, args.effort, args.judge_max_tokens)
            probe = client.probe_models(changes)
            print(f"connection test: {'ok' if probe.get('ok') else probe.get('detail')}")
            applied = client.configure(changes)
            print(f"configured: {', '.join(sorted(applied)) or 'nothing new'}", flush=True)
            from scripts.rehearsal.inprocess import EXPERT_MODEL, JUDGE_MODEL

            expected = {
                "model.static": EXPERT_MODEL,
                "model.judge": JUDGE_MODEL,
                "model.mediator": EXPERT_MODEL,
                "model.reporter": EXPERT_MODEL,
                "effort": args.effort,
                "max_tokens.judge": args.judge_max_tokens,
                **expected,
            }
        params = {"loop_steps": brain.loop_steps, "slow_seconds": brain.slow_seconds}
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
                )
            )
    finally:
        client.close()
        if server is not None:
            server.stop()
    return records


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
            job_timeout_s=args.timeout,
            effort=args.effort,
            judge_max_tokens=args.judge_max_tokens,
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
    return 1 if failed or differences else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--scenario", default="normal", choices=sorted(SCENARIOS))
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--out", default="rehearsal-results")
    parser.add_argument("--in-process", action="store_true", help="no stack: run in this process")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--email", default="")
    parser.add_argument("--password-env", default="REHEARSAL_PASSWORD")
    parser.add_argument("--stub-url", default="", help="a stub already running; else one starts")
    parser.add_argument("--stub-port", type=int, default=8765)
    parser.add_argument("--configure", action="store_true", help="point the stack at the stub")
    parser.add_argument("--provider", default="openai", choices=["openai", "anthropic"])
    parser.add_argument("--effort", default="high")
    parser.add_argument("--judge-max-tokens", type=int, default=9000)
    parser.add_argument("--expect", action="append", default=[], help="key=value in force")
    parser.add_argument("--tokens-per-second", type=float, default=0.0)
    parser.add_argument("--first-token-seconds", type=float, default=0.0)
    parser.add_argument("--window", type=int, default=200_000)
    parser.add_argument("--slots", type=int, default=1)
    parser.add_argument("--loop-steps", type=int, default=None)
    parser.add_argument("--slow-seconds", type=float, default=None)
    parser.add_argument("--timeout", type=float, default=3600.0, help="seconds to wait per job")
    args = parser.parse_args(argv)
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
