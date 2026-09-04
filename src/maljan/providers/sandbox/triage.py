"""Hatching Triage cloud sandbox behind the provider contract.

Triage detonates on Hatching's own cloud VMs and hands back two report
shapes per run: one overview (``overview.json``) for the whole sample, and
one behavioural report (``report_triage.json``) per task. Submission is a
multipart POST, completion is polled rather than pushed, and the sandbox
publishes no per-API-call log — ``UNAVAILABLE`` on this provider says exactly
that, so a rendered report never reads like a clean sample by omission.

Endpoints verified against https://tria.ge/docs/cloud-api/ on 2026-09-04.
The docs root itself returns HTTP 403 to an automated fetch; every path below
and the terminal-status set were instead confirmed against the indexed
content of the "Samples", "Overview Report", "Resources" and "Conventions"
sub-pages, which were reachable. What was actually confirmed:

- ``POST /samples`` — sample submission (the "Samples" page); multipart
  field names ``file``, ``_json``, ``kind`` (``"file"``/``"url"``/``"fetch"``/
  ``"import"``), ``target``, ``interactive``, ``password``, ``profiles``
  (an array of ``{"profile": ..., "pick": ...}`` mappings), ``user_tags``,
  ``defaults.timeout``, ``defaults.network``.
- ``GET /samples/{sampleID}`` — status; quoted exactly by the "Samples" page,
  whose Sample Object definition enumerates the status progression pending,
  static_analysis, scheduled, running, processing, then the two terminal
  states reported and failed.
- ``GET /samples/{sampleID}/overview.json`` — quoted exactly by the
  "Overview Report" page.
- ``GET /samples/{sampleID}/{taskID}/report_triage.json`` — quoted exactly by
  the "Samples" page; returns ``404 REPORT_NOT_AVAILABLE`` before the task
  reaches "reported".
- ``GET /samples/{sampleID}/{taskID}/dump.pcap`` — quoted in full, including
  the ``https://tria.ge/api/v0`` base, alongside its documented ``.pcapng``
  sibling — this is also what confirms the base URL already configured on
  ``SandboxTriageConfig.base_url``.
- ``GET /resources`` — "List all resources available" (the "Resources"
  page); the cheapest authenticated read this API documents, used below for
  the connection test the same way CAPE2 uses ``tasks/view/1/``.
- Auth: ``Authorization: Bearer <apikey>``, quoted exactly by the
  "Conventions" page.

None of the five path constants or the terminal-status set needed correcting
against the brief. No rate-limit, 429 or Retry-After section was reachable in
any of the pages above; the backoff and Retry-After handling in
``wait_for_completion`` is therefore defensive engineering, not a documented
contract, and is called out as such here rather than implied to be spec'd.

A first pass at ``report_triage.json``'s ``network`` shape (flat
``requests``/``flows`` arrays with CAPE-like fields) turned out to be wrong —
found during review, not confirmed against anything. The "Dynamic Report"
docs page, reached the same way as the pages above, gives the real shape:
``network.flows[]`` carries the endpoint as one combined ``"host:port"``
string (no separate port field) plus per-flow ``proto``/``country``/
``as_num``/``as_org``; ``network.requests[]`` is a discriminated union —
``domain_req``/``domain_resp`` for a DNS lookup, ``web_req``/``web_resp`` for
an HTTP request — never a flat DNS/HTTP row. ``triage_overview_to_sandbox_report``
(``schemas/sandbox_report.py``) maps both into the shapes
``network_extractor``/``network_parser`` actually read, not Triage's own
field names.
"""

from __future__ import annotations

import json
import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from maljan.core.logger import logger
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

if TYPE_CHECKING:
    from maljan.core.config import SandboxTriageConfig, Settings
    from maljan.schemas.sandbox_report import SandboxRun

# The five calls this provider makes, as named constants so a documentation
# change is a one-line edit. Verified against https://tria.ge/docs/cloud-api/
# on 2026-09-04 (see the module docstring for exactly what was reachable and
# how each constant was confirmed).
SUBMIT_PATH = "/samples"  # POST, multipart: file + _json
STATUS_PATH = "/samples/{sample_id}"  # GET, status "reported" is terminal
OVERVIEW_PATH = "/samples/{sample_id}/overview.json"  # GET
TASK_REPORT_PATH = "/samples/{sample_id}/{task}/report_triage.json"  # GET
PCAP_PATH = "/samples/{sample_id}/{task}/dump.pcap"  # GET, streamed
TERMINAL_STATUSES = frozenset({"reported", "failed"})

# The read used by both connection tests (this provider's own ``probe`` and
# the settings UI's ``probe_triage``): "List all resources available", the
# cheapest authenticated GET this API documents — the same role CAPE2's
# ``/apiv2/tasks/view/1/`` plays for that provider.
RESOURCES_PATH = "/resources"

_BACKOFF_FACTOR = 1.5
_MAX_INTERVAL_SECONDS = 60.0


@register_sandbox_provider("triage")
class TriageSandboxProvider(SandboxProvider):
    """Hatching Triage cloud sandbox: submit, poll, fetch, all over REST.

    Triage never publishes a per-API-call log, so there is no ``apistats``,
    ``calls``, registry timeline or generic-event stream to map, and a file
    sample gets no screenshot either (the "Dynamic Report" docs page lists
    Triage's own top-level report fields — Version/Sample/Task/Errors/
    Analysis/Processes/Signatures/Network/Debug/Dumped/Extracted — and none
    of them is a screenshot). ``UNAVAILABLE`` names all five rather than
    leaving them silently empty, which would read exactly like a clean
    sample.
    """

    UNAVAILABLE: ClassVar[tuple[str, ...]] = (
        "apistats",
        "calls",
        "registry",
        "generic_events",
        "screenshots",
    )

    def __init__(self, cfg: SandboxTriageConfig) -> None:
        self._cfg = cfg
        self._http: httpx.Client | None = None
        # Instance attributes, not module functions, so a test can drive the
        # clock and the sleeps without patching the stdlib.
        self._sleep = time.sleep
        self._now = time.monotonic

    @classmethod
    def from_settings(cls, cfg: Settings) -> TriageSandboxProvider:
        return cls(cfg.sandbox.triage)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=bool(self._cfg.fetch_pcap),
            provides_tools=False,
            report_format="triage",
            degrade_on_failure=True,
        )

    def _require_token(self) -> str:
        token = self._cfg.api_token.get_secret_value()
        if not token:
            raise ProviderError(
                "Hatching Triage requires an API token; set sandbox.triage.api_token."
            )
        return token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._require_token()}"}

    def _get_http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self._cfg.base_url,
                headers=self._auth_headers(),
                timeout=60.0,
            )
        return self._http

    @staticmethod
    def _raise_for_status(response: httpx.Response, operation: str) -> None:
        if response.status_code >= 400:
            raise ProviderError(
                f"Triage {operation} failed (HTTP {response.status_code}): {response.text[:200]}"
            )

    def submit(self, sample_path: str | Path) -> str:
        # Checked before the file is opened or any request is built: a
        # missing token is a configuration error, not something worth
        # burning a filesystem check or a connection on first.
        headers = self._auth_headers()
        path = Path(sample_path)
        payload: dict[str, Any] = {"kind": "file", "interactive": False}
        if self._cfg.profile:
            payload["profiles"] = [{"profile": self._cfg.profile, "pick": "default"}]
        with open(path, "rb") as fh:
            response = self._get_http().post(
                SUBMIT_PATH,
                files={
                    "file": (path.name, fh, "application/octet-stream"),
                    "_json": (None, json.dumps(payload), "application/json"),
                },
                headers=headers,
            )
        self._raise_for_status(response, "submit")
        data = response.json()
        sample_id = data.get("id")
        if not sample_id:
            raise ProviderError("Unexpected Triage submit response: no sample id returned.")
        return str(sample_id)

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        headers = self._auth_headers()
        interval = float(poll_interval_seconds or self._cfg.poll_interval_seconds)
        budget = float(
            timeout_seconds if timeout_seconds is not None else self._cfg.timeout_seconds
        )
        deadline = self._now() + budget
        http = self._get_http()
        url = STATUS_PATH.format(sample_id=task_id)
        while True:
            # Checked at the top of every iteration, including the rate-limit
            # branch below: a server that keeps answering 429/503 past the
            # deadline must still raise rather than loop forever.
            if self._now() >= deadline:
                raise ProviderError(f"Triage task {task_id} did not complete within {budget:.0f}s.")
            response = http.get(url, headers=headers)
            if response.status_code in (429, 503):
                # "Come back later" — no documented rate limit was reachable
                # (see the module docstring), so a Retry-After header is
                # honoured when present and the ordinary backoff otherwise.
                retry_after = response.headers.get("Retry-After")
                wait_seconds = float(retry_after) if retry_after else interval
                self._sleep(wait_seconds)
                if not retry_after:
                    interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)
                continue
            self._raise_for_status(response, "status check")
            status = str(response.json().get("status") or "")
            if status in TERMINAL_STATUSES:
                return status
            self._sleep(interval)
            interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)

    @staticmethod
    def _behavioral_task_names(overview: dict[str, Any]) -> list[str]:
        """Names of every behavioural task in an overview, in listed order.

        The one place this is worked out, shared by ``fetch`` (which needs
        every behavioural task's report) and ``fetch_pcap`` (which needs the
        first one's capture) — so a sample whose first task isn't literally
        named ``"behavioral1"``, or that ran several, is handled the same way
        in both places instead of one of them guessing.
        """
        tasks = overview.get("tasks")
        names: list[str] = []
        for one_task in tasks if isinstance(tasks, list) else []:
            if not isinstance(one_task, dict) or one_task.get("kind") != "behavioral":
                continue
            name = str(one_task.get("name") or "")
            if name:
                names.append(name)
        return names

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        headers = self._auth_headers()
        http = self._get_http()
        overview_response = http.get(OVERVIEW_PATH.format(sample_id=task_id), headers=headers)
        self._raise_for_status(overview_response, "overview fetch")
        overview = overview_response.json()

        task_reports: dict[str, dict[str, Any]] = {}
        for name in self._behavioral_task_names(overview):
            response = http.get(
                TASK_REPORT_PATH.format(sample_id=task_id, task=name), headers=headers
            )
            if response.status_code >= 400:
                # A task that never reached "reported" has no report yet; the
                # overview alone still yields a usable, if thinner, report.
                continue
            task_reports[name] = response.json()

        report = triage_overview_to_sandbox_report(
            overview, provider="triage", task_reports=task_reports, task_id=str(task_id)
        )
        return SandboxRun(
            task_id=str(task_id),
            sample_sha256=report.target.sha256,
            sample_name=report.target.name,
            status="reported",
            report=report,
            raw=overview,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        if not self._cfg.fetch_pcap:
            return None
        headers = self._auth_headers()
        http = self._get_http()
        overview_response = http.get(OVERVIEW_PATH.format(sample_id=task_id), headers=headers)
        if overview_response.status_code >= 400:
            logger.info(
                "Triage: could not fetch the overview for %s (HTTP %d) while looking for a "
                "PCAP task; skipping.",
                task_id,
                overview_response.status_code,
            )
            return None
        names = self._behavioral_task_names(overview_response.json())
        if not names:
            logger.info("Triage: sample %s has no behavioural task; no PCAP to fetch.", task_id)
            return None

        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / f"triage_{task_id}.pcap"
        url = PCAP_PATH.format(sample_id=task_id, task=names[0])
        try:
            with http.stream("GET", url, headers=headers) as response:
                if response.status_code >= 400:
                    return None
                with open(out, "wb") as f:
                    for chunk in response.iter_bytes(65536):
                        f.write(chunk)
        except Exception:
            # Never a hard failure: the network analyst falls back to the
            # structured ``network`` block alone, exactly as CAPEv2Client's
            # fetch_pcap already behaves for this project's other sandbox.
            return None

        # libpcap/pcapng global header is 24 bytes; anything smaller is empty.
        size = out.stat().st_size if out.exists() else 0
        if size < 24:
            return None
        return str(out)

    async def probe(self) -> ProviderProbe:
        """List resources: the cheapest documented call that exercises URL and token."""
        t0 = time.perf_counter()
        try:
            token = self._require_token()
        except ProviderError as exc:
            return ProviderProbe(ok=False, detail=str(exc))
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{self._cfg.base_url.rstrip('/')}{RESOURCES_PATH}"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            from maljan.core.settings_overrides import redact_url

            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}"),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        return ProviderProbe(
            ok=response.status_code < 400,
            detail=f"HTTP {response.status_code}",
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        """Release the REST connection pool, if one was ever built. Never raises."""
        client, self._http = self._http, None
        if client is not None:
            with suppress(Exception):
                client.close()
