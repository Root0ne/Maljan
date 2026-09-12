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

import hashlib
import json
import re
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx

from maljan.core.logger import logger
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.limits import read_capped, stream_to_file_capped
from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

if TYPE_CHECKING:
    from maljan.core.config import SandboxTriageConfig, Settings
    from maljan.schemas.sandbox_report import SandboxRun

# The five calls this provider makes, as named constants so a documentation
# change is a one-line edit. Verified against https://tria.ge/docs/cloud-api/
# on 2026-09-04 (see the module docstring for exactly what was reachable and
# how each constant was confirmed).
SUBMIT_PATH = "/samples"  # POST, multipart: file + _json
OWNED_SAMPLES_PATH = "/samples"  # GET ?subset=owned, the caller's own submissions
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

# A submission whose response never arrived is reconciled against the
# caller's own recent samples before anything is posted a second time.
_RECONCILE_LIMIT = 20
_RECONCILE_WINDOW_SECONDS = 600.0
_SUBMIT_RETRY_DELAY_SECONDS = 2.0

_SAFE_PATH_COMPONENT_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _safe_path_component(value: str) -> str:
    """Keep only characters safe in a filename and a URL path segment.

    M12 (final review): ``task_id`` comes from Triage's own submit response
    and the task name from its overview — both are interpolated into a
    destination path and a URL path. The trust boundary is the operator's
    own configured Triage instance, so the exposure is small, but a
    ``Path(...).name``-style guard costs nothing. A value that sanitises to
    nothing (empty, or e.g. all ``..``/``/``) falls back to a fresh uuid
    rather than producing an empty or traversal-prone path segment.
    """
    cleaned = _SAFE_PATH_COMPONENT_RE.sub("_", value).strip("._")
    return cleaned or uuid.uuid4().hex


def _parse_retry_after(value: str, now: float) -> float | None:
    """RFC 9110 permits delta-seconds or an HTTP-date; a server may send either.

    Returns seconds to wait, or ``None`` when the header is present but
    unparseable in both forms (the caller falls back to its own backoff
    rather than raising, and than crashing the poll loop on a header from a
    third party this provider does not control).
    """
    try:
        return float(value)
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        # RFC 9110 HTTP-dates are always GMT; treat a naive value as such
        # rather than comparing it against a UTC "now" as if it were local.
        when = when.replace(tzinfo=UTC)
    return (when - datetime.now(UTC)).total_seconds()


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
        self._now_utc = lambda: datetime.now(UTC)

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

    def _profile_for(self, path: Path) -> str:
        """The VM profile this sample's format asks for, else the plain default.

        ``profile_by_format`` is keyed by detected file type with ``"*"`` as
        its fallback, and ``profile`` is the fallback behind that — so an
        operator who never touches the map keeps the profile they configured.
        """
        from maljan.providers.sandbox.formats import detect_sample_format, option_for_format

        file_type, _platform = detect_sample_format(path)
        return option_for_format(self._cfg.profile_by_format, file_type, self._cfg.profile)

    def _post_sample(self, path: Path, headers: dict[str, str]) -> httpx.Response:
        payload: dict[str, Any] = {"kind": "file", "interactive": False}
        profile = self._profile_for(path)
        if profile:
            payload["profiles"] = [{"profile": profile, "pick": "default"}]
        with open(path, "rb") as fh:
            return self._get_http().post(
                SUBMIT_PATH,
                files={
                    "file": (path.name, fh, "application/octet-stream"),
                    "_json": (None, json.dumps(payload), "application/json"),
                },
                headers=headers,
            )

    @staticmethod
    def _sha256_of(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _submitted_at(entry: dict[str, Any]) -> datetime | None:
        """Parse a sample's own timestamp, whichever of the two fields carries it."""
        raw = str(entry.get("submitted") or entry.get("created") or "")
        if not raw:
            return None
        try:
            when = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
        return when if when.tzinfo else when.replace(tzinfo=UTC)

    def _find_recent_owned_sample(self, sha256: str, headers: dict[str, str]) -> str | None:
        """The id of this operator's own newest sample with ``sha256``, if it is fresh.

        Answers ``None`` for anything uncertain — an unreachable listing, an
        error status, a body in another shape, a match older than the
        reconcile window — because a wrong id here would attach a run to
        somebody else's detonation of the same file.
        """
        try:
            response = self._get_http().get(
                OWNED_SAMPLES_PATH,
                params={"subset": "owned", "limit": _RECONCILE_LIMIT},
                headers=headers,
            )
        except httpx.HTTPError as exc:
            logger.warning("Triage: could not list owned samples to reconcile: %s", exc)
            return None
        if response.status_code >= 400:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        rows = body.get("data") if isinstance(body, dict) else None
        if not isinstance(rows, list):
            return None
        now = self._now_utc()
        candidates: list[tuple[datetime, str]] = []
        for row in rows:
            if not isinstance(row, dict) or not row.get("id"):
                continue
            if str(row.get("sha256") or "").lower() != sha256.lower():
                continue
            when = self._submitted_at(row)
            if when is None or (now - when).total_seconds() > _RECONCILE_WINDOW_SECONDS:
                continue
            candidates.append((when, str(row["id"])))
        if not candidates:
            return None
        return max(candidates)[1]

    def submit(self, sample_path: str | Path) -> str:
        # Checked before the file is opened or any request is built: a
        # missing token is a configuration error, not something worth
        # burning a filesystem check or a connection on first.
        headers = self._auth_headers()
        path = Path(sample_path)
        try:
            response = self._post_sample(path, headers)
        except httpx.TransportError as exc:
            # The upload can have been accepted in full and only the response
            # dropped — live run S6: the sample was on Triage, reported,
            # while the run treated the submission as failed and lost its
            # sandbox data. Look for it before posting the same file again,
            # so a reconciled submission leaves no orphan behind. An HTTP
            # status is a different matter and is never retried: a 401 or a
            # 400 means the request itself was refused.
            logger.warning("Triage: submit response was dropped (%s); reconciling.", exc)
            existing = self._find_recent_owned_sample(self._sha256_of(path), headers)
            if existing:
                logger.info("Triage: the dropped submission is sample %s; reusing it.", existing)
                return existing
            self._sleep(_SUBMIT_RETRY_DELAY_SECONDS)
            try:
                response = self._post_sample(path, headers)
            except httpx.TransportError:
                raise ProviderError(f"Triage submit failed: {exc}") from exc
            # Anything else the retry raises is left exactly as it is: only a
            # dropped transport is this path's business, and rewriting an
            # unrelated failure into "Triage submit failed" would hide it.
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
                # The header may be delta-seconds or an HTTP-date (RFC 9110);
                # either way the wait is clamped to what remains of this
                # call's own deadline, since the top-of-loop check above
                # cannot interrupt a sleep already in progress — a server
                # answering e.g. "Retry-After: 86400" must not park this
                # call for a day.
                retry_after = response.headers.get("Retry-After")
                parsed = _parse_retry_after(retry_after, self._now()) if retry_after else None
                # A sustained ``Retry-After: 0`` (or a negative/expired
                # HTTP-date) must not spin the loop: floor the wait at the
                # current backoff interval whenever the header does not ask
                # for a positive wait, the same as when it is absent.
                honoured = parsed is not None and parsed > 0
                wait_seconds: float = parsed if parsed is not None and honoured else interval
                remaining = deadline - self._now()
                clamped = min(wait_seconds, _MAX_INTERVAL_SECONDS, remaining)
                if clamped > 0:
                    self._sleep(clamped)
                if not honoured:
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

        The live API returns ``tasks`` as a dict keyed by task id while the
        documented shape is a list; both are read here, keeping the order the
        overview listed them in.
        """
        tasks = overview.get("tasks")
        if isinstance(tasks, dict):
            listed: list[Any] = list(tasks.values())
        elif isinstance(tasks, list):
            listed = list(tasks)
        else:
            listed = []
        names: list[str] = []
        for one_task in listed:
            if not isinstance(one_task, dict) or one_task.get("kind") != "behavioral":
                continue
            name = str(one_task.get("name") or "")
            if name:
                names.append(name)
        return names

    def _json_capped(
        self,
        http: httpx.Client,
        url: str,
        headers: dict[str, str],
        operation: str,
        *,
        skip_errors: bool = False,
    ) -> Any:
        """One JSON body, streamed and refused past the cap.

        ``skip_errors`` is for the bodies a run can do without: a behavioural
        task that never reached "reported" answers 4xx, and the overview alone
        still yields a usable, if thinner, report.
        """
        with http.stream("GET", url, headers=headers) as response:
            if response.status_code >= 400:
                if skip_errors:
                    return None
                response.read()
                self._raise_for_status(response, operation)
            body = read_capped(response, what=f"The Triage {operation.split()[0]} body")
        try:
            return json.loads(body)
        except ValueError as exc:
            raise ProviderError(f"Triage {operation} did not return valid JSON.") from exc

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        headers = self._auth_headers()
        http = self._get_http()
        # Streamed and capped rather than fetched whole: an overview
        # and its behavioural reports are the bodies Triage legitimately sends
        # by the hundreds of megabytes, and their size is the remote end's
        # choice alone.
        overview = self._json_capped(
            http, OVERVIEW_PATH.format(sample_id=task_id), headers, "overview fetch"
        )

        task_reports: dict[str, dict[str, Any]] = {}
        for name in self._behavioral_task_names(overview):
            report = self._json_capped(
                http,
                TASK_REPORT_PATH.format(sample_id=task_id, task=name),
                headers,
                "task report fetch",
                # A task that never reached "reported" has no report yet; the
                # overview alone still yields a usable, if thinner, report.
                skip_errors=True,
            )
            if report is None:
                continue
            task_reports[name] = report

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
        safe_task_id = _safe_path_component(str(task_id))
        safe_task_name = _safe_path_component(names[0])
        out = dest / f"triage_{safe_task_id}.pcap"
        url = PCAP_PATH.format(sample_id=safe_task_id, task=safe_task_name)
        try:
            with http.stream("GET", url, headers=headers) as response:
                if response.status_code >= 400:
                    return None
                # A capture past the cap degrades this call the way
                # every other pcap failure does, rather than filling the disk.
                stream_to_file_capped(response, out, what="The Triage capture")
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
