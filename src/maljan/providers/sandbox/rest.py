"""Any HTTP sandbox, described rather than coded.

CAPEv2 and Triage each get an adapter because each has a documented API worth
writing against. A lab running something else — a home-grown detonation
service, a vendor appliance, a fork of Cuckoo — has an API too, and it is
almost always the same four calls in a different order with different field
names. This provider is those four calls with the names in settings: where to
POST the sample, where the task id is in the answer, where to poll, which
state values are terminal, where the report is, and (when the report is in no
shape this project already reads) where each channel of it lives.

The poll loop is Triage's, deliberately and by import rather than by copy: the
deadline is checked at the top of every iteration including the rate-limited
branch, ``Retry-After`` is parsed as delta-seconds or an HTTP-date and clamped
to what remains of the budget, and the interval backs off 1.5x to 60 s.
"""

from __future__ import annotations

import time
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from maljan.core.logger import logger
from maljan.providers.base import ProviderProbe, SandboxCapabilities, SandboxProvider
from maljan.providers.errors import PACKET_CAPTURE, ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.limits import read_capped, stream_to_file_capped
from maljan.providers.sandbox.rest_mapping import compile_mapping
from maljan.providers.sandbox.triage import (
    _BACKOFF_FACTOR,
    _MAX_INTERVAL_SECONDS,
    POLL_TRANSPORT_ERRORS,
    _parse_retry_after,
    _safe_path_component,
    fetch_artefact,
    poll_deadline_error,
    poll_failure,
    stop_if_cancelled,
    wait_after_poll_failure,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from maljan.core.config import SandboxRestConfig, Settings
    from maljan.core.report_formats import ReportFormat, SignatureScale
    from maljan.providers.sandbox.rest_mapping import CompiledMapping
    from maljan.schemas.sandbox_report import SandboxRun


def _fill_task_id(template: str, task_id: str) -> str:
    """Substitute ``{task_id}`` in a path template without ``str.format``.

    Regression (F11): an operator-configured path can carry any other
    ``{...}`` an unrelated tool left behind (a doc example, a copy-pasted
    OpenAPI path parameter); ``str.format`` raises ``KeyError``/``IndexError``
    on those, an uncaught 500 from the probe route and an unwrapped exception
    on the job path rather than a legible ``ProviderError``. A single
    ``replace`` only ever touches the one placeholder this project defines,
    so a stray brace elsewhere in the string passes through untouched.
    """
    return template.replace("{task_id}", task_id)


def _validate_task_id_template(label: str, template: str) -> None:
    """Reject a path template with a brace outside the one placeholder.

    Called once, from ``from_settings``, so a mistyped path fails loudly at
    configuration time rather than mid-job the first time ``_fill_task_id``
    is asked to fill in a real task id.
    """
    if "{" not in template and "}" not in template:
        return
    remainder = template.replace("{task_id}", "")
    if "{" in remainder or "}" in remainder:
        from maljan.providers.errors import ProviderConfigurationError

        raise ProviderConfigurationError(
            f"sandbox.rest.{label} {template!r} has a brace outside the single "
            "{task_id} placeholder"
        )


@register_sandbox_provider("rest")
class RestSandboxProvider(SandboxProvider):
    """Submit, poll, fetch and (optionally) capture, all from configuration."""

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "Any HTTP sandbox"
    choice_order = 4
    title = "Generic REST API"
    description = "Any sandbox with an HTTP API, described by the paths the next steps fill in."
    probe_label = "Test sandbox API"
    settings_intro = "Where the sandbox API lives and how a request authenticates."

    def __init__(
        self,
        cfg: SandboxRestConfig,
        mapping: CompiledMapping,
        formats: Iterable[ReportFormat] = (),
    ) -> None:
        from maljan.providers.sandbox.readers import sandbox_formats

        self._cfg = cfg
        self._mapping = mapping
        # The registry's formats (``sandbox.report_formats`` over the built-ins,
        # and the registered readers), which name the sandbox a report's
        # lineage sentence states and the scale its signatures are read on.
        self._formats = sandbox_formats(formats)
        # Each declared format's own mapping, compiled once here so a bad path
        # is refused before a job detonates anything.
        self._format_mappings: dict[str, CompiledMapping] = {
            fmt.name: compile_mapping(fmt.mapping)
            for fmt in self._formats
            if getattr(fmt, "mapping", None) is not None
        }
        self._http: httpx.Client | None = None
        # Instance attributes, not module functions, so a test can drive the
        # clock and the sleeps without patching the stdlib.
        self._sleep = time.sleep
        self._now = time.monotonic
        if not cfg.verify_tls:
            logger.warning("rest sandbox provider: TLS verification is off for %s.", cfg.base_url)

    @classmethod
    def from_settings(cls, cfg: Settings) -> RestSandboxProvider:
        """Compile the mapping here: a bad JSONPath must not reach a job."""
        from maljan.providers.errors import ProviderConfigurationError

        rest = cfg.sandbox.rest
        if not rest.base_url:
            raise ProviderConfigurationError("sandbox.rest.base_url is required")
        _validate_task_id_template("status.path", rest.status.path)
        _validate_task_id_template("report.path", rest.report.path)
        if rest.report.pcap_path:
            _validate_task_id_template("report.pcap_path", rest.report.pcap_path)
        return cls(rest, compile_mapping(rest.mapping), cfg.sandbox.report_formats)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=bool(self._cfg.report.pcap_path),
            accepts_uploaded_report=False,
            provides_tools=False,
            report_format=self._reader_id(),
            degrade_on_failure=True,
        )

    def _reader_id(self) -> str:
        """The reader that reads the fetched body: a declared format's, else the one named."""
        from maljan.providers.sandbox.readers import sandbox_format_named

        name = self._cfg.report.format
        fmt = sandbox_format_named(name, self._formats)
        return fmt.reader if fmt is not None and fmt.reader else name

    # ---- plumbing ----------------------------------------------------

    def _auth_headers(self) -> dict[str, str]:
        token = self._cfg.auth.token.get_secret_value()
        if not token:
            return {}
        scheme = self._cfg.auth.scheme.strip()
        return {self._cfg.auth.header: f"{scheme} {token}".strip() if scheme else token}

    def _tls_note(self) -> str:
        return " TLS verification is off." if not self._cfg.verify_tls else ""

    def _get_http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(
                base_url=self._cfg.base_url,
                headers=self._auth_headers(),
                timeout=60.0,
                verify=self._cfg.verify_tls,
            )
        return self._http

    def _redact(self, text: str) -> str:
        """Strip the credential out of a body a server chose to echo back.

        A misbehaving or misconfigured sandbox can reflect the request it
        received (the header line, or just the token) into an error body;
        that body is truncated and folded into a ``ProviderError`` message
        below, which can reach a log. Never let the secret ride along.
        """
        redacted = text
        token = self._cfg.auth.token.get_secret_value()
        if token:
            scheme = self._cfg.auth.scheme.strip()
            header_value = f"{scheme} {token}".strip() if scheme else token
            # The full header value first (it contains the token), then any
            # bare occurrence of the token left over, so neither survives.
            redacted = redacted.replace(header_value, "***").replace(token, "***")
        return redacted

    def _raise_for_status(self, response: httpx.Response, operation: str) -> None:
        if response.status_code >= 400:
            body = self._redact(response.text[:200])
            raise ProviderError(f"Sandbox {operation} failed (HTTP {response.status_code}): {body}")

    def _select_one(self, expression: str, payload: Any, what: str) -> str:
        """One scalar out of a response, or a failure that names the path."""
        import jsonpath_rfc9535

        try:
            found = [node.value for node in jsonpath_rfc9535.compile(expression).finditer(payload)]
        except Exception as exc:  # noqa: BLE001
            raise ProviderError(f"{what}: {expression!r} is not a usable JSONPath ({exc})") from exc
        if not found:
            raise ProviderError(f"{what}: {expression!r} matched nothing in the response")
        value = found[0]
        if isinstance(value, (dict, list)):
            raise ProviderError(
                f"{what}: {expression!r} matched a {type(value).__name__}, not a value"
            )
        return str(value)

    # ---- the four calls ----------------------------------------------

    def submission_address(self) -> str | None:
        """The host ``submit.path`` reaches on the base URL, merged as httpx merges them.

        An absolute ``submit.path`` names its own host, which is where the
        sample goes; it is stated, not refused.
        """
        from maljan.providers.base import requested_host

        return requested_host(self._cfg.base_url, self._cfg.submit.path)

    def submit(self, sample_path: str | Path) -> str:
        path = Path(sample_path)
        files: dict[str, Any] = {
            self._cfg.submit.file_field: (path.name, path.read_bytes(), "application/octet-stream")
        }
        # Both maps ride along verbatim as extra multipart fields; a
        # ``submit_fields`` entry wins a name collision, since it is the one an
        # operator reaches for when tuning a single submission.
        for name, value in self._cfg.submit.extra_fields.items():
            files[name] = (None, value)
        for name, value in self._cfg.submit.submit_fields.items():
            files[name] = (None, value)
        response = self._get_http().request(
            self._cfg.submit.method, self._cfg.submit.path, files=files
        )
        self._raise_for_status(response, "submit")
        return self._select_one(self._cfg.submit.task_id_path, response.json(), "task id")

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        interval = float(poll_interval_seconds or self._cfg.poll_interval_seconds)
        budget = float(
            timeout_seconds if timeout_seconds is not None else self._cfg.timeout_seconds
        )
        deadline = self._now() + budget
        http = self._get_http()
        # The task id came back from the sandbox's own submit response; it is
        # interpolated into a URL path here exactly as it is into a filename
        # in ``fetch_pcap``, so it gets the same guard against a server that
        # hands back a path-traversal payload instead of an opaque id.
        url = _fill_task_id(self._cfg.status.path, _safe_path_component(str(task_id)))
        done = {v.lower() for v in self._cfg.status.done_values}
        failed = {v.lower() for v in self._cfg.status.failed_values}
        what = f"Sandbox task {task_id}"
        last_error = ""
        while True:
            # Checked at the top of every iteration, including the rate-limit
            # branch: a server that keeps answering 429 past the deadline must
            # raise rather than loop forever.
            if self._now() >= deadline:
                raise poll_deadline_error(what, budget, last_error)
            # A poll that failed in transit, or a 5xx, is the sandbox busy and
            # not a verdict: waited out to the deadline, as Triage's is.
            try:
                response = http.get(url)
            except POLL_TRANSPORT_ERRORS as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                interval = wait_after_poll_failure(
                    self._sleep, self._now, interval, deadline, what, last_error
                )
                continue
            if response.status_code in (429, 503):
                retry_after = response.headers.get("Retry-After")
                parsed = _parse_retry_after(retry_after, self._now()) if retry_after else None
                # A sustained ``Retry-After: 0`` (or a negative/expired
                # HTTP-date) must not spin the loop: floor the wait at the
                # current backoff interval whenever the header does not ask
                # for a positive wait, the same as when it is absent.
                honoured = parsed is not None and parsed > 0
                wait_seconds: float = parsed if parsed is not None and honoured else interval
                clamped = min(wait_seconds, _MAX_INTERVAL_SECONDS, deadline - self._now())
                if clamped > 0:
                    self._sleep(clamped)
                if not honoured:
                    interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)
                continue
            failure = poll_failure(response)
            if failure is None:
                self._raise_for_status(response, "status check")
                try:
                    payload = response.json()
                except ValueError as exc:
                    failure = f"an unparsable status body ({exc})"
            if failure is not None:
                last_error = failure
                interval = wait_after_poll_failure(
                    self._sleep, self._now, interval, deadline, what, last_error
                )
                continue
            state = self._select_one(self._cfg.status.state_path, payload, "status").lower()
            if state in done:
                return "reported"
            if state in failed:
                return "failed"
            self._sleep(interval)
            interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)

    def signature_scale(
        self, run: SandboxRun, formats: Iterable[ReportFormat] | None = None
    ) -> SignatureScale | None:
        """The scale the report's format declares; where no format declares the
        report's reader (the mapping reader's), the scale these settings declare,
        else the reader's own."""
        from maljan.core.report_formats import format_named

        if self._cfg.report.format in self._format_mappings:
            # A declared format read through its own mapping: its own scale.
            return run.report.signature_scale
        found = format_named(run.report.source_format, formats)
        if found is not None:
            return found.signature_scale
        return self._cfg.report.signature_scale() or run.report.signature_scale

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.providers.errors import ProviderConfigurationError
        from maljan.providers.sandbox.readers import (
            mapping_refusal,
            required_reader,
            sandbox_format_named,
        )
        from maljan.schemas.sandbox_report import SandboxRun

        # Streamed rather than fetched whole: a report is the one
        # body a sandbox legitimately sends by the hundreds of megabytes, and
        # this is the only place the size of the answer is the remote end's
        # choice alone.
        with self._get_http().stream(
            "GET", _fill_task_id(self._cfg.report.path, _safe_path_component(str(task_id)))
        ) as response:
            if response.status_code >= 400:
                response.read()
                self._raise_for_status(response, "report fetch")
            body = read_capped(response, what="The sandbox report")
        from maljan.core.safe_json import loads

        try:
            # Read at any nesting depth (``core.safe_json``).
            payload = loads(body)
        except ValueError as exc:
            raise ProviderError("Sandbox report is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ProviderError("Sandbox report is not a JSON object.")

        # ``report.format`` names a declared format or a registered reader. A
        # declared format is read as the report-upload provider reads it: by
        # its reader, through its own mapping where it declares one, on its
        # own scale. Otherwise the reader it names reads the body, the mapping
        # reader through ``sandbox.rest.mapping`` with the scale these
        # settings declare.
        name = self._cfg.report.format
        fmt = sandbox_format_named(name, self._formats)
        refusal = mapping_refusal(fmt)
        if refusal:
            raise ProviderConfigurationError(refusal)
        own = self._format_mappings.get(name)
        report = required_reader(self._reader_id()).read(
            payload,
            provider=self.id,
            task_id=str(task_id),
            fmt=fmt,
            mapping=own if own is not None else self._mapping,
            signature_scale=None if own is not None else self._cfg.report.signature_scale(),
        )
        return SandboxRun(
            task_id=str(task_id),
            sample_sha256=report.target.sha256,
            sample_name=report.target.name,
            status="reported",
            report=report,
            raw=payload,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        if not self._cfg.report.pcap_path:
            return None
        stop_if_cancelled(PACKET_CAPTURE)
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        safe = _safe_path_component(str(task_id))
        out = dest / f"rest_{safe}.pcap"
        url = _fill_task_id(self._cfg.report.pcap_path, safe)
        http = self._get_http()

        def keep(response: httpx.Response) -> bool:
            # A capture past the cap fails this fetch rather than filling the disk.
            stream_to_file_capped(response, out, what="The sandbox capture")
            return True

        # Never a hard failure of the run, as for every sandbox: a transient
        # failure is asked again, a lasting one or an empty file is said
        # (``ArtefactFetchFailed``), and the bytes go with the answer.
        return fetch_artefact(
            lambda: http.stream("GET", url),
            keep,
            out,
            artefact=PACKET_CAPTURE,
            what=f"Sandbox task {task_id}",
            sleep=self._sleep,
            interval=float(self._cfg.poll_interval_seconds),
        )

    async def probe(self) -> ProviderProbe:
        """Ask the status endpoint about a task that does not exist.

        Any HTTP answer proves the URL resolves and the credential was
        accepted or rejected legibly — a 404 for a fake task is a *pass*, and
        the detail says so, because the alternative is asking an operator to
        detonate something to find out whether their base URL is right.
        """
        t0 = time.perf_counter()
        if not self._cfg.base_url:
            return ProviderProbe(ok=False, detail="no base URL configured")
        url = f"{self._cfg.base_url.rstrip('/')}{_fill_task_id(self._cfg.status.path, 'probe')}"
        try:
            async with httpx.AsyncClient(timeout=10.0, verify=self._cfg.verify_tls) as client:
                response = await client.get(url, headers=self._auth_headers())
        except httpx.HTTPError as exc:
            from maljan.core.settings_overrides import redact_url

            return ProviderProbe(
                ok=False,
                detail=redact_url(f"{type(exc).__name__}: {exc}") + self._tls_note(),
                latency_ms=int((time.perf_counter() - t0) * 1000),
            )
        ok = response.status_code not in (401, 403)
        detail = f"reachable, status endpoint answered {response.status_code} for a fake task"
        if not ok:
            detail = f"HTTP {response.status_code}: the credential was refused"
        return ProviderProbe(
            ok=ok,
            detail=detail + self._tls_note(),
            latency_ms=int((time.perf_counter() - t0) * 1000),
        )

    def close(self) -> None:
        client, self._http = self._http, None
        if client is not None:
            with suppress(Exception):
                client.close()
        logger.debug("rest sandbox provider closed.")
