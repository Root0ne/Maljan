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
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping
from maljan.providers.sandbox.triage import (
    _BACKOFF_FACTOR,
    _MAX_INTERVAL_SECONDS,
    _parse_retry_after,
    _safe_path_component,
)

if TYPE_CHECKING:
    from maljan.core.config import SandboxRestConfig, Settings
    from maljan.providers.sandbox.rest_mapping import CompiledMapping
    from maljan.schemas.sandbox_report import SandboxRun


@register_sandbox_provider("rest")
class RestSandboxProvider(SandboxProvider):
    """Submit, poll, fetch and (optionally) capture, all from configuration."""

    def __init__(self, cfg: SandboxRestConfig, mapping: CompiledMapping) -> None:
        self._cfg = cfg
        self._mapping = mapping
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
        return cls(rest, compile_mapping(rest.mapping))

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=True,
            can_poll=True,
            can_fetch_report=True,
            can_fetch_pcap=bool(self._cfg.report.pcap_path),
            accepts_uploaded_report=False,
            provides_tools=False,
            report_format=self._cfg.report.format,
            degrade_on_failure=True,
        )

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

    @staticmethod
    def _raise_for_status(response: httpx.Response, operation: str) -> None:
        if response.status_code >= 400:
            raise ProviderError(
                f"Sandbox {operation} failed (HTTP {response.status_code}): {response.text[:200]}"
            )

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

    def submit(self, sample_path: str | Path) -> str:
        path = Path(sample_path)
        files: dict[str, Any] = {
            self._cfg.submit.file_field: (path.name, path.read_bytes(), "application/octet-stream")
        }
        for name, value in self._cfg.submit.extra_fields.items():
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
        url = self._cfg.status.path.format(task_id=task_id)
        done = {v.lower() for v in self._cfg.status.done_values}
        failed = {v.lower() for v in self._cfg.status.failed_values}
        while True:
            # Checked at the top of every iteration, including the rate-limit
            # branch: a server that keeps answering 429 past the deadline must
            # raise rather than loop forever.
            if self._now() >= deadline:
                raise ProviderError(
                    f"Sandbox task {task_id} did not complete within {budget:.0f}s."
                )
            response = http.get(url)
            if response.status_code in (429, 503):
                retry_after = response.headers.get("Retry-After")
                parsed = _parse_retry_after(retry_after, self._now()) if retry_after else None
                wait_seconds = parsed if parsed is not None else interval
                clamped = min(wait_seconds, _MAX_INTERVAL_SECONDS, deadline - self._now())
                if clamped > 0:
                    self._sleep(clamped)
                if parsed is None:
                    interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)
                continue
            self._raise_for_status(response, "status check")
            state = self._select_one(self._cfg.status.state_path, response.json(), "status").lower()
            if state in done:
                return "reported"
            if state in failed:
                return "failed"
            self._sleep(interval)
            interval = min(interval * _BACKOFF_FACTOR, _MAX_INTERVAL_SECONDS)

    def fetch(self, task_id: str) -> SandboxRun:
        from maljan.schemas.sandbox_report import (
            SandboxRun,
            cape_report_to_sandbox_report,
            triage_overview_to_sandbox_report,
        )

        response = self._get_http().get(self._cfg.report.path.format(task_id=task_id))
        self._raise_for_status(response, "report fetch")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ProviderError("Sandbox report is not a JSON object.")

        fmt = self._cfg.report.format
        if fmt == "triage":
            report = triage_overview_to_sandbox_report(
                payload, provider="rest", task_id=str(task_id)
            )
        elif fmt in ("cape2", "cuckoo"):
            # The same readers the report-upload provider uses, so a CAPE-shaped
            # body reaches the nine raw-CAPE consumers by identity here too.
            report = cape_report_to_sandbox_report(
                payload, provider="rest", source_format=fmt, task_id=str(task_id)
            )
        else:
            result = apply_mapping(self._mapping, payload, provider="rest", task_id=str(task_id))
            report = result.report
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
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        safe = _safe_path_component(str(task_id))
        out = dest / f"rest_{safe}.pcap"
        url = self._cfg.report.pcap_path.format(task_id=safe)
        try:
            with self._get_http().stream("GET", url) as response:
                if response.status_code >= 400:
                    return None
                with open(out, "wb") as fh:
                    for chunk in response.iter_bytes(65536):
                        fh.write(chunk)
        except Exception:  # noqa: BLE001 — never a hard failure, as for every sandbox
            return None
        # libpcap/pcapng global header is 24 bytes; anything smaller is empty.
        if not out.exists() or out.stat().st_size < 24:
            return None
        return str(out)

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
        url = f"{self._cfg.base_url.rstrip('/')}{self._cfg.status.path.format(task_id='probe')}"
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
