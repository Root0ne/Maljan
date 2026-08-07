"""CAPEv2Client — live CAPEv2 REST API sandbox backend.

Phase 6: CAPEv2 Sandbox Integration

Submits samples to a running CAPEv2 instance, polls for completion, and
fetches the full JSON report. The report structure is identical to the
existing fixture JSON schema, so DynamicParser and NetworkParser require
zero changes.

Requirements:
  - httpx: uv add httpx
  - A running CAPEv2 instance reachable from this host.

CAPEv2 API endpoints used:
  POST /apiv2/tasks/create/file/        -- submit a sample file
  GET  /apiv2/tasks/view/{id}/          -- check task status
  GET  /apiv2/tasks/get/report/{id}/    -- fetch completed JSON report

Authentication:
  CAPEv2 uses token authentication. Set the API token via the
  SANDBOX__CAPE2__API_TOKEN environment variable or pass it directly:
    CAPEv2Client(base_url="http://cape2-host:8000", api_token="abc123")

Error handling:
  - HTTP errors raise SandboxError with the status code and response body.
  - Timeout raises SandboxTimeoutError.
  - Missing httpx raises SandboxNotAvailableError at instantiation.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.loaders.sandbox_client import (
    SandboxError,
    SandboxNotAvailableError,
    SandboxTimeoutError,
    SubmissionResult,
)


class CAPEv2Client:
    """Live CAPEv2 REST API sandbox client.

    Usage:
        client = CAPEv2Client(
            base_url="http://cape2-host:8000",
            api_token="your_api_token",
        )
        task_id = client.submit("/path/to/malware.exe")
        status = client.wait_for_completion(task_id, timeout_seconds=600)
        result = client.fetch_report(task_id)
        logger.debug("Behavior data: %s", result.report.get("behavior"))

    Args:
        base_url:    CAPEv2 server URL (e.g. "http://localhost:8000").
        api_token:   CAPEv2 REST API authentication token. May be empty
                     for unauthenticated local instances.
        timeout:     Default HTTP request timeout in seconds. Sized for the
                     small JSON status/report calls.
        upload_timeout: Deadline for the sample upload specifically, which is
                     orders of magnitude larger than a status check. Never
                     narrower than ``timeout`` — an operator who raised the
                     global value meant it.
    """

    def __init__(
        self,
        base_url: str,
        api_token: Any = "",
        timeout: int = 30,
        upload_timeout: int = 300,
    ) -> None:
        try:
            import httpx  # noqa: F401
        except ImportError as exc:
            raise SandboxNotAvailableError(
                "httpx is required for CAPEv2Client. Install with: uv add httpx"
            ) from exc

        import httpx

        if hasattr(api_token, "get_secret_value"):
            token_value: str = api_token.get_secret_value()
        else:
            token_value = str(api_token or "")

        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._upload_timeout = max(int(upload_timeout), int(timeout))
        self._headers: dict[str, str] = {}
        if token_value:
            self._headers["Authorization"] = f"Token {token_value}"

        # Persistent HTTP client for connection reuse across polling cycles
        self._http = httpx.Client(
            base_url=self._base_url,
            headers=self._headers,
            timeout=self._timeout,
        )

    def submit(self, sample_path: str | Path) -> str:
        """Submit a sample file to CAPEv2 and return the task ID.

        POST /apiv2/tasks/create/file/

        Args:
            sample_path: Local path to the sample binary.

        Returns:
            Task ID string.

        Raises:
            SandboxError: On HTTP or API error.
        """
        path = Path(sample_path)
        if not path.exists():
            raise SandboxError(f"Sample file not found: {path}")

        logger.info("CAPEv2Client: submitting '%s' to %s", path.name, self._base_url)
        with open(path, "rb") as f:
            try:
                # Its own deadline. The client-wide ``timeout`` is sized for
                # ``GET /apiv2/tasks/view/<id>/`` — a few hundred bytes of JSON
                # — and a sample upload is orders of magnitude larger while
                # competing with whatever the sandbox is already running. On
                # 2026-08-07 that mismatch produced "Submission request failed:
                # timed out" 35 s in, and the run silently lost its sandbox.
                #
                # Deliberately no retry, unlike ``wait_for_completion``: this
                # POST is not idempotent, a request that timed out client-side
                # may still have been accepted, and a blind retry would burn a
                # second detonation slot on a one-VM instance.
                response = self._http.post(
                    "/apiv2/tasks/create/file/",
                    files={"file": (path.name, f, "application/octet-stream")},
                    timeout=self._upload_timeout,
                )
            except Exception as exc:
                raise SandboxError(f"Submission request failed: {exc}") from exc

        self._raise_for_status(response, "submit")
        data = response.json()

        # Upstream CAPEv2 wraps the payload as
        # ``{"error": false, "data": {"task_ids": [42]}, ...}``. Older
        # versions returned flat ``{"task_id": 42}`` or ``{"task_ids": [...]}``;
        # we accept either shape to stay compatible with both.
        inner = data.get("data") if isinstance(data.get("data"), dict) else {}
        task_id = (
            data.get("task_id")
            or (data.get("task_ids") or [None])[0]
            or inner.get("task_id")
            or (inner.get("task_ids") or [None])[0]
        )
        if task_id is None:
            raise SandboxError(f"Unexpected submit response: {data}")

        logger.info("CAPEv2Client: task_id=%s assigned.", task_id)
        return str(task_id)

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> str:
        """Poll GET /apiv2/tasks/view/{task_id}/ until status is terminal.

        Terminal statuses: "reported", "failed", "aborted".
        Non-terminal: "pending", "running", "processing".

        Args:
            task_id:                Task ID from submit().
            timeout_seconds:        Maximum wait time in seconds.
            poll_interval_seconds:  Seconds between polls.

        Returns:
            Final task status string.

        Raises:
            SandboxTimeoutError: When timeout_seconds elapses.
            SandboxError:        On a permanent API error (auth, unknown task).
        """
        terminal = {"reported", "failed", "aborted"}
        deadline = time.monotonic() + timeout_seconds

        logger.info(
            "CAPEv2Client: polling task %s (timeout=%ds, interval=%ds).",
            task_id,
            timeout_seconds,
            poll_interval_seconds,
        )

        # A poll failure is not a task failure. This loop exists to wait out a
        # busy sandbox, and the characteristic symptom of a busy CAPE — single
        # VM here, detonations serialised — is a slow or refused API response.
        # Re-raising on the first hiccup meant the retry loop died exactly when
        # it was needed: on 2026-07-29 a 1200s wait ended after 127s with
        # "Poll request failed: timed out", discarding ~18 minutes of budget
        # and silently degrading the run to static-only. Transient errors are
        # now absorbed and the deadline alone decides when to give up.
        last_error: str | None = None
        consecutive_errors = 0

        while time.monotonic() < deadline:
            transient: str | None = None
            status = ""
            try:
                response = self._http.get(f"/apiv2/tasks/view/{task_id}/")
                code = int(response.status_code)
                if code >= 500 or code == 429:
                    # "Come back later" — a loaded CAPE, not a verdict.
                    transient = f"HTTP {code}: {response.text[:120]}"
                else:
                    # Other 4xx are verdicts: a bad token or a deleted task
                    # will still be bad in twenty minutes, so abort rather
                    # than burn the budget. Propagates past this handler.
                    self._raise_for_status(response, "poll")
                    data = response.json()
                    status = str(data.get("data", {}).get("status", "unknown"))
            except SandboxError:
                raise
            except Exception as exc:
                # Transport-level: timeout, connection reset, unparsable body.
                transient = f"{type(exc).__name__}: {exc}"

            if transient is not None:
                last_error = transient
                consecutive_errors += 1
                logger.warning(
                    "CAPEv2Client: poll %d for task %s failed transiently (%s); retrying.",
                    consecutive_errors,
                    task_id,
                    transient,
                )
                time.sleep(poll_interval_seconds)
                continue

            if consecutive_errors:
                logger.info(
                    "CAPEv2Client: task %s reachable again after %d failed poll(s).",
                    task_id,
                    consecutive_errors,
                )
                consecutive_errors = 0

            logger.debug("CAPEv2Client: task %s status=%s.", task_id, status)

            if status in terminal:
                logger.info("CAPEv2Client: task %s -> %s.", task_id, status)
                return str(status)

            time.sleep(poll_interval_seconds)

        suffix = f" Last poll error: {last_error}" if last_error else ""
        raise SandboxTimeoutError(
            f"Task {task_id} did not complete within {timeout_seconds}s.{suffix}"
        )

    def fetch_report(self, task_id: str) -> SubmissionResult:
        """Fetch the full JSON report for a completed task.

        GET /apiv2/tasks/get/report/{task_id}/

        Note: the upstream CAPEv2 route is ``/apiv2/tasks/get/report/<id>/``
        (see ``external/CAPEv2/web/apiv2/urls.py``). Earlier versions of
        this client used ``/apiv2/tasks/report/<id>/`` which always 404'd
        against a real instance.

        Args:
            task_id: Task ID from submit().

        Returns:
            SubmissionResult with the report dict.

        Raises:
            SandboxError: When the report is unavailable.
        """
        logger.info("CAPEv2Client: fetching report for task %s.", task_id)
        try:
            response = self._http.get(f"/apiv2/tasks/get/report/{task_id}/")
        except Exception as exc:
            raise SandboxError(f"Report request failed: {exc}") from exc

        self._raise_for_status(response, "fetch_report")
        report: dict[str, Any] = response.json()

        target = report.get("target", {})
        return SubmissionResult(
            task_id=task_id,
            sample_sha256=target.get("sha256", ""),
            sample_name=target.get("name", ""),
            status="reported",
            report=report,
        )

    def fetch_pcap(self, task_id: str, dest_dir: str | Path) -> str | None:
        """Download the task's raw PCAP into ``dest_dir``; return the local path.

        ``GET /apiv2/tasks/get/pcap/{task_id}/`` streams the libpcap capture of
        the detonation's traffic. The network analyst's local PCAP MCP
        (read_pcap_summary / extract_dns / extract_http) then deep-inspects it
        for beaconing / tunnelling that the structured ``network`` block can't
        express. Returns None when the task has no PCAP (404), the payload is
        empty, or the download fails — the analyst then works from the
        structured IOCs alone (never a hard failure).
        """
        dest = Path(dest_dir)
        dest.mkdir(parents=True, exist_ok=True)
        out = dest / f"cape_task_{task_id}.pcap"
        try:
            with self._http.stream("GET", f"/apiv2/tasks/get/pcap/{task_id}/", timeout=120) as resp:
                if resp.status_code == 404:
                    logger.info("CAPEv2Client: task %s has no PCAP (404).", task_id)
                    return None
                if resp.status_code >= 400:
                    logger.warning(
                        "CAPEv2Client: PCAP fetch HTTP %d for task %s.",
                        resp.status_code,
                        task_id,
                    )
                    return None
                with open(out, "wb") as f:
                    for chunk in resp.iter_bytes(65536):
                        f.write(chunk)
        except Exception as exc:
            logger.warning("CAPEv2Client: PCAP download failed for task %s: %s", task_id, exc)
            return None

        # libpcap/pcapng global header is 24 bytes; anything smaller is empty.
        size = out.stat().st_size if out.exists() else 0
        if size < 24:
            logger.info(
                "CAPEv2Client: PCAP for task %s empty/too small (%d bytes) — skipping.",
                task_id,
                size,
            )
            return None
        logger.info("CAPEv2Client: PCAP for task %s -> %s (%d bytes).", task_id, out, size)
        return str(out)

    def close(self) -> None:
        """Close the underlying HTTP client connection pool."""
        self._http.close()

    def __enter__(self) -> CAPEv2Client:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _raise_for_status(response: Any, operation: str) -> None:
        """Raise SandboxError for non-2xx responses."""
        if response.status_code >= 400:
            raise SandboxError(
                f"CAPEv2 {operation} failed (HTTP {response.status_code}): {response.text[:200]}"
            )
