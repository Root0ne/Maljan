"""Recorded Future Sandbox (tria.ge / Hatching Triage) — SandboxClient impl.

This client targets the public Triage API documented at https://tria.ge/docs.
It satisfies the ``SandboxClient`` Protocol and is interchangeable with
``CAPEv2Client`` / ``MockSandboxClient`` from ``ServiceContainer``.

Intended use
------------
Maljan is research software. Triage's public cloud is suitable for academic
reproducibility: every accepted submission yields a citeable
``https://tria.ge/<sample_id>`` URL that reviewers can verify.

The public cloud has two hard constraints that make it unsuitable for
private / customer samples:

* All submissions are world-visible.
* Submissions cannot be deleted via the API.

The container logs a WARNING whenever this backend is activated so the
operator is reminded. For private samples use the ``cape2`` backend.

Pipeline
--------
``TriageClient.submit(sample_path)``        -> task ID
``TriageClient.wait_for_completion(tid)``   -> final status string
``TriageClient.fetch_report(tid)``          -> SubmissionResult

The normalizer rewrites Triage's schema to the CAPE-compatible shape Maljan
parsers already understand, so ``DynamicParser`` / ``NetworkParser`` do not
need to know which sandbox produced the report.

Endpoints (docs-verified, 2026-05)
----------------------------------
* ``POST /v0/samples``                                   submit a sample
* ``GET  /v0/samples/{id}``                              status object
* ``GET  /v0/samples/{id}/summary``                      summary report
* ``GET  /v0/samples/{id}/overview.json``                aggregated signatures + IOCs
* ``GET  /v0/samples/{id}/{task_id}/report_triage.json`` per-task behavior
* ``GET  /v0/search``                                    corpus search

Status values: ``pending``, ``static_analysis``, ``scheduled``, ``running``,
``processing``, ``reported`` (terminal), ``failed`` (terminal).
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.loaders.sandbox_client import SubmissionResult

if TYPE_CHECKING:
    from pydantic import SecretStr

_DEFAULT_BASE_URL = "https://api.tria.ge"
_API_VERSION = "/v0"
_FINAL_STATUSES: frozenset[str] = frozenset({"reported", "failed"})
_REPORTABLE_STATUSES: frozenset[str] = frozenset({"reported"})
_TRIAGE_VIEW_URL = "https://tria.ge/{sample_id}"


# ---------------------------------------------------------------------------
# Normalizer — Triage schema -> Maljan CAPE-compatible shape
# ---------------------------------------------------------------------------


def _normalize_report(triage_report: dict[str, Any], sample_name: str) -> dict[str, Any]:
    """Convert a Triage summary payload to Maljan's CAPE-shaped report.

    Input (Triage ``GET /samples/{id}/summary``)::

        {
          "sample": {"id": "...", "md5": "...", "sha256": "...", ...},
          "tasks": {"behavioral1": {"processes": [...], "ttp_tags": [...], ...}},
          "network": {"flows": [...], "requests": [...]},
          "signatures": [{"name": "...", "score": ...}, ...]
        }

    Output (matches existing fixture JSON consumed by DynamicParser /
    NetworkParser)::

        {
          "target":    {"file": {"sha256": "...", "md5": "...", "name": "...", "size": N}},
          "behavior":  {"processes": [...], "calls": [...], "apistats": {...}},
          "network":   {"dns": [...], "http": [...], "tcp": [...], "udp": [...],
                        "hosts": [...], "domains": [...]},
          "signatures":[{"name": "...", "description": "...", "severity": N, "marks": [...]}],
          "ttp_tags":  ["T1055", ...]
        }
    """
    raw_sample = triage_report.get("sample", {})
    sample_meta = raw_sample if isinstance(raw_sample, dict) else {}

    raw_tasks = triage_report.get("tasks", {})
    tasks = raw_tasks if isinstance(raw_tasks, dict) else {}

    target = {
        "file": {
            "sha256": sample_meta.get("sha256", ""),
            "md5": sample_meta.get("md5", ""),
            "name": sample_meta.get("name", sample_name),
            "size": sample_meta.get("size", 0),
        }
    }

    all_processes: list[dict[str, Any]] = []
    all_calls: list[dict[str, Any]] = []
    apistats: dict[str, dict[str, int]] = {}
    all_ttp_tags: set[str] = set()

    for task_data in tasks.values():
        if not isinstance(task_data, dict):
            continue

        for proc in task_data.get("processes", []) or []:
            if not isinstance(proc, dict):
                continue
            proc_name = proc.get("name", "unknown")
            normalized_proc: dict[str, Any] = {
                "process_name": proc_name,
                "pid": proc.get("pid", 0),
                "ppid": proc.get("ppid", 0),
                "command_line": proc.get("cmd", ""),
                "calls": [],
            }
            for call in proc.get("calls", []) or []:
                if not isinstance(call, dict):
                    continue
                api_name = str(call.get("api", call.get("name", "")) or "")
                normalized_call = {
                    "category": call.get("category", ""),
                    "api": api_name,
                    "arguments": call.get("args", call.get("arguments", [])),
                    "return_value": str(call.get("return_value", "")),
                }
                normalized_proc["calls"].append(normalized_call)
                all_calls.append(normalized_call)
                apistats.setdefault(proc_name, {})
                apistats[proc_name][api_name] = apistats[proc_name].get(api_name, 0) + 1
            all_processes.append(normalized_proc)

        for tag in task_data.get("ttp_tags", []) or []:
            if isinstance(tag, str):
                all_ttp_tags.add(tag)

    behavior = {
        "processes": all_processes,
        "calls": all_calls,
        "apistats": apistats,
    }

    raw_network = triage_report.get("network", {})
    if not isinstance(raw_network, dict):
        raw_network = {}

    def _coerce_list(*candidates: Any) -> list[Any]:
        for c in candidates:
            if isinstance(c, list):
                return c
        return []

    network: dict[str, Any] = {
        "dns": _coerce_list(raw_network.get("dns")),
        "http": _coerce_list(raw_network.get("http"), raw_network.get("requests")),
        "tcp": _coerce_list(raw_network.get("tcp"), raw_network.get("flows")),
        "udp": _coerce_list(raw_network.get("udp")),
        "hosts": _coerce_list(raw_network.get("hosts")),
        "domains": _coerce_list(raw_network.get("domains")),
    }

    raw_sigs = triage_report.get("signatures", [])
    if not isinstance(raw_sigs, list):
        raw_sigs = []
    signatures: list[dict[str, Any]] = []
    for sig in raw_sigs:
        if not isinstance(sig, dict):
            continue
        signatures.append(
            {
                "name": sig.get("name", ""),
                "description": sig.get("description", sig.get("name", "")),
                "severity": sig.get("score", sig.get("severity", 1)),
                "marks": sig.get("marks", []),
            }
        )

    return {
        "target": target,
        "behavior": behavior,
        "network": network,
        "signatures": signatures,
        "ttp_tags": sorted(all_ttp_tags),
    }


# ---------------------------------------------------------------------------
# TriageClient
# ---------------------------------------------------------------------------


class TriageClient:
    """Async/sync REST client for Recorded Future Sandbox (tria.ge).

    Sync methods use a dedicated ``httpx.Client``, async methods use
    ``httpx.AsyncClient``. The two are independent so a LangGraph node can
    call either path safely from within or outside a running event loop.

    Args:
        api_token:      Bearer token from https://tria.ge/account (Researcher tier).
        base_url:       API base URL. Trailing ``/v0`` is tolerated and stripped.
        timeout:        Submission-to-report wait ceiling (seconds).
        poll_interval:  Status poll interval (seconds).
    """

    def __init__(
        self,
        api_token: str | SecretStr = "",
        base_url: str = _DEFAULT_BASE_URL,
        timeout: int = 600,
        poll_interval: int = 15,
    ) -> None:
        if hasattr(api_token, "get_secret_value"):
            self._api_token = api_token.get_secret_value()  # type: ignore[union-attr]
        else:
            self._api_token = str(api_token or "")
        base_url = (base_url or _DEFAULT_BASE_URL).rstrip("/")
        if base_url.endswith(_API_VERSION):
            base_url = base_url[: -len(_API_VERSION)]
        self._base_url = base_url
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._api_prefix = f"{self._base_url}{_API_VERSION}"
        self._http_async: Any = None
        self._http_sync: Any = None

    # ------------------------------------------------------------------
    # SandboxClient Protocol
    # ------------------------------------------------------------------

    def submit(self, sample_path: str | Path) -> str:
        path = Path(sample_path) if not isinstance(sample_path, Path) else sample_path
        if not path.exists():
            raise FileNotFoundError(f"Sample not found: {path}")
        return self._sync_submit(path)

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> str:
        return self._sync_wait(task_id, timeout_seconds, poll_interval_seconds)

    def fetch_report(self, task_id: str) -> SubmissionResult:
        return self._sync_fetch_report(task_id)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        if self._http_sync is not None:
            try:
                self._http_sync.close()
            finally:
                self._http_sync = None

    async def aclose(self) -> None:
        if self._http_async is not None:
            try:
                await self._http_async.aclose()
            finally:
                self._http_async = None

    # ------------------------------------------------------------------
    # All-in-one async path (used by FileDataLoader.load_from_sandbox)
    # ------------------------------------------------------------------

    async def submit_and_wait(self, sample_path: Path) -> SubmissionResult:
        try:
            task_id = await self._async_submit(sample_path)
            status = await self._async_wait(task_id)
            if status not in _REPORTABLE_STATUSES:
                return SubmissionResult(
                    task_id=task_id,
                    sample_name=sample_path.name,
                    status=status,
                    error=f"Task ended with status: {status}",
                )
            return await self._async_fetch_report(task_id)
        except Exception as exc:
            logger.error("TriageClient.submit_and_wait failed: %s", exc)
            return SubmissionResult(
                task_id="",
                sample_name=sample_path.name,
                status="failed",
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        # Authorization header is intentionally not logged; httpx debug logs
        # would expose bearer tokens.
        return {"Authorization": f"Bearer {self._api_token}"} if self._api_token else {}

    def _get_http(self) -> Any:
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("TriageClient requires 'httpx'. Install with: uv add httpx") from exc
        if self._http_async is None:
            self._http_async = httpx.AsyncClient(
                base_url=self._api_prefix,
                headers=self._headers(),
                timeout=60.0,
            )
        return self._http_async

    def _get_http_sync(self) -> Any:
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("TriageClient requires 'httpx'. Install with: uv add httpx") from exc
        if self._http_sync is None:
            self._http_sync = httpx.Client(
                base_url=self._api_prefix,
                headers=self._headers(),
                timeout=60.0,
            )
        return self._http_sync

    # ------------------------------------------------------------------
    # Sync internals
    # ------------------------------------------------------------------

    def _sync_submit(self, sample_path: Path) -> str:
        import json as _json

        http = self._get_http_sync()
        filename = sample_path.name
        sha256 = _sha256_file(sample_path)
        logger.info("TriageClient: submitting '%s' (sha256=%s...).", filename, sha256[:16])
        # ``interactive: false`` lets Triage auto-select profiles after the
        # static-analysis pre-screen. No explicit ``profiles`` array — letting
        # the backend pick keeps research-paper submissions deterministic per
        # Triage's tier and avoids 400s when a profile id is retired.
        payload = {"kind": "file", "interactive": False}
        with sample_path.open("rb") as fh:
            response = http.post(
                "/samples",
                files={"file": (filename, fh, "application/octet-stream")},
                data={"_json": _json.dumps(payload)},
            )
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Triage /samples submission failed: HTTP {response.status_code} — "
                f"{response.text[:200]}"
            )
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Triage /samples returned non-dict: {data!r}")
        task_id: str = data.get("id", "")
        if not task_id:
            raise RuntimeError(f"Triage returned no task ID: {data}")
        logger.info("TriageClient: submitted task=%s (URL: %s).", task_id, _view_url(task_id))
        return task_id

    def _sync_wait(
        self,
        task_id: str,
        timeout_seconds: int,
        poll_interval_seconds: int,
    ) -> str:
        http = self._get_http_sync()
        deadline = time.monotonic() + timeout_seconds
        attempt = 0
        backoff = float(poll_interval_seconds)
        max_backoff = max(60.0, backoff * 4)
        consecutive_failures = 0
        while time.monotonic() < deadline:
            attempt += 1
            try:
                response = http.get(f"/samples/{task_id}")
            except Exception as exc:
                consecutive_failures += 1
                logger.warning(
                    "TriageClient: poll #%d failed (%s); backoff=%.1fs.",
                    attempt,
                    exc,
                    backoff,
                )
                time.sleep(backoff)
                backoff = min(max_backoff, backoff * 2)
                if consecutive_failures >= 5:
                    raise RuntimeError(
                        f"Triage status polling failed {consecutive_failures} times in a row"
                    ) from exc
                continue
            consecutive_failures = 0
            if response.status_code != 200:
                logger.warning("TriageClient: poll HTTP %d, retrying.", response.status_code)
                time.sleep(backoff)
                backoff = min(max_backoff, backoff * 1.5)
                continue
            data = response.json()
            if not isinstance(data, dict):
                time.sleep(backoff)
                continue
            status: str = data.get("status", "")
            if status in _FINAL_STATUSES:
                return status
            backoff = float(poll_interval_seconds)
            time.sleep(backoff)
        return "timeout"

    def _sync_fetch_report(self, task_id: str) -> SubmissionResult:
        http = self._get_http_sync()
        response = http.get(f"/samples/{task_id}/summary")
        if response.status_code != 200:
            return SubmissionResult(
                task_id=task_id,
                status="failed",
                error=f"Report fetch failed: HTTP {response.status_code}",
            )
        triage_data = response.json()
        if not isinstance(triage_data, dict):
            return SubmissionResult(
                task_id=task_id,
                status="failed",
                error="Report fetch returned non-dict body",
            )
        sample_name = _resolve_sample_name(triage_data, task_id)
        normalized = _normalize_report(triage_data, sample_name=sample_name)
        normalized["sandbox_url"] = _view_url(task_id)
        return SubmissionResult(
            task_id=task_id,
            sample_name=sample_name,
            sample_sha256=str(normalized["target"]["file"].get("sha256", "")),
            status=str(triage_data.get("status", "reported")),
            report=normalized,
        )

    # ------------------------------------------------------------------
    # Async internals
    # ------------------------------------------------------------------

    async def _async_submit(self, sample_path: Path) -> str:
        import json as _json

        http = self._get_http()
        filename = sample_path.name
        sha256 = _sha256_file(sample_path)
        logger.info("TriageClient: submitting '%s' (sha256=%s...).", filename, sha256[:16])
        payload = {"kind": "file", "interactive": False}
        with sample_path.open("rb") as fh:
            response = await http.post(
                "/samples",
                files={"file": (filename, fh, "application/octet-stream")},
                data={"_json": _json.dumps(payload)},
            )
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Triage /samples submission failed: HTTP {response.status_code} — "
                f"{response.text[:200]}"
            )
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError(f"Triage /samples returned non-dict: {data!r}")
        task_id: str = data.get("id", "")
        if not task_id:
            raise RuntimeError(f"Triage returned no task ID: {data}")
        logger.info("TriageClient: submitted task=%s (URL: %s).", task_id, _view_url(task_id))
        return task_id

    async def _async_wait(self, task_id: str) -> str:
        http = self._get_http()
        deadline = time.monotonic() + self._timeout
        attempt = 0
        backoff = float(self._poll_interval)
        max_backoff = max(60.0, backoff * 4)
        consecutive_failures = 0
        while time.monotonic() < deadline:
            attempt += 1
            try:
                response = await http.get(f"/samples/{task_id}")
            except Exception as exc:
                consecutive_failures += 1
                logger.warning(
                    "TriageClient: poll #%d failed (%s); backoff=%.1fs.",
                    attempt,
                    exc,
                    backoff,
                )
                await asyncio.sleep(backoff)
                backoff = min(max_backoff, backoff * 2)
                if consecutive_failures >= 5:
                    raise RuntimeError(
                        f"Triage status polling failed {consecutive_failures} times in a row"
                    ) from exc
                continue
            consecutive_failures = 0
            if response.status_code != 200:
                logger.warning("TriageClient: poll HTTP %d, retrying.", response.status_code)
                await asyncio.sleep(backoff)
                backoff = min(max_backoff, backoff * 1.5)
                continue
            backoff = float(self._poll_interval)
            data = response.json()
            if not isinstance(data, dict):
                await asyncio.sleep(self._poll_interval)
                continue
            status: str = data.get("status", "")
            if status in _FINAL_STATUSES:
                return status
            await asyncio.sleep(self._poll_interval)
        return "timeout"

    async def _async_fetch_report(self, task_id: str) -> SubmissionResult:
        http = self._get_http()
        response = await http.get(f"/samples/{task_id}/summary")
        if response.status_code != 200:
            return SubmissionResult(
                task_id=task_id,
                status="failed",
                error=f"Report fetch failed: HTTP {response.status_code}",
            )
        triage_data = response.json()
        if not isinstance(triage_data, dict):
            return SubmissionResult(
                task_id=task_id,
                status="failed",
                error="Report fetch returned non-dict body",
            )
        sample_name = _resolve_sample_name(triage_data, task_id)
        normalized = _normalize_report(triage_data, sample_name=sample_name)
        normalized["sandbox_url"] = _view_url(task_id)

        # Best-effort enrichment. Each step is wrapped: failure logs a warning
        # but the summary-derived report is still returned to the pipeline.
        try:
            await self._enrich_from_overview(task_id, normalized)
        except Exception as exc:
            logger.warning("TriageClient: overview enrichment failed (%s).", exc)
        try:
            await self._enrich_from_task_reports(task_id, triage_data, normalized)
        except Exception as exc:
            logger.warning("TriageClient: per-task enrichment failed (%s).", exc)

        sigs = normalized.get("signatures") or []
        network = normalized.get("network") or {}
        logger.info(
            "TriageClient: post-enrichment task=%s signatures=%d dns=%d http=%d tcp=%d udp=%d.",
            task_id,
            len(sigs) if isinstance(sigs, list) else 0,
            len(network.get("dns", []) or []),
            len(network.get("http", []) or []),
            len(network.get("tcp", []) or []),
            len(network.get("udp", []) or []),
        )

        return SubmissionResult(
            task_id=task_id,
            sample_name=sample_name,
            sample_sha256=str(normalized["target"]["file"].get("sha256", "")),
            status="reported",
            report=normalized,
        )

    # ------------------------------------------------------------------
    # Richer endpoints — additive enrichment
    # ------------------------------------------------------------------

    async def fetch_overview(self, sample_id: str) -> dict[str, Any]:
        """``GET /samples/{id}/overview.json`` — aggregated signatures + IOCs."""
        http = self._get_http()
        try:
            resp = await http.get(f"/samples/{sample_id}/overview.json")
            if resp.status_code != 200:
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.debug("TriageClient: overview fetch failed (%s).", exc)
            return {}

    async def fetch_task_report(self, sample_id: str, task_id: str) -> dict[str, Any]:
        """``GET /samples/{sample_id}/{task_id}/report_triage.json`` — rich behavior."""
        http = self._get_http()
        try:
            resp = await http.get(f"/samples/{sample_id}/{task_id}/report_triage.json")
            if resp.status_code != 200:
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.debug("TriageClient: task report fetch failed (%s).", exc)
            return {}

    async def fetch_pcapng(self, sample_id: str, task_id: str) -> bytes:
        """``GET /samples/{sample_id}/{task_id}/dump.pcapng`` — decrypted PCAP."""
        http = self._get_http()
        try:
            resp = await http.get(f"/samples/{sample_id}/{task_id}/dump.pcapng")
            if resp.status_code != 200:
                return b""
            return bytes(resp.content)
        except Exception as exc:
            logger.debug("TriageClient: pcapng fetch failed (%s).", exc)
            return b""

    async def search_corpus(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """``GET /v0/search`` — find similar samples (e.g. ``family:emotet``)."""
        http = self._get_http()
        try:
            resp = await http.get("/search", params={"query": query, "limit": str(limit)})
            if resp.status_code != 200:
                return []
            data = resp.json()
            samples = data.get("data") if isinstance(data, dict) else None
            return list(samples) if isinstance(samples, list) else []
        except Exception as exc:
            logger.debug("TriageClient: search failed (%s).", exc)
            return []

    async def _enrich_from_overview(self, sample_id: str, normalized: dict[str, Any]) -> None:
        overview = await self.fetch_overview(sample_id)
        if not overview:
            return
        sample_block = overview.get("sample")
        if isinstance(sample_block, dict):
            existing = normalized.get("target", {}).get("file", {})
            if not existing.get("sha256"):
                existing["sha256"] = str(sample_block.get("sha256", "") or "").lower()
            if not existing.get("md5"):
                existing["md5"] = sample_block.get("md5", "")
            if not existing.get("size"):
                existing["size"] = int(sample_block.get("size") or 0)
            if not existing.get("name") or existing.get("name") == sample_id:
                existing["name"] = (
                    sample_block.get("filename")
                    or sample_block.get("target")
                    or existing.get("name", sample_id)
                )
        sigs = overview.get("signatures")
        if isinstance(sigs, list):
            normalized.setdefault("signatures_rich", sigs)
        targets = overview.get("targets")
        if isinstance(targets, list):
            for tgt in targets:
                if isinstance(tgt, dict) and tgt.get("tags"):
                    normalized.setdefault("attack_tags", []).extend(
                        [t for t in tgt["tags"] if isinstance(t, str)]
                    )
        # ``extracted[].config`` is Triage's family-attribution gold: c2, keys,
        # mutex, botnet, campaign. Promote it verbatim so downstream agents can
        # quote it.
        extracted = overview.get("extracted")
        if isinstance(extracted, list):
            normalized.setdefault("extracted", extracted)
        analysis = overview.get("analysis")
        if isinstance(analysis, dict):
            normalized.setdefault("analysis", analysis)

    async def _enrich_from_task_reports(
        self, sample_id: str, summary: dict[str, Any], normalized: dict[str, Any]
    ) -> None:
        tasks_block = summary.get("tasks")
        if not isinstance(tasks_block, dict):
            return
        per_task: list[dict[str, Any]] = []
        # Cap to bound cost — 5 behavioral tasks covers the longest profile chain.
        for task_id, task_info in list(tasks_block.items())[:5]:
            if not isinstance(task_info, dict):
                continue
            kind = task_info.get("kind")
            if kind not in {"behavioral1", "behavioral2", "static1"}:
                continue
            task_report = await self.fetch_task_report(sample_id, str(task_id))
            if task_report:
                per_task.append({"task_id": task_id, "report": task_report})
        if per_task:
            normalized.setdefault("behavior_rich", per_task)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _view_url(sample_id: str) -> str:
    """Public-cloud URL teammates / reviewers can open to verify a submission."""
    return _TRIAGE_VIEW_URL.format(sample_id=sample_id)


def _resolve_sample_name(triage_data: dict[str, Any], task_id: str) -> str:
    """Best-effort extraction of the original filename.

    Triage's ``summary.sample`` can be a dict, a bare sha256 string, or
    omitted entirely. When the filename cannot be recovered we substitute a
    visible placeholder so static analyst prompts do not silently treat the
    task id as a binary filename (a Ghidra-load failure mode observed in the
    2026-05-19 audit, fix APK-SAND-01).
    """
    raw_sample = triage_data.get("sample")
    if isinstance(raw_sample, dict) and raw_sample.get("name"):
        return str(raw_sample["name"])
    if isinstance(raw_sample, str) and re.fullmatch(r"[0-9a-fA-F]{64}", raw_sample):
        return raw_sample
    logger.warning(
        "TriageClient: task=%s sample.name absent; using placeholder. "
        "Downstream analyst prompts will reference the placeholder rather "
        "than the original filename.",
        task_id,
    )
    return f"_triage_no_name_{task_id}"
