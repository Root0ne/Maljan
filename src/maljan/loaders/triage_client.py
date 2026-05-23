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

# File-extension -> Triage OS resource tag. The tags come straight from
# ``GET /v0/resources`` on the public Researcher tier (2026-05). When the
# extension is unknown we fall back to ``os:windows10-2004-x64`` because
# the Windows sandbox accepts a far wider range of payloads (PowerShell,
# scripts, generic archives) than the platform-specific ones.
_EXT_TO_OS_TAG: dict[str, str] = {
    ".apk": "os:android-13-x64",
    ".dex": "os:android-13-x64",
    ".elf": "os:ubuntu-22.04-amd64",
    ".so": "os:ubuntu-22.04-amd64",
    ".sh": "os:ubuntu-22.04-amd64",
    ".deb": "os:ubuntu-22.04-amd64",
    ".bin": "os:ubuntu-22.04-amd64",
    ".dmg": "os:macos-10.15-amd64",
    ".pkg": "os:macos-10.15-amd64",
    ".app": "os:macos-10.15-amd64",
    ".scpt": "os:macos-10.15-amd64",
    # Everything else -> Windows. Triage's Windows profile is the default
    # for PE family + scripts + most documents.
}
_DEFAULT_OS_TAG = "os:windows10-2004-x64"


def _pick_profile_tag(sample_path: Path, force_tag: str | None = None) -> str:
    """Pick a Triage OS resource tag for the sample.

    ``force_tag`` (when truthy) wins unconditionally — operators can pin a
    specific platform via ``SANDBOX__TRIAGE_FORCE_OS_TAG``. Otherwise the
    file extension is mapped through ``_EXT_TO_OS_TAG`` with a Windows
    fallback.
    """
    if force_tag:
        return force_tag
    ext = sample_path.suffix.lower()
    return _EXT_TO_OS_TAG.get(ext, _DEFAULT_OS_TAG)


# ---------------------------------------------------------------------------
# Normalizer — Triage schema -> Maljan CAPE-compatible shape
# ---------------------------------------------------------------------------


def _normalize_report(triage_report: dict[str, Any], sample_name: str) -> dict[str, Any]:
    """Convert a Triage summary payload to Maljan's CAPE-shaped report.

    Triage's ``GET /samples/{id}/summary`` returns sample identity *either*
    as a nested dict ``{"sample": {"sha256": "...", "name": "..."}}`` *or* as
    a bare string id with top-level ``sha256`` / ``target`` / ``score`` keys.
    The latter is what the modern Recorded Future Sandbox actually emits;
    the former survives for legacy compatibility. This normalizer accepts
    both.

    Output (matches existing fixture JSON consumed by DynamicParser /
    NetworkParser)::

        {
          "target":    {"file": {"sha256": "...", "md5": "...", "name": "...", "size": N}},
          "behavior":  {"processes": [...], "calls": [...], "apistats": {...}},
          "network":   {"dns": [...], "http": [...], "tcp": [...], "udp": [...],
                        "hosts": [...], "domains": [...]},
          "signatures":[{"name": "...", "description": "...", "severity": N, "marks": [...]}],
          "ttp_tags":  ["T1055", ...],
          "triage_score": <int, optional>  # overall maliciousness 1-10
        }
    """
    raw_sample = triage_report.get("sample", {})
    sample_meta = raw_sample if isinstance(raw_sample, dict) else {}

    raw_tasks = triage_report.get("tasks", {})
    tasks = raw_tasks if isinstance(raw_tasks, dict) else {}

    # Modern shape: top-level sha256 / target (filename) / score.
    top_sha256 = triage_report.get("sha256", "")
    top_target = triage_report.get("target", "")
    top_score = triage_report.get("score")

    sha256 = sample_meta.get("sha256") or top_sha256 or ""
    filename = sample_meta.get("name") or top_target or sample_name
    target = {
        "file": {
            "sha256": str(sha256).lower(),
            "md5": sample_meta.get("md5", ""),
            "name": filename,
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

    result: dict[str, Any] = {
        "target": target,
        "behavior": behavior,
        "network": network,
        "signatures": signatures,
        "ttp_tags": sorted(all_ttp_tags),
    }
    if isinstance(top_score, int):
        result["triage_score"] = top_score
    return result


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
        timeout: int = 1800,
        poll_interval: int = 15,
        interactive: bool = False,
        auto_profile: bool = False,
        force_os_tag: str | None = None,
        behavioral_timeout: int = 120,
        network_mode: str = "internet",
        pcap_dir: str | None = None,
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
        self._interactive = interactive
        self._auto_profile = auto_profile
        self._force_os_tag = force_os_tag
        self._behavioral_timeout = behavioral_timeout
        self._network_mode = network_mode
        self._pcap_dir = Path(pcap_dir) if pcap_dir else None
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
    # Submission payload builder
    # ------------------------------------------------------------------

    def _build_submit_payload(self, sample_path: Path) -> dict[str, Any]:
        """Return the ``_json`` payload for ``POST /samples``.

        Two strategies:

        1. ``interactive=False`` (default) — embed an explicit profile
           ``{"profile": {"tags": ["os:..."]}}``. Triage starts behavioral
           execution immediately. Works on accounts with no saved profiles
           (the typical Researcher tier).
        2. ``interactive=True`` — pause at ``static_analysis``; the wait
           loop POSTs ``/samples/{id}/profile {auto: true}`` later. Only
           useful when the account has saved profiles configured via the
           web UI.
        """
        payload: dict[str, Any] = {
            "kind": "file",
            "interactive": bool(self._interactive),
        }
        if not self._interactive:
            tag = _pick_profile_tag(sample_path, self._force_os_tag)
            payload["profiles"] = [{"profile": {"tags": [tag]}}]
        payload["defaults"] = {
            "timeout": int(self._behavioral_timeout),
            "network": self._network_mode or "internet",
        }
        return payload

    # ------------------------------------------------------------------
    # Sync internals
    # ------------------------------------------------------------------

    def _sync_submit(self, sample_path: Path) -> str:
        import json as _json

        http = self._get_http_sync()
        filename = sample_path.name
        sha256 = _sha256_file(sample_path)
        payload = self._build_submit_payload(sample_path)
        logger.info(
            "TriageClient: submitting '%s' (sha256=%s..., profile=%s).",
            filename,
            sha256[:16],
            _summarize_profile(payload),
        )
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

    def _sync_select_profile_auto(self, task_id: str) -> bool:
        """POST ``/samples/{id}/profile`` with ``{auto: true}`` (sync).

        Triggers behavioral execution after the sample has reached
        ``static_analysis``. Returns True on 200/201, False otherwise — the
        caller decides whether to keep polling regardless.
        """
        import json as _json

        http = self._get_http_sync()
        try:
            resp = http.post(
                f"/samples/{task_id}/profile",
                content=_json.dumps({"auto": True}),
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            logger.warning("TriageClient: auto-profile POST failed (%s).", exc)
            return False
        if resp.status_code in (200, 201):
            logger.info("TriageClient: auto-profile selected for task=%s.", task_id)
            return True
        logger.warning(
            "TriageClient: auto-profile HTTP %d for task=%s — body: %s",
            resp.status_code,
            task_id,
            resp.text[:200],
        )
        return False

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
        profile_selected = False
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
            # Auto-profile transition. When the task pauses at
            # ``static_analysis`` (interactive submission), POST the auto
            # profile to actually trigger behavioral execution. Idempotent —
            # only fires once per ``_sync_wait`` invocation.
            if (
                status == "static_analysis"
                and self._interactive
                and self._auto_profile
                and not profile_selected
            ):
                if self._sync_select_profile_auto(task_id):
                    profile_selected = True
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

        try:
            overview = self._sync_fetch_overview(task_id)
            if overview:
                _apply_overview(overview, normalized, fallback_sample_id=task_id)
        except Exception as exc:
            logger.warning("TriageClient: overview enrichment failed (%s).", exc)
        try:
            per_task = self._sync_fetch_task_reports(task_id, triage_data)
            _apply_per_task_report(per_task, normalized)
        except Exception as exc:
            logger.warning("TriageClient: per-task enrichment failed (%s).", exc)

        # PCAPNG is opt-in (large bytes). Per-task pcaps land under
        # ``<pcap_dir>/<sample_id>/<task_id>.pcapng``; paths are surfaced
        # under ``normalized["pcapng_paths"]`` for downstream consumers.
        if self._pcap_dir is not None:
            try:
                pcap_paths = self._sync_fetch_pcapngs(task_id, triage_data)
                if pcap_paths:
                    normalized["pcapng_paths"] = pcap_paths
            except Exception as exc:
                logger.warning("TriageClient: pcapng fetch failed (%s).", exc)

        normalized["cti"] = _synthesize_cti(normalized)
        _log_post_enrichment(task_id, normalized)
        return SubmissionResult(
            task_id=task_id,
            sample_name=sample_name,
            sample_sha256=str(normalized["target"]["file"].get("sha256", "")),
            status=str(triage_data.get("status", "reported")),
            report=normalized,
        )

    def _sync_fetch_pcapngs(self, sample_id: str, summary: dict[str, Any]) -> list[str]:
        if self._pcap_dir is None:
            return []
        http = self._get_http_sync()
        tasks_block = summary.get("tasks")
        if not isinstance(tasks_block, dict):
            return []
        target_dir = self._pcap_dir / sample_id
        target_dir.mkdir(parents=True, exist_ok=True)
        out: list[str] = []
        for task_id in list(tasks_block.keys())[:5]:
            task_info = tasks_block.get(task_id)
            kind = str((task_info or {}).get("kind") or "")
            if not kind.startswith("behavioral"):
                continue
            try:
                resp = http.get(f"/samples/{sample_id}/{task_id}/dump.pcapng")
            except Exception as exc:
                logger.debug("TriageClient: pcapng GET failed for %s (%s).", task_id, exc)
                continue
            if resp.status_code != 200 or not resp.content:
                continue
            target_path = target_dir / f"{task_id}.pcapng"
            target_path.write_bytes(resp.content)
            out.append(str(target_path))
            logger.info(
                "TriageClient: pcapng saved task=%s -> %s (%d bytes).",
                task_id,
                target_path,
                len(resp.content),
            )
        return out

    def _sync_fetch_overview(self, sample_id: str) -> dict[str, Any]:
        http = self._get_http_sync()
        try:
            resp = http.get(f"/samples/{sample_id}/overview.json")
            if resp.status_code != 200:
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except Exception as exc:
            logger.debug("TriageClient: sync overview fetch failed (%s).", exc)
            return {}

    def _sync_fetch_task_reports(
        self, sample_id: str, summary: dict[str, Any]
    ) -> list[dict[str, Any]]:
        http = self._get_http_sync()
        tasks_block = summary.get("tasks")
        if not isinstance(tasks_block, dict):
            return []
        out: list[dict[str, Any]] = []
        for task_id, task_info in list(tasks_block.items())[:5]:
            if not isinstance(task_info, dict):
                continue
            kind = str(task_info.get("kind") or "")
            if not kind.startswith(("static", "behavioral")):
                continue
            try:
                resp = http.get(f"/samples/{sample_id}/{task_id}/report_triage.json")
                if resp.status_code != 200:
                    continue
                body = resp.json()
                if isinstance(body, dict):
                    out.append({"task_id": task_id, "report": body})
            except Exception as exc:
                logger.debug("TriageClient: sync task report fetch failed (%s).", exc)
        return out

    # ------------------------------------------------------------------
    # Async internals
    # ------------------------------------------------------------------

    async def _async_submit(self, sample_path: Path) -> str:
        import json as _json

        http = self._get_http()
        filename = sample_path.name
        sha256 = _sha256_file(sample_path)
        payload = self._build_submit_payload(sample_path)
        logger.info(
            "TriageClient: submitting '%s' (sha256=%s..., profile=%s).",
            filename,
            sha256[:16],
            _summarize_profile(payload),
        )
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

    async def _async_select_profile_auto(self, task_id: str) -> bool:
        import json as _json

        http = self._get_http()
        try:
            resp = await http.post(
                f"/samples/{task_id}/profile",
                content=_json.dumps({"auto": True}),
                headers={"Content-Type": "application/json"},
            )
        except Exception as exc:
            logger.warning("TriageClient: auto-profile POST failed (%s).", exc)
            return False
        if resp.status_code in (200, 201):
            logger.info("TriageClient: auto-profile selected for task=%s.", task_id)
            return True
        logger.warning(
            "TriageClient: auto-profile HTTP %d for task=%s — body: %s",
            resp.status_code,
            task_id,
            resp.text[:200],
        )
        return False

    async def _async_wait(self, task_id: str) -> str:
        http = self._get_http()
        deadline = time.monotonic() + self._timeout
        attempt = 0
        backoff = float(self._poll_interval)
        max_backoff = max(60.0, backoff * 4)
        consecutive_failures = 0
        profile_selected = False
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
            if (
                status == "static_analysis"
                and self._interactive
                and self._auto_profile
                and not profile_selected
            ):
                if await self._async_select_profile_auto(task_id):
                    profile_selected = True
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

        try:
            await self._enrich_from_overview(task_id, normalized)
        except Exception as exc:
            logger.warning("TriageClient: overview enrichment failed (%s).", exc)
        try:
            await self._enrich_from_task_reports(task_id, triage_data, normalized)
        except Exception as exc:
            logger.warning("TriageClient: per-task enrichment failed (%s).", exc)

        if self._pcap_dir is not None:
            try:
                pcap_paths = await self._async_fetch_pcapngs(task_id, triage_data)
                if pcap_paths:
                    normalized["pcapng_paths"] = pcap_paths
            except Exception as exc:
                logger.warning("TriageClient: pcapng fetch failed (%s).", exc)

        normalized["cti"] = _synthesize_cti(normalized)
        _log_post_enrichment(task_id, normalized)
        return SubmissionResult(
            task_id=task_id,
            sample_name=sample_name,
            sample_sha256=str(normalized["target"]["file"].get("sha256", "")),
            status="reported",
            report=normalized,
        )

    async def _async_fetch_pcapngs(self, sample_id: str, summary: dict[str, Any]) -> list[str]:
        if self._pcap_dir is None:
            return []
        http = self._get_http()
        tasks_block = summary.get("tasks")
        if not isinstance(tasks_block, dict):
            return []
        target_dir = self._pcap_dir / sample_id
        target_dir.mkdir(parents=True, exist_ok=True)
        out: list[str] = []
        for task_id in list(tasks_block.keys())[:5]:
            task_info = tasks_block.get(task_id)
            kind = str((task_info or {}).get("kind") or "")
            if not kind.startswith("behavioral"):
                continue
            try:
                resp = await http.get(f"/samples/{sample_id}/{task_id}/dump.pcapng")
            except Exception as exc:
                logger.debug("TriageClient: async pcapng GET failed for %s (%s).", task_id, exc)
                continue
            if resp.status_code != 200 or not resp.content:
                continue
            target_path = target_dir / f"{task_id}.pcapng"
            target_path.write_bytes(resp.content)
            out.append(str(target_path))
            logger.info(
                "TriageClient: pcapng saved task=%s -> %s (%d bytes).",
                task_id,
                target_path,
                len(resp.content),
            )
        return out

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
        _apply_overview(overview, normalized, fallback_sample_id=sample_id)

    async def _enrich_from_task_reports(
        self, sample_id: str, summary: dict[str, Any], normalized: dict[str, Any]
    ) -> None:
        tasks_block = summary.get("tasks")
        if not isinstance(tasks_block, dict):
            return
        per_task: list[dict[str, Any]] = []
        for task_id, task_info in list(tasks_block.items())[:5]:
            if not isinstance(task_info, dict):
                continue
            kind = str(task_info.get("kind") or "")
            if not kind.startswith(("static", "behavioral")):
                continue
            task_report = await self.fetch_task_report(sample_id, str(task_id))
            if task_report:
                per_task.append({"task_id": task_id, "report": task_report})
        _apply_per_task_report(per_task, normalized)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _apply_overview(
    overview: dict[str, Any], normalized: dict[str, Any], fallback_sample_id: str
) -> None:
    """Merge fields from ``overview.json`` into the normalized report.

    Captures everything the overview carries that is CTI-relevant: sample
    identity, signatures (with ATT&CK ttp + indicators), targets (with
    family + iocs), and the family-attribution ``extracted[].config`` block.
    """
    sample_block = overview.get("sample")
    if isinstance(sample_block, dict):
        existing = normalized.setdefault("target", {}).setdefault("file", {})
        if not existing.get("sha256"):
            existing["sha256"] = str(sample_block.get("sha256", "") or "").lower()
        if not existing.get("md5"):
            existing["md5"] = sample_block.get("md5", "")
        if not existing.get("size"):
            existing["size"] = int(sample_block.get("size") or 0)
        if not existing.get("name") or existing.get("name") == fallback_sample_id:
            existing["name"] = (
                sample_block.get("filename")
                or sample_block.get("target")
                or existing.get("name", fallback_sample_id)
            )
        # The overview also carries IOCs at sample level on some tiers.
        sample_iocs = sample_block.get("iocs")
        if isinstance(sample_iocs, dict):
            normalized.setdefault("overview_sample_iocs", sample_iocs)

    sigs = overview.get("signatures")
    if isinstance(sigs, list) and sigs:
        normalized.setdefault("signatures_rich", sigs)
        if not normalized.get("signatures"):
            normalized["signatures"] = [
                {
                    "name": s.get("name", ""),
                    "description": s.get("desc") or s.get("description") or s.get("name", ""),
                    "severity": s.get("score", s.get("severity", 1)),
                    "ttp": s.get("ttp", []),
                    "tags": s.get("tags", []),
                    "indicators": s.get("indicators", []),
                    "yara_rule": s.get("yara_rule", ""),
                    "marks": s.get("marks", []),
                }
                for s in sigs
                if isinstance(s, dict)
            ]
        # Top-level overview signatures often carry the only TTPs that
        # surface for static-leaning analyses — promote them into the
        # normalized ttp_tags / attack_tags lists.
        for s in sigs:
            if not isinstance(s, dict):
                continue
            for ttp in s.get("ttp", []) or []:
                if isinstance(ttp, str):
                    normalized.setdefault("ttp_tags", []).append(ttp)
            for tag in s.get("tags", []) or []:
                if isinstance(tag, str):
                    normalized.setdefault("attack_tags", []).append(tag)

    targets = overview.get("targets")
    if isinstance(targets, list):
        normalized.setdefault("targets", targets)
        for tgt in targets:
            if not isinstance(tgt, dict):
                continue
            if tgt.get("tags"):
                normalized.setdefault("attack_tags", []).extend(
                    [t for t in tgt["tags"] if isinstance(t, str)]
                )
            if tgt.get("family"):
                normalized.setdefault("families", []).extend(
                    [f for f in tgt["family"] if isinstance(f, str)]
                )
            target_iocs = tgt.get("iocs")
            if isinstance(target_iocs, dict):
                bucket = normalized.setdefault(
                    "overview_target_iocs",
                    {"urls": [], "domains": [], "ips": []},
                )
                for url in target_iocs.get("urls", []) or []:
                    if isinstance(url, str):
                        bucket["urls"].append(url)
                for d in target_iocs.get("domains", []) or []:
                    if isinstance(d, str):
                        bucket["domains"].append(d)
                for ip in target_iocs.get("ips", []) or []:
                    if isinstance(ip, str):
                        bucket["ips"].append(ip)
            for sig in tgt.get("signatures", []) or []:
                if not isinstance(sig, dict):
                    continue
                normalized.setdefault("signatures_rich", []).append(sig)
                for ttp in sig.get("ttp", []) or []:
                    if isinstance(ttp, str):
                        normalized.setdefault("ttp_tags", []).append(ttp)
                for tag in sig.get("tags", []) or []:
                    if isinstance(tag, str):
                        normalized.setdefault("attack_tags", []).append(tag)

    extracted = overview.get("extracted")
    if isinstance(extracted, list):
        normalized.setdefault("extracted", extracted)

    analysis = overview.get("analysis")
    if isinstance(analysis, dict):
        normalized.setdefault("analysis", analysis)
        if "triage_score" not in normalized and isinstance(analysis.get("score"), int):
            normalized["triage_score"] = analysis["score"]
        if isinstance(analysis.get("family"), list):
            normalized.setdefault("families", []).extend(
                [f for f in analysis["family"] if isinstance(f, str)]
            )
        # Triage often puts platform / behavior bands ("android",
        # "defense_evasion", etc.) under analysis.tags. Promote them to
        # attack_tags so the CTI block surfaces them.
        if isinstance(analysis.get("tags"), list):
            normalized.setdefault("attack_tags", []).extend(
                [t for t in analysis["tags"] if isinstance(t, str)]
            )


def _apply_per_task_report(per_task: list[dict[str, Any]], normalized: dict[str, Any]) -> None:
    """Ingest per-task ``report_triage.json`` payloads into the normalized report.

    Each entry is ``{"task_id": "...", "report": {...}}``. We pull network
    flows + requests, process tree, dumped files, signature indicators, and
    promote extracted configs (family / c2 / keys / credentials) when the
    overview did not already carry them. ``behavior`` and ``network``
    sections in ``normalized`` are mutated in place — duplicates are not
    de-duped here (the CTI synthesizer flattens uniquely).
    """
    if not per_task:
        return

    normalized.setdefault("behavior_rich", per_task)
    behavior = normalized.setdefault(
        "behavior",
        {"processes": [], "calls": [], "apistats": {}},
    )
    network = normalized.setdefault(
        "network",
        {"dns": [], "http": [], "tcp": [], "udp": [], "hosts": [], "domains": []},
    )

    for entry in per_task:
        report = entry.get("report") if isinstance(entry, dict) else None
        if not isinstance(report, dict):
            continue

        # --- analysis-level fields (per-task) ---
        analysis = report.get("analysis")
        if isinstance(analysis, dict):
            for ttp in analysis.get("ttp", []) or []:
                if isinstance(ttp, str):
                    normalized.setdefault("ttp_tags", []).append(ttp)
            for tag in analysis.get("tags", []) or []:
                if isinstance(tag, str):
                    normalized.setdefault("attack_tags", []).append(tag)

        # --- processes ---
        for proc in report.get("processes", []) or []:
            if not isinstance(proc, dict):
                continue
            behavior["processes"].append(
                {
                    "process_name": proc.get("image") or proc.get("name") or "unknown",
                    "pid": proc.get("pid", 0),
                    "ppid": proc.get("ppid", 0),
                    "command_line": proc.get("cmd", ""),
                    "image": proc.get("image", ""),
                    "started": proc.get("started"),
                    "terminated": proc.get("terminated"),
                }
            )

        # --- network flows + requests ---
        net = report.get("network")
        if isinstance(net, dict):
            for flow in net.get("flows", []) or []:
                if not isinstance(flow, dict):
                    continue
                proto = (flow.get("proto") or "").lower()
                dst = flow.get("dst") or ""
                flow_summary = {
                    "src": flow.get("src", ""),
                    "dst": dst,
                    "proto": proto,
                    "domain": flow.get("domain", ""),
                    "tls_sni": flow.get("tls_sni", ""),
                    "tls_ja3": flow.get("tls_ja3", ""),
                    "tls_ja3s": flow.get("tls_ja3s", ""),
                    "country": flow.get("country", ""),
                    "as_org": flow.get("as_org", ""),
                    "rx_bytes": flow.get("rx_bytes", 0),
                    "tx_bytes": flow.get("tx_bytes", 0),
                }
                if proto == "udp":
                    network["udp"].append(flow_summary)
                else:
                    network["tcp"].append(flow_summary)
                if flow.get("domain"):
                    network["domains"].append(flow["domain"])
                if dst:
                    host = dst.split(":", 1)[0]
                    if host:
                        network["hosts"].append(host)

            for req in net.get("requests", []) or []:
                if not isinstance(req, dict):
                    continue
                dns_req = req.get("dns_request")
                dns_resp = req.get("dns_response")
                if isinstance(dns_req, dict) or isinstance(dns_resp, dict):
                    network["dns"].append(
                        {
                            "request": dns_req,
                            "response": dns_resp,
                            "at": req.get("at"),
                        }
                    )
                http_req = req.get("http_request")
                http_resp = req.get("http_response")
                if isinstance(http_req, dict) or isinstance(http_resp, dict):
                    network["http"].append(
                        {
                            "method": (http_req or {}).get("method", "") if http_req else "",
                            "url": (http_req or {}).get("url", "") if http_req else "",
                            "headers": (http_req or {}).get("headers", []) if http_req else [],
                            "status": (http_resp or {}).get("status", "") if http_resp else "",
                            "at": req.get("at"),
                        }
                    )

        # --- dumped files ---
        for dump in report.get("dumped", []) or []:
            if not isinstance(dump, dict):
                continue
            normalized.setdefault("dumped", []).append(
                {
                    "name": dump.get("name", ""),
                    "path": dump.get("path", ""),
                    "kind": dump.get("kind", ""),
                    "sha256": dump.get("sha256", ""),
                    "md5": dump.get("md5", ""),
                    "length": dump.get("length", 0),
                    "pid": dump.get("pid"),
                }
            )

        # --- extracted: configs, dropper, ransom note, credentials ---
        for ex in report.get("extracted", []) or []:
            if isinstance(ex, dict):
                normalized.setdefault("extracted", []).append(ex)

        # --- per-task signatures with their full ATT&CK + indicator surface ---
        for sig in report.get("signatures", []) or []:
            if not isinstance(sig, dict):
                continue
            normalized.setdefault("signatures_rich", []).append(sig)
            for ttp in sig.get("ttp", []) or []:
                if isinstance(ttp, str):
                    normalized.setdefault("ttp_tags", []).append(ttp)


def _synthesize_cti(normalized: dict[str, Any]) -> dict[str, Any]:
    """Produce a flat ``report["cti"]`` block from already-enriched data.

    The block is the single source of truth a paper / dashboard / API
    response can quote without walking every nested Triage structure.
    Lists are deduped while preserving first-seen order.
    """

    def _dedupe(items: list[Any]) -> list[Any]:
        seen: set[Any] = set()
        out: list[Any] = []
        for item in items:
            try:
                if item in seen:
                    continue
            except TypeError:  # unhashable (dict / list)
                if item in out:
                    continue
                out.append(item)
                continue
            seen.add(item)
            out.append(item)
        return out

    cti: dict[str, Any] = {
        "family": [],
        "ttp": [],
        "tags": [],
        "c2": {"urls": [], "domains": [], "ips": []},
        "mutexes": [],
        "keys": [],
        "credentials": [],
        "dropped_files": [],
        "dropper_urls": [],
        "ransom_notes": [],
        "network": {
            "dns_queries": [],
            "http_urls": [],
            "domains": [],
            "ips": [],
            "tls_ja3": [],
            "tls_sni": [],
        },
        "indicators": [],
        "yara_rules": [],
        "score": normalized.get("triage_score"),
    }

    # --- families ---
    cti["family"].extend(normalized.get("families", []) or [])
    analysis = normalized.get("analysis")
    if isinstance(analysis, dict) and isinstance(analysis.get("family"), list):
        cti["family"].extend([f for f in analysis["family"] if isinstance(f, str)])

    # --- TTPs ---
    cti["ttp"].extend([t for t in normalized.get("ttp_tags", []) or [] if isinstance(t, str)])
    cti["tags"].extend([t for t in normalized.get("attack_tags", []) or [] if isinstance(t, str)])

    # --- extracted[*].config — the C2 / credential / key gold ---
    for ex in normalized.get("extracted", []) or []:
        if not isinstance(ex, dict):
            continue
        cfg = ex.get("config")
        if isinstance(cfg, dict):
            if cfg.get("family") and cfg["family"] not in cti["family"]:
                cti["family"].append(cfg["family"])
            for c2 in cfg.get("c2", []) or []:
                _classify_c2(c2, cti["c2"])
            for mutex in cfg.get("mutex", []) or []:
                if isinstance(mutex, str):
                    cti["mutexes"].append(mutex)
            for key in cfg.get("keys", []) or []:
                if isinstance(key, dict):
                    cti["keys"].append(
                        {
                            "kind": key.get("kind", ""),
                            "key": key.get("key", ""),
                            "value": key.get("value"),
                        }
                    )
            for cred in cfg.get("credentials", []) or []:
                if isinstance(cred, dict):
                    cti["credentials"].append(cred)
            for cmd in cfg.get("command_lines", []) or []:
                if isinstance(cmd, str):
                    cti.setdefault("command_lines", []).append(cmd)
            for d in cfg.get("dns", []) or []:
                if isinstance(d, str):
                    cti["c2"]["domains"].append(d)
        # top-level credentials block on extracted item
        ec = ex.get("credentials")
        if isinstance(ec, dict):
            cti["credentials"].append(ec)
        # dropper URLs
        dr = ex.get("dropper")
        if isinstance(dr, dict):
            for entry in dr.get("urls", []) or []:
                if isinstance(entry, dict) and entry.get("url"):
                    cti["dropper_urls"].append({"type": entry.get("type", ""), "url": entry["url"]})
        # ransom note
        rn = ex.get("ransom_note")
        if isinstance(rn, dict):
            cti["ransom_notes"].append(
                {
                    "family": rn.get("family", ""),
                    "emails": rn.get("emails", []),
                    "wallets": rn.get("wallets", []),
                    "urls": rn.get("urls", []),
                    "contact": rn.get("contact", []),
                    "note": rn.get("note", ""),
                }
            )

    # --- network IOCs ---
    network = normalized.get("network", {}) or {}
    for dns in network.get("dns", []) or []:
        if not isinstance(dns, dict):
            continue
        # Triage shapes: either {"name": "...", "answers": [...]} or
        # {"request": {...}, "response": {...}}.
        if dns.get("name"):
            cti["network"]["dns_queries"].append(dns["name"])
        req = dns.get("request")
        if isinstance(req, dict):
            for q in req.get("questions", []) or []:
                if isinstance(q, dict) and q.get("name"):
                    cti["network"]["dns_queries"].append(q["name"])
            for d in req.get("domains", []) or []:
                if isinstance(d, str):
                    cti["network"]["domains"].append(d)
        resp = dns.get("response")
        if isinstance(resp, dict):
            for ip in resp.get("ip", []) or []:
                if isinstance(ip, str):
                    cti["network"]["ips"].append(ip)
            for ans in resp.get("answers", []) or []:
                if isinstance(ans, dict) and ans.get("value"):
                    val = ans["value"]
                    if isinstance(val, str):
                        if any(ch.isdigit() for ch in val) and val.count(".") == 3:
                            cti["network"]["ips"].append(val)
                        else:
                            cti["network"]["domains"].append(val)

    for http in network.get("http", []) or []:
        if isinstance(http, dict) and http.get("url"):
            cti["network"]["http_urls"].append(http["url"])

    for collection in (network.get("tcp"), network.get("udp"), network.get("hosts")):
        if not isinstance(collection, list):
            continue
        for item in collection:
            if isinstance(item, dict):
                if item.get("domain"):
                    cti["network"]["domains"].append(item["domain"])
                if item.get("tls_sni"):
                    cti["network"]["tls_sni"].append(item["tls_sni"])
                if item.get("tls_ja3"):
                    cti["network"]["tls_ja3"].append(item["tls_ja3"])
                if item.get("dst"):
                    host = item["dst"].split(":", 1)[0] if ":" in item["dst"] else item["dst"]
                    if host:
                        if host.replace(".", "").replace(":", "").isdigit():
                            cti["network"]["ips"].append(host)
                        else:
                            cti["network"]["domains"].append(host)
            elif isinstance(item, str):
                if any(ch.isdigit() for ch in item) and item.count(".") == 3:
                    cti["network"]["ips"].append(item)
                else:
                    cti["network"]["domains"].append(item)

    for d in network.get("domains", []) or []:
        if isinstance(d, str):
            cti["network"]["domains"].append(d)

    overview_iocs = normalized.get("overview_sample_iocs")
    if isinstance(overview_iocs, dict):
        for u in overview_iocs.get("urls", []) or []:
            if isinstance(u, str):
                cti["network"]["http_urls"].append(u)
        for d in overview_iocs.get("domains", []) or []:
            if isinstance(d, str):
                cti["network"]["domains"].append(d)
        for ip in overview_iocs.get("ips", []) or []:
            if isinstance(ip, str):
                cti["network"]["ips"].append(ip)

    # --- dumped files ---
    for dump in normalized.get("dumped", []) or []:
        if isinstance(dump, dict) and dump.get("sha256"):
            cti["dropped_files"].append(
                {
                    "name": dump.get("name", ""),
                    "sha256": dump["sha256"],
                    "md5": dump.get("md5", ""),
                    "path": dump.get("path", ""),
                }
            )

    # --- signatures: indicators + yara rules + ttp + tags ---
    for sig in (normalized.get("signatures", []) or []) + (
        normalized.get("signatures_rich", []) or []
    ):
        if not isinstance(sig, dict):
            continue
        if sig.get("yara_rule"):
            cti["yara_rules"].append(sig["yara_rule"])
        for ttp in sig.get("ttp", []) or []:
            if isinstance(ttp, str):
                cti["ttp"].append(ttp)
        for tag in sig.get("tags", []) or []:
            if isinstance(tag, str):
                cti["tags"].append(tag)
        for ind in sig.get("indicators", []) or []:
            if isinstance(ind, dict) and ind.get("ioc"):
                cti["indicators"].append(
                    {
                        "ioc": ind["ioc"],
                        "description": ind.get("description", ""),
                        "yara_rule": ind.get("yara_rule", ""),
                    }
                )

    # --- target-level IOCs from overview ---
    overview_tgt_iocs = normalized.get("overview_target_iocs")
    if isinstance(overview_tgt_iocs, dict):
        for u in overview_tgt_iocs.get("urls", []) or []:
            if isinstance(u, str):
                cti["network"]["http_urls"].append(u)
        for d in overview_tgt_iocs.get("domains", []) or []:
            if isinstance(d, str):
                cti["network"]["domains"].append(d)
        for ip in overview_tgt_iocs.get("ips", []) or []:
            if isinstance(ip, str):
                cti["network"]["ips"].append(ip)

    # Dedupe every flat list (preserves order).
    cti["family"] = _dedupe(cti["family"])
    cti["ttp"] = _dedupe(cti["ttp"])
    cti["tags"] = _dedupe(cti["tags"])
    cti["mutexes"] = _dedupe(cti["mutexes"])
    cti["yara_rules"] = _dedupe(cti["yara_rules"])
    for key in cti["c2"]:
        cti["c2"][key] = _dedupe(cti["c2"][key])
    for key in cti["network"]:
        cti["network"][key] = _dedupe(cti["network"][key])
    cti["keys"] = _dedupe(cti["keys"])
    cti["credentials"] = _dedupe(cti["credentials"])
    cti["dropper_urls"] = _dedupe(cti["dropper_urls"])
    cti["dropped_files"] = _dedupe(cti["dropped_files"])
    cti["indicators"] = _dedupe(cti["indicators"])

    return cti


def _summarize_profile(payload: dict[str, Any]) -> str:
    """Render a single-line description of a submit payload's profile choice."""
    if payload.get("interactive"):
        return "interactive (manual)"
    profiles = payload.get("profiles") or []
    if not profiles:
        return "auto-pick (no embedded profile)"
    first = profiles[0]
    if isinstance(first, dict):
        prof = first.get("profile")
        if isinstance(prof, dict):
            return f"embedded tags={prof.get('tags', [])}"
        if isinstance(prof, str):
            return f"saved profile={prof!r}"
    return f"profiles={profiles!r}"


def _classify_c2(value: Any, c2: dict[str, list[str]]) -> None:
    """Bucket a ``extracted.config.c2[*]`` entry into URL / domain / IP."""
    if not isinstance(value, str) or not value:
        return
    v = value.strip()
    if v.startswith(("http://", "https://", "ftp://", "tcp://", "udp://")):
        c2["urls"].append(v)
        return
    host = v
    if "/" in host:
        host = host.split("/", 1)[0]
    if ":" in host and host.count(":") == 1:
        host = host.split(":", 1)[0]
    if host.replace(".", "").isdigit():
        c2["ips"].append(host)
    else:
        c2["domains"].append(host)


def _log_post_enrichment(task_id: str, normalized: dict[str, Any]) -> None:
    sigs = normalized.get("signatures") or []
    network = normalized.get("network") or {}
    cti = normalized.get("cti") or {}
    cti_c2 = cti.get("c2") or {}
    cti_net = cti.get("network") or {}
    logger.info(
        "TriageClient: post-enrichment task=%s sigs=%d dns=%d http=%d tcp=%d udp=%d "
        "family=%s c2_urls=%d c2_domains=%d c2_ips=%d net_doms=%d net_ips=%d "
        "dropped=%d ttps=%d.",
        task_id,
        len(sigs) if isinstance(sigs, list) else 0,
        len(network.get("dns", []) or []),
        len(network.get("http", []) or []),
        len(network.get("tcp", []) or []),
        len(network.get("udp", []) or []),
        cti.get("family") or [],
        len(cti_c2.get("urls", [])),
        len(cti_c2.get("domains", [])),
        len(cti_c2.get("ips", [])),
        len(cti_net.get("domains", [])),
        len(cti_net.get("ips", [])),
        len(cti.get("dropped_files", [])),
        len(cti.get("ttp", [])),
    )


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

    Triage's ``GET /samples/{id}/summary`` exposes the filename in any of
    three shapes depending on the API tier / endpoint generation:

    1. Modern: top-level ``target`` field holds the filename.
    2. Modern alt: top-level ``filename`` field.
    3. Legacy: nested ``sample.name`` dict.
    4. Edge: ``sample`` is a bare sha256 string (no filename available).

    When none yield a usable filename we substitute a visible placeholder so
    static analyst prompts do not silently treat the task id as a binary
    filename (a Ghidra-load failure mode observed in the 2026-05-19 audit,
    fix APK-SAND-01).
    """
    top_target = triage_data.get("target")
    if isinstance(top_target, str) and top_target:
        return top_target
    top_filename = triage_data.get("filename")
    if isinstance(top_filename, str) and top_filename:
        return top_filename
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
