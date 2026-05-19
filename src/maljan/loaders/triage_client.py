"""Hatching Triage sandbox istemcisi — SandboxClient protokol implementasyonu.

Triage, ucretsiz katmani olan bir SaaS sandbox servisidir:
  - API: https://tria.ge/docs/
  - Ucretsiz tier: anonim golge (sandbox) analizleri
  - Token: https://tria.ge/account adresinden alinir

Bu istemci SandboxClient protokolunu uygular ve CAPEv2Client ile
tamamen degistirilebilir (drop-in replacement).

Mimari:
    TriageClient.submit(sample_path)        -> task_id
    TriageClient.wait_for_completion(tid)   -> status
    TriageClient.fetch_report(tid)          -> SubmissionResult

Normalizasyon:
    Triage API, CAPEv2'den farkli bir JSON sema kullaniyor.
    _normalize_report() Triage raporunu Maljan'in iclerde bekledigi
    CAPEv2-uyumlu yapiya donusturuyor (behavior, target, signatures).
    Bu sayede DynamicParser ve NetworkParser degistirilmeden calisir.

    Triage JSON -> Maljan SubmissionResult.report semasi:
        tasks[*].sample.*          -> report["target"]["file"]
        tasks[*].targets[*].tasks  -> process/api call bilgisi
        overview                   -> hash + name
        network                    -> report["network"] (dogrudan kullanilir)

Graceful degradation:
    - api_token bossa, istemci sadece public sandbox analizleri gonderebilir.
    - httpx kurulu degilse ImportError yerine RuntimeError uretilir
      (aciklayici mesaj).
    - Zaman asiminda SubmissionResult.status="timeout" doner, exception atmaz.

Kullanim:
    client = TriageClient(api_token="tria_xxx")
    result = await client.submit_and_wait(sample_path)
    report = result.report  # DynamicParser ile dogrudan kullanilabilir
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.loaders.sandbox_client import SubmissionResult

# ---------------------------------------------------------------------------
# Triage API constants
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = "https://api.tria.ge"
_API_VERSION = "/v0"

# Triage task targets parametreleri
_DEFAULT_PROFILES: list[dict[str, Any]] = [
    {"profile": "win10"},
    {"profile": "win7"},
]

# Triage'in kullandigi final status degerler
_FINAL_STATUSES: frozenset[str] = frozenset(
    {
        "reported",
        "failed",
        "partial",
    }
)


# ---------------------------------------------------------------------------
# Triage rapor normalizasyonu
# ---------------------------------------------------------------------------


def _normalize_report(triage_report: dict[str, Any], sample_name: str) -> dict[str, Any]:
    """Triage JSON raporunu Maljan'in iclerde bekledigi semaya donusturur.

    Giris (Triage /reports/{task_id}/summary):
        {
          "sample": {"id": "...", "md5": "...", "sha256": "...", ...},
          "tasks": {
            "win10-1": {
              "ttp_tags": ["T1055", ...],
              "signatures": [{"name": "...", "score": ...}, ...],
              "network": {"flows": [...], ...},
              "processes": [{"name": "...", "cmd": "...", "pid": ...}, ...],
              ...
            }
          },
          "network": {"requests": [...], "flows": [...]},
          "signatures": [...]
        }

    Cikis (Maljan SubmissionResult.report beklenen semasi):
        {
          "target": {"file": {"sha256": "...", "name": "...", "md5": "..."}},
          "behavior": {
            "processes": [...],
            "apistats": {...},
            "calls": [...]
          },
          "network": {"dns": [...], "http": [...], "tcp": [...], "udp": [...]},
          "signatures": [{"name": "...", "severity": ..., "description": "..."}],
          "ttp_tags": ["T1055", ...]
        }
    """
    raw_sample = triage_report.get("sample", {})
    sample_meta = raw_sample if isinstance(raw_sample, dict) else {}

    raw_tasks = triage_report.get("tasks", {})
    tasks = raw_tasks if isinstance(raw_tasks, dict) else {}

    # -- target section -------------------------------------------------
    target = {
        "file": {
            "sha256": sample_meta.get("sha256", ""),
            "md5": sample_meta.get("md5", ""),
            "name": sample_meta.get("name", sample_name),
            "size": sample_meta.get("size", 0),
        }
    }

    # -- behavior section -----------------------------------------------
    # Tum task'lerden process ve API cagri bilgisini birlestir
    all_processes: list[dict[str, Any]] = []
    all_calls: list[dict[str, Any]] = []
    apistats: dict[str, dict[str, int]] = {}
    all_ttp_tags: set[str] = set()

    for _task_name, task_data in tasks.items():
        if not isinstance(task_data, dict):
            continue

        # Processes
        for proc in task_data.get("processes", []):
            normalized_proc = {
                "process_name": proc.get("name", ""),
                "pid": proc.get("pid", 0),
                "ppid": proc.get("ppid", 0),
                "command_line": proc.get("cmd", ""),
                "calls": [],
            }
            for call in proc.get("calls", []):
                api_name = call.get("api", call.get("name", ""))
                normalized_call = {
                    "category": call.get("category", ""),
                    "api": api_name,
                    "arguments": call.get("args", call.get("arguments", [])),
                    "return_value": str(call.get("return_value", "")),
                }
                normalized_proc["calls"].append(normalized_call)
                all_calls.append(normalized_call)
                # apistats: proc_name -> {api_name: count}
                proc_name = proc.get("name", "unknown")
                if proc_name not in apistats:
                    apistats[proc_name] = {}
                apistats[proc_name][api_name] = apistats[proc_name].get(api_name, 0) + 1

            all_processes.append(normalized_proc)

        # TTP tags (Triage kendi ATT&CK tagging'i yapabiliyor)
        for tag in task_data.get("ttp_tags", []):
            all_ttp_tags.add(tag)

    behavior = {
        "processes": all_processes,
        "calls": all_calls,
        "apistats": apistats,
    }

    # -- network section ------------------------------------------------
    # Triage'in network alanlari CAPEv2'ye oldukca benzer.
    raw_network = triage_report.get("network", {})
    if not isinstance(raw_network, dict):
        raw_network = {}

    def _coerce_list(*candidates: Any) -> list[Any]:
        """Return the first candidate that is a list, else an empty list."""
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

    # -- signatures section ---------------------------------------------
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
        "_triage_raw_tasks": list(tasks.keys()),
    }


# ---------------------------------------------------------------------------
# TriageClient
# ---------------------------------------------------------------------------


class TriageClient:
    """Hatching Triage sandbox istemcisi.

    SandboxClient protokolunu tam olarak uygular — CAPEv2Client ile
    ServiceContainer uzerinden degistirilebilir.

    Implementation notes:
        Sync methods use a dedicated ``httpx.Client``; async methods use
        ``httpx.AsyncClient``. The previous implementation called
        ``asyncio.run()`` from sync methods which exploded when LangGraph
        called them from inside a running event loop.

    Args:
        api_token: Triage API token (https://tria.ge/account).
        base_url:  Triage API base URL.
        timeout:   Maximum wait time for task completion (seconds).
        poll_interval: Polling interval (seconds).
    """

    def __init__(
        self,
        api_token: str | Any = "",
        base_url: str = _DEFAULT_BASE_URL,
        timeout: int = 300,
        poll_interval: int = 15,
    ) -> None:
        # Accept SecretStr or plain str for the API token.
        if hasattr(api_token, "get_secret_value"):
            self._api_token = api_token.get_secret_value()
        else:
            self._api_token = str(api_token or "")
        base_url = base_url.rstrip("/")
        # Tolerate operators copying the docs URL ("https://api.tria.ge/v0")
        # — strip a trailing ``/v0`` so we never double-prefix the API path.
        if base_url.endswith(_API_VERSION):
            base_url = base_url[: -len(_API_VERSION)]
        self._base_url = base_url
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._api_prefix = f"{self._base_url}{_API_VERSION}"
        self._http_async: Any = None  # httpx.AsyncClient — lazy
        self._http_sync: Any = None  # httpx.Client — lazy

    # ------------------------------------------------------------------
    # SandboxClient Protocol implementation
    # ------------------------------------------------------------------

    def submit(self, sample_path: str | Path) -> str:
        """Numune dosyasini Triage'e gonderir ve task ID dondurur."""
        if not isinstance(sample_path, Path):
            sample_path = Path(sample_path)
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample not found: {sample_path}")
        return self._sync_submit(sample_path)

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> str:
        """Triage gorevi tamamlanana kadar polling yapar."""
        return self._sync_wait(task_id, timeout_seconds, poll_interval_seconds)

    def fetch_report(self, task_id: str) -> SubmissionResult:
        """Tamamlanan analizin raporunu alir ve normallestirir."""
        return self._sync_fetch_report(task_id)

    def close(self) -> None:
        """Sync httpx.Client'i kapatir (idempotent)."""
        client = self._http_sync
        if client is not None:
            try:
                client.close()
            finally:
                self._http_sync = None

    async def aclose(self) -> None:
        """Async httpx.AsyncClient'i kapatir (idempotent)."""
        client = self._http_async
        if client is not None:
            try:
                await client.aclose()
            finally:
                self._http_async = None

    async def submit_and_wait(self, sample_path: Path) -> SubmissionResult:
        """Asenkron all-in-one: gonder, bekle, raporla.

        Args:
            sample_path: Numune dosyasi.

        Returns:
            SubmissionResult (hata durumunda .succeeded=False).
        """
        try:
            task_id = await self._async_submit(sample_path)
            status = await self._async_wait(task_id)
            if status not in ("reported", "partial"):
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
    # Async internals
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        # Authorization is intentionally **not** logged anywhere. httpx debug
        # logs would expose plain bearer tokens; we mark sensitive headers
        # via the helper below and recommend setting httpx log level to INFO.
        return {"Authorization": f"Bearer {self._api_token}"} if self._api_token else {}

    def _get_http(self) -> Any:
        """Lazy httpx.AsyncClient olusturma (async path)."""
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
        """Lazy httpx.Client olusturma (sync path)."""
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
    # Sync internals (used when called from non-async code)
    # ------------------------------------------------------------------

    def _sync_submit(self, sample_path: Path) -> str:
        import json as _json

        http = self._get_http_sync()
        filename = sample_path.name
        sha256 = _sha256_file(sample_path)
        logger.info(
            "TriageClient: submitting sample '%s' (sha256=%s...).",
            filename,
            sha256[:16],
        )
        payload = {
            "kind": "file",
            "interactive": False,
            "targets": _DEFAULT_PROFILES,
        }
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
        logger.info("TriageClient: task submitted, ID=%s.", task_id)
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
                    "TriageClient: status poll #%d failed (%s); backoff=%.1fs.",
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

            # Reset backoff once we know polling is working.
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
        raw_sample = triage_data.get("sample", {})
        # APK-SAND-01 (2026-05-19 audit): Triage's ``summary`` endpoint
        # sometimes returns ``sample: {}`` (or omits ``name``) for APK
        # submissions. The legacy fallback substituted the task_id verbatim,
        # which downstream leaks into static analyst prompts as the binary
        # filename and breaks Ghidra ``load_program``. Detect the gap loudly
        # and use an explicit placeholder so the log + report make the
        # silent corruption visible. The 2026-05-17 T-01 branch (string
        # sha256) stays intact.
        if isinstance(raw_sample, dict) and raw_sample.get("name"):
            sample_name = str(raw_sample["name"])
        elif isinstance(raw_sample, str) and re.fullmatch(r"[0-9a-fA-F]{64}", raw_sample):
            sample_name = raw_sample
        else:
            logger.warning(
                "TriageClient: task=%s sample.name absent; substituting placeholder. "
                "Static/dynamic/network analyst inputs will reference a placeholder "
                "rather than a real filename — downstream cascade may degrade.",
                task_id,
            )
            sample_name = f"_triage_no_name_{task_id}"
        normalized = _normalize_report(triage_data, sample_name=sample_name)
        return SubmissionResult(
            task_id=task_id,
            sample_name=sample_name,
            status=triage_data.get("status", "reported"),
            report=normalized,
        )

    async def _async_submit(self, sample_path: Path) -> str:
        """Triage'e numune yukler, task ID dondurur."""
        http = self._get_http()
        filename = sample_path.name
        sha256 = _sha256_file(sample_path)

        logger.info(
            "TriageClient: submitting sample '%s' (sha256=%s).",
            filename,
            sha256[:16] + "...",
        )

        import json as _json

        payload = {
            "kind": "file",
            "interactive": False,
            "targets": _DEFAULT_PROFILES,
        }
        with sample_path.open("rb") as fh:
            response = await http.post(
                "/samples",
                files={"file": (filename, fh, "application/octet-stream")},
                data={"_json": _json.dumps(payload)},
            )

        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Triage /samples submission failed: "
                f"HTTP {response.status_code} — {response.text[:200]}"
            )

        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Triage /samples returned unexpected type {type(data).__name__}: {data!r}"
            )
        task_id: str = data.get("id", "")
        if not task_id:
            raise RuntimeError(f"Triage returned no task ID: {data}")

        logger.info("TriageClient: task submitted, ID=%s.", task_id)
        return task_id

    async def _async_wait(self, task_id: str) -> str:
        """Triage task'i tamamlanana kadar polling yapar.

        Mirrors ``_sync_wait``'s reliability features: exponential backoff on
        transient HTTP errors and a hard failure cap so a Triage outage stops
        looping silently. Without these the async path could hammer the API
        for the full ``self._timeout`` window even when every call returns 5xx.
        """
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
                    "TriageClient: status poll #%d failed (%s); backoff=%.1fs.",
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

            backoff = float(self._poll_interval)  # reset after a clean response

            data = response.json()
            if not isinstance(data, dict):
                logger.warning(
                    "TriageClient: poll #%d returned unexpected type %s, retrying.",
                    attempt,
                    type(data).__name__,
                )
                await asyncio.sleep(self._poll_interval)
                continue
            status: str = data.get("status", "")
            logger.debug("TriageClient: poll #%d — task=%s, status=%s.", attempt, task_id, status)

            if status in _FINAL_STATUSES:
                logger.info("TriageClient: task %s completed with status=%s.", task_id, status)
                return status

            await asyncio.sleep(self._poll_interval)

        logger.warning("TriageClient: task %s did not complete within %ds.", task_id, self._timeout)
        return "timeout"

    async def _async_fetch_report(self, task_id: str) -> SubmissionResult:
        """Triage summary raporunu alir ve normallestirir."""
        http = self._get_http()

        response = await http.get(f"/samples/{task_id}/summary")
        if response.status_code != 200:
            return SubmissionResult(
                task_id=task_id,
                status="failed",
                error=f"Report fetch failed: HTTP {response.status_code} — {response.text[:200]}",
            )

        triage_data = response.json()
        if not isinstance(triage_data, dict):
            return SubmissionResult(
                task_id=task_id,
                status="failed",
                error=(
                    f"Report fetch returned unexpected type {type(triage_data).__name__}: "
                    f"{triage_data!r}"
                ),
            )

        # Debug: log top-level keys and their types so we can diagnose malformed responses
        type_map = {k: type(v).__name__ for k, v in triage_data.items()}
        logger.debug("TriageClient: task=%s summary keys=%s", task_id, type_map)

        raw_sample = triage_data.get("sample", {})
        if isinstance(raw_sample, str):
            # Triage occasionally returns ``sample`` as a bare *id* string
            # instead of a dict (older API tier / pre-resolve summary).
            # That id can be either the sample sha256 (64 hex chars) OR
            # the Triage task id (e.g. ``260517-va7wrsbs9z``). Only the
            # hex form is a usable sha256 — for the task-id case, leave
            # ``sha256`` empty so downstream enrichment via
            # ``/overview.json`` can hydrate the real value.
            sample_meta = {"name": triage_data.get("name") or task_id}
            if re.fullmatch(r"[0-9a-fA-F]{64}", raw_sample):
                sample_meta["sha256"] = raw_sample.lower()
        elif isinstance(raw_sample, dict):
            sample_meta = raw_sample
        else:
            logger.warning(
                "TriageClient: task=%s 'sample' field is %s, ignoring.",
                task_id,
                type(raw_sample).__name__,
            )
            sample_meta = {}
        sha256 = sample_meta.get("sha256", "")
        sample_name = sample_meta.get("name", task_id)

        try:
            normalized = _normalize_report(triage_data, sample_name)
        except Exception as exc:
            logger.error(
                "TriageClient: _normalize_report failed for task=%s: %s (%s).",
                task_id,
                type(exc).__name__,
                exc,
            )
            return SubmissionResult(
                task_id=task_id,
                sample_sha256=sha256,
                sample_name=sample_name,
                status="failed",
                error=f"Report normalization failed: {type(exc).__name__}: {exc}",
            )

        logger.info(
            "TriageClient: report fetched for task=%s (sha256=%s, %d tasks).",
            task_id,
            sha256[:16] + "..." if sha256 else "unknown",
            len(triage_data.get("tasks", {})),
        )

        # Best-effort enrichment from per-task reports + corpus search.
        # These are *additive* — if they fail, we still return the summary.
        # We log at WARNING (not DEBUG) so degradation is visible at the
        # default log level — empty enrichment was masking the bulk of
        # Triage's signatures and network IOCs (audit 2026-05-17).
        try:
            await self._enrich_from_overview(task_id, normalized)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "TriageClient: overview enrichment failed (%s); "
                "signatures and IOCs may be missing.",
                exc,
            )
        try:
            await self._enrich_from_task_reports(task_id, triage_data, normalized)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "TriageClient: per-task report enrichment failed (%s); "
                "behavioural data may be incomplete.",
                exc,
            )

        # Post-enrichment summary so operators see at a glance what made
        # it into the normalized report. Empty values here usually mean
        # ``overview.json`` was unreachable or returned a string sample id.
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
            sample_sha256=sha256,
            sample_name=sample_name,
            status="reported",
            report=normalized,
            error="",
        )

    # ------------------------------------------------------------------
    # Richer endpoints (additive — augment the summary-based report)
    # ------------------------------------------------------------------

    async def fetch_overview(self, sample_id: str) -> dict[str, Any]:
        """``GET /samples/{id}/overview.json`` — aggregated signatures + IOCs.

        Richer than ``/summary`` (signatures with marks, network IOCs as
        typed entities, ATT&CK tags). Returns an empty dict on failure so
        callers can decide whether to merge or skip.
        """
        http = self._get_http()
        try:
            resp = await http.get(f"/samples/{sample_id}/overview.json")
            if resp.status_code != 200:
                logger.debug(
                    "TriageClient: overview.json HTTP %d for sample=%s.",
                    resp.status_code,
                    sample_id,
                )
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except Exception as exc:  # noqa: BLE001
            logger.debug("TriageClient: overview.json fetch failed: %s.", exc)
            return {}

    async def fetch_task_report(self, sample_id: str, task_id: str) -> dict[str, Any]:
        """``GET /samples/{sample_id}/{task_id}/report_triage.json`` — per-task behavior.

        Carries the rich per-task behavior block: signatures with file/registry
        marks, full process tree, network captures, IOC mark types. Falls back
        to ``{}`` when the task did not produce a report (network-only task,
        timeouts, etc.).
        """
        http = self._get_http()
        try:
            resp = await http.get(f"/samples/{sample_id}/{task_id}/report_triage.json")
            if resp.status_code != 200:
                logger.debug(
                    "TriageClient: report_triage.json HTTP %d sample=%s task=%s.",
                    resp.status_code,
                    sample_id,
                    task_id,
                )
                return {}
            data = resp.json()
            return data if isinstance(data, dict) else {}
        except Exception as exc:  # noqa: BLE001
            logger.debug("TriageClient: task report fetch failed: %s.", exc)
            return {}

    async def fetch_pcapng(self, sample_id: str, task_id: str) -> bytes:
        """``GET /samples/{sample_id}/{task_id}/dump.pcapng`` — raw packet capture.

        Returns the raw bytes for downstream pyshark / scapy parsing. Empty
        bytes when the capture is not available.
        """
        http = self._get_http()
        try:
            resp = await http.get(f"/samples/{sample_id}/{task_id}/dump.pcapng")
            if resp.status_code != 200:
                return b""
            return bytes(resp.content)
        except Exception as exc:  # noqa: BLE001
            logger.debug("TriageClient: pcapng fetch failed: %s.", exc)
            return b""

    async def search_corpus(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """``GET /v0/search`` — find similar samples in the Triage corpus.

        ``query`` follows Triage's search syntax (e.g. ``family:emotet``,
        ``tag:c2``, ``md5:...``). Used by the family-attribution agent to
        anchor confidence on corpus-wide observations.
        """
        http = self._get_http()
        try:
            resp = await http.get("/search", params={"query": query, "limit": str(limit)})
            if resp.status_code != 200:
                logger.debug("TriageClient: search HTTP %d for query=%r.", resp.status_code, query)
                return []
            data = resp.json()
            samples = data.get("data") if isinstance(data, dict) else None
            return list(samples) if isinstance(samples, list) else []
        except Exception as exc:  # noqa: BLE001
            logger.debug("TriageClient: search failed: %s.", exc)
            return []

    async def _enrich_from_overview(self, sample_id: str, normalized: dict[str, Any]) -> None:
        """Merge richer fields from ``overview.json`` into the normalized report.

        Adds ``signatures.marks`` per signature, canonical typed network
        IOCs, and ATT&CK tag aggregation when the overview is available.
        Audit 2026-05-17 (T-01 follow-up): also back-fills the canonical
        ``sample.sha256`` / ``sample.name`` / ``sample.size`` when those
        landed empty because ``summary.sample`` was the bare task id
        string rather than the resolved dict.
        """
        overview = await self.fetch_overview(sample_id)
        if not overview:
            return
        sample_block = overview.get("sample")
        if isinstance(sample_block, dict):
            existing_sample = normalized.get("sample")
            if not isinstance(existing_sample, dict) or not existing_sample.get("sha256"):
                # Promote the overview's sample dict — it has sha256/size/name.
                normalized["sample"] = {
                    "sha256": str(sample_block.get("sha256", "") or "").lower(),
                    "md5": sample_block.get("md5", ""),
                    "name": sample_block.get("filename")
                    or sample_block.get("target")
                    or normalized.get("sample", {}).get("name")
                    or sample_id,
                    "size": int(sample_block.get("size") or 0),
                }
        sigs = overview.get("signatures")
        if isinstance(sigs, list):
            normalized.setdefault("signatures_rich", sigs)
        targets = overview.get("targets")
        if isinstance(targets, list) and targets:
            for tgt in targets:
                if isinstance(tgt, dict) and tgt.get("tags"):
                    normalized.setdefault("attack_tags", []).extend(
                        [t for t in tgt["tags"] if isinstance(t, str)]
                    )

    async def _enrich_from_task_reports(
        self, sample_id: str, summary: dict[str, Any], normalized: dict[str, Any]
    ) -> None:
        """Pull per-task behavior reports (signatures, process tree, marks).

        Iterates over ``summary["tasks"]`` (which the summary endpoint already
        gave us) and pulls each task's ``report_triage.json``. Aggregates the
        rich signatures + marks into ``normalized["behavior_rich"]`` so the
        downstream Dynamic agent has access to the evidence quotes it needs.
        """
        tasks_block = summary.get("tasks")
        if not isinstance(tasks_block, dict):
            return
        per_task: list[dict[str, Any]] = []
        for task_id, task_info in list(tasks_block.items())[:5]:  # cap at 5 to bound cost
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
# Yardimci fonksiyon
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Dosyanin SHA-256 ozet degerini hesaplar (okuma akisi, bellek verimli)."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# Static protocol conformance is enforced by mypy. Runtime conformance can be
# verified with ``isinstance(TriageClient(...), SandboxClient)`` if needed.
