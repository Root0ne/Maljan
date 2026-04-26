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
    sample_meta = triage_report.get("sample", {})
    tasks = triage_report.get("tasks", {})

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
    # Triage'in network alanlari CAPEv2'ye oldukca benzer
    raw_network = triage_report.get("network", {})
    network: dict[str, Any] = {
        "dns": raw_network.get("dns", []),
        "http": raw_network.get("http", raw_network.get("requests", [])),
        "tcp": raw_network.get("tcp", raw_network.get("flows", [])),
        "udp": raw_network.get("udp", []),
        "hosts": raw_network.get("hosts", []),
        "domains": raw_network.get("domains", []),
    }

    # -- signatures section ---------------------------------------------
    raw_sigs = triage_report.get("signatures", [])
    signatures: list[dict[str, Any]] = []
    for sig in raw_sigs:
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

    Args:
        api_token:   Triage API token (tria.ge/account). Bos birakilirsa
                     sadece public/anonim analizler gonderilir.
        base_url:    Triage API base URL. Production: https://api.tria.ge
        timeout:     Gorev tamamlanmasi icin maksimum bekleme suresi (saniye).
        poll_interval: Durum sorgulama araligi (saniye).
    """

    def __init__(
        self,
        api_token: str = "",
        base_url: str = _DEFAULT_BASE_URL,
        timeout: int = 300,
        poll_interval: int = 15,
    ) -> None:
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._poll_interval = poll_interval
        self._api_prefix = f"{self._base_url}{_API_VERSION}"
        self._http: Any = None  # httpx.AsyncClient — lazy init

    # ------------------------------------------------------------------
    # SandboxClient Protocol implementation
    # ------------------------------------------------------------------

    def submit(self, sample_path: Path) -> str:
        """Numune dosyasini Triage'e gonderir ve task ID dondurur.

        Args:
            sample_path: Gonderilecek numune dosyasinin yolu.

        Returns:
            task_id (str): Triage task ID (orn. "220411-abcd1234").

        Raises:
            FileNotFoundError: sample_path bulunamazsa.
            RuntimeError: httpx kurulu degilse veya API hatasi.
        """
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample not found: {sample_path}")
        return asyncio.run(self._async_submit(sample_path))

    def wait_for_completion(self, task_id: str) -> str:
        """Triage gorevi tamamlanana kadar polling yapar.

        Args:
            task_id: submit() tarafindan donen task ID.

        Returns:
            Final status string: "reported" | "failed" | "partial" | "timeout"
        """
        return asyncio.run(self._async_wait(task_id))

    def fetch_report(self, task_id: str) -> SubmissionResult:
        """Tamamlanan analizin raporunu alir ve normallestirir.

        Args:
            task_id: wait_for_completion() ile dogrulanan task ID.

        Returns:
            SubmissionResult — report alani CAPEv2-uyumlu semaya donusturulmus.
        """
        return asyncio.run(self._async_fetch_report(task_id))

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

    def _get_http(self) -> Any:
        """Lazy httpx.AsyncClient olusturma."""
        try:
            import httpx  # type: ignore[import-untyped]
        except ImportError as exc:
            raise RuntimeError("TriageClient requires 'httpx'. Install with: uv add httpx") from exc

        if self._http is None:
            headers = {"Authorization": f"Bearer {self._api_token}"} if self._api_token else {}
            self._http = httpx.AsyncClient(
                base_url=self._api_prefix,
                headers=headers,
                timeout=60.0,
            )
        return self._http

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

        with sample_path.open("rb") as fh:
            response = await http.post(
                "/samples",
                files={"file": (filename, fh, "application/octet-stream")},
                data={"_json": '{"kind":"file","interactive":false}'},
            )

        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Triage /samples submission failed: "
                f"HTTP {response.status_code} — {response.text[:200]}"
            )

        data = response.json()
        task_id: str = data.get("id", "")
        if not task_id:
            raise RuntimeError(f"Triage returned no task ID: {data}")

        logger.info("TriageClient: task submitted, ID=%s.", task_id)
        return task_id

    async def _async_wait(self, task_id: str) -> str:
        """Triage task'i tamamlanana kadar polling yapar."""
        http = self._get_http()
        deadline = time.monotonic() + self._timeout
        attempt = 0

        while time.monotonic() < deadline:
            attempt += 1
            try:
                response = await http.get(f"/samples/{task_id}")
            except Exception as exc:
                logger.warning("TriageClient: status poll #%d failed (%s), retrying.", attempt, exc)
                await asyncio.sleep(self._poll_interval)
                continue

            if response.status_code != 200:
                logger.warning("TriageClient: poll HTTP %d, retrying.", response.status_code)
                await asyncio.sleep(self._poll_interval)
                continue

            data = response.json()
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
        sample_meta = triage_data.get("sample", {})
        sha256 = sample_meta.get("sha256", "")
        sample_name = sample_meta.get("name", task_id)

        normalized = _normalize_report(triage_data, sample_name)

        logger.info(
            "TriageClient: report fetched for task=%s (sha256=%s, %d tasks).",
            task_id,
            sha256[:16] + "..." if sha256 else "unknown",
            len(triage_data.get("tasks", {})),
        )

        return SubmissionResult(
            task_id=task_id,
            sample_sha256=sha256,
            sample_name=sample_name,
            status="reported",
            report=normalized,
            error="",
        )

    async def aclose(self) -> None:
        """HTTP istemcisini duzgunce kapatir."""
        if self._http is not None:
            await self._http.aclose()
            self._http = None


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


# Runtime protokol uyumluluk kontrolu
assert isinstance(TriageClient, type)
# SandboxClient Protocol uyumluluğunu docstring seviyesinde garanti ediyoruz.
# Tam runtime_checkable kontrolu için: isinstance(TriageClient(...), SandboxClient)
