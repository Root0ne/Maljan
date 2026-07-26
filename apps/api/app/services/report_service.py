"""Report service — business logic for report retrieval and export."""

import asyncio
import re
import string
import uuid
from typing import TYPE_CHECKING, Any, NamedTuple

from arq import ArqRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.logging_config import get_logger
from app.models.job import AnalysisJob
from app.models.report import AnalysisReport
from app.models.user import User

if TYPE_CHECKING:  # pragma: no cover — import cycle-free typing only
    from maljan.reporting.models import MalwareReport

logger = get_logger("service.report")

# Download names are derived from attacker-controlled file names, so everything
# outside this set is collapsed to "-" before it reaches a Content-Disposition
# header — a quote or a newline there is a header-injection primitive.
_UNSAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Digest prefix length used in download names — long enough to stay unique
# across a corpus, short enough to read.
_HASH_NAME_CHARS = 16


class EnrichmentEnqueueError(RuntimeError):
    """Raised when the ARQ enqueue for enrichment fails (503 to the client)."""


class RenderedReport(NamedTuple):
    """A rendered export plus the download name derived from the sample."""

    content: bytes
    filename: str


def _export_filename(report: "MalwareReport", extension: str) -> str:
    """Build a safe, informative download name for a rendered report."""
    stem = (report.identity.file_name or "").strip()
    if not stem:
        stem = (report.identity.hashes.sha256 or "report")[:_HASH_NAME_CHARS]
    stem = _shorten_hash_like(stem)
    stem = _UNSAFE_FILENAME_RE.sub("-", stem).strip("-.") or "report"
    return f"maljan-{stem[:60]}.{extension}"


def _shorten_hash_like(stem: str) -> str:
    """Collapse a hash-shaped file name to a readable prefix.

    Malware pipelines routinely store a sample under its own digest, and this
    one is no exception — the live corpus is full of ``<sha256>.exe``. Left
    alone that produced ``maljan-<60 chars of hash>.pdf``: truncated mid-digest,
    so it neither identified the sample nor kept the original extension. Keeping
    a short prefix plus the extension says strictly more in a quarter the width.
    """
    base, dot, ext = stem.rpartition(".")
    if not dot:
        base, ext = stem, ""
    if len(base) < 32 or not all(c in string.hexdigits for c in base):
        return stem
    short = base[:_HASH_NAME_CHARS]
    return f"{short}.{ext}" if ext else short


class ReportService:
    """Handles report retrieval, STIX export, and MITRE mapping."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._arq_redis: ArqRedis | None = None

    async def _get_arq_redis(self) -> ArqRedis:
        """Lazy-initialize ARQ Redis connection for job enqueueing."""
        if self._arq_redis is None:
            from arq.connections import RedisSettings, create_pool

            self._arq_redis = await create_pool(RedisSettings.from_dsn(settings.redis_url))
        return self._arq_redis

    async def list_reports(
        self,
        user: User,
        page: int = 1,
        page_size: int = 20,
    ) -> dict:
        """List all reports for the user's jobs with pagination."""
        from sqlalchemy import func
        from sqlalchemy.orm import selectinload

        base_query = (
            select(AnalysisReport)
            .options(selectinload(AnalysisReport.job).selectinload(AnalysisJob.sample))
            .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
            .where(AnalysisJob.created_by == user.id)
        )

        # Count
        count_result = await self.db.execute(
            select(func.count()).select_from(base_query.subquery())
        )
        total = count_result.scalar() or 0

        # Fetch page
        result = await self.db.execute(
            base_query.order_by(AnalysisReport.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        reports = result.scalars().all()

        # Enrich with computed fields for the frontend
        items: list[dict] = []
        for report in reports:
            sample_filename = (
                report.job.sample.original_filename
                if report.job and report.job.sample
                else "unknown"
            )
            mitre = report.mitre_techniques or []
            findings = report.agent_findings or []
            items.append(
                {
                    "id": str(report.id),
                    "job_id": str(report.job_id),
                    "sample_filename": sample_filename,
                    "verdict": report.verdict,
                    "overall_confidence": report.overall_confidence,
                    "malware_category": report.malware_category,
                    "created_at": report.created_at.isoformat() if report.created_at else None,
                    "techniques_count": len(mitre) if isinstance(mitre, list) else 0,
                    "findings_count": len(findings),
                }
            )

        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    async def get_report(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> AnalysisReport | None:
        """Get a report by ID, scoped to the requesting user's jobs."""
        result = await self.db.execute(
            select(AnalysisReport)
            .options(selectinload(AnalysisReport.agent_findings))
            .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
            .where(
                AnalysisReport.id == report_id,
                AnalysisJob.created_by == user.id,
            )
        )
        return result.scalar_one_or_none()

    async def delete_report(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> bool:
        """Delete a report owned by ``user``. Returns False when not found.

        Audit 2026-07-26 (Ö4). Scoped through the owning job exactly like
        ``get_report`` so one user can never delete another's report.
        ``AnalysisReport.agent_findings`` is declared with
        ``cascade="all, delete-orphan"``, so the findings go with it.
        """
        report = await self.get_report(report_id, user)
        if report is None:
            return False
        await self.db.delete(report)
        await self.db.flush()
        logger.info(
            "Report deleted: id=%s",
            report_id,
            extra={"user_id": str(user.id)},
        )
        return True

    async def get_report_by_job(
        self,
        job_id: uuid.UUID,
        user: User,
    ) -> AnalysisReport | None:
        """Get the report for a specific job."""
        result = await self.db.execute(
            select(AnalysisReport)
            .options(selectinload(AnalysisReport.agent_findings))
            .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
            .where(
                AnalysisReport.job_id == job_id,
                AnalysisJob.created_by == user.id,
            )
        )
        return result.scalar_one_or_none()

    async def get_stix_bundle(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> dict | None:
        """Extract the STIX 2.1 bundle from a report."""
        report = await self.get_report(report_id, user)
        if not report:
            return None
        return report.stix_bundle

    async def get_mitre_techniques(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> list | None:
        """Extract MITRE ATT&CK techniques from a report."""
        report = await self.get_report(report_id, user)
        if not report:
            return None
        return report.mitre_techniques

    async def get_malware_report(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> dict | None:
        """Return the full ``MalwareReport`` JSON document (Faz 5).

        Returns ``None`` when the row exists but predates the feature (the
        column is ``NULL``); the caller distinguishes that from a missing
        report via ``get_report``.
        """
        report = await self.get_report(report_id, user)
        if not report:
            return None
        return report.malware_report

    async def get_malware_report_markdown(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> str | None:
        """Return the markdown rendering of the comprehensive report."""
        # The renderer stores its output on the pipeline ``state`` rather than
        # inside the MalwareReport itself — we re-render here so the API path
        # stays consistent with newer reports whose markdown was not persisted.
        loaded = await self._load_malware_report(report_id, user, "markdown")
        if loaded is None:
            return None
        from maljan.reporting.renderers import MarkdownRenderer

        return str(MarkdownRenderer().render(loaded))

    async def get_malware_report_html(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> RenderedReport | None:
        """Render the comprehensive report as a standalone HTML document (Phase 6)."""
        loaded = await self._load_malware_report(report_id, user, "html")
        if loaded is None:
            return None
        from maljan.reporting.renderers import HtmlRenderer

        return RenderedReport(
            content=HtmlRenderer().render(loaded).encode("utf-8"),
            filename=_export_filename(loaded, "html"),
        )

    async def get_malware_report_pdf(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> RenderedReport | None:
        """Render the comprehensive report as PDF (Phase 6).

        Raises:
            PdfUnavailableError: WeasyPrint is not loadable on this host; the
                router turns that into a 503 rather than a 500, because the
                report itself is fine and every other export still works.
        """
        loaded = await self._load_malware_report(report_id, user, "pdf")
        if loaded is None:
            return None
        from maljan.reporting.renderers import HtmlRenderer, PdfRenderer

        html_doc = HtmlRenderer().render(loaded)
        # WeasyPrint is synchronous and CPU-bound (roughly a second on a
        # figure-heavy report), so it must not run on the event loop — a single
        # export would otherwise stall every other request on this worker.
        pdf = await asyncio.to_thread(PdfRenderer.render_html, html_doc)
        return RenderedReport(content=pdf, filename=_export_filename(loaded, "pdf"))

    async def _load_malware_report(
        self,
        report_id: uuid.UUID,
        user: User,
        export: str,
    ) -> "MalwareReport | None":
        """Fetch + validate the stored MalwareReport, or ``None`` if unusable."""
        mr = await self.get_malware_report(report_id, user)
        if not mr:
            return None
        from maljan.reporting.models import MalwareReport

        try:
            return MalwareReport.model_validate(mr)
        except Exception as exc:  # noqa: BLE001
            logger.warning("get_malware_report_%s: validation failed (%s).", export, exc)
            return None

    async def get_malware_report_iocs(
        self,
        report_id: uuid.UUID,
        user: User,
        kind: str | None = None,
    ) -> list[dict] | None:
        """Flatten the typed IOC collections into a single list.

        ``kind`` filter accepts ``domain`` / ``ip`` / ``url`` / ``user_agent`` /
        ``ja3`` / ``ja3s`` / ``hash``. None returns every kind.
        """
        mr = await self.get_malware_report(report_id, user)
        if not mr:
            return None
        out: list[dict] = []
        identity = mr.get("identity") or {}
        hashes = identity.get("hashes") or {}
        for algo, value in hashes.items():
            if not value or (kind and kind != "hash"):
                continue
            out.append({"kind": "hash", "value": f"{algo}:{value}"})
        network = mr.get("network") or {}
        if not kind or kind == "domain":
            for dom in network.get("domains") or []:
                out.append(
                    {
                        "kind": "domain",
                        "value": dom.get("fqdn", ""),
                        "is_suspicious": bool(dom.get("is_suspicious")),
                        "notes": dom.get("reason"),
                    }
                )
        if not kind or kind == "ip":
            for ip in network.get("ips") or []:
                out.append(
                    {
                        "kind": "ip",
                        "value": ip.get("address", ""),
                        "is_suspicious": bool(ip.get("is_suspicious")),
                    }
                )
        if not kind or kind == "url":
            for url in network.get("urls") or []:
                out.append({"kind": "url", "value": url.get("url", "")})
        if not kind or kind == "user_agent":
            for ua in network.get("user_agents") or []:
                out.append({"kind": "user_agent", "value": ua})
        if not kind or kind == "ja3":
            for ja3 in network.get("ja3_fingerprints") or []:
                out.append({"kind": "ja3", "value": ja3})
        if not kind or kind == "ja3s":
            for ja3s in network.get("ja3s_fingerprints") or []:
                out.append({"kind": "ja3s", "value": ja3s})
        return [row for row in out if row.get("value")]

    async def get_malware_report_signature(
        self,
        report_id: uuid.UUID,
        user: User,
        kind: str,
    ) -> str | None:
        """Return the concatenated rule bodies for a single signature ``kind``.

        ``kind`` is one of ``yara``, ``sigma``, ``suricata``, ``snort``.

        Distinguishes "report missing" (``None`` -> caller raises 404) from
        "report exists but no bodies of this kind" (empty string -> caller
        returns 200 with an empty body). The previous behaviour collapsed
        both into ``None`` which made the UI treat an empty Suricata set
        as a missing report.
        """
        mr = await self.get_malware_report(report_id, user)
        if not mr:
            return None
        signatures = mr.get("detection_signatures") or []
        bodies: list[str] = []
        for sig in signatures:
            if sig.get("kind") != kind:
                continue
            name = sig.get("name") or "rule"
            body = sig.get("body") or ""
            bodies.append(f"// {name}\n{body}")
        return "\n\n".join(bodies) if bodies else ""

    async def enqueue_enrichment(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> str | None:
        """Enqueue an ARQ threat-intel enrichment job for ``report_id``.

        Returns the ARQ job id, ``None`` when ARQ refused (already queued —
        unique key collision) or raises :class:`EnrichmentEnqueueError`
        when the Redis connection itself failed.

        Authorization is delegated to ``get_report`` — a 404 here means the
        caller does not own the report.
        """
        report = await self.get_report(report_id, user)
        if not report:
            return None
        try:
            pool = await self._get_arq_redis()
            job = await pool.enqueue_job(
                "enrich_threat_intel",
                str(report_id),
                _job_id=f"enrich:{report_id}",
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("enrich enqueue failed: %s", exc)
            raise EnrichmentEnqueueError(str(exc)) from exc
        return job.job_id if job is not None else None

    async def get_negotiation_timeline(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> dict[str, Any] | None:
        """Build a timeline of the multi-agent negotiation for visualization.

        Returns structured data suitable for rendering a debate timeline
        showing how agents' positions evolved through negotiation rounds.
        """
        report = await self.get_report(report_id, user)
        if not report:
            return None

        negotiation = report.negotiation_log or {}
        discussion = negotiation.get("discussion_history", [])
        confidence_history = negotiation.get("confidence_history", [])

        # Group arguments by round
        agents_per_round: dict[int, list] = {}

        for i, arg in enumerate(discussion):
            # Approximate round assignment based on agent cycling
            round_num = i  # Simple sequential for now
            if round_num not in agents_per_round:
                agents_per_round[round_num] = []
            agents_per_round[round_num].append(arg)

        return {
            "total_rounds": negotiation.get("iteration_count", 0),
            "reached_consensus": negotiation.get("is_consensus", False),
            "confidence_curve": confidence_history,
            "discussion_timeline": discussion,
            "agent_findings": [
                {
                    "agent_name": f.agent_name,
                    "domain": f.domain,
                    "final_confidence": f.final_confidence,
                    "revision_rounds": f.revision_rounds,
                    "claims_count": len(f.claims or []),
                    "dissent_count": len(f.dissent_items or []),
                    "status": getattr(f, "status", "complete"),
                    "status_reason": getattr(f, "status_reason", None),
                }
                for f in (report.agent_findings or [])
            ],
        }
