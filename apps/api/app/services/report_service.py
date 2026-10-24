"""Report service — business logic for report retrieval and export."""

import asyncio
import re
import string
import uuid
from typing import TYPE_CHECKING, Any, NamedTuple

from arq import ArqRedis
from maljan.reporting.builder import ioc_table
from maljan.reporting.models import ConsolidatedIOC
from maljan.reporting.renderers.stix_renderer import SAMPLE_DIGESTS, publishes, yes_because
from maljan.reporting.run_diff import RunRecord, diff_runs
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.job import AnalysisJob
from app.models.report import AnalysisReport
from app.models.user import User
from app.services.audit_chain import record_report_deletion

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


def _typed_report(mr: dict) -> Any:
    """The stored report as the model the IOC table is built from, or ``None``.

    A report that will not validate has no table to rebuild; the feed then
    serves the rows the report stored, and says so in the log.
    """
    from maljan.reporting.models import MalwareReport

    try:
        return MalwareReport.model_validate(mr)
    except Exception as exc:  # noqa: BLE001 — a feed answers, and says what broke
        logger.error(
            "the stored report could not be read as a report model; the feed serves the IOC "
            "rows it stored (%s: %s)",
            type(exc).__name__,
            log_safe(exc),
        )
        return None


def _feed_value(kind: str, ioc_type: str, value: str) -> str:
    """A row's value as the feed has always written it: a digest after its algorithm."""
    if kind != "hash":
        return value
    algorithm = ioc_type.strip().lower().replace("-", "")
    return f"{algorithm}:{value}" if algorithm and algorithm != "hash" else value


def _network_rows(mr: dict) -> dict[tuple[str, str], dict]:
    """The network block's domain and address rows, by kind and folded value."""
    network = mr.get("network") or {}
    found: dict[tuple[str, str], dict] = {}
    for kind, rows, key in (("domain", "domains", "fqdn"), ("ip", "ips", "address")):
        for row in network.get(rows) or []:
            if isinstance(row, dict) and row.get(key):
                found.setdefault((kind, str(row[key]).strip().lower().rstrip(".")), row)
    return found


def _identity_rows(mr: dict) -> list[ConsolidatedIOC]:
    """The sample's own digests as the IOC table lists them, read from the stored identity."""
    identity = mr.get("identity")
    hashes = identity.get("hashes") if isinstance(identity, dict) else None
    if not isinstance(hashes, dict):
        return []
    return [
        ConsolidatedIOC(
            type=label,
            kind="hash",
            value=str(hashes[field]).strip(),
            source="identity",
            context="the sample",
            description="the sample",
            published=yes_because("identity"),
        )
        for label, field in SAMPLE_DIGESTS
        if str(hashes.get(field) or "").strip()
    ]


# The kinds a feed another system reads carries only when asked for by name: a
# leaked credential and a wallet address are a responder's to see in the
# report, not values to hand every consumer of ``include=all``.
_ASKED_FOR_BY_NAME = frozenset({"secret", "crypto_wallet"})


def ioc_feed_rows(mr: dict, kind: str | None = None) -> list[dict]:
    """Every row of the report's IOC table, as ``/reports/{id}/iocs`` serves it.

    Built from the one table the report's §9 prints (``builder.ioc_table``:
    rebuilt from the stored report by the current rule), so the feed and the
    table cannot diverge: each row carries the table's kind, source, publish
    answer and recovery note, and ``published`` is that answer's decision.
    A domain or an address keeps the network block's suspicion flag and
    reason. A stored report the model cannot read serves the rows it stored.
    The sample's own digests, which the router established and no rule
    decides, are served even when the table cannot be read at all. A
    ``secret`` or ``crypto_wallet`` row is served only to a ``kind`` filter
    that names its kind.
    """
    typed = _typed_report(mr)
    if typed is not None:
        table = ioc_table(typed)
    else:
        table = []
        for stored in mr.get("consolidated_iocs") or []:
            try:
                table.append(ConsolidatedIOC.model_validate(stored))
            except Exception:  # noqa: BLE001, S112 — a row that will not read is no row
                continue
    if not any(row.source == "identity" for row in table):
        table = [*_identity_rows(mr), *table]
    network = _network_rows(mr)
    out: list[dict] = []
    for row in table:
        row_kind = str(row.kind or "")
        if not row.value or (kind and kind != row_kind):
            continue
        if row_kind in _ASKED_FOR_BY_NAME and kind != row_kind:
            continue
        listed = network.get((row_kind, row.value.strip().lower().rstrip("."))) or {}
        out.append(
            {
                "kind": row_kind,
                "value": _feed_value(row_kind, row.type, row.value),
                "is_suspicious": bool(listed.get("is_suspicious")),
                # An analyst's mutex, path, key, task or service carries the
                # rule's refusal as its note, as it always has.
                "notes": listed.get("reason")
                or (row.published if row.source == "analyst" and not row.is_network else None),
                "source": row.source,
                "published": publishes(row.published),
                "publish_answer": row.published,
                "recovered_by": row.recovered_by or None,
            }
        )
    return out


# What a report stored before the current publish rule is told about its
# export: the bundle is the one stored, and is not re-rendered when served,
# because a render mints fresh ids and timestamps every time.
OLD_RULE_STIX_NOTE = (
    "This report was stored before its IOC table, /iocs and MISP attributes were built by "
    "the current publish rule. They are rebuilt by that rule when served; the STIX bundle "
    "is served as it was rendered when the report was stored, and may carry fewer "
    "indicators than the table publishes."
)


def with_current_iocs(mr: Any, owner: str) -> tuple[Any, str | None]:
    """The stored report as served: its IOC table rebuilt, and MISP attributes when it has none.

    The table is the one ``/iocs`` and §9 read (``builder.ioc_table``), so the
    console's indicator panel shows the rows the feed serves. A report stored
    before MISP attributes were built has them built here, their uuids derived
    from ``owner`` (the report's id). The second value is the note a report
    stored under the earlier rule carries about its STIX bundle, else
    ``None``. A report the model cannot read is served as stored.
    """
    if not isinstance(mr, dict):
        return mr, None
    typed = _typed_report(mr)
    if typed is None:
        return mr, None
    from maljan.reporting.misp import build_misp_attributes

    table = ioc_table(typed)
    served = {**mr, "consolidated_iocs": [row.model_dump(mode="json") for row in table]}
    note = None
    if mr.get("misp_attributes") is None:
        served["misp_attributes"] = build_misp_attributes(typed, table, owner=owner)
        note = OLD_RULE_STIX_NOTE
    return served, note


def run_record(report: AnalysisReport) -> RunRecord:
    """A stored report as the run diff reads it, every value as stored."""
    job = report.job
    sample = job.sample if job is not None else None
    duration = job.duration_seconds if job is not None else None
    return RunRecord(
        report_id=str(report.id),
        job_id=str(report.job_id),
        created_at=report.created_at.isoformat() if report.created_at else None,
        verdict=report.verdict,
        overall_confidence=report.overall_confidence,
        malware_category=report.malware_category,
        malware_report=report.malware_report,
        run_summary=report.run_summary,
        stix_bundle=report.stix_bundle,
        agent_findings=[
            {
                "agent_name": f.agent_name,
                "status": f.status,
                "final_confidence": f.final_confidence,
                "revision_rounds": f.revision_rounds,
                "claims": f.claims,
            }
            for f in (report.agent_findings or [])
        ],
        sample_sha256=sample.sha256 if sample is not None else None,
        sample_file_name=sample.original_filename if sample is not None else None,
        duration_seconds=float(duration) if duration is not None else None,
    )


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
                    # A report kept from a job that failed after it was built
                    # says so in the list too; ``None`` for a completed run.
                    "incomplete_reason": report.incomplete_reason,
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
            .options(
                selectinload(AnalysisReport.agent_findings),
                selectinload(AnalysisReport.transcript),
            )
            .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
            .where(
                AnalysisReport.id == report_id,
                AnalysisJob.created_by == user.id,
            )
        )
        return result.scalar_one_or_none()

    async def get_report_for_diff(
        self,
        run_id: uuid.UUID,
        user: User,
        *,
        by: str = "report",
    ) -> AnalysisReport | None:
        """One report the caller may read, with its job and sample loaded.

        The same ownership rule as ``get_report`` and ``get_report_by_job``:
        the report's job must belong to the caller, and anything else is
        ``None``. ``by="job"`` looks the run up by its job id, which is the id
        the console's analysis pages carry.
        """
        match = AnalysisReport.job_id == run_id if by == "job" else AnalysisReport.id == run_id
        result = await self.db.execute(
            select(AnalysisReport)
            .options(
                selectinload(AnalysisReport.agent_findings),
                selectinload(AnalysisReport.job).selectinload(AnalysisJob.sample),
            )
            .join(AnalysisJob, AnalysisReport.job_id == AnalysisJob.id)
            .where(match, AnalysisJob.created_by == user.id)
        )
        return result.scalar_one_or_none()

    async def diff_reports(
        self,
        run_a: uuid.UUID,
        run_b: uuid.UUID,
        user: User,
        *,
        by: str = "report",
    ) -> dict[str, Any] | None:
        """What changed between two stored runs, or ``None`` when either is not readable.

        Both runs must be readable by the caller; one that is not answers
        exactly as a missing one does, so the route's 404 says nothing about
        whether someone else's run exists. The comparison itself is pure and
        linear in the two records, and runs on a worker thread because two
        large reports and their bundles are real work.
        """
        report_a = await self.get_report_for_diff(run_a, user, by=by)
        if report_a is None:
            return None
        report_b = await self.get_report_for_diff(run_b, user, by=by)
        if report_b is None:
            return None
        return await asyncio.to_thread(diff_runs, run_record(report_a), run_record(report_b))

    async def delete_report(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> bool:
        """Delete a report owned by ``user``. Returns False when not found.

        Scoped through the owning job exactly like
        ``get_report`` so one user can never delete another's report.
        ``AnalysisReport.agent_findings`` and ``.transcript`` are both
        declared with ``cascade="all, delete-orphan"``, so the findings and
        the stored conversation go with it. The deletion is first written onto
        the audit chain in this transaction; when that append does not land,
        ``audit_chain.DeletionNotChained`` propagates and nothing is deleted.
        """
        report = await self.get_report(report_id, user)
        if report is None:
            return False
        await record_report_deletion(self.db, report, user_id=user.id)
        await self.db.delete(report)
        await self.db.flush()
        logger.info(
            "Report deleted: id=%s",
            log_safe(report_id),
            extra={"user_id": log_safe(user.id)},
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
            .options(
                selectinload(AnalysisReport.agent_findings),
                selectinload(AnalysisReport.transcript),
            )
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
        source: str = "export",
    ) -> dict | None:
        """Extract the STIX 2.1 bundle from a report.

        ``source="judge"`` answers with the judge's own bundle and the map from
        its labels to the published ids — the bundle every export decline row
        says the object is unchanged in — or ``None`` for a report stored
        before it was kept.
        """
        report = await self.get_report(report_id, user)
        if not report:
            return None
        if source == "judge":
            return report.judge_stix_bundle
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
        """Return the full ``MalwareReport`` JSON document.

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
        *,
        nonce: str | None = None,
    ) -> RenderedReport | None:
        """Render the comprehensive report as a standalone HTML document.

        ``nonce`` is forwarded to ``HtmlRenderer`` for the report's CSP nonce;
        it is ``None`` by default so existing callers are unaffected.
        """
        loaded = await self._load_malware_report(report_id, user, "html")
        if loaded is None:
            return None
        from maljan.reporting.renderers import HtmlRenderer

        return RenderedReport(
            content=HtmlRenderer().render(loaded, nonce=nonce).encode("utf-8"),
            filename=_export_filename(loaded, "html"),
        )

    async def get_malware_report_pdf(
        self,
        report_id: uuid.UUID,
        user: User,
    ) -> RenderedReport | None:
        """Render the comprehensive report as PDF.

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
        include: str = "published",
    ) -> list[dict] | None:
        """The report's IOC table as a flat list, filtered by kind and by publication.

        ``kind`` is a row kind of the table (``hash``, ``domain``, ``ip``,
        ``url``, ``email``, ``user_agent``, ``ja3``, ``ja3s``, ``path``,
        ``registry``, ``mutex``, ``scheduled_task``, ``service``, ``command``,
        ...). None returns every kind.

        ``include`` decides what a consumer gets. This is a feed another system
        acts on, so the default is what the platform would *publish*: the rows
        of the report's IOC table whose answer is ``yes``, the answer the STIX
        export is built from (:func:`ioc_feed_rows`). ``all`` returns every
        row and ``unpublished`` only the withheld ones, each carrying its
        ``source`` and its ``published`` flag, for a reader who is triaging
        rather than acting.
        """
        mr = await self.get_malware_report(report_id, user)
        if not mr:
            return None
        rows = ioc_feed_rows(mr, kind)
        wanted = str(include or "published").strip().lower()
        if wanted == "all":
            return rows
        keep = wanted != "unpublished"
        return [row for row in rows if row["published"] is keep]

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
            from app.worker.enrich_worker import enqueue_enrichment

            pool = await self._get_arq_redis()
            # One place knows the task's name and the queue it belongs on, so
            # the operator's button and the automatic path cannot drift apart.
            return await enqueue_enrichment(pool, report_id)
        except Exception as exc:  # noqa: BLE001
            logger.error("enrich enqueue failed: %s", exc)
            raise EnrichmentEnqueueError(str(exc)) from exc

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
            # ``None`` when consensus did not apply: fewer than two analysts
            # produced claims, so there was no agreement to reach or miss.
            "reached_consensus": negotiation.get("is_consensus", False),
            "consensus_applicable": negotiation.get("consensus_applicable", True),
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
