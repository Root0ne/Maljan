"""Report service — business logic for report retrieval and export."""

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.logging_config import get_logger
from app.models.job import AnalysisJob
from app.models.report import AnalysisReport
from app.models.user import User

logger = get_logger("service.report")


class ReportService:
    """Handles report retrieval, STIX export, and MITRE mapping."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

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
            items.append({
                "id": str(report.id),
                "job_id": str(report.job_id),
                "sample_filename": sample_filename,
                "verdict": report.verdict,
                "overall_confidence": report.overall_confidence,
                "malware_category": report.malware_category,
                "created_at": report.created_at.isoformat() if report.created_at else None,
                "techniques_count": len(mitre) if isinstance(mitre, list) else 0,
                "findings_count": len(findings),
            })

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
                }
                for f in (report.agent_findings or [])
            ],
        }
