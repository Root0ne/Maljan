"""``run_summary.agent_stats`` can tell "nothing to read" from "never answered".

Three things can leave an analyst with no claims: it had no data, it read its
data and found nothing to say, and its model ended without a structured report.
The transcript event, the ``AgentFinding`` row and the UI all learned to name
the third. ``agent_stats`` did not, so the one view an operator skims — and the
one the judge's degradation note is built from — still showed it as
``no_data: false`` with a claim count of zero.

The worker's own vocabulary is bounded here too: the column feeds a TypeScript
union, so a status an ISR invented must not reach it.
"""

from __future__ import annotations

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(agent: str, *, claims: int = 0, status: str | None = None) -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain=agent,
        claims=[
            ClaimEvidence(claim=f"finding {n}", evidence_ref=f"ev_000{n}", confidence=0.8)
            for n in range(claims)
        ],
        status=status,
        status_reason="the model ended without a structured report" if status else None,
    )


def _stats(reports: dict[str, AgentISR], no_data: set[str] | None = None) -> list[dict]:
    builder = RunSummaryBuilder(start_time=0.0).set_isr_stats(reports, no_data=no_data)
    return [
        {"agent_id": s.agent_id, "no_data": s.no_data, "status": s.status, "claims": s.claim_count}
        for s in builder._agent_stats
    ]


class TestTheThreeWaysToHaveNoClaims:
    def test_an_analyst_that_never_answered_says_so(self) -> None:
        (row,) = _stats({"static": _isr("static", status="no_claims")})

        assert row["status"] == "no_claims"
        assert row["no_data"] is False
        assert row["claims"] == 0

    def test_an_analyst_with_nothing_to_read_is_unchanged(self) -> None:
        (row,) = _stats({"dynamic": _isr("dynamic")}, no_data={"dynamic"})

        assert row["no_data"] is True
        assert row["status"] == ""

    def test_an_analyst_that_read_its_data_and_found_nothing(self) -> None:
        (row,) = _stats({"network": _isr("network")})

        assert row["no_data"] is False
        assert row["status"] == ""

    def test_an_analyst_that_answered_declares_nothing(self) -> None:
        (row,) = _stats({"static": _isr("static", claims=3)})

        assert row["status"] == ""
        assert row["claims"] == 3


class TestItReachesTheSummaryDict:
    def test_the_row_carries_the_status(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_sample("a" * 64, "s.exe")
            .set_verdict("Malware", 1)
            .set_isr_stats({"static": _isr("static", status="no_claims")})
            .build()
            .to_dict()
        )

        assert summary["agent_stats"][0]["status"] == "no_claims"


class TestWhatTheWorkerWillPersist:
    def test_the_vocabulary_is_the_one_the_ui_renders(self) -> None:
        from app.worker.analysis_worker import _AGENT_FINDING_STATUSES

        assert _AGENT_FINDING_STATUSES == {
            "complete",
            "no_data",
            "no_claims",
            "failed",
            "timeout",
        }
