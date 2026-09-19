"""The stored report, and the markdown rendered from it, are the final ones.

The report node writes the run summary's last fields — the validation block,
which of the named techniques were published, the stage rollup and the run's
elapsed time — and it used to write them *after* it had both rendered the
markdown and taken the snapshot the worker stores. So a served report printed
`24 claimed, 24 published` over four published techniques, carried no section
naming the twenty it did not publish, and gave the judge stage's clock (311.7 s)
as a 396.3 s run's. The console, which reads the run-summary column rather than
the stored report, had the right numbers all along — which is what said the
data was fine and the snapshot was stale.

What is served is rendered on request from the stored report, so this drives
the node and then renders the way the API does.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from maljan.reporting.models import MalwareReport
from maljan.reporting.renderers import MarkdownRenderer
from tests.stages import paper_profile

# Two techniques the judge named, one of which the sample's own domain rules
# out. The summary the judge wrote knows neither of those facts.
PUBLISHED = "T1055"
CLAIMED_ONLY = "T1027"


@pytest.fixture
def container() -> Any:
    fake = MagicMock()
    fake.agent_registry.list_agents.return_value = ["static"]
    fake.analyst_keys.return_value = ["static"]
    fake.agent_role.side_effect = lambda n: n
    fake.is_mock = False
    fake.config.reporting.enabled = True
    fake.config.llm.parallel_analysts = False
    fake.config.negotiation.max_iterations = 3
    fake.active_profile.return_value = paper_profile(["static"], parallel=False)
    fake.get_narrative_agent.return_value = None
    fake.get_report_composer.return_value = None
    fake.get_static_provider.return_value.capabilities.provides_evidence = False
    return fake


def _state() -> dict[str, Any]:
    """A run whose judge-written summary is deliberately not the final one."""
    return {
        "file_hash": "e" * 64,
        "file_name": "sample.exe",
        "sample_path": None,
        "static_sample_path": None,
        "static_sample_paths": {},
        "remote_sample_paths": {},
        "sandbox_report": None,
        "file_type": "pe",
        "platform": "windows",
        "reports": {},
        "revised_reports": {},
        "isr_reports": {},
        "evidence_ledger": [],
        "tool_evidence": {},
        "discussion_history": [],
        "sycophancy_detected": False,
        "confidence_history": [],
        "iteration_count": 0,
        "is_consensus": False,
        "final_decision": "Malware",
        "judge_report": None,
        "stix_output": {"objects": []},
        # What the judge wrote: both ids named, neither marked, and a clock
        # that stopped when the verdict did.
        "run_summary": {
            "elapsed_seconds": 11.5,
            "corroboration": {
                PUBLISHED: {"asserted_by": [], "claimed_by": ["static"]},
                CLAIMED_ONLY: {"asserted_by": [], "claimed_by": ["static"]},
            },
        },
        "malware_report": None,
        "malware_report_markdown": None,
        "stix_bundle_extended": None,
        "report_error": None,
        "verdict_fallback": None,
        "degraded_mode": False,
        "degradation_reasons": [],
        "function_hash_matches": [],
        "family_rag_candidates": [],
        "validation_findings": {},
        "validation_retries": 0,
        "validation_fed_back": {},
        "validation_not_run": [],
        "triage_facts": {},
        "nudge_retry_modes": {},
        "budget_records": {},
        "stage_results": {},
        # A whole run, against the 11.5 s the judge's own clock recorded.
        "run_started_at": time.time() - 400.0,
    }


def _published_and_marked(report: MalwareReport) -> MalwareReport:
    """The report as the checks leave it: one technique published, one marked."""
    from maljan.reporting.models import CapabilityCell, TTPMapping

    report.ttp_mappings = [
        TTPMapping(technique_id=PUBLISHED, technique_name=PUBLISHED, tactic="TA0005")
    ]
    report.capability_matrix = [
        CapabilityCell(
            tactic="TA0005",
            tactic_name="Defense Evasion",
            technique_id=CLAIMED_ONLY,
            technique_name=CLAIMED_ONLY,
            not_published="outside the sample's ATT&CK domain",
        )
    ]
    return report


async def _run(container: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """The node's result, and the summary the worker stores in its own column."""
    from maljan.pipeline.nodes import make_report_node
    from maljan.reporting.builder import MalwareReportBuilder

    deterministic = MalwareReportBuilder.build_deterministic

    def _build(self: MalwareReportBuilder) -> MalwareReport:
        return _published_and_marked(deterministic(self))

    with patch.object(MalwareReportBuilder, "build_deterministic", _build):
        result = await make_report_node(container)(_state())  # type: ignore[arg-type]
    return result, result.get("run_summary") or {}


@pytest.mark.asyncio
class TestTheStoredReportIsTheFinalOne:
    async def test_the_snapshot_carries_the_published_marks(self, container: Any) -> None:
        result, column = await _run(container)

        stored = (result["malware_report"] or {}).get("run_summary") or {}
        rows = stored.get("corroboration") or {}

        assert rows[CLAIMED_ONLY]["not_published"] == "outside the sample's ATT&CK domain"
        assert "not_published" not in rows[PUBLISHED]
        assert rows == (column.get("corroboration") or {}), "the two surfaces are one summary"

    async def test_the_snapshot_carries_the_run_s_elapsed_time(self, container: Any) -> None:
        result, column = await _run(container)

        stored = (result["malware_report"] or {}).get("run_summary") or {}

        assert stored["elapsed_seconds"] > 399.0, "the judge's 11.5 s was not the run"
        assert stored["elapsed_seconds"] == column["elapsed_seconds"]

    async def test_the_snapshot_carries_the_finished_stage_rollup(self, container: Any) -> None:
        result, column = await _run(container)

        stored = (result["malware_report"] or {}).get("run_summary") or {}

        assert stored.get("stages") == column.get("stages")


@pytest.mark.asyncio
class TestWhatIsServedFromIt:
    @staticmethod
    def _served(result: dict[str, Any]) -> str:
        """The markdown the API renders on request from the stored report."""
        return MarkdownRenderer().render(MalwareReport.model_validate(result["malware_report"]))

    async def test_the_counts_say_what_the_summary_says(self, container: Any) -> None:
        result, _column = await _run(container)

        assert "TTPs: 2 claimed, 1 published" in self._served(result)

    async def test_the_unpublished_technique_is_named(self, container: Any) -> None:
        served = self._served((await _run(container))[0])

        assert "Claims that were not published as techniques" in served
        assert CLAIMED_ONLY in served

    async def test_the_elapsed_line_is_the_run_s(self, container: Any) -> None:
        result, _column = await _run(container)
        served = self._served(result)
        stored = (result["malware_report"] or {}).get("run_summary") or {}

        assert f"Elapsed: {stored['elapsed_seconds']:.1f}s" in served
        assert "Elapsed: 11.5s" not in served

    async def test_the_node_s_own_copy_is_the_same_rendering(self, container: Any) -> None:
        """One renderer, one source: the CLI's copy cannot differ from the served one."""
        result, _column = await _run(container)

        assert result["malware_report_markdown"] == self._served(result)
