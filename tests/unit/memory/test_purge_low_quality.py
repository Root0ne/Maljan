"""Unit tests for the LTM purge_low_quality utility (audit follow-up 2026-05-19).

Targets the in-memory backend so the contract is exercised without
requiring a running Qdrant. The Qdrant code path is structurally
identical and is covered by a separate integration test that runs only
when ``MALJAN_QDRANT_URL`` is set.
"""

from __future__ import annotations

from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import StoredCase, build_stored_case


def _case(
    sample_id: str,
    *,
    techniques: list[str] | None = None,
    corroborated: int = 0,
    errors: bool = False,
) -> StoredCase:
    techniques = techniques or []
    return StoredCase(
        sample_id=sample_id,
        summary_text=f"summary for {sample_id}",
        technique_ids=techniques,
        corroborated_count=corroborated,
        total_techniques=len(techniques),
        has_analyst_errors=errors,
    )


class TestPurgeLowQuality:
    def test_purges_zero_technique_uncorroborated_cases(self) -> None:
        store = InMemoryStore()
        store.store(_case("low", techniques=[], corroborated=0))
        store.store(_case("high", techniques=["T1", "T2", "T3"], corroborated=2))
        assert store.count() == 2

        removed = store.purge_low_quality()
        assert removed == 1
        assert store.count() == 1
        kept = store.retrieve("summary", top_k=5)
        assert {c.sample_id for c in kept} == {"high"}

    def test_keeps_corroborated_low_technique_when_require_uncorroborated(self) -> None:
        store = InMemoryStore()
        store.store(_case("corro", techniques=["T1"], corroborated=2))
        store.store(_case("alone", techniques=["T1"], corroborated=0))

        # With require_uncorroborated=True (the default), the corroborated
        # case stays even though it only has 1 technique.
        removed = store.purge_low_quality()
        assert removed == 1
        assert {c.sample_id for c in store.retrieve("summary", top_k=5)} == {"corro"}

    def test_drops_corroborated_when_require_uncorroborated_disabled(self) -> None:
        store = InMemoryStore()
        store.store(_case("corro", techniques=["T1"], corroborated=2))

        removed = store.purge_low_quality(require_uncorroborated=False)
        assert removed == 1
        assert store.count() == 0

    def test_negative_max_techniques_disables_technique_branch(self) -> None:
        store = InMemoryStore()
        store.store(_case("zero", techniques=[], corroborated=0))
        store.store(_case("err", techniques=["T1", "T2"], corroborated=1, errors=True))

        # max=-1 disables the technique branch; analyst errors still purge.
        removed = store.purge_low_quality(max_total_techniques=-1)
        assert removed == 1
        assert {c.sample_id for c in store.retrieve("summary", top_k=5)} == {"zero"}

    def test_include_analyst_errors_flag_can_be_disabled(self) -> None:
        store = InMemoryStore()
        store.store(_case("err", techniques=["T1", "T2"], corroborated=1, errors=True))
        # Even with errors=True, leaving include_analyst_errors=False keeps
        # the case (it has 2 techniques and 1 corroboration so the
        # technique branch also passes).
        removed = store.purge_low_quality(include_analyst_errors=False)
        assert removed == 0
        assert store.count() == 1

    def test_purge_is_idempotent(self) -> None:
        store = InMemoryStore()
        store.store(_case("low", techniques=[], corroborated=0))
        store.purge_low_quality()
        # Second call has nothing left to remove.
        assert store.purge_low_quality() == 0


class TestBuildStoredCaseQualitySignals:
    """build_stored_case should propagate the audit quality signals."""

    def test_propagates_quality_signals_from_kwargs(self) -> None:
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="ransomware behavior",
                    evidence_ref="file:hash",
                    technique_id="T1486",
                    confidence=0.9,
                )
            ],
            dissent_items=[],
        )
        case = build_stored_case(
            sample_id="abc",
            isr_reports={"static": isr},
            corroborated_count=3,
            total_techniques=5,
            has_analyst_errors=True,
        )
        assert case.corroborated_count == 3
        assert case.total_techniques == 5
        assert case.has_analyst_errors is True

    def test_defaults_total_techniques_from_collected_ids(self) -> None:
        from maljan.schemas.isr_models import AgentISR, ClaimEvidence

        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="c1",
                    evidence_ref="e1",
                    technique_id="T1059.001",
                    confidence=0.8,
                ),
                ClaimEvidence(
                    claim="c2",
                    evidence_ref="e2",
                    technique_id="T1027",
                    confidence=0.8,
                ),
            ],
            dissent_items=[],
        )
        case = build_stored_case(sample_id="abc", isr_reports={"static": isr})
        # total_techniques defaults to len(technique_ids) when not given.
        assert case.total_techniques == 2
        assert case.corroborated_count == 0
        assert case.has_analyst_errors is False
