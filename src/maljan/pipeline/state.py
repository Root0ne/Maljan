"""Analysis state schema for the LangGraph workflow.

The state uses agent-keyed dicts (reports, isr_reports) instead of hardcoded
per-agent fields. Adding a new agent does NOT require any schema change.
"""

import operator
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field

from maljan.schemas.isr_models import AgentISR


class AgentArgument(BaseModel):
    """A single argument or finding raised by an agent during negotiation."""

    agent_name: str = Field(..., description="Name of the agent submitting the argument")
    finding: str = Field(..., description="The main finding or rebuttal")
    confidence_score: float = Field(0.0, description="Confidence of this specific argument (0-1)")


def _merge_dicts[V](left: dict[str, V], right: dict[str, V]) -> dict[str, V]:
    """LangGraph reducer: shallow merge; right keys overwrite left."""
    merged: dict[str, V] = {**left}
    merged.update(right)
    return merged


class AnalysisState(TypedDict):
    """State dictionary passed between all nodes in the LangGraph workflow."""

    # Sample metadata
    file_hash: str
    file_name: str | None
    sample_path: str | None
    sandbox_report: dict[str, Any] | None

    # Wave 4 (2026-05-28): file_type + canonical platform inferred at
    # pipeline bootstrap. Consumed by the Sigma/YARA scan helpers in the
    # judge node (filter out platform-incompatible rules) and the TTP
    # cascade (drop platform-mismatched techniques). Optional because
    # legacy state dicts persisted before Wave 4 don't carry them.
    file_type: str | None
    platform: str | None

    # Wave 6 (2026-05-28, GHIDRA-DELIVERY-01): the container-visible path
    # at which the static analyst's Ghidra MCP server can read the sample.
    # The worker mirrors the MinIO download into ``data/samples/`` (host)
    # which the Ghidra container sees through its bind mount at
    # ``/data/samples/`` — this field carries the resolved container path
    # so the analyst node can hand the LLM a ``load_program`` argument
    # that actually resolves on the Ghidra side. ``None`` when no host
    # mirror is available (e.g. legacy state or worker-side download
    # failure); the static analyst then short-circuits to a zero-claim
    # ISR via the existing PIPE-ANA-01 guard.
    static_sample_path: str | None

    # Per-agent text reports
    reports: Annotated[dict[str, str], _merge_dicts]
    revised_reports: Annotated[dict[str, str], _merge_dicts]

    # Per-agent structured ISR reports
    isr_reports: Annotated[dict[str, AgentISR], _merge_dicts]

    # Mediator/argument log (append-only)
    discussion_history: Annotated[list[AgentArgument], operator.add]

    # Sycophancy detection flag for the latest negotiation round
    sycophancy_detected: bool

    # Per-round mean-confidence values for adaptive termination
    confidence_history: Annotated[list[float], operator.add]

    # Iteration tracking
    iteration_count: int
    is_consensus: bool

    # Final output
    final_decision: Literal["Malware", "Benign", "Suspicious"] | None
    judge_report: str | None
    stix_output: dict[str, Any] | None

    # Observability: serialized RunSummary dict, populated after verdict generation.
    run_summary: dict[str, Any] | None

    # Comprehensive malware analysis report produced by ``report_node`` after
    # the judge verdict. Stays ``None`` if the reporting feature is disabled
    # (``config.reporting.enabled = False``) — downstream consumers fall back
    # to the legacy ``judge_report`` / ``stix_output`` pair.
    malware_report: dict[str, Any] | None
    malware_report_markdown: str | None
    stix_bundle_extended: dict[str, Any] | None

    # CONF-INFL-01 (2026-05-19 audit): flag set by the judge node when a
    # run produced TTPs but zero LLM analyst corroboration, or when one
    # or more analyst reports are tagged ``[ERROR]``. Consumers (report
    # node + dashboard) cap ``overall_confidence`` and surface a clear
    # "degraded" indicator instead of displaying the inflated cascade-
    # only confidence as if it were a fully corroborated verdict.
    degraded_mode: bool
    degradation_reasons: list[str]

    # Sandbox CTI block surfaced by the judge node when the active sandbox
    # client (currently TriageClient) synthesised ``report["cti"]``.
    # Consumed by the report node to embed the deterministic threat-intel
    # snapshot under ``stix_bundle_extended["x_maljan_cti"]``.
    sandbox_cti: dict[str, Any] | None

    # F10 (2026-07-05): attribution side-channels written by the judge node
    # (``make_judge_node``) and read back by the report node to populate
    # ``FamilyAttribution.function_hash_matches`` / ``family_rag_candidates``
    # / ``attck_case_candidates``. These MUST be declared channels — a
    # ``StateGraph(AnalysisState)`` only persists keys present in this
    # TypedDict, so an undeclared write is dropped between nodes and the
    # report node's ``state.get(...)`` always saw ``[]`` (silent data loss
    # on enriched runs with real function-hash / RAG overlap).
    function_hash_matches: list[dict[str, Any]]
    family_rag_candidates: list[dict[str, Any]]
    attck_case_candidates: list[dict[str, Any]]
