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
    status: str = Field(
        default="complete",
        description=(
            "``complete`` | ``failed`` | ``timeout``. Whether this contribution "
            "was actually produced. A mediation that *errored* and one where the "
            "agents simply did not converge both leave ``is_consensus=False`` "
            "with a 0.0 confidence, and until this field existed the only thing "
            "telling them apart anywhere in the system was the literal prefix "
            "'[ERROR] Mediation ' inside ``finding`` — sniffed independently by "
            "the router and by two frontend components. Every stored run in the "
            "database was an errored mediation presented as a calm disagreement."
        ),
    )


def _merge_dicts[V](left: dict[str, V], right: dict[str, V]) -> dict[str, V]:
    """LangGraph reducer: shallow merge; right keys overwrite left."""
    merged: dict[str, V] = {**left}
    merged.update(right)
    return merged


def _merge_counts(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    """LangGraph reducer for a per-code counter: add, never replace."""
    merged = dict(left)
    for key, value in right.items():
        merged[key] = merged.get(key, 0) + int(value)
    return merged


def _merge_stage_results(
    left: dict[str, dict[str, Any]], right: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """LangGraph reducer for ``stage_results``: merge per stage, not per key.

    A parallel analysis stage is several nodes and each of them writes the
    stage it belongs to, so a plain shallow merge would record whichever agent
    LangGraph happened to finish last and throw the rest away. The counts add
    up, the agent and technique lists union, and ``ran`` is true when any node
    of the stage ran — which is what "did this stage happen" means for a stage
    of three analysts, one of which had no data.
    """
    merged: dict[str, dict[str, Any]] = {k: dict(v) for k, v in left.items()}
    for key, entry in right.items():
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(entry)
            continue
        agents = list(dict.fromkeys([*existing.get("agents", []), *entry.get("agents", [])]))
        # Per-agent skip reasons: each member of a parallel stage writes its
        # own, so they merge rather than the last writer winning.
        agent_reasons = {
            **(existing.get("agent_reasons") or {}),
            **(entry.get("agent_reasons") or {}),
        }
        techniques = list(
            dict.fromkeys([*existing.get("technique_ids", []), *entry.get("technique_ids", [])])
        )
        merged[key] = {
            **existing,
            **entry,
            "ran": bool(existing.get("ran")) or bool(entry.get("ran")),
            "reason": entry.get("reason") or existing.get("reason") or "",
            "claim_count": int(existing.get("claim_count") or 0)
            + int(entry.get("claim_count") or 0),
            "finding_count": int(existing.get("finding_count") or 0)
            + int(entry.get("finding_count") or 0),
            # A chain's nodes each took their turn, so their times add up; a
            # fan-out's ran at once, so the stage took as long as its slowest
            # member. Summing a parallel stage reported three times the wall
            # clock the operator watched.
            "duration_ms": (
                max(int(existing.get("duration_ms") or 0), int(entry.get("duration_ms") or 0))
                if str(entry.get("mode") or existing.get("mode") or "") == "parallel"
                else int(existing.get("duration_ms") or 0) + int(entry.get("duration_ms") or 0)
            ),
            "agents": agents,
            **({"agent_reasons": agent_reasons} if agent_reasons else {}),
            "technique_ids": techniques,
        }
    return merged


class AnalysisState(TypedDict):
    """State dictionary passed between all nodes in the LangGraph workflow."""

    # Sample metadata
    file_hash: str
    file_name: str | None
    sample_path: str | None
    sandbox_report: dict[str, Any] | None

    # file_type + canonical platform inferred at pipeline bootstrap. Read by
    # the report's identity block and the FP linter's platform checks.
    # Optional because legacy state dicts persisted earlier don't carry them.
    file_type: str | None
    platform: str | None

    # The container-visible path
    # at which the static analyst's Ghidra MCP server can read the sample.
    # The worker mirrors the MinIO download into ``data/samples/`` (host)
    # which the Ghidra container sees through its bind mount at
    # ``/data/samples/`` — this field carries the resolved container path
    # so the analyst node can hand the LLM a ``load_program`` argument
    # that actually resolves on the Ghidra side. ``None`` when no host
    # mirror is available (e.g. legacy state or worker-side download
    # failure); the static analyst then short-circuits to a zero-claim
    # ISR via the existing missing-path guard.
    static_sample_path: str | None

    # One container-visible path per static provider a profile
    # uses, keyed by provider id. ``static_sample_path`` above stays exactly
    # what it was — the *globally configured* provider's path, which is what
    # the provider layer's contract promises and what every single-provider run
    # reads — and this is the second and later entries a profile with two
    # static analysts needs. Empty on every default-profile run.
    static_sample_paths: dict[str, str]

    # Where each tool server was handed the sample, when it was handed the
    # bytes rather than a path (``agents.sample_staging``). Written by the
    # analyst nodes from ``ResolvedAgent.path_by_server`` and read by the
    # transcript and the report, so a run against a remote tool server records
    # which path its tools were actually called with. Empty unless a server is
    # reached over HTTP: a stdio sidecar shares this filesystem and is handed
    # the path, so a default-profile run populates nothing here.
    remote_sample_paths: Annotated[dict[str, str], _merge_dicts]

    # Per-agent text reports
    reports: Annotated[dict[str, str], _merge_dicts]
    revised_reports: Annotated[dict[str, str], _merge_dicts]

    # Per-agent structured ISR reports
    isr_reports: Annotated[dict[str, AgentISR], _merge_dicts]

    # Every tool call the run made, in the order the ids were issued. Written
    # by the analyst nodes from ``agent.drain_evidence_entries()`` and read
    # by ``report_node``, which builds the report's sections out of it and
    # attaches the index a reader cites. Append-only: two analysts running in
    # parallel each contribute their own calls and neither overwrites the
    # other. Each value is a ``LedgerEntry`` model dump.
    evidence_ledger: Annotated[list[dict[str, Any]], operator.add]

    # The same calls grouped per agent, in the previous capture shape. Derived
    # from the ledger by the analyst node that wrote it, and kept only while
    # its remaining readers migrate to ``evidence_ledger``.
    tool_evidence: Annotated[dict[str, list[dict[str, Any]]], _merge_dicts]

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

    # Set by ``report_node`` when the deterministic report build raises,
    # instead of populating ``malware_report``. Must be declared here like
    # every other node-to-node channel above — an undeclared key is dropped
    # by ``StateGraph(AnalysisState)`` between nodes, which is exactly what
    # happened before this field existed: the worker's failure check always
    # read ``None`` and a pipeline that produced no report was persisted as
    # a quietly successful run.
    report_error: str | None

    # Set by the judge node when a run produced no corroborated technique, or
    # when an analyst failed, or when the sandbox was unreachable. It is put to
    # the judge in the verdict prompt so the confidence it sets already
    # reflects it, and rendered in the report header so a reader sees why.
    degraded_mode: bool
    degradation_reasons: list[str]

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

    # What each analyst was told was wrong with its answer and did not fix,
    # after its one retry (``pipeline.validation``). Per agent, so the run
    # summary can name who; merged rather than appended because an agent that
    # revises replaces its own findings, and never another agent's.
    validation_findings: Annotated[dict[str, list[dict[str, str]]], _merge_dicts]

    # What each stage of the active profile did: whether it ran, why it did
    # not, what it produced and how long it took. Written by every node of
    # every stage and read by the report node for ``run_summary.stages`` and by
    # the conditions of the stages downstream. A dict keyed by stage rather
    # than a list because the writers are concurrent, and merged per stage
    # rather than per key because a parallel stage has several of them.
    stage_results: Annotated[dict[str, dict[str, Any]], _merge_stage_results]

    # What the triage pack established and how it went: the four facts a
    # stage condition reads (``conditions.TriageFacts``), the entry and
    # failure counts and the wall clock the run summary reports, and the
    # degradation reasons the judge carries forward. Written once by the
    # triage node; empty on a run whose team has no triage stage.
    triage_facts: dict[str, Any]

    # Which analysts had their final-answer nudge sent another way than the
    # plain one, and which way. Written by the analyst nodes, merged per agent,
    # read by the judge into ``run_summary.nudge``.
    nudge_retry_modes: Annotated[dict[str, str], _merge_dicts]

    # How many feedback retries the run spent, across every producer.
    # Append-only: two analysts running in parallel each add their own.
    validation_retries: Annotated[int, operator.add]

    # The checks that could not run on this run, by code — the validity
    # check on a box with no ATT&CK catalogue. Append-only; the judge reads
    # the distinct codes into ``run_summary.validation.not_run``.
    validation_not_run: Annotated[list[str], operator.add]

    # Every violation a producer was *shown*, by code. A violation the retry
    # fixed leaves no other trace on the run, and ``by_code`` built from the
    # leftovers alone reported ``{}`` beside a non-zero retry count. Counts
    # add across the analysts that ran in parallel.
    validation_fed_back: Annotated[dict[str, int], _merge_counts]
