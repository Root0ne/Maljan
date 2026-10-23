"""Long-Term Memory abstractions for Maljan.

Defines the StoredCase dataclass and the MemoryStore Protocol that all
backend implementations must satisfy. The Protocol is runtime-checkable so
isinstance() guards in tests and container code work without importing concrete
backends.

Design goals:
  - Zero external dependencies in this module (importable everywhere).
  - Protocol-based: swappable backends without changing caller code.
  - StoredCase captures all signals needed for few-shot retrieval: the
    free-text summary (used for similarity search), extracted technique IDs
    (for TTP-level deduplication), the malware category the judge assessed,
    and the full STIX bundle JSON (for future cross-case correlation).

MemoryStore.retrieve() contract:
  - Returns at most top_k cases ordered by descending relevance score.
  - Returns [] when the store is empty or query is blank.
  - Never raises on empty store — callers do not need to guard.

MemoryStore.store() contract:
  - Upserts by sample_id: storing the same sample_id twice replaces the
    older entry. This prevents the store from growing unboundedly during
    repeated analysis runs on the same sample.

Helper build_stored_case():
  - Convenience factory that creates a StoredCase from pipeline artifacts
    (ISR reports dict + STIX Bundle JSON string). Callers (app.py, nodes.py)
    use this after give_verdict() to persist results without manual field
    construction.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from maljan.analysis.technique_ids import TECHNIQUE_ID_EXACT_RE

if TYPE_CHECKING:
    from maljan.memory.function_hash_store import FunctionMatch
    from maljan.schemas.isr_models import AgentISR


# ---------------------------------------------------------------------------
# StoredCase — unit of long-term memory
# ---------------------------------------------------------------------------


@dataclass
class StoredCase:
    """A single persisted analysis result for long-term retrieval.

    Attributes:
        sample_id:          Unique identifier for the analysed sample.
        summary_text:       Free-text representation used for similarity
                            search. Should include claim text, evidence
                            references, and technique descriptions.
        technique_ids:      ATT&CK technique IDs found in this analysis.
        malware_category:   Inferred malware category string from SchemaPruner
                            (e.g. "RANSOMWARE", "RAT", "UNKNOWN").
        stix_bundle_json:   JSON-serialized STIX 2.1 Bundle for this sample.
        created_at:         UTC timestamp of when this case was stored.
        corroborated_count: How many TTPs were corroborated across multiple
                            analysts at write time. Persisted so retroactive
                            quality purges can identify low-signal runs even
                            after the write-time quality gate.
        total_techniques:   Total distinct technique_ids recorded for this run.
        has_analyst_errors: Whether any analyst returned an ``[ERROR]`` prefix
                            during this analysis. Strong indicator of a
                            degraded pipeline pass.
        owner:              Whose job wrote the case (``memory_owner``), or
                            ``None`` for an unscoped write: a run with no
                            owner, and every case stored before owners were
                            recorded. See :func:`recall` for who reads it.
    """

    sample_id: str
    summary_text: str
    technique_ids: list[str] = field(default_factory=list)
    malware_category: str = "UNKNOWN"
    stix_bundle_json: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    corroborated_count: int = 0
    total_techniques: int = 0
    has_analyst_errors: bool = False
    owner: str | None = None


# ---------------------------------------------------------------------------
# MemoryStore Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class MemoryStore(Protocol):
    """Backend-agnostic interface for long-term case memory.

    All concrete implementations (InMemoryStore, QdrantStore) must satisfy
    this Protocol, and every caller builds one through
    ``maljan.memory.store_factory.build_memory_store``. A caller never asks
    which backend it holds: what a backend cannot do it says through this
    interface (``function_hash_store`` answering ``None``); a backend derives
    from ``MemoryStoreDefaults`` for those answers. The
    @runtime_checkable decorator enables isinstance() checks in tests and
    container code.

    Implementations:
        InMemoryStore  -- pure-Python cosine similarity (no infra required)
        QdrantStore    -- Qdrant vector database (requires Docker + qdrant-client)
    """

    def store(self, case: StoredCase) -> None:
        """Persist a case. Upserts by sample_id (replaces existing entry)."""
        ...

    def retrieve(
        self,
        query: str,
        top_k: int = 3,
        exclude_sample_id: str | None = None,
    ) -> list[StoredCase]:
        """Return the top_k most similar stored cases for the given query.

        A backend that keeps owners (``keeps_owners``) also takes ``owner``
        and answers only that owner's cases; called without it, only the
        unscoped ones. Callers go through :func:`recall`.

        Args:
            query:  Free-text search query (typically the ISR summary text).
            top_k:  Maximum number of cases to return. May return fewer when
                    the store contains fewer than top_k entries.
            exclude_sample_id: Optional sha256 to filter out; prevents a
                sample's prior run from being injected as a "weighted
                prior" for itself.

        Returns:
            List of StoredCase objects, ordered by descending relevance.
            Empty list when store is empty or query is blank.
        """
        ...

    def count(self) -> int:
        """Return the number of cases currently in the store."""
        ...

    def clear(self) -> None:
        """Remove all stored cases. Primarily used in tests."""
        ...

    def purge_low_quality(
        self,
        *,
        max_total_techniques: int = 1,
        require_uncorroborated: bool = True,
        include_analyst_errors: bool = True,
        dry_run: bool = False,
    ) -> int:
        """Delete stored cases that fall below the write-time quality gate.

        A case is considered low-quality (and therefore purged) when **any**
        of the following hold:

        - ``total_techniques <= max_total_techniques`` (default 1) AND
          ``corroborated_count == 0`` if ``require_uncorroborated`` is True.
        - ``has_analyst_errors`` is True (a pipeline pass with any
          ``[ERROR]`` analyst output) — when ``include_analyst_errors``.

        Returns the number of cases removed. Implementations should be safe to
        invoke on collections that pre-date the quality-signal payload — older
        points with no ``total_techniques`` field are treated as 0 and so are
        considered low-quality by default. Operators can disable that branch
        by passing ``max_total_techniques=-1``.

        ``dry_run`` counts the cases the same gate would remove and removes
        none of them.
        """
        ...

    def readiness(self) -> str:
        """Say what the store reached, or raise ``MemoryStoreError`` when it cannot.

        A store with no server of its own answers without any I/O. The answer
        is a short phrase for an operator; ``/health`` reports it.
        """
        ...

    def function_hash_store(self) -> FunctionHashIndex | None:
        """The exact-match function-hash store kept beside these cases, or ``None``.

        ``None`` is the backend saying it holds no function hashes; every
        caller then leaves function-hash attribution out, whichever backend
        it is.
        """
        ...

    def close(self) -> None:
        """Release what the store holds open (a client, a connection); a no-op without one."""
        ...


class MemoryStoreDefaults:
    """The interface's optional capabilities, answered as "not offered".

    A backend derives from this and implements what it can: a store with no
    server answers ``readiness`` without I/O, keeps no function hashes, keeps
    no owners and has nothing to close. Every caller then degrades the same
    way for it as for any backend without the capability.
    """

    # Whether the backend files a case under its owner and answers an owner's
    # reads with that owner's cases alone. A backend that does not is never
    # written to nor read from for an owned job (:func:`recall`).
    keeps_owners: bool = False

    def readiness(self) -> str:
        return "in process"

    def function_hash_store(self) -> FunctionHashIndex | None:
        return None

    def close(self) -> None:
        return None

    def case_of(self, sample_id: str, owner: str | None = None) -> StoredCase | None:
        """The case stored for ``sample_id`` (``owner``'s, or the unscoped one), or ``None``.

        Optional: a backend that offers no read by id answers ``None``, and
        no earlier run is shown (:func:`earlier_case`).
        """
        return None


@runtime_checkable
class FunctionHashIndex(Protocol):
    """Exact-match store of per-function opcode hashes keyed to a family.

    One entry per (sample, function hash); a re-analysis replaces the
    sample's entries. Every method degrades to an empty answer on a backend
    error, so attribution never breaks an analysis.
    """

    def upsert_sample(self, sample_id: str, family: str, functions: list[tuple[str, str]]) -> int:
        """Write ``(func_hash, func_name)`` pairs for ``sample_id``; the number written.

        An index that keeps owners (``keeps_owners``) also takes ``owner``.
        """
        ...

    def match(self, hashes: list[str], exclude_sample_id: str | None = None) -> list[FunctionMatch]:
        """Stored functions whose hash is in ``hashes``, other than ``exclude_sample_id``'s.

        An index that keeps owners also takes ``owner``; callers go through
        :func:`match_functions`.
        """
        ...

    def count(self) -> int:
        """The number of stored function hashes."""
        ...


# ---------------------------------------------------------------------------
# Owners: whose memory a job reads and writes
# ---------------------------------------------------------------------------
#
# The rule, for cases and for function hashes alike:
#
# - A job with an owner (``ServiceContainer.memory_owner``) writes under that
#   owner and reads that owner's entries, nobody else's.
# - A job with no owner (the command line, a caller that names none) writes
#   unscoped entries and reads the unscoped ones.
# - An entry stored before owners were recorded carries none, so it cannot be
#   attributed to anyone: it stays in the unscoped pool, readable by unscoped
#   jobs as it always was, and never reaches a job with an owner. A cross-owner
#   read fails closed.
# - A backend that cannot keep owners (``keeps_owners`` false) is neither
#   written to nor read from by a job with an owner.
# - A read with no job behind it (no container) reads nothing (``NO_MEMORY``).


def owner_key(owner: Any) -> str | None:
    """The owner as entries are filed under it, or ``None`` for unscoped."""
    text = str(owner).strip() if owner is not None else ""
    return text or None


def keeps_owners(store: Any) -> bool:
    """Whether ``store`` files entries under their owner and scopes its reads by it."""
    return getattr(store, "keeps_owners", False) is True


class _NoMemory:
    """The owner of a read that has no job to read for: it reads nothing."""

    def __repr__(self) -> str:
        return "NO_MEMORY"


# What ``memory_owner_of`` answers for no container, or one that states no
# owner it can be read as: neither an owner's memory nor the unscoped pool.
NO_MEMORY: Any = _NoMemory()


def memory_owner_of(container: Any) -> Any:
    """The owner whose memory ``container``'s job reads and writes.

    ``None`` for a job that is unscoped (a container whose ``memory_owner``
    is ``None``), and :data:`NO_MEMORY` for no container at all or one whose
    owner is not text: :func:`recall` and :func:`match_functions` read nothing
    for it.
    """
    if container is None:
        return NO_MEMORY
    value = getattr(container, "memory_owner", NO_MEMORY)
    if value is None:
        return None
    return owner_key(value) if isinstance(value, str) else NO_MEMORY


def recall(
    store: Any,
    query: str,
    *,
    top_k: int = 3,
    exclude_sample_id: str | None = None,
    owner: Any = None,
) -> list[StoredCase]:
    """``store.retrieve`` for the job's owner, under the rule above."""
    if owner is NO_MEMORY:
        return []
    scoped = owner_key(owner)
    if scoped is None:
        try:
            cases = store.retrieve(query, top_k=top_k, exclude_sample_id=exclude_sample_id)
        except TypeError:
            # A backend older than ``exclude_sample_id``.
            cases = store.retrieve(query, top_k=top_k)
            if exclude_sample_id:
                cases = [c for c in cases if c.sample_id != exclude_sample_id]
        return [c for c in cases if owner_key(getattr(c, "owner", None)) is None]
    if not keeps_owners(store):
        return []
    cases = store.retrieve(query, top_k=top_k, exclude_sample_id=exclude_sample_id, owner=scoped)
    return [c for c in cases if owner_key(getattr(c, "owner", None)) == scoped]


def match_functions(
    index: Any,
    hashes: list[str],
    *,
    exclude_sample_id: str | None = None,
    owner: Any = None,
) -> list[FunctionMatch]:
    """``index.match`` for the job's owner, under the rule above."""
    if owner is NO_MEMORY:
        return []
    scoped = owner_key(owner)
    if scoped is None:
        return list(index.match(hashes, exclude_sample_id=exclude_sample_id))
    if not keeps_owners(index):
        return []
    return list(index.match(hashes, exclude_sample_id=exclude_sample_id, owner=scoped))


# ---------------------------------------------------------------------------
# An earlier run on this sample: hypotheses, never evidence
# ---------------------------------------------------------------------------
#
# Every similarity read above leaves the sample's own case out
# (``exclude_sample_id``): an earlier run is not prior art for itself. What
# that run reported is still worth checking, so it is read here by the sample's
# sha256, under the same owner rule, and shown to the run's agents as
# hypotheses (:func:`earlier_run_block`). It has no evidence id, so nothing
# cites it and nothing corroborates with it, and the publish rules read this
# run alone: a technique it reported that no source of this run stands behind
# is published or not as it would be without it, with a note saying so
# (``capability_matrix.EARLIER_RUN_UNSUPPORTED_NOTE``).

EARLIER_RUN_HEADING = "=== AN EARLIER RUN ON THIS SAMPLE: hypotheses, not evidence ==="
EARLIER_RUN_END = "=== END EARLIER RUN ==="
EARLIER_RUN_STATEMENT = (
    "An earlier run on this sample (the same sha256) reported what follows. Treat each item "
    "as a hypothesis to check with this run's tools, not as evidence: it has no evidence id, "
    "it cannot be cited, and it corroborates nothing."
)


def earlier_case(store: Any, sample_id: str, *, owner: Any = None) -> StoredCase | None:
    """The case an earlier run stored for ``sample_id``, under the owner rule above, or ``None``.

    Read by the sample's id (``case_of``), never by similarity. ``None`` as
    well for a backend that offers no such read, and for an answer that is not
    the sample's own case of this owner.
    """
    sha = str(sample_id or "").strip()
    if owner is NO_MEMORY or not sha:
        return None
    read = getattr(store, "case_of", None)
    if not callable(read):
        return None
    scoped = owner_key(owner)
    if scoped is None:
        case = read(sha)
    elif keeps_owners(store):
        case = read(sha, owner=scoped)
    else:
        return None
    if not isinstance(case, StoredCase) or case.sample_id != sha:
        return None
    return case if owner_key(case.owner) == scoped else None


def earlier_case_of(container: Any, sample_id: str) -> StoredCase | None:
    """:func:`earlier_case` for ``container``'s job, read once per sample. Never raises.

    Kept on the container (``earlier_cases``) for the length of the job, so
    every agent briefed in it is shown the same case and the store is asked
    once. A store that cannot be built or read is no earlier case.
    """
    sha = str(sample_id or "").strip()
    if container is None or not sha:
        return None
    kept = getattr(container, "earlier_cases", None)
    if isinstance(kept, dict) and sha in kept:
        held = kept[sha]
        return held if isinstance(held, StoredCase) else None
    case: StoredCase | None = None
    try:
        case = earlier_case(container.get_memory_store(), sha, owner=memory_owner_of(container))
    except Exception as exc:  # noqa: BLE001 — memory never costs a run
        from maljan.core.logger import logger

        logger.debug("LTM: the earlier run on this sample was not read (%s).", exc)
    if isinstance(kept, dict):
        kept[sha] = case
    return case


def earlier_techniques(case: StoredCase | None) -> list[str]:
    """The technique ids ``case`` reported, each once, upper-cased, and only technique ids."""
    out: list[str] = []
    for raw in getattr(case, "technique_ids", None) or []:
        tid = str(raw or "").strip().upper()
        if TECHNIQUE_ID_EXACT_RE.fullmatch(tid) and tid not in out:
            out.append(tid)
    return out


def earlier_run_block(case: StoredCase | None) -> str:
    """The earlier run on this sample as its agents are shown it, or ``""`` for none.

    The day it was stored and its technique ids, under a heading that says
    they are hypotheses. Not its summary: that is the earlier run's claims,
    whose evidence ids name that run's ledger, not this one's. Not its
    category: an earlier verdict's word is no hypothesis a tool can check.
    """
    if case is None:
        return ""
    techniques = earlier_techniques(case)
    stored = case.created_at.astimezone(UTC).strftime("%Y-%m-%d")
    return "\n".join(
        [
            EARLIER_RUN_HEADING,
            EARLIER_RUN_STATEMENT,
            f"  Stored: {stored}",
            f"  Earlier techniques: {', '.join(techniques) if techniques else 'none'}",
            EARLIER_RUN_END,
        ]
    )


def earlier_run_text(container: Any, sample_id: str) -> str:
    """:func:`earlier_run_block` of the earlier run on ``container``'s sample. Never raises."""
    return earlier_run_block(earlier_case_of(container, sample_id))


def earlier_run_of(container: Any, sample_id: str) -> Any:
    """The ``EarlierRun`` record of what the agents were shown, or ``None``. Never raises.

    The record the judge's bundle carries (``stix_models.EARLIER_RUN_PROPERTY``),
    from the same case :func:`earlier_run_text` showed.
    """
    case = earlier_case_of(container, sample_id)
    if case is None:
        return None
    from maljan.schemas.stix_models import EarlierRun

    return EarlierRun(
        sample_id=case.sample_id,
        techniques=earlier_techniques(case),
        stored=case.created_at.astimezone(UTC).strftime("%Y-%m-%d"),
    )


# ---------------------------------------------------------------------------
# Family names, as the function-hash corpus files them
# ---------------------------------------------------------------------------

_FAMILY_SEPARATORS = re.compile(r"[\s_\-.]+")


def family_key(name: Any) -> str:
    """One spelling of a family name, for filing and grouping: ``""`` for none.

    The judge writes the family as free text, so one family arrives as
    ``AgentTesla``, ``Agent Tesla`` and ``agent-tesla``. Compatibility-folded,
    case-folded, with spaces, hyphens, underscores and dots taken out.
    """
    text = unicodedata.normalize("NFKC", str(name or "")).casefold().strip()
    return _FAMILY_SEPARATORS.sub("", text)


# ---------------------------------------------------------------------------
# Helper: build_stored_case
# ---------------------------------------------------------------------------


def a_past_case_technique(claim: Any) -> bool:
    """Whether a claim's id is one a later run may be shown as this case's technique.

    Not an id the ATT&CK catalogue lacks, and not one on a claim that reads as
    absence and was kept when asked: a later judge is shown a past case's
    techniques as priors, and a benign run's "does not contain any obvious
    persistence mechanisms" with T1547 would teach it a technique the case said
    was not there. The id stays published in its own run's report; only the
    memory of it is left out.
    """
    return bool(getattr(claim, "technique_id_valid", True)) and not bool(
        getattr(claim, "kept_after_absence_question", False)
    )


def build_stored_case(
    sample_id: str,
    isr_reports: dict[str, AgentISR],
    stix_bundle_json: str = "",
    malware_category: str = "UNKNOWN",
    corroborated_count: int = 0,
    total_techniques: int = 0,
    has_analyst_errors: bool = False,
) -> StoredCase:
    """Build a StoredCase from pipeline artifacts.

    The judge node builds the case once its verdict is read, and holds it on
    the container rather than storing it; the case is written by
    ``ServiceContainer.remember_the_run`` once the job has completed, so a job
    that fails after its judge leaves no case:

        from maljan.memory.long_term_memory import build_stored_case

        container.pending_memory_case = build_stored_case(
            sample_id=sample_id,
            isr_reports=state["isr_reports"],
            stix_bundle_json=bundle.model_dump_json(),
            malware_category=assessed_category,
        )
        ...
        container.remember_the_run()  # after the job is recorded as completed

    The summary_text is constructed by concatenating all claim text, evidence
    references, and technique IDs from every ISR report. This produces a
    rich, keyword-dense string for similarity search.

    Args:
        sample_id:          Identifier for the analysed sample.
        isr_reports:        Dict of agent_name -> AgentISR produced by pipeline.
        stix_bundle_json:   JSON string of the final Bundle (may be empty).
        malware_category:   Inferred malware category from SchemaPruner.

    Returns:
        StoredCase ready to pass to MemoryStore.store().
    """
    technique_ids: list[str] = []
    for isr in isr_reports.values():
        for claim in isr.claims:
            if not claim.technique_id or not a_past_case_technique(claim):
                continue
            if claim.technique_id not in technique_ids:
                technique_ids.append(claim.technique_id)

    summary_text = _case_text(isr_reports, None)

    return StoredCase(
        sample_id=sample_id,
        summary_text=summary_text,
        technique_ids=technique_ids,
        malware_category=malware_category,
        stix_bundle_json=stix_bundle_json,
        corroborated_count=corroborated_count,
        total_techniques=total_techniques or len(technique_ids),
        has_analyst_errors=has_analyst_errors,
    )


def _case_text(isr_reports: Mapping[str, AgentISR], keep: set[str] | None) -> str:
    """The case's search text: every claim, its evidence, and the ids the case keeps.

    ``keep`` ``None`` keeps each id ``a_past_case_technique`` allows; a set
    keeps only the ids in it. The claim's own words stay either way.
    """
    parts: list[str] = []
    for agent_name, isr in isr_reports.items():
        parts.append(f"[{agent_name.upper()}]")
        for claim in isr.claims:
            parts.append(claim.claim)
            if claim.evidence_ref:
                parts.append(claim.evidence_ref)
            tid = str(claim.technique_id or "")
            if not tid or not a_past_case_technique(claim):
                continue
            if keep is None or tid.strip().upper() in keep:
                parts.append(tid)
    return " ".join(parts)


def with_published_techniques(
    case: StoredCase,
    published: Iterable[str],
    isr_reports: Mapping[str, AgentISR] | None = None,
    corroborated: Iterable[str] = (),
) -> StoredCase:
    """``case`` moved to the techniques the run published, in place of the ones claimed.

    The judge builds the case before the report decides what is published;
    the report node hands it the published ids once they are known, so the
    case, the report, the export and ``mitre.json`` count one set. An id every
    claim naming it left out of memory (``a_past_case_technique``) stays out
    although the run published it. The total follows the ids kept, the
    corroborated count is the kept ids ``corroborated`` names (named by more
    than one source), and the search text lists only the kept ids beside the
    claims' own words — the text is what a later run's attribution reads.
    """
    withheld: set[str] = set()
    remembered: set[str] = set()
    for isr in (isr_reports or {}).values():
        for claim in getattr(isr, "claims", None) or []:
            tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
            if not tid:
                continue
            (remembered if a_past_case_technique(claim) else withheld).add(tid)
    kept: list[str] = []
    for raw in published:
        tid = str(raw or "").strip().upper()
        if not TECHNIQUE_ID_EXACT_RE.fullmatch(tid):
            # A tactic id (``TA0005``) or a malformed one is no technique, and
            # a later run must not be shown it as one this case found.
            continue
        if tid not in kept and not (tid in withheld and tid not in remembered):
            kept.append(tid)
    agreed = {str(tid or "").strip().upper() for tid in corroborated}
    return replace(
        case,
        technique_ids=kept,
        total_techniques=len(kept),
        corroborated_count=sum(1 for tid in kept if tid in agreed),
        summary_text=(
            _case_text(isr_reports, set(kept)) if isr_reports is not None else case.summary_text
        ),
    )


def is_thin_case(case: StoredCase) -> bool:
    """Whether a case is too thin to teach a later run.

    Nothing corroborated, and one technique at most.
    """
    return case.corroborated_count == 0 and case.total_techniques <= 1
