"""One tool call a job made, kept so the report's citations resolve.

A report section says which ledger entries it was built from; this table is
what those ids point at. Rows hang off the job rather than the report because
a run that failed before the report assembled still made the calls, and the
calls are the part worth keeping.

The application only ever inserts rows and deletes a job's whole ledger on a
re-run; nothing in the database enforces that, but each row carries a digest
and a chain value, so a changed, removed or reordered row is found by
recomputing the chain (``app.services.ledger_chain``). What it does enforce is
that a job holds each ``entry_id`` and each ``seq`` once, so a citation
resolves to one call. ``seq`` is the order the ids were issued in across the
whole job, and it is the ordering key: agent
names cannot separate calls that two analysts made in parallel.
``created_at`` is the moment the call returned, derived from ``started_at``
and ``duration_ms`` when the row is built; a call the recorder never stamped
falls back to the write time, which is the whole batch's and says only that.
"""

import uuid
from typing import Any

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.base import TimestampMixin, UUIDPrimaryKeyMixin


class EvidenceEntry(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "evidence_entries"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # The citation string the model was shown and the report quotes, e.g.
    # ``ev_0007``.
    entry_id: Mapped[str] = mapped_column(String(32), nullable=False)
    stage: Mapped[str] = mapped_column(String(32), nullable=False, default="analysis")
    agent: Mapped[str] = mapped_column(String(100), nullable=False)
    # The tool server the tool came from; NULL for an in-process tool.
    server: Mapped[str | None] = mapped_column(String(100), nullable=True)
    tool: Mapped[str] = mapped_column(String(200), nullable=False)

    ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # The failure text when ``ok`` is false, and what the tool said would make
    # the next call succeed, when it said (``maljan.tools.errors``).
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # How long the call waited for a free slot at its server before it was
    # sent; ``duration_ms`` runs from the moment it was sent. The chain digest
    # seals it when non-zero.
    waited_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    seq: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    args: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    # Whether the model's arguments were truncated and were closed off before
    # the call ran, and what it wrote before they were
    # (``maljan.agents.evidence_recorder``).
    args_repaired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    args_raw: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The model whose turn asked for the call, as ``provider/model``; NULL
    # where nothing named it, including every row written before the column.
    model: Mapped[str | None] = mapped_column(String(300), nullable=True)
    # Text, not String(n): a decompilation runs to thousands of characters, and
    # no per-answer cap stands in front of it. What is stored is the text the
    # model was handed, or empty with ``truncated`` once the agent's byte
    # budget was spent (schemas.evidence).
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    structured: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    # The function index's exception-directory ranges, by function start,
    # kept beside its answer for evidence roots (``maljan.analysis.evidence_roots``);
    # never part of the answer. NULL on every other entry and every older row.
    function_ranges: Mapped[Any | None] = mapped_column(JSONB, nullable=True)

    # Whether the output was dropped because the agent's byte budget was
    # spent. It is the only thing that says so: a failed call also has an
    # empty output, and a reader that infers the trim from the emptiness
    # states a cause that did not happen.
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # The characters the tool-output guardrail cut from the answer before the
    # model read it; such an entry keeps what the model read and is
    # ``truncated``. Zero for an answer stored whole and every older row.
    chars_dropped: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    # The id of the earlier identical call this one was answered from, when
    # the repeat suppressor served it rather than running the tool again.
    repeated_of: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # A human label for what the call was aimed at, parsed out of the
    # arguments by the recorder — a function name, an address, a host.
    symbol: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Unix timestamp the call started at. With ``duration_ms`` it places the
    # call on the run's clock, which ``created_at`` cannot: that is written
    # when the row is persisted, long after the call happened.
    started_at: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Where the tool's declaration lives, what it declared about the answer,
    # the reputation record, and the operator's pack step, each as the entry
    # recorded it when it was written (``maljan.schemas.evidence.LedgerEntry``).
    # NULL where the entry carried none and on every row older than the
    # columns: absent, never false or empty.
    source: Mapped[str | None] = mapped_column(String, nullable=True)
    facts: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    reputation: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    pack_step: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    # True when ``structured`` is the server's own structured answer beside a
    # prose text; NULL otherwise, the rule the entry's dump keeps.
    structured_from_server: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # The role and console tab the calling agent's definition declared.
    agent_role: Mapped[str | None] = mapped_column(String, nullable=True)
    agent_tab: Mapped[str | None] = mapped_column(String, nullable=True)
    # Where the parts of the answer this row does not keep whole are kept
    # whole in object storage (``maljan.schemas.evidence_spill``): one
    # reference per part with the object key, the byte length and the SHA-256,
    # or the reason the upload failed. NULL where nothing was taken and on
    # every row older than the column.
    spilled: Mapped[Any | None] = mapped_column(JSONB, nullable=True)
    # The row's place in the job's hash chain (``app.services.ledger_chain``):
    # the SHA-256 of every column above in canonical form, and the chain value
    # after it, the SHA-256 of the previous row's chain value and this digest
    # in ``seq`` order. NULL on every row written before sealing existed.
    digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint("job_id", "entry_id", name="uq_evidence_entries_job_entry_id"),
        UniqueConstraint("job_id", "seq", name="uq_evidence_entries_job_seq"),
    )

    def __repr__(self) -> str:
        return f"<EvidenceEntry {self.entry_id} {self.agent}/{self.tool} ok={self.ok}>"
