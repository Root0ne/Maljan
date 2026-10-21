"""Response shapes for a job's evidence ledger."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _absent(value: Any) -> bool:
    return value is None


class EvidenceEntryResponse(BaseModel):
    """One recorded tool call, as the report's citations name it."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    entry_id: str
    stage: str
    agent: str
    server: str | None = None
    tool: str
    ok: bool
    error: str | None = None
    remediation: str | None = None
    duration_ms: int
    # 0 where the call never queued and on a row written before the column.
    waited_ms: int = 0
    seq: int
    args: dict[str, Any] | None = None
    args_repaired: bool = False
    args_raw: str | None = None
    # The model whose turn asked for the call; ``None`` where nothing named it.
    model: str | None = None
    output: str = ""
    structured: Any | None = None
    # The function index's exception-directory ranges kept beside its answer;
    # ``None`` on every other entry and on a row older than the column.
    function_ranges: Any | None = None
    # Whether the output was dropped to keep the agent inside its byte budget.
    # It is the only thing that says so, and a reader has to say it from this
    # rather than from an empty ``output``: a failed call is empty too.
    truncated: bool = False
    # The characters the tool-output guardrail cut from the answer the model
    # read; 0 for an answer stored whole, and for a row older than the column.
    chars_dropped: int = 0
    # The earlier identical call this one was answered from, the label the
    # recorder parsed out of the arguments, and the run-clock time the call
    # started at. ``None`` where the row predates the columns.
    repeated_of: str | None = None
    symbol: str | None = None
    started_at: float | None = None
    created_at: datetime | None = None
    # The seven fields the entry carries beside the call: where the tool's
    # declaration lives, what it declared about the answer, the reputation
    # record, the operator's pack step, whether ``structured`` is the server's
    # own answer, and the calling agent's role and tab. Each is left out of the
    # response where the row holds none, as the entry's own dump leaves it out,
    # so a row older than the columns reads exactly as it did: absent, never
    # false or empty.
    source: str | None = Field(default=None, exclude_if=_absent)
    facts: dict[str, Any] | None = Field(default=None, exclude_if=_absent)
    reputation: dict[str, Any] | None = Field(default=None, exclude_if=_absent)
    pack_step: dict[str, Any] | None = Field(default=None, exclude_if=_absent)
    structured_from_server: bool | None = Field(default=None, exclude_if=_absent)
    agent_role: str | None = Field(default=None, exclude_if=_absent)
    agent_tab: str | None = Field(default=None, exclude_if=_absent)
    # Where the parts of the answer this entry does not keep whole are kept
    # whole: one reference per part the run shortened, blanked or dropped
    # (``answer``, ``structured_content``, ``output``, ``structured``), each
    # with ``key``, ``bytes`` and ``sha256``, or with ``error`` and no key when
    # the upload failed. Absent where nothing was taken and on an older row.
    # The bytes are served by ``GET /jobs/{id}/evidence/{entry_id}/objects/{part}``.
    spilled: list[dict[str, Any]] | None = Field(default=None, exclude_if=_absent)
    # The row's digest over every column it persists, and the job's chain value
    # after it in ``seq`` order (``app.services.ledger_chain``); with them a
    # reader recomputes the chain from this page alone. Absent on a row written
    # before sealing existed.
    digest: str | None = Field(default=None, exclude_if=_absent)
    chain: str | None = Field(default=None, exclude_if=_absent)

    @field_validator("structured_from_server", mode="before")
    @classmethod
    def _only_true_is_kept(cls, value: Any) -> bool | None:
        """Absent unless it was true, the rule the entry's dump keeps."""
        return True if value is True else None

    @field_validator("args_repaired", "truncated", mode="before")
    @classmethod
    def _absent_is_false(cls, value: Any) -> bool:
        """A row written before the column existed made an ordinary call."""
        return bool(value)

    @field_validator("chars_dropped", "waited_ms", mode="before")
    @classmethod
    def _absent_is_zero(cls, value: Any) -> int:
        """A row written before the column existed recorded no cut and no wait."""
        return int(value or 0)


class LedgerVerificationResponse(BaseModel):
    """What recomputing a job's ledger chain against its seal found (``services.ledger_verify``).

    ``status`` is ``verified``, ``broken``, ``deleted``, ``other_key``, ``unverifiable`` or
    ``not_sealed``;
    ``reason`` says why in a sentence, ``first_broken_seq`` names the first row
    to blame when one is, ``checks`` lists what held and ``notes`` what was not
    checked or holds only weakly.
    """

    job_id: str
    status: str
    reason: str | None = None
    first_broken_seq: int | None = None
    entries: int = 0
    head: str | None = None
    seal: dict[str, Any] | None = None
    amendments: int = 0
    checks: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EvidenceListResponse(BaseModel):
    """One page of a job's ledger, in the order the calls were made."""

    job_id: uuid.UUID
    entries: list[EvidenceEntryResponse]
    total: int
    page: int
    page_size: int
