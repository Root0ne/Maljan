"""Response shapes for a job's evidence ledger."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


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

    @field_validator("args_repaired", "truncated", mode="before")
    @classmethod
    def _absent_is_false(cls, value: Any) -> bool:
        """A row written before the column existed made an ordinary call."""
        return bool(value)

    @field_validator("chars_dropped", mode="before")
    @classmethod
    def _absent_is_zero(cls, value: Any) -> int:
        """A row written before the column existed recorded no cut."""
        return int(value or 0)


class EvidenceListResponse(BaseModel):
    """One page of a job's ledger, in the order the calls were made."""

    job_id: uuid.UUID
    entries: list[EvidenceEntryResponse]
    total: int
    page: int
    page_size: int
