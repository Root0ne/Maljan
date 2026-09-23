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
    # Whether the output was dropped to keep the agent inside its byte budget.
    # It is the only thing that says so, and a reader has to say it from this
    # rather than from an empty ``output``: a failed call is empty too.
    truncated: bool = False
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


class EvidenceListResponse(BaseModel):
    """One page of a job's ledger, in the order the calls were made."""

    job_id: uuid.UUID
    entries: list[EvidenceEntryResponse]
    total: int
    page: int
    page_size: int
