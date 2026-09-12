"""Response shapes for a job's evidence ledger."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


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
    duration_ms: int
    seq: int
    args: dict[str, Any] | None = None
    output: str = ""
    structured: Any | None = None
    created_at: datetime | None = None


class EvidenceListResponse(BaseModel):
    """One page of a job's ledger, in the order the calls were made."""

    job_id: uuid.UUID
    entries: list[EvidenceEntryResponse]
    total: int
    page: int
    page_size: int
