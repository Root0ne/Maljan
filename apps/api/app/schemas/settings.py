"""DTOs for the runtime-settings routes.

Kept dumb by design: no logic lives here, just the wire shapes that
``app.api.v1.settings`` maps ``SettingsService`` and catalog objects onto.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CatalogEntryDTO(BaseModel):
    key: str
    namespace: str
    path: str
    type: str
    default: Any = None
    nullable: bool
    choices: list[str] | None = None
    minimum: float | None = None
    maximum: float | None = None
    secret: bool
    group: str
    title: str
    description: str
    applies: str
    editable: bool
    reason: str | None = None
    probe: str | None = None
    applies_when: dict[str, list[str]] | None = None
    order: int = 0
    choices_from: str | None = None
    editor: str | None = None
    subgroup: str | None = None
    advanced: bool = False
    required_env: dict[str, list[str]] | None = None


class GroupDTO(BaseModel):
    key: str
    title: str
    description: str = ""
    entries: list[CatalogEntryDTO]


class SchemaResponse(BaseModel):
    groups: list[GroupDTO]


class ValueDTO(BaseModel):
    value: Any = None
    is_set: bool | None = None
    hint: str | None = None
    source: str
    updated_at: datetime | None = None
    updated_by: uuid.UUID | None = None


class ValuesResponse(BaseModel):
    values: dict[str, ValueDTO]


class PatchRequest(BaseModel):
    changes: dict[str, Any] = Field(min_length=1, max_length=500)


class PatchResponse(BaseModel):
    applied: list[str]
    applies: dict[str, int]
    # Advisory, keyed by the same dotted path the 422 errors use. A warning
    # never refuses the write — it is what the console draws on the card the
    # operator was editing, for a configuration that is legal and will not do
    # what they expect.
    warnings: dict[str, str] = Field(default_factory=dict)


class ResetResponse(BaseModel):
    reset: list[str]


class ExportResponse(BaseModel):
    format: str
    exported_at: datetime
    values: dict[str, Any]
    secrets_omitted: list[str] = Field(
        description=(
            "Names of what the export left out: catalog keys whose stored value is a "
            "secret, plus informational paths like "
            "'core.mcp.servers.<name>.auth_token' for a server whose token was dropped "
            "from the core.mcp.servers map. Those nested paths are not catalog keys -- "
            "importing one back as a top-level key is rejected as an unknown key; the "
            "token is restored as the nested auth_token field inside the map instead."
        )
    )


class ImportRequest(BaseModel):
    format: str
    values: dict[str, Any] = Field(default_factory=dict)


class ProbeRequest(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)


class ProbeResponse(BaseModel):
    ok: bool
    latency_ms: int
    detail: str
    models: list[str] | None = None
    # the server's whole manifest, so the editor can render it as tick boxes
    tools: list[str] | None = None
    # Structured, probe-specific facts the generic renderer ignores and a
    # dedicated editor reads. The agent probe is the first user: a prompt hash
    # and a per-server status do not fit in a sentence.
    details: dict[str, Any] | None = None


class ContextWindowResponse(BaseModel):
    """The window the configured models serve, and what it buys one answer.

    ``source`` is one of four words an operator can act on: ``declared`` (the
    settings name it), ``probed`` (the server reported it), ``table`` (the
    vendored figure for this model family) and ``fallback`` (nothing answered).
    ``detail`` says the same thing in a sentence. ``cap`` is what one tool
    answer may take on an empty conversation, which is the most it can be;
    ``derived`` is false when the operator set the cap themselves, and ``cap``
    is then their number and the window decides nothing. Where the window is
    ``fallback`` nothing is derived from it either — ``cap`` is the documented
    constant and ``remedy`` names the setting that would change that.
    """

    tokens: int
    source: str
    detail: str
    chars_per_token: int
    reply_tokens: int
    answer_share: float
    cap: int
    derived: bool
    setting: int
    remedy: str = ""


class VirustotalRegisterResponse(BaseModel):
    """The VirusTotal server as it stands after a registration.

    The token is never part of it: ``auth_token`` carries the same mask the
    server map shows for a stored credential, so the console can render "set
    from the UI" without the value ever reaching a browser. The agent id and
    the public handle are VirusTotal's own names for this deployment, which is
    what an operator matches against their VirusTotal account.
    """

    server: str
    enabled: bool
    transport: str
    url: str
    auth_token: str
    agent_id: str
    public_handle: str
    tools: list[str] | None = None


class MappingPreviewRequest(BaseModel):
    sample: dict[str, Any]
    mapping: dict[str, Any]


class ConditionValidateRequest(BaseModel):
    """One stage's ``when`` expression, as the operator has typed it so far."""

    expression: str = Field("", max_length=2000)


class ConditionValidateResponse(BaseModel):
    """Everything wrong with the expression. An empty list means it is fine."""

    valid: bool
    problems: list[str]


class TeamLintRequest(BaseModel):
    """The teams as the editor has staged them. A field left out is read from the store."""

    profiles: dict[str, Any] | None = None
    definitions: dict[str, Any] | None = None
    profile: str | None = None


class TeamFindingDTO(BaseModel):
    """One lint finding. ``path`` is the dotted key a save refusal would use."""

    severity: str
    code: str
    message: str
    team: str | None = None
    stage: str | None = None
    field: str | None = None
    agent: str | None = None
    path: str


class TeamNodeDTO(BaseModel):
    key: str
    label: str
    kind: str
    agents: list[str]
    when: str
    reads: str
    mode: str
    row: int
    column: int


class TeamEdgeDTO(BaseModel):
    source: str
    target: str
    implicit: bool
    legal: bool


class TeamGraphDTO(BaseModel):
    nodes: list[TeamNodeDTO]
    edges: list[TeamEdgeDTO]
    rows: int
    columns: int


class TeamLintResponse(BaseModel):
    """Every finding, errors first, and each team laid out for the preview."""

    findings: list[TeamFindingDTO]
    graphs: dict[str, TeamGraphDTO]


class ChannelPreview(BaseModel):
    matched: int
    kept: int
    dropped: int
    truncated: bool = False
    sample_rows: list[Any]
    error: str | None = None


class MappingPreviewResponse(BaseModel):
    target_sha256: str
    channels: dict[str, ChannelPreview]
