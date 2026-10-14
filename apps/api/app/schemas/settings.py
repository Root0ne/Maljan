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
    choice_labels: dict[str, str] | None = None
    choice_titles: dict[str, str] | None = None
    choice_descriptions: dict[str, str] | None = None
    choice_facts: dict[str, dict[str, Any]] | None = None
    builtin_servers: list[str] | None = None
    reserved_servers: list[str] | None = None
    capability_servers: dict[str, list[str]] | None = None
    data_source_choices: list[str] | None = None
    agent_keys: list[str] | None = None
    builtin_agent_keys: list[str] | None = None


class GroupDTO(BaseModel):
    key: str
    title: str
    description: str = ""
    entries: list[CatalogEntryDTO]


class SchemaResponse(BaseModel):
    groups: list[GroupDTO]
    # The label of every connection test the API answers, by probe id: the
    # providers' own declarations and the API's own probes.
    probe_labels: dict[str, str] = Field(default_factory=dict)
    # Every post-verdict enrichment source in force, in its declared order:
    # key, label, the indicator kinds it answers, whether it is enabled, the
    # catalog key holding its credential (or whether it holds its own), its
    # server for a server source, and whether it declares a connection test.
    enrichment_sources: list[dict[str, Any]] = Field(default_factory=list)
    # Every tool server in force that declares ``credential_bootstrap``, by
    # key: its label, the family it registers under and its operator note.
    credential_servers: dict[str, dict[str, str]] = Field(default_factory=dict)
    # How a tool declaration's fields split (``core.tool_declarations.
    # declaration_fields``): the word naming no kind, and each kind-free and
    # kind-dependent field with its default, so the console's declaration box
    # applies the API's rules from the API's own list.
    tool_declaration_fields: dict[str, Any] = Field(default_factory=dict)
    # Per block (``mcp.servers.<key>`` or a provider block's path), the tools
    # whose stored change the model refuses over what this release ships
    # (``core.settings_overrides.refused_tool_changes``): each is in force as
    # shipped, and the console marks it for the operator to reset or edit.
    tool_facts_conflicts: dict[str, list[str]] = Field(default_factory=dict)
    # Each stored triage pack step the settings leave out, by id (else
    # ``#<position>``), with why, sanitised
    # (``core.settings_overrides.pack_steps_left_out``): whatever left it out
    # (a step this release cannot run, a reset of the server it calls, a
    # shipped declaration that changed its tool's kind), the shipped step it
    # changed, if any, is in force, and the console marks it on the steps.
    pack_steps_left_out: dict[str, str] = Field(default_factory=dict)
    # Each stored value the settings model refuses (``core.<path>`` -> why),
    # read past here so the page can open and the admin repair it
    # (``core.settings_overrides.stored_settings``, the settings page alone;
    # every read that runs something refuses it): its default is shown
    # until it is saved again or reset, and the console says so beside it.
    stored_values_refused: dict[str, str] = Field(default_factory=dict)


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
    # The MCP probe's harmless calls the admin confirmed, by tool name, after
    # the previous probe listed them (``details.proposals.planned``). Empty:
    # nothing is called. Read by ``/test/mcp`` alone.
    confirmed_calls: list[str] = Field(default_factory=list)


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


class AttckStatusResponse(BaseModel):
    """The cached ATT&CK bundles as the worker that holds them reads them.

    ``domains`` carries, per domain, whether a bundle is cached, its release
    and date, when it was written and how old it is, and when the automatic
    check is next due; ``last_check``, ``last_update`` and ``running`` are
    the worker's record of the console's check and update.
    """

    refresh_days: int
    next_check_at: str | None = None
    domains: list[dict[str, Any]]
    last_check: dict[str, Any] | None = None
    last_update: dict[str, Any] | None = None
    running: dict[str, Any] | None = None


class AttckCheckResponse(BaseModel):
    """One comparison of the cache with MITRE's release index.

    ``outcome`` is ``up_to_date``, ``outdated`` or ``failed``; a failed read of
    the index is never reported as up to date.
    """

    ok: bool
    outcome: str
    reason: str = ""
    checked_at: str | None = None
    refresh_days: int | None = None
    next_check_at: str | None = None
    domains: list[dict[str, Any]] = Field(default_factory=list)


class AttckUpdateStarted(BaseModel):
    job_id: str


class AttckUpdateProgress(BaseModel):
    """Where one update is: ``queued``, ``running``, ``done`` or ``unknown``."""

    job_id: str
    state: str
    result: dict[str, Any] | None = None


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


class EffortOptionsResponse(BaseModel):
    """What a per-agent effort field may offer for one provider and model.

    ``takes_effort`` is false for a provider that sends no reasoning effort,
    and the field is not drawn. ``levels`` is the list to choose from, or
    ``None`` where each endpoint names its own levels and the value is typed
    as the endpoint takes it. ``levels_source`` is ``models_api`` when the
    Anthropic Models API described the model, ``settings`` when the list is
    the setting's own, ``none`` otherwise. ``global_key``/``global_value``
    are the provider-wide setting an unset field inherits.
    ``undescribed_levels`` are offered levels the Models API's description
    said nothing about; the run sends them and the API answers.
    """

    provider: str
    model: str
    takes_effort: bool
    levels: list[str] | None
    undescribed_levels: list[str] = []
    levels_source: str
    global_key: str | None = None
    global_value: str | None = None


class CredentialBootstrapResponse(BaseModel):
    """A tool server as it stands after its credential was obtained.

    The token is never part of it: ``auth_token`` carries the same mask the
    server map shows for a stored credential, so the console can render "set
    from the UI" without the value ever reaching a browser. ``facts`` are the
    answer's values the server's declaration names (an id, a handle): what an
    operator matches against the service's own listing of this deployment.
    """

    server: str
    enabled: bool
    transport: str
    url: str
    auth_token: str
    facts: dict[str, str] = Field(default_factory=dict)
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
