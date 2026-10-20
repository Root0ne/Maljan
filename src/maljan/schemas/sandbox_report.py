"""The neutral sandbox report every sandbox reader produces.

``SandboxReport`` is the one form every consumer reads, whichever sandbox
produced the report: the target and its hashes, the processes and their tree,
the behaviour and API calls, the signatures (with the scale their format
declares), the network flows, DNS and HTTP, the dropped files, the extracted
configurations and payloads, the memory and process dumps, the IDS alerts,
the sections the sandbox cannot produce, and the ``channels`` and ``extras``
for anything with no declared place of its own. The readers that fill it are
registered (``providers.sandbox.readers``); the document every consumer reads
is laid out from it by ``schemas.sandbox_document``.

Every model here is deliberately permissive: ``model_config =
ConfigDict(extra="ignore")`` so an unexpected sandbox field never breaks
ingestion, and every collection defaults to empty rather than ``None`` so a
consumer can iterate a fresh ``SandboxReport()`` without a null check.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidatorFunctionWrapHandler,
    field_validator,
    model_serializer,
)

from maljan.core.legacy_tool_tables import STORED_LINEAGE_MARKER_FORMAT
from maljan.core.report_formats import SignatureScale, reader_display_name
from maljan.schemas.sandbox_document import (
    GROUP_ROWS_KEY,
    kept_source,
)
from maljan.schemas.sandbox_document import (
    SUMMARY_KEYS as _DOCUMENT_SUMMARY_KEYS,
)


def _int(value: Any) -> int:
    """Best-effort int coercion; malformed sandbox data becomes ``0``, never a crash."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _rows(value: Any) -> list[dict[str, Any]]:
    """Keep only the dict entries of a possibly-mixed sandbox-report array."""
    return [row for row in _list(value) if isinstance(row, dict)]


def _list(value: Any) -> list[Any]:
    """``value`` when it is a list, else nothing: a block of the wrong shape holds no rows."""
    return value if isinstance(value, list) else []


def _as_str_list(value: Any) -> list[str]:
    """Coerce a sandbox field that is sometimes a list, sometimes a scalar, to ``list[str]``."""
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value else []


def _dict_identity_or_validate(value: Any, handler: ValidatorFunctionWrapHandler) -> dict[str, Any]:
    """Return ``value`` unchanged when it is already a dict; otherwise validate normally.

    This is the narrow fix a bare ``SkipValidation[dict[str, Any]]`` does not
    give: a source's own blocks are held by identity (a report's ``raw``, the
    parts a reader keeps as published), but ``SkipValidation`` accepts
    *anything* — a string, a list, ``None`` — and would hand it on as if it
    were a report. A dict still passes through untouched (same object, no
    pydantic-core rebuild); anything else still goes through the ordinary
    ``dict[str, Any]`` validator and still raises ``ValidationError``.
    """
    if isinstance(value, dict):
        return value
    return cast("dict[str, Any]", handler(value))


def _without_empty(
    model: BaseModel, handler: SerializerFunctionWrapHandler, fields: tuple[str, ...]
) -> Any:
    """The model's dump without the ``fields`` that hold nothing.

    The places a reader fills only for some sandboxes: a report stored before
    they existed, and a report from a reader that never fills them, dump as
    they always did.
    """
    dumped = handler(model)
    if isinstance(dumped, dict):
        for name in fields:
            if name in dumped and not dumped[name]:
                del dumped[name]
    return dumped


class SandboxTarget(BaseModel):
    """The sample identity a sandbox detonated."""

    model_config = ConfigDict(extra="ignore")

    sha256: str = ""
    md5: str = ""
    name: str = ""
    file_type: str = ""
    mime_type: str = ""
    size: int = 0
    # The other digests a sandbox computed for the sample, where it says.
    sha1: str = ""
    sha512: str = ""
    ssdeep: str = ""

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("sha1", "sha512", "ssdeep"))


class SandboxProcess(BaseModel):
    """One process in the sandbox's flat process list (parent/child ids only)."""

    model_config = ConfigDict(extra="ignore")

    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    first_seen: str = ""
    calls: list[dict[str, Any]] = Field(default_factory=list)
    # The fields the sandbox wrote on the process that the fields above do not
    # hold, under the sandbox's own names: read, never dropped.
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("extra",))


class SandboxSignatureRow(BaseModel):
    """One sandbox signature hit, marks carried through unprocessed."""

    model_config = ConfigDict(extra="ignore")

    name: str = ""
    description: str = ""
    # ``None`` where the sandbox gave a severity no number or declared rung
    # reads (its word is then kept in ``extra``): unknown, never 0.
    severity: int | None = 0
    marks: list[Any] = Field(default_factory=list)
    ttp_tags: list[str] = Field(default_factory=list)
    # The signature's other fields, under the sandbox's own names.
    extra: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("extra",))


class SandboxDnsRequest(BaseModel):
    """One DNS request a sandbox recorded asking one or more names: the structural form.

    A reader that saw one DNS message ask several names fills one of these (in
    ``SandboxNetwork.dns_requests``) rather than writing a row per name and
    linking them itself: the document's one chokepoint
    (``schemas.sandbox_document.dns_rows``) writes the request's rows, the
    request's answers and other fields once on its first name's row, and mints
    the links between them. Each name then reads the answers for its own name
    and alias chain, and every answer that names no name
    (``schemas.sandbox_document.DnsAnswers``), so a request grouped wrongly can
    never credit a named answer to another name.

    ``questions`` holds each asked name as its row's own fields (``request``,
    the name, and ``type``, the record type asked for); ``answers`` the
    request's answers as the reader writes them (each ``data``, and the
    ``name`` it answers and its ``type`` where the sandbox says); ``extra`` the
    request's other fields.
    """

    model_config = ConfigDict(extra="ignore")

    questions: list[dict[str, Any]] = Field(default_factory=list)
    answers: list[Any] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class SandboxNetwork(BaseModel):
    """Network IOC rows, carried through close to their sandbox shape.

    ``domains`` is ``list[str | dict[str, Any]]`` rather than a strict
    ``list[dict]`` because a CAPE report emits both shapes for that one array
    (a bare hostname string, or a ``{"domain": ...}`` row).
    """

    model_config = ConfigDict(extra="ignore")

    dns: list[dict[str, Any]] = Field(default_factory=list)
    http: list[dict[str, Any]] = Field(default_factory=list)
    tcp: list[dict[str, Any]] = Field(default_factory=list)
    udp: list[dict[str, Any]] = Field(default_factory=list)
    hosts: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[str | dict[str, Any]] = Field(default_factory=list)
    tls: list[dict[str, Any]] = Field(default_factory=list)
    # ICMP is rarer than the rest and is exactly why it is modelled: a sample
    # whose only outbound traffic is an ICMP probe used to render as a sample
    # with no network activity at all.
    icmp: list[dict[str, Any]] = Field(default_factory=list)
    pcap_local_path: str | None = None
    # The DNS requests a reader expresses structurally (:class:`SandboxDnsRequest`),
    # written into the document's DNS rows after ``dns`` by its chokepoint.
    dns_requests: list[SandboxDnsRequest] = Field(default_factory=list)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, ("dns_requests",))


class SandboxReport(BaseModel):
    """The sandbox-agnostic report. ``provider``/``source_format`` are the one
    thing every reader needs and nothing can infer, so they are the two
    required fields; everything else defaults to empty.

    ``source_format`` is the id of the registered reader that read the report
    (``providers.sandbox.readers``)."""

    model_config = ConfigDict(extra="ignore")

    provider: str
    source_format: str = Field(min_length=1)
    task_id: str = ""
    target: SandboxTarget = Field(default_factory=SandboxTarget)
    processes: list[SandboxProcess] = Field(default_factory=list)
    apistats: dict[str, dict[str, int]] = Field(default_factory=dict)
    generic_events: list[dict[str, Any]] = Field(default_factory=list)
    signatures: list[SandboxSignatureRow] = Field(default_factory=list)
    network: SandboxNetwork = Field(default_factory=SandboxNetwork)
    dropped_files: list[dict[str, Any]] = Field(default_factory=list)
    # list[str], not list[dict]: the real shape is behavior.summary.keys, a
    # flat array of registry-path strings (confirmed against every one of the
    # 97 real reports under data/cape_reports/ — 139,056 string entries, zero
    # dicts). A dict-only filter here would silently drop all of it, the same
    # mistake ``file_writes`` had below.
    registry: list[str] = Field(default_factory=list)
    # Everything a sandbox reports that this schema has no field for, kept
    # rather than dropped. ``registry`` above is the Windows-only channel this
    # project grew first; a Linux guest publishes systemd units and syscalls,
    # an Android one permissions and receivers, a macOS one launchd jobs, and
    # none of those had anywhere to land. Keys are namespaced by platform
    # ("android.permissions", "linux.systemd", "macos.launchd") so two
    # sandboxes cannot collide on a bare word, and rows stay close to the
    # shape the sandbox published them in.
    # Each channel's rows, or one block a reader keeps whole (a mapped
    # report's unnamed block), held as the sandbox published it.
    channels: dict[str, Any] = Field(default_factory=dict)
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    cti: dict[str, Any] = Field(default_factory=dict)
    # The sections this sandbox structurally cannot produce, by the platform's
    # own section ids (``SECTION_IDS``: ``api_calls``, ``events``,
    # ``registry`` …), never a sandbox's own words; a report stored before
    # the ids were normalised is read through ``LEGACY_SECTION_IDS``.
    unavailable: list[str] = Field(default_factory=list)
    # The run-time limit the sandbox set for the task, in seconds, as its own
    # report says (Triage's task ``timeout``): the limit, not a measured
    # duration, and never the value this platform asked for. ``None`` where the
    # report says nothing.
    run_limit_seconds: int | None = None
    # What the reader read, where it reads less than the whole of what a
    # sandbox can give: ``"overview"`` for a Triage report read from its
    # overview alone (no behavioural task report was read), ``"tasks"`` for
    # one read with them. Empty where the reader reads one body. Held for the
    # run in hand (``reader_of``) and left out of a dump, so a stored or golden
    # report reads as it always did.
    read_from: str = Field(default="", exclude=True)
    # True when no sandbox ran at all and this report stands in for one. A real
    # run that observed nothing is not synthetic: its emptiness is a finding.
    synthetic: bool = Field(default=False)
    raw: dict[str, Any] = Field(default_factory=dict)
    _validate_raw = field_validator("raw", mode="wrap")(_dict_identity_or_validate)
    # Ruled in during the pre-flight scan, beyond the brief's own field list:
    # an agent hunting Linux persistence reads both of these directly
    # (``behavior.summary.{files,write_files,modified_files,wrote_files}`` and
    # the top-level ``file_writes``/``files_written`` arrays) and keep only
    # the string entries of each (its own ``isinstance(p, str)`` guard) — a
    # dict-shaped entry is not richer data, it is a shape the consumer already
    # discards, so both are coerced to ``list[str]`` here rather than filtered
    # to dicts only.
    summary: dict[str, list[str]] = Field(default_factory=dict)
    file_writes: list[str] = Field(default_factory=list)
    # The places a reader fills where its sandbox has them. ``process_tree``
    # is the process tree as the sandbox nests it (each node's ``children``);
    # ``resolved_apis`` the API names the sample resolved at run time;
    # ``extracted`` the configurations and payloads the sandbox extracted, a
    # list, or lists by name, as the sandbox groups them; ``procdumps`` the
    # process dumps; ``memory`` the regions of process memory the sandbox
    # recorded; ``ids_alerts`` the alerts an intrusion detection engine raised
    # on the run's traffic.
    # Rows as the sandbox published them, held by reference: never copied
    # or wrapped row by row.
    process_tree: list[Any] = Field(default_factory=list)
    resolved_apis: list[Any] = Field(default_factory=list)
    extracted: list[Any] | dict[str, Any] = Field(default_factory=list)
    procdumps: list[Any] = Field(default_factory=list)
    memory: list[Any] = Field(default_factory=list)
    ids_alerts: list[Any] = Field(default_factory=list)
    # Every block the reader read that has no place above, under the source's
    # own name and nested as the source nests it in the document's sections
    # (``schemas.sandbox_document``): kept, never dropped, and read by the
    # section tool and the whole-report slice. Held for the run in hand (the
    # document carries it) and left out of a dump.
    extras: dict[str, Any] = Field(default_factory=dict, exclude=True)
    # True for a report the mock sandbox read from a recorded fixture: an
    # observation of some earlier detonation, not of this run
    # (``pipeline.sandbox_status``).
    recorded_fixture: bool = False
    # What a signature's severity number means in this report: the scale the
    # report's format declares, set by the reader that read it. Held for the
    # run in hand and left out of a dump.
    signature_scale: SignatureScale | None = Field(default=None, exclude=True)
    # A reader that keeps its source's own arrangement (``schemas.
    # sandbox_document.decompose``): each place as the source published it, and
    # the order of the keys of each of the document's sections. ``None``: the
    # document is laid out from the fields above. Held for the run in hand and
    # left out of a dump.
    published: dict[str, Any] = Field(default_factory=dict, exclude=True)
    arrangement: dict[str, list[str]] | None = Field(default=None, exclude=True)

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> Any:
        return _without_empty(self, handler, _FILLED_ONLY)


# The fields a report dumps only where they hold something.
_FILLED_ONLY: tuple[str, ...] = (
    "process_tree",
    "resolved_apis",
    "extracted",
    "procdumps",
    "memory",
    "ids_alerts",
    "recorded_fixture",
)


class SandboxRun(BaseModel):
    """One sandbox job's outcome: the neutral report plus the job's own status.

    ``report`` has no safe empty value — a run without a report is not a run —
    so it is the one field with no default.
    """

    model_config = ConfigDict(extra="ignore")

    task_id: str
    sample_sha256: str = ""
    sample_name: str = ""
    status: str = "reported"
    report: SandboxReport
    # Same wrap-validator identity fix as SandboxReport.raw above, and for the
    # same reason: a sandbox provider's ``fetch()`` sets both
    # ``SandboxRun.raw`` and ``SandboxReport.raw`` to the very same
    # client-returned dict, and ``test_fetch_keeps_the_raw_report_by_identity``
    # depends on ``run.raw is <that dict>`` holding exactly as it does for the
    # report — a plain ``dict[str, Any]`` field does not hold that (confirmed
    # empirically: pydantic-core rebuilds the container even when every value
    # already validates), so this field needs the same protection.
    raw: dict[str, Any]
    _validate_raw = field_validator("raw", mode="wrap")(_dict_identity_or_validate)
    error: str = ""


# The behaviour summary's lists the model holds, as the document names them
# (``schemas.sandbox_document.SUMMARY_KEYS``): the file, mutex, command and
# service lists an agent hunting persistence and host artefacts reads, and the
# read, write and delete lists beside them.
_SUMMARY_KEYS: tuple[str, ...] = _DOCUMENT_SUMMARY_KEYS

# Blocks a CAPE guest other than Windows publishes, and the namespaced channel
# each one lands in. ``behavior.processes`` is shared across every guest and
# already has a field of its own, so it is not repeated here. A block CAPE did
# not emit produces no channel at all — an absent channel and an empty one say
# different things, and only one of them means the sandbox looked.
_CAPE_CHANNEL_SOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("linux.strace", ("strace",)),
    ("linux.syscalls", ("syscalls",)),
    ("linux.systemd", ("systemd",)),
    ("android.permissions", ("permissions",)),
    ("android.receivers", ("receivers",)),
    ("android.services", ("services",)),
    ("android.activities", ("activities",)),
    ("macos.launchd", ("launchd",)),
)


def _channel_rows(value: Any) -> list[dict[str, Any]]:
    """One channel's rows, with a bare string wrapped so every row is a mapping."""
    if isinstance(value, dict):
        return [{"name": str(k), "value": v} for k, v in value.items()]
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for entry in value:
        if isinstance(entry, dict):
            rows.append(entry)
        elif entry not in (None, ""):
            rows.append({"value": entry})
    return rows


def _cape_channels(
    raw: dict[str, Any], behavior: dict[str, Any]
) -> dict[str, list[dict[str, Any]]]:
    """The non-Windows blocks a CAPE report carries, namespaced by platform.

    CAPE's Linux and Android packages publish beside the shared
    ``behavior.processes`` rather than instead of it, and nothing downstream
    could see any of it. Each block is looked for at the top level and under
    ``behavior``, since CAPE places them in both depending on the package.
    """
    channels: dict[str, list[dict[str, Any]]] = {}
    for channel, keys in _CAPE_CHANNEL_SOURCES:
        for key in keys:
            rows = _channel_rows(raw.get(key))
            if not rows:
                rows = _channel_rows(behavior.get(key))
            if rows:
                channels[channel] = rows
                break
    # Anything the operator's own sandbox already namespaced is taken as-is.
    declared = raw.get("channels")
    if isinstance(declared, dict):
        for name, value in declared.items():
            rows = _channel_rows(value)
            if rows:
                channels[str(name)] = rows
    return channels


# The section ids a report's ``unavailable`` list names, as the sandbox
# sections read them (``analysis.sandbox_sections.SECTION_PREFIXES``), and the
# words an earlier report or a sandbox's own list used for two of them.
SECTION_IDS: tuple[str, ...] = ("api_calls", "apistats", "events", "registry", "screenshots")
LEGACY_SECTION_IDS: dict[str, str] = {"calls": "api_calls", "generic_events": "events"}


def section_id(name: Any) -> str:
    """A section named in an ``unavailable`` list, as the platform's own id.

    The id itself, lower-cased; a word an earlier report used for one
    (``calls``, ``generic_events``) is read as the id it meant.
    """
    word = str(name or "").strip().lower()
    return LEGACY_SECTION_IDS.get(word, word)


# The list fields of the model a normaliser may fill, as one vocabulary: what
# each reader below declares it can fill, and what the sandbox sections read
# (``analysis.sandbox_sections``) to tell a list the reader never fills, which
# says nothing, from one the sandbox left empty, which is a finding.
REPORT_LIST_FIELDS: tuple[str, ...] = (
    "processes",
    "processes.calls",
    "apistats",
    "generic_events",
    "signatures",
    "network.dns",
    "network.http",
    "network.tcp",
    "network.udp",
    "network.hosts",
    "network.domains",
    "network.tls",
    "network.icmp",
    "dropped_files",
    "registry",
    "channels",
    "screenshots",
    *(f"summary.{key}" for key in _SUMMARY_KEYS),
    "file_writes",
    "process_tree",
    "resolved_apis",
    "extracted",
    "procdumps",
    "memory",
    "ids_alerts",
)

# What :func:`cape_report_to_sandbox_report` can fill: every list field, each
# read from the report's own block of that name.
CAPE_NORMALISER_FILLS: frozenset[str] = frozenset(REPORT_LIST_FIELDS)


def report_fills(report: SandboxReport) -> frozenset[str]:
    """The list fields of ``report`` that hold at least one row."""
    from maljan.schemas.sandbox_document import dns_requests_have_place

    network = report.network
    # The structural requests fill ``network.dns`` only where the document can
    # hold their rows.
    requests = network.dns_requests if dns_requests_have_place(report) else ()
    held: dict[str, Any] = {
        "processes": report.processes,
        "processes.calls": any(p.calls for p in report.processes),
        "apistats": report.apistats,
        "generic_events": report.generic_events,
        "signatures": report.signatures,
        "dropped_files": report.dropped_files,
        "registry": report.registry,
        "channels": report.channels,
        "screenshots": report.screenshots,
        "file_writes": report.file_writes,
        **{
            f"network.{kind}": getattr(network, kind)
            for kind in ("dns", "http", "tcp", "udp", "hosts", "domains", "tls", "icmp")
        },
        "network.dns": network.dns or requests,
        **{f"summary.{key}": report.summary.get(key) for key in _SUMMARY_KEYS},
        "process_tree": report.process_tree,
        "resolved_apis": report.resolved_apis,
        "extracted": report.extracted,
        "procdumps": report.procdumps,
        "memory": report.memory,
        "ids_alerts": report.ids_alerts,
    }
    return frozenset(name for name, value in held.items() if value)


@dataclass(frozen=True)
class Reading:
    """What one reader can fill, and how its report reaches the sections."""

    fills: frozenset[str]
    # How the reader read less than the whole of what its sandbox can give,
    # as the clause a section's ``no:`` sentence says it in (``read from its
    # overview alone``); empty where it read everything.
    partial: str = ""
    # Laid out from the form's own fields (``schemas.sandbox_document``), where
    # a pid or parent of 0 is the form's "not stated", rather than as the
    # source published its rows.
    rendered: bool = True


# What a report read by a reader that keeps its source's arrangement reached
# its readers as (``reader_of``): as its source published it, or laid out from
# the form's fields, when the report was built without a source.
READ_FROM_RAW = "raw"
READ_FROM_MODEL = "model"
# What the Triage reader read (``SandboxReport.read_from``).
READ_FROM_OVERVIEW = "overview"
READ_FROM_TASKS = "tasks"


def reader_of(report: SandboxReport) -> tuple[str, str, str]:
    """``(provider, source_format, read_from)`` of the reader behind ``report``.

    ``read_from`` is the report's own where its reader set it; for a reader
    that keeps its source's arrangement, whether the report reaches its
    readers as its source published it (``raw``) or laid out from the form
    (``model``, a report built with no source).
    """
    read_from = report.read_from
    if not read_from:
        if keeps_its_source(report):
            read_from = READ_FROM_RAW
        else:
            from maljan.providers.sandbox.readers import report_reader

            reader = report_reader(report.source_format)
            if reader is not None and reader.keeps_source_arrangement:
                read_from = READ_FROM_MODEL
    return report.provider, report.source_format, read_from


def keeps_its_source(report: SandboxReport) -> bool:
    """Whether ``report``'s document is its source's own arrangement: a source with any block."""
    return bool(report.arrangement and report.arrangement.get(""))


def normaliser_reading(
    source_format: str, provider: str = "", read_from: str = ""
) -> Reading | None:
    """What the registered reader ``source_format`` names can fill, or ``None`` when unknown.

    Each reader declares it (``ReportReader.reading``), by what it read
    (``read_from``) and, where that is not said, by the provider.
    """
    from maljan.providers.sandbox.readers import report_reader

    reader = report_reader(str(source_format or "").strip().lower())
    if reader is None:
        return None
    return reader.reading(str(read_from or "").strip().lower(), str(provider or "").strip().lower())


# The words a CAPE report gives four of its blocks, and the document's word
# for each (``schemas.sandbox_document.PLACES``): the CAPE reader's
# declaration, read by its reader and nowhere else.
CAPE_RENAMES: dict[str, str] = {
    "CAPE": "extracted",
    "procdump": "procdumps",
    "procmemory": "memory",
    "suricata": "ids",
}


# The words a document laid out before the parts' words were declared used for
# the four renamed blocks: every such document was CAPE's shape, whichever
# sandbox produced it, so a part missing under the document's word is read
# under the word it had then (:func:`stored_place`).
STORED_DOCUMENT_WORDS: dict[str, str] = {new: old for old, new in CAPE_RENAMES.items()}


def stored_place(document: Any, name: str, default: Any = None) -> Any:
    """The part ``name`` of ``document``, read under its earlier word where the new one is absent.

    A document checkpointed before the parts were renamed is read as what it
    holds rather than stated as holding nothing.
    """
    from maljan.schemas.sandbox_document import PLACES, place

    found = place(document, name, _ABSENT)
    if found is not _ABSENT:
        return found
    path = PLACES[name]
    earlier = STORED_DOCUMENT_WORDS.get(path[0])
    if earlier is None or not isinstance(document, Mapping) or path[0] in document:
        return default
    node: Any = document.get(earlier, _ABSENT)
    for key in path[1:]:
        if not isinstance(node, Mapping) or key not in node:
            return default
        node = node[key]
    return default if node is _ABSENT else node


_ABSENT = object()


def _block(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _text_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _extracted(value: Any) -> list[Any] | dict[str, Any]:
    if isinstance(value, dict):
        return value
    return list(value) if isinstance(value, list) else []


def cape_report_to_sandbox_report(
    raw: dict[str, Any],
    *,
    provider: str,
    source_format: str,
    task_id: str = "",
    keep_arrangement: bool = True,
    renames: Mapping[str, str] | None = None,
) -> SandboxReport:
    """Read a CAPE/Cuckoo-shaped report into the neutral form.

    ``source_format`` is the id of the registered reader that read it, which
    the report records (``SandboxReport.source_format``); never assumed.

    Every place the form names is filled from the report's own block of that
    name. With ``keep_arrangement`` (the CAPE, Cuckoo and mock readers) the
    report also keeps its source's arrangement: each place as the report
    published it, every block with no place under its own name, and the order
    of both (``schemas.sandbox_document.decompose``), so the document laid out
    from the form is the report itself, its four renamed blocks
    (:data:`CAPE_RENAMES`) under the document's words. The original dict is
    carried whole in ``raw``.
    """
    behavior_field, net_field, target_field = (
        raw.get("behavior"),
        raw.get("network"),
        raw.get("target"),
    )
    behavior = behavior_field if isinstance(behavior_field, dict) else {}
    net = net_field if isinstance(net_field, dict) else {}
    target = target_field if isinstance(target_field, dict) else {}
    file_block_field = target.get("file")
    file_block = file_block_field if isinstance(file_block_field, dict) else {}
    summary_field = behavior.get("summary")
    summary_raw = summary_field if isinstance(summary_field, dict) else {}
    cti_field = raw.get("cti")

    processes = [
        SandboxProcess(
            pid=_int(p.get("pid")),
            ppid=_int(p.get("ppid")),
            name=str(p.get("process_name") or p.get("name") or ""),
            command_line=str(p.get("command_line") or p.get("cmd") or ""),
            first_seen=str(p.get("first_seen") or ""),
            calls=[c for c in _list(p.get("calls")) if isinstance(c, dict)],
        )
        for p in _list(behavior.get("processes"))
        if isinstance(p, dict)
    ]
    signatures = [
        SandboxSignatureRow(
            name=str(s.get("name") or ""),
            description=str(s.get("description") or s.get("name") or ""),
            severity=_int(s.get("severity") or s.get("score")),
            marks=list(_list(s.get("marks"))),
            ttp_tags=_as_str_list(s.get("ttp_tags") or s.get("attck_id")),
        )
        for s in _list(raw.get("signatures"))
        if isinstance(s, dict)
    ]
    published: dict[str, Any] = {}
    extras: dict[str, Any] = {}
    arrangement: dict[str, list[str]] | None = None
    if keep_arrangement:
        words = CAPE_RENAMES if renames is None else renames
        published, extras, arrangement = kept_source(raw, words)
    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or _block(raw.get("info")).get("id") or ""),
        target=SandboxTarget(
            # CAPE nests the hashes under target.file.*; a handful of other
            # builds (and the neutral providers upstream of this one) put them
            # directly on target. Both are checked so neither shape loses data.
            sha256=str(target.get("sha256") or file_block.get("sha256") or ""),
            md5=str(target.get("md5") or file_block.get("md5") or ""),
            name=str(target.get("name") or file_block.get("name") or ""),
            file_type=str(file_block.get("type") or ""),
            mime_type=str(file_block.get("type") or ""),
            size=_int(file_block.get("size")),
            sha1=str(target.get("sha1") or file_block.get("sha1") or ""),
            sha512=str(target.get("sha512") or file_block.get("sha512") or ""),
            ssdeep=str(target.get("ssdeep") or file_block.get("ssdeep") or ""),
        ),
        processes=processes,
        apistats={
            str(pid): {str(api): _int(n) for api, n in (stats or {}).items()}
            for pid, stats in _block(behavior.get("apistats")).items()
            if isinstance(stats, dict)
        },
        generic_events=[g for g in _list(behavior.get("generic")) if isinstance(g, dict)],
        signatures=signatures,
        network=SandboxNetwork(
            dns=_rows(net.get("dns")),
            http=_rows(net.get("http")),
            tcp=_rows(net.get("tcp")),
            udp=_rows(net.get("udp")),
            hosts=_rows(net.get("hosts")),
            domains=[d for d in _list(net.get("domains")) if isinstance(d, str | dict)],
            tls=_rows(net.get("tls")),
            icmp=_rows(net.get("icmp")),
            pcap_local_path=_text_or_none(net.get("pcap_local_path")),
        ),
        dropped_files=_rows(raw.get("dropped")),
        registry=_as_str_list(summary_raw.get("keys")),
        channels=_cape_channels(raw, behavior),
        screenshots=_rows(raw.get("screenshots")),
        cti=cti_field if isinstance(cti_field, dict) else {},
        unavailable=[],
        synthetic=bool(raw.get("synthetic")),
        raw=raw,
        summary={key: _as_str_list(summary_raw.get(key)) for key in _SUMMARY_KEYS},
        file_writes=_as_str_list(raw.get("file_writes") or raw.get("files_written")),
        process_tree=_rows(behavior.get("processtree")),
        resolved_apis=_as_str_list(summary_raw.get("resolved_apis")),
        extracted=_extracted(raw.get("CAPE")),
        procdumps=_rows(raw.get("procdump")),
        memory=_rows(raw.get("procmemory")),
        ids_alerts=_rows(_block(raw.get("suricata")).get("alerts")),
        extras=extras,
        published=published,
        arrangement=arrangement,
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split Triage's combined ``"host:port"`` flow endpoint.

    Triage's dynamic-report flows carry the destination as one string rather
    than separate host/port fields (confirmed against the "Dynamic Report"
    docs page on 2026-09-04). A value with no trailing ``:<digits>`` is kept
    whole as the host, port ``None`` — this also covers a bare IPv6 address,
    which is never mistaken for a port suffix (its last group can be all
    digits: ``2001:db8::1``). An IPv6 address Triage writes with brackets
    (``[2001:db8::1]:443``) is returned without them, as every other source
    states one.
    """
    if value.count(":") > 1 and not value.startswith("["):
        # Several colons without brackets: a bare IPv6 address, whose last
        # group is not a port (``2001:db8::1``), or no host at all.
        return value, None
    host, sep, port_str = value.rpartition(":")
    if sep and port_str.isdigit():
        return _unbracketed(host), int(port_str)
    return _unbracketed(value), None


def _unbracketed(host: str) -> str:
    """``host`` without the brackets that set an IPv6 address apart from its port."""
    if len(host) > 2 and host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


# The key a flow row states its attribution under: ``True`` when the process
# that made the flow is the sample's or one it started, ``False`` when the
# report names that process and it is neither, and absent when the report does
# not say. A platform fact, so it is right or it is not there.
SAMPLE_TREE_KEY = "sample_process_tree"
# The image of the process outside the sample's tree that made a flow, on
# the flow's row: which process reached the address, as the report names it.
FLOW_PROCESS_KEY = "process"


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip().strip('"').strip("'"))[-1].lower()


def _named_files(proc: dict[str, Any]) -> set[str]:
    """The file names a process record runs: its image, and each path its command line names.

    Whole file names, never slices: a command line's first word and every
    comma- or space-separated path in it (``rundll32.exe <dll>,#1`` runs the
    DLL), each cut to its file name.
    """
    names = {_basename(str(proc.get("image") or ""))}
    for token in re.split(r"[\s,]+", str(proc.get("cmd") or "")):
        cleaned = token.strip().strip('"').strip("'")
        if cleaned:
            names.add(_basename(cleaned))
    return {name for name in names if name}


def _is_the_sample(proc: dict[str, Any], sample: dict[str, Any]) -> bool:
    """Whether a process record with no ``orig`` mark runs the submitted file.

    A file name the process runs equals the name the sample was submitted
    under, or is the sample's digest with an extension (a sandbox names the
    staged copy by its hash). An equal name, never a contained one: a guest's
    ``MicrosoftEdgeUpdate.exe`` is not a sample submitted as ``update.exe``.
    """
    target = _basename(str(sample.get("target") or ""))
    digest = str(sample.get("sha256") or "").strip().lower()
    for name in _named_files(proc):
        if target and name == target:
            return True
        if digest and name.rsplit(".", 1)[0] == digest:
            return True
    return False


# Which of the two facts alone names a flow's process as the sample's, on a
# row whose attribution is therefore not stated: ``"marked"`` when the sandbox
# marks it as the sample's and it runs none of the submitted file's names and
# descends from none of its processes, ``"file"`` when it runs the submitted
# file (or descends from a process that does) and the sandbox marks it not. A
# row stored before the value was normalised says ``"orig"`` for ``"marked"``.
LINEAGE_DISPUTED_KEY = "lineage_disputed"
LINEAGE_MARKED = "marked"
LINEAGE_FILE = "file"
# Beside a disputed row: the name published text gives the sandbox whose mark
# it is, the display name its report format declares
# (``core.report_formats.reader_display_name``).
LINEAGE_MARKED_BY_KEY = "lineage_marked_by"
# The value a row stored before the normalisation gives a marked process, and
# the sandbox such a row, which names no marker, was marked by: the one
# reader that wrote one (the triage format's declared name).
LINEAGE_MARKED_STORED = "orig"


def _reach(parent: dict[Any, Any], roots: set[Any]) -> set[Any]:
    """Every listed process whose parent chain reaches one of ``roots``, the roots included.

    Each process's answer is settled once: a chain is walked only up to the
    first process already settled, and every process on it takes that answer,
    so a long chain or many processes cost time linear in the list.
    """
    settled: dict[Any, bool] = {}
    for procid in parent:
        chain: list[Any] = []
        on_chain: set[Any] = set()
        current, reaches = procid, False
        while current:
            if current in settled:
                reaches = settled[current]
                break
            if current in roots:
                reaches = settled[current] = True
                break
            if current in on_chain:
                break
            on_chain.add(current)
            chain.append(current)
            current = parent.get(current)
        for node in chain:
            settled[node] = reaches
    return {procid for procid in parent if settled.get(procid)}


class _Lineage:
    """What one task's process records say about the sample's process tree."""

    def __init__(
        self,
        tree: set[Any],
        disputed: dict[Any, str],
        images: dict[Any, str],
        stated: bool,
    ) -> None:
        self.tree = frozenset(tree)
        self.disputed = dict(disputed)
        self.images = dict(images)
        # Whether either fact names any process, which is what lets a listed
        # process outside every tree be stated as outside it.
        self.stated = stated


def _sample_process_tree(task: dict[str, Any], sample: dict[str, Any]) -> _Lineage:
    """The sample's process tree in one task, read from the two facts the report holds.

    The two facts: the processes Triage marks ``orig``, and the processes that
    run the submitted file (:func:`_is_the_sample`: its name or the digest's,
    equal and never contained). Each gives a tree, the processes whose parent
    chain (``procid_parent``) reaches one it names. Where both name processes,
    a process in both trees is the sample's, a listed process in neither is
    not, and one in exactly one tree is disputed: the facts disagree, so its
    attribution is not stated. A desktop process Triage marked, which runs
    none of the submitted file's names and descends from none of its
    processes, was read as the sample on the mark alone and the address it
    reached published as the sample's. Where only one fact names any process,
    its tree is the answer; where neither does, nothing is stated.
    """
    processes = [p for p in task.get("processes") or [] if isinstance(p, dict)]
    parent = {p.get("procid"): p.get("procid_parent") for p in processes if p.get("procid")}
    # As the report writes them, for a reader: the case is the file's own.
    images = {
        p.get("procid"): re.split(r"[\\/]", str(p.get("image") or p.get("name") or "").strip())[-1]
        for p in processes
        if p.get("procid")
    }
    marked = {p.get("procid") for p in processes if p.get("procid") and p.get("orig") is True}
    named = {p.get("procid") for p in processes if p.get("procid") and _is_the_sample(p, sample)}
    by_mark, by_file = _reach(parent, marked), _reach(parent, named)
    if marked and named:
        disputed = {procid: LINEAGE_MARKED for procid in by_mark - by_file}
        disputed.update({procid: LINEAGE_FILE for procid in by_file - by_mark})
        return _Lineage(by_mark & by_file, disputed, images, True)
    return _Lineage(by_mark or by_file, {}, images, bool(marked or named))


# The sandbox whose ``orig`` mark a row stored without its marker's name was
# read by, by the name its format declares (``core.legacy_tool_tables``). A
# report read now names the format it was read as.
LINEAGE_STORED_MARKED_BY = reader_display_name(STORED_LINEAGE_MARKER_FORMAT)


def _flow_attribution(
    flow: dict[str, Any], lineage: _Lineage, marked_by: str = LINEAGE_STORED_MARKED_BY
) -> dict[str, Any]:
    """What one Triage flow says about the process that made it, and its network facts.

    ``procid`` and ``pid`` as the flow gives them; ``sample_process_tree`` only
    where the report settles it (see ``SAMPLE_TREE_KEY``); for a listed
    process outside the tree, or one the two facts disagree about
    (``LINEAGE_DISPUTED_KEY``), its image (``FLOW_PROCESS_KEY``), which is
    what the publish rule names when it refuses the row; the destination's AS
    number, AS organisation and country where Triage recorded them.
    """
    out: dict[str, Any] = {}
    procid = flow.get("procid")
    if procid not in (None, ""):
        out["procid"] = procid
        if procid in lineage.tree:
            out[SAMPLE_TREE_KEY] = True
        elif procid in lineage.disputed:
            out[LINEAGE_DISPUTED_KEY] = lineage.disputed[procid]
            if lineage.disputed[procid] == LINEAGE_MARKED:
                out[LINEAGE_MARKED_BY_KEY] = marked_by
            if lineage.images.get(procid):
                out[FLOW_PROCESS_KEY] = lineage.images[procid]
        elif lineage.stated and procid in lineage.images:
            out[SAMPLE_TREE_KEY] = False
            if lineage.images.get(procid):
                out[FLOW_PROCESS_KEY] = lineage.images[procid]
    if flow.get("pid") not in (None, ""):
        out["pid"] = flow.get("pid")
    for key in ("as_num", "as_org", "country"):
        if flow.get(key) not in (None, ""):
            out[key] = flow[key]
    return out


# What :func:`triage_overview_to_sandbox_report` can fill: the process list,
# the signatures, the dumped files, the flows split into TCP and UDP with a
# host row per destination, the DNS and HTTP requests with their names, and
# what the sandbox extracted. Every other list it leaves empty whatever the
# report holds. Given the overview alone it fills the signatures and the
# extracted items and nothing else: the processes, the dumped files and the
# network are read from the task reports.
TRIAGE_OVERVIEW_FILLS: frozenset[str] = frozenset({"signatures", "extracted"})
# The overview's blocks and a signature's fields the reader reads into places
# of their own; every other one is kept under its own name.
_TRIAGE_OVERVIEW_READ: frozenset[str] = frozenset({"sample", "signatures", "extracted"})
_TRIAGE_SIGNATURE_READ: frozenset[str] = frozenset({"name", "desc", "score", "indicators", "ttp"})
# A task report's blocks the reader reads into places of their own, and the
# fields of a flow and of a request it reads; every other one is kept.
_TRIAGE_TASK_READ: frozenset[str] = frozenset({"processes", "dumped", "network"})
_TRIAGE_FLOW_READ: frozenset[str] = frozenset(
    {"proto", "dst", "procid", "pid", "as_num", "as_org", "country"}
)
_TRIAGE_REQUEST_READ: frozenset[str] = frozenset(
    {"domain_req", "domain_resp", "web_req", "web_resp"}
)
# The key a kept task block's row names its task by; the block itself is held
# under the document's grouped-rows key (``schemas.sandbox_document``).
TASK_KEY = "task_report"
TASK_ROWS_KEY = GROUP_ROWS_KEY


def _keep_task_block(channels: dict[str, Any], name: str, task: str, value: Any) -> None:
    """One task report's block, kept whole in the channel ``name`` as one row naming its task.

    The block is held by reference, as the task report holds it (``rows``):
    nothing of it is copied or wrapped, so a block costs one small row
    whatever its size. Nothing with no value is kept.
    """
    if value in (None, "", [], {}):
        return
    channels.setdefault(name, []).append({TASK_KEY: task, TASK_ROWS_KEY: value})


TRIAGE_NORMALISER_FILLS: frozenset[str] = frozenset(
    {
        "processes",
        "signatures",
        "dropped_files",
        "network.tcp",
        "network.udp",
        "network.hosts",
        "network.dns",
        "network.domains",
        "network.http",
        "extracted",
        # The task reports' blocks with no place of their own.
        "channels",
    }
)


def triage_overview_to_sandbox_report(
    overview: dict[str, Any],
    *,
    provider: str,
    source_format: str,
    task_reports: dict[str, dict[str, Any]] | None = None,
    task_id: str = "",
    marked_by: str = "",
) -> SandboxReport:
    """Map a Triage overview (plus its behavioural task reports) onto the model.

    ``provider`` and ``source_format`` are the sandbox provider and the id of
    the registered reader that read it, which the report records; neither is
    assumed. ``marked_by`` is the name the format the report was matched as
    declares (its ``display_name``, else its name), which a disputed row names
    its marking sandbox by; empty is the name ``source_format`` declares.

    Triage reports what it observed, not every API call: there is no per-call
    log, no apistats, no registry timeline, no generic-event stream and (for a
    file sample) no screenshot. Those five sections are listed in
    ``unavailable`` rather than left empty and silent, because an empty
    dynamic section reads exactly like a clean sample — and the report
    renderers say so out loud.

    Every other channel a consumer reads is populated straight from the
    fixture shape confirmed against Triage's "Dynamic Report" docs page on
    2026-09-04: each task's ``network.flows`` (tcp/udp, split by ``proto``,
    plus a synthesised ``network.hosts`` row per destination carrying that
    flow's ASN/country) and ``network.requests`` (``domain_req``/
    ``domain_resp`` pairs for DNS, ``web_req``/``web_resp`` pairs for HTTP),
    and each task's ``dumped`` files for ``dropped_files``. Every one of these
    is mapped into the *consumer* shape (``network.dns`` rows as
    ``{request, type, answers: [{data}]}``, ``network.tcp``/``udp`` rows as
    ``{dst, dport}``) rather than passed through in Triage's own shape, so
    ``network_extractor``/``network_parser`` read real domains and IPs
    instead of rendering ``N/A`` for fields they don't recognise.

    ``TriageSandboxProvider`` is imported here, inside the function body rather
    than at module scope, because it is the one caller: the provider module
    imports this function at import time, so a module-level import back would
    be circular. By the time anything actually calls this function, both
    modules have finished loading regardless of which one a caller reached
    first.
    """
    from maljan.providers.sandbox.triage import TriageSandboxProvider

    marker = marked_by or reader_display_name(source_format)
    sample_field, analysis_field = overview.get("sample"), overview.get("analysis")
    sample = sample_field if isinstance(sample_field, dict) else {}
    analysis = analysis_field if isinstance(analysis_field, dict) else {}
    processes: list[SandboxProcess] = []
    dropped_files: list[dict[str, Any]] = []
    network = SandboxNetwork()
    hosts_by_ip: dict[str, dict[str, Any]] = {}
    # Whether any behavioural task report was read: without one, the report is
    # the overview's alone, and says so (``read_from``).
    tasks_read = 0
    extracted = _rows(overview.get("extracted"))
    channels: dict[str, Any] = {}
    for task_name, task in (task_reports or {}).items():
        if not isinstance(task, dict):
            continue
        tasks_read += 1
        # The task report's blocks with no place of their own (its signatures
        # with their per-process indicators, the task, the errors, ...), kept
        # whole as ``task.<block>`` channels, each row naming its task; what
        # it extracted joins the overview's.
        for block, value in task.items():
            if block == "extracted":
                # Each row as the task lists it, by reference: a row the
                # overview lists too is kept twice rather than compared with
                # every row before it.
                extracted.extend(_rows(value))
            elif block not in _TRIAGE_TASK_READ:
                _keep_task_block(channels, f"task.{block}", str(task_name), value)
        lineage = _sample_process_tree(task, sample)
        for proc in task.get("processes") or []:
            if not isinstance(proc, dict):
                continue
            pid_key = "procid" if proc.get("procid") else "pid"
            ppid_key = "procid_parent" if proc.get("procid_parent") else "ppid"
            name_key = "image" if proc.get("image") else "name"
            read = {pid_key, ppid_key, name_key, "cmd", "started"}
            processes.append(
                SandboxProcess(
                    pid=_int(proc.get(pid_key)),
                    ppid=_int(proc.get(ppid_key)),
                    name=str(proc.get(name_key) or ""),
                    command_line=str(proc.get("cmd") or ""),
                    first_seen=str(proc.get("started") or ""),
                    calls=[],
                    # What the task report says of the process beyond those
                    # (the guest's own pid and parent, the sample mark, when
                    # it ended), under its own names.
                    extra={k: v for k, v in proc.items() if k not in read},
                )
            )
        dumped_field = task.get("dumped")
        dropped_files.extend(_rows(dumped_field))

        net_field = task.get("network")
        net = net_field if isinstance(net_field, dict) else {}
        for block, value in net.items():
            if block not in ("flows", "requests"):
                _keep_task_block(channels, f"task.network.{block}", str(task_name), value)

        for flow in _rows(net.get("flows")):
            proto = str(flow.get("proto") or "").lower()
            dst_host, dst_port = _split_host_port(str(flow.get("dst") or ""))
            if not dst_host:
                continue
            row: dict[str, Any] = {"dst": dst_host, "dport": dst_port}
            row.update(_flow_attribution(flow, lineage, marker))
            # The flow's other fields (its source, times, bytes, protocols,
            # the name and TLS facts the sandbox recorded), under their own names.
            flow_extra = {k: v for k, v in flow.items() if k not in _TRIAGE_FLOW_READ}
            if flow_extra:
                row["extra"] = flow_extra
            if proto == "tcp":
                network.tcp.append(row)
            elif proto == "udp":
                network.udp.append(row)
            host_row = hosts_by_ip.setdefault(dst_host, {"ip": dst_host})
            as_num, as_org = flow.get("as_num"), flow.get("as_org")
            if as_num or as_org:
                host_row["asn"] = " ".join(str(x) for x in (as_num, as_org) if x)
            if flow.get("country"):
                host_row["country_name"] = str(flow["country"])

        for req in _rows(net.get("requests")):
            domain_req_field = req.get("domain_req")
            domain_req = domain_req_field if isinstance(domain_req_field, dict) else None
            domain_resp_field = req.get("domain_resp")
            domain_resp = domain_resp_field if isinstance(domain_resp_field, dict) else None
            web_req_field = req.get("web_req")
            web_req = web_req_field if isinstance(web_req_field, dict) else None
            web_resp_field = req.get("web_resp")
            web_resp = web_resp_field if isinstance(web_resp_field, dict) else None
            # The request's own fields beside the four it is read from (the flow
            # it rode on, its time), kept on each row it gives.
            req_extra = {k: v for k, v in req.items() if k not in _TRIAGE_REQUEST_READ}

            if domain_req is not None:
                answers = [
                    {"data": str(a["value"])}
                    for a in _rows((domain_resp or {}).get("answers"))
                    if a.get("value")
                ]
                # The request in the structural form
                # (``SandboxDnsRequest``): the document's chokepoint writes its
                # rows, its answers and other fields once, and links its names.
                questions = [
                    q for q in _rows(domain_req.get("questions")) if str(q.get("name") or "")
                ]
                if len(questions) > 1:
                    # Several questions: each answer keeps the name it answers
                    # and its type, so each question is given the answers for
                    # its own name and its alias chain (``DnsAnswers``).
                    answers = [
                        {
                            "data": str(a["value"]),
                            **({"name": str(a["name"])} if a.get("name") else {}),
                            **({"type": str(a["type"])} if a.get("type") else {}),
                        }
                        for a in _rows((domain_resp or {}).get("answers"))
                        if a.get("value")
                    ]
                if questions:
                    network.dns_requests.append(
                        SandboxDnsRequest(
                            questions=[
                                {
                                    "request": str(q.get("name") or ""),
                                    "type": str(q.get("type") or ""),
                                }
                                for q in questions
                            ],
                            answers=answers,
                            extra=req_extra,
                        )
                    )
                network.domains.extend(str(q.get("name") or "") for q in questions)

            if web_req is not None:
                parsed_url = urlsplit(str(web_req.get("url") or ""))
                headers_field = web_req.get("headers")
                headers = headers_field if isinstance(headers_field, dict) else {}
                http_row: dict[str, Any] = {
                    "host": parsed_url.hostname or "",
                    "uri": parsed_url.path or "/",
                    "method": str(web_req.get("method") or ""),
                    "status": (web_resp or {}).get("status"),
                    "port": parsed_url.port,
                    "encrypted": parsed_url.scheme == "https",
                    "user_agent": str(headers.get("User-Agent") or ""),
                }
                # The whole request and answer beyond those fields (the URL with
                # its query, every header, the answer's own fields).
                http_extra: dict[str, Any] = dict(req_extra)
                request_rest = {k: v for k, v in web_req.items() if k != "method"}
                if request_rest:
                    http_extra["request"] = request_rest
                response_rest = {k: v for k, v in (web_resp or {}).items() if k != "status"}
                if response_rest:
                    http_extra["response"] = response_rest
                if http_extra:
                    http_row["extra"] = http_extra
                network.http.append(http_row)
    network.hosts = list(hosts_by_ip.values())

    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or sample.get("id") or ""),
        target=SandboxTarget(
            sha256=str(sample.get("sha256") or ""),
            md5=str(sample.get("md5") or ""),
            name=str(sample.get("target") or ""),
            file_type=str(sample.get("kind") or ""),
            mime_type=str(sample.get("kind") or ""),
            size=_int(sample.get("size")),
            sha1=str(sample.get("sha1") or ""),
            sha512=str(sample.get("sha512") or ""),
            ssdeep=str(sample.get("ssdeep") or ""),
        ),
        processes=processes,
        apistats={},
        generic_events=[],
        signatures=[
            SandboxSignatureRow(
                name=str(s.get("name") or ""),
                description=str(s.get("desc") or s.get("name") or ""),
                severity=_int(s.get("score")),
                marks=list(s.get("indicators") or []),
                ttp_tags=_as_str_list(s.get("ttp")),
                extra={k: v for k, v in s.items() if k not in _TRIAGE_SIGNATURE_READ},
            )
            for s in (overview.get("signatures") or [])
            if isinstance(s, dict)
        ],
        # The configurations, droppers and credentials Triage extracted, as
        # its overview and its task reports list them.
        extracted=extracted,
        channels=channels,
        # The overview's other blocks (the analysis tags, the task list, the
        # per-target summaries, the report version), under their own names.
        extras={k: v for k, v in overview.items() if k not in _TRIAGE_OVERVIEW_READ},
        network=network,
        dropped_files=dropped_files,
        registry=[],
        screenshots=[],
        cti={"family": _as_str_list(analysis.get("family")), "score": analysis.get("score")},
        unavailable=list(TriageSandboxProvider.UNAVAILABLE),
        run_limit_seconds=_triage_run_limit(overview),
        read_from=READ_FROM_TASKS if tasks_read else READ_FROM_OVERVIEW,
        raw=overview,
    )


def _triage_run_limit(overview: dict[str, Any]) -> int | None:
    """The run-time limit Triage set for the task: its behavioural tasks' ``timeout``.

    The overview lists each task with the run-time limit it was given, not how
    long it ran. ``None`` when no behavioural task carries one, or when two
    carry different ones: one figure for the run would then be a figure the
    report does not state.
    """
    tasks = overview.get("tasks")
    rows = list(tasks.values()) if isinstance(tasks, dict) else tasks
    seen: set[int] = set()
    for task in rows if isinstance(rows, list) else []:
        if not isinstance(task, dict) or str(task.get("kind") or "") != "behavioral":
            continue
        value = task.get("timeout")
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            seen.add(value)
    return seen.pop() if len(seen) == 1 else None
