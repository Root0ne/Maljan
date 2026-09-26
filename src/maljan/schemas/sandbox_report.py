"""The neutral sandbox report every sandbox adapter produces.

Today ``SubmissionResult.report`` *is* the raw CAPEv2 JSON, and nine
consumers (extractors, parsers, the attribution and persistence layers) read
CAPE-shaped keys directly out of it. ``SandboxReport`` is the vocabulary a
sandbox-agnostic pipeline reads instead; :func:`cape_report_to_sandbox_report`
is the one-way reader that fills it from a CAPE/Cuckoo-shaped dict, and
``maljan.providers.cape_view.to_cape_shaped_dict`` is the renderer that turns
it back into the dict today's consumers already know how to read.

Every model here is deliberately permissive: ``model_config =
ConfigDict(extra="ignore")`` so an unexpected sandbox field never breaks
ingestion, and every collection defaults to empty rather than ``None`` so a
consumer can iterate a fresh ``SandboxReport()`` without a null check.
"""

from __future__ import annotations

import re
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidatorFunctionWrapHandler, field_validator


def _int(value: Any) -> int:
    """Best-effort int coercion; malformed sandbox data becomes ``0``, never a crash."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _rows(value: Any) -> list[dict[str, Any]]:
    """Keep only the dict entries of a possibly-mixed sandbox-report array."""
    return [row for row in (value or []) if isinstance(row, dict)]


def _as_str_list(value: Any) -> list[str]:
    """Coerce a sandbox field that is sometimes a list, sometimes a scalar, to ``list[str]``."""
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)] if value else []


def _dict_identity_or_validate(value: Any, handler: ValidatorFunctionWrapHandler) -> dict[str, Any]:
    """Return ``value`` unchanged when it is already a dict; otherwise validate normally.

    This is the narrow fix a bare ``SkipValidation[dict[str, Any]]`` does not
    give: identity (``rendered is raw``) is what ``to_cape_shaped_dict``'s
    short circuit depends on, but ``SkipValidation`` accepts *anything* —
    a string, a list, ``None`` — and would hand it to every consumer as if it
    were the CAPE dict. A dict still passes through untouched (same object,
    no pydantic-core rebuild); anything else still goes through the ordinary
    ``dict[str, Any]`` validator and still raises ``ValidationError``.
    """
    if isinstance(value, dict):
        return value
    return cast("dict[str, Any]", handler(value))


class SandboxTarget(BaseModel):
    """The sample identity a sandbox detonated."""

    model_config = ConfigDict(extra="ignore")

    sha256: str = ""
    md5: str = ""
    name: str = ""
    file_type: str = ""
    mime_type: str = ""
    size: int = 0


class SandboxProcess(BaseModel):
    """One process in the sandbox's flat process list (parent/child ids only)."""

    model_config = ConfigDict(extra="ignore")

    pid: int = 0
    ppid: int = 0
    name: str = ""
    command_line: str = ""
    first_seen: str = ""
    calls: list[dict[str, Any]] = Field(default_factory=list)


class SandboxSignatureRow(BaseModel):
    """One sandbox signature hit, marks carried through unprocessed."""

    model_config = ConfigDict(extra="ignore")

    name: str = ""
    description: str = ""
    severity: int = 0
    marks: list[Any] = Field(default_factory=list)
    ttp_tags: list[str] = Field(default_factory=list)


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


class SandboxReport(BaseModel):
    """The sandbox-agnostic report. ``provider``/``source_format`` are the one
    thing every reader needs and nothing can infer, so they are the two
    required fields; everything else defaults to empty."""

    model_config = ConfigDict(extra="ignore")

    provider: str
    source_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"]
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
    channels: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    screenshots: list[dict[str, Any]] = Field(default_factory=list)
    cti: dict[str, Any] = Field(default_factory=dict)
    unavailable: list[str] = Field(default_factory=list)
    # The run-time limit the sandbox set for the task, in seconds, as its own
    # report says (Triage's task ``timeout``): the limit, not a measured
    # duration, and never the value this platform asked for. ``None`` where the
    # report says nothing.
    run_limit_seconds: int | None = None
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


_SUMMARY_KEYS: tuple[str, ...] = (
    "files",
    "write_files",
    "modified_files",
    "wrote_files",
    # The three channels an agent asks about when it is hunting persistence
    # and host artefacts. They were passed over while the report's dynamic
    # section was recomputed from ``behavior`` inside the report builder; now
    # that an agent has to ask, a channel the render drops is a question the
    # agent cannot get an answer to.
    "mutexes",
    "executed_commands",
    "created_services",
    "started_services",
)

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


def cape_report_to_sandbox_report(
    raw: dict[str, Any],
    *,
    provider: str,
    source_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"] = "cape2",
    task_id: str = "",
) -> SandboxReport:
    """Read a CAPE/Cuckoo-shaped report into the neutral model, keeping ``raw``.

    Deliberately lossless in one direction only: everything the neutral model
    names is copied out, and the original dict is carried whole in ``raw`` so
    ``to_cape_shaped_dict`` can hand today's consumers the very object they
    would have received before the provider layer existed.
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
            calls=[c for c in (p.get("calls") or []) if isinstance(c, dict)],
        )
        for p in (behavior.get("processes") or [])
        if isinstance(p, dict)
    ]
    signatures = [
        SandboxSignatureRow(
            name=str(s.get("name") or ""),
            description=str(s.get("description") or s.get("name") or ""),
            severity=_int(s.get("severity") or s.get("score")),
            marks=list(s.get("marks") or []),
            ttp_tags=_as_str_list(s.get("ttp_tags") or s.get("attck_id")),
        )
        for s in (raw.get("signatures") or [])
        if isinstance(s, dict)
    ]
    return SandboxReport(
        provider=provider,
        source_format=source_format,
        task_id=str(task_id or (raw.get("info") or {}).get("id") or ""),
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
        ),
        processes=processes,
        apistats={
            str(pid): {str(api): _int(n) for api, n in (stats or {}).items()}
            for pid, stats in (behavior.get("apistats") or {}).items()
            if isinstance(stats, dict)
        },
        generic_events=[g for g in (behavior.get("generic") or []) if isinstance(g, dict)],
        signatures=signatures,
        network=SandboxNetwork(
            dns=_rows(net.get("dns")),
            http=_rows(net.get("http")),
            tcp=_rows(net.get("tcp")),
            udp=_rows(net.get("udp")),
            hosts=_rows(net.get("hosts")),
            domains=list(net.get("domains") or []),
            tls=_rows(net.get("tls")),
            icmp=_rows(net.get("icmp")),
            pcap_local_path=net.get("pcap_local_path") or None,
        ),
        dropped_files=_rows(raw.get("dropped")),
        registry=_as_str_list((behavior.get("summary") or {}).get("keys")),
        channels=_cape_channels(raw, behavior),
        screenshots=_rows(raw.get("screenshots")),
        cti=cti_field if isinstance(cti_field, dict) else {},
        unavailable=[],
        synthetic=bool(raw.get("synthetic")),
        raw=raw,
        summary={key: _as_str_list(summary_raw.get(key)) for key in _SUMMARY_KEYS},
        file_writes=_as_str_list(raw.get("file_writes") or raw.get("files_written")),
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    """Split Triage's combined ``"host:port"`` flow endpoint.

    Triage's dynamic-report flows carry the destination as one string rather
    than separate host/port fields (confirmed against the "Dynamic Report"
    docs page on 2026-09-04). A value with no trailing ``:<digits>`` is kept
    whole as the host, port ``None`` — this also covers a bare IPv6 address,
    which is never mistaken for a port suffix since the part after the last
    ``:`` would not be all-digits.
    """
    host, sep, port_str = value.rpartition(":")
    if sep and port_str.isdigit():
        return host, int(port_str)
    return value, None


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
# row whose attribution is therefore not stated: ``"orig"`` when Triage marks
# it and it runs none of the submitted file's names and descends from none of
# its processes, ``"file"`` when it runs the submitted file (or descends from a
# process that does) and Triage marks it not.
LINEAGE_DISPUTED_KEY = "lineage_disputed"


def _reach(parent: dict[Any, Any], roots: set[Any]) -> set[Any]:
    """Every listed process whose parent chain reaches one of ``roots``, the roots included."""
    tree: set[Any] = set()
    for procid in parent:
        seen: set[Any] = set()
        current = procid
        while current and current not in seen:
            if current in roots:
                tree.add(procid)
                break
            seen.add(current)
            current = parent.get(current)
    return tree


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
        disputed = {procid: "orig" for procid in by_mark - by_file}
        disputed.update({procid: "file" for procid in by_file - by_mark})
        return _Lineage(by_mark & by_file, disputed, images, True)
    return _Lineage(by_mark or by_file, {}, images, bool(marked or named))


def _flow_attribution(flow: dict[str, Any], lineage: _Lineage) -> dict[str, Any]:
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


def triage_overview_to_sandbox_report(
    overview: dict[str, Any],
    *,
    provider: str = "triage",
    task_reports: dict[str, dict[str, Any]] | None = None,
    task_id: str = "",
) -> SandboxReport:
    """Map a Triage overview (plus its behavioural task reports) onto the model.

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

    sample_field, analysis_field = overview.get("sample"), overview.get("analysis")
    sample = sample_field if isinstance(sample_field, dict) else {}
    analysis = analysis_field if isinstance(analysis_field, dict) else {}
    processes: list[SandboxProcess] = []
    dropped_files: list[dict[str, Any]] = []
    network = SandboxNetwork()
    hosts_by_ip: dict[str, dict[str, Any]] = {}
    for task in (task_reports or {}).values():
        lineage = _sample_process_tree(task, sample)
        for proc in task.get("processes") or []:
            if not isinstance(proc, dict):
                continue
            processes.append(
                SandboxProcess(
                    pid=_int(proc.get("procid") or proc.get("pid")),
                    ppid=_int(proc.get("procid_parent") or proc.get("ppid")),
                    name=str(proc.get("image") or proc.get("name") or ""),
                    command_line=str(proc.get("cmd") or ""),
                    first_seen=str(proc.get("started") or ""),
                    calls=[],
                )
            )
        dumped_field = task.get("dumped")
        dropped_files.extend(_rows(dumped_field))

        net_field = task.get("network")
        net = net_field if isinstance(net_field, dict) else {}

        for flow in _rows(net.get("flows")):
            proto = str(flow.get("proto") or "").lower()
            dst_host, dst_port = _split_host_port(str(flow.get("dst") or ""))
            if not dst_host:
                continue
            row: dict[str, Any] = {"dst": dst_host, "dport": dst_port}
            row.update(_flow_attribution(flow, lineage))
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

            if domain_req is not None:
                answers = [
                    {"data": str(a["value"])}
                    for a in _rows((domain_resp or {}).get("answers"))
                    if a.get("value")
                ]
                for question in _rows(domain_req.get("questions")):
                    name = str(question.get("name") or "")
                    if not name:
                        continue
                    network.dns.append(
                        {
                            "request": name,
                            "type": str(question.get("type") or ""),
                            "answers": answers,
                        }
                    )
                    network.domains.append(name)

            if web_req is not None:
                parsed_url = urlsplit(str(web_req.get("url") or ""))
                headers_field = web_req.get("headers")
                headers = headers_field if isinstance(headers_field, dict) else {}
                network.http.append(
                    {
                        "host": parsed_url.hostname or "",
                        "uri": parsed_url.path or "/",
                        "method": str(web_req.get("method") or ""),
                        "status": (web_resp or {}).get("status"),
                        "port": parsed_url.port,
                        "encrypted": parsed_url.scheme == "https",
                        "user_agent": str(headers.get("User-Agent") or ""),
                    }
                )
    network.hosts = list(hosts_by_ip.values())

    return SandboxReport(
        provider=provider,
        source_format="triage",
        task_id=str(task_id or sample.get("id") or ""),
        target=SandboxTarget(
            sha256=str(sample.get("sha256") or ""),
            md5=str(sample.get("md5") or ""),
            name=str(sample.get("target") or ""),
            file_type=str(sample.get("kind") or ""),
            mime_type=str(sample.get("kind") or ""),
            size=_int(sample.get("size")),
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
            )
            for s in (overview.get("signatures") or [])
            if isinstance(s, dict)
        ],
        network=network,
        dropped_files=dropped_files,
        registry=[],
        screenshots=[],
        cti={"family": _as_str_list(analysis.get("family")), "score": analysis.get("score")},
        unavailable=list(TriageSandboxProvider.UNAVAILABLE),
        run_limit_seconds=_triage_run_limit(overview),
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
