"""The job's sandbox report, as tools instead of one wall of JSON.

The report is the neutral sandbox report's document
(``schemas.sandbox_document``), whichever sandbox and reader produced it; each
tool reads its parts by name (``place``), never by a sandbox's own key.

The dynamic analyst has always been handed the whole report as text, chunked
to fit and truncated where it did not. That is the wrong shape for a model
that wants three specific things: what ran, what it talked to, and what the
sandbox's own signatures said. These tools let it ask.

In-process on purpose — there is no server to open, no transport to bind and
nothing to time out, because the report is already in the container. That is
what ``ToolRef(kind="sandbox")`` resolves to: a tool set built from the report
the job already downloaded.

One of the tools, ``sandbox_items``, reads the report as the sections of
``analysis.sandbox_sections``: whole items, each with the id a claim cites it
by, filtered by section, process id, a substring of any text value, a
signature or a list of ids. It is the one tool of the set another analyst may
be given on its own (``BaseAnalyst._sandbox_items_tool``).

A report the container does not have yields the same tools, each answering
``{"error": "no sandbox report for this job"}``, and the mock sandbox's empty
stand-in yields tools answering the sentence that says no sandbox ran. The
agent then knows the channel is empty rather than silently seeing tools that
return nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.pipeline.sandbox_status import NOT_RUN, sandbox_status
from maljan.providers.call_arguments import pick_argument
from maljan.schemas.sandbox_document import place
from maljan.utils.marked_cut import marked_cut

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

# Every list a tool answers with is the whole list unless the caller asks for
# a page: ``offset`` is where the page starts and ``limit`` how many rows it
# holds, 0 for all of them. A page that stops short says so — ``N of M rows``
# and the ``next_offset`` to ask for — and how much of an answer a model reads
# at once is the platform's tool-answer sizing to decide, which says what it
# cut. A fixed row count used to cut every view at 200 rows without a word to
# the projection that read it, and an address past row 200 never reached the
# report.


def _page(rows: Sequence[Any], offset: Any = 0, limit: Any = 0) -> tuple[list[Any], dict[str, Any]]:
    """One page of ``rows`` and what it says about itself when it is not all of them."""
    start = max(0, _count(offset))
    wanted = _count(limit)
    stop = start + wanted if wanted > 0 else len(rows)
    shown = list(rows[start:stop])
    if start == 0 and len(shown) == len(rows):
        return shown, {}
    meta: dict[str, Any] = {"shown": f"{len(shown)} of {len(rows)} rows, from offset {start}"}
    if stop < len(rows):
        meta["next_offset"] = stop
    return shown, meta


def _count(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


_NO_REPORT = {"error": "no sandbox report for this job", "tool": "sandbox"}


def _no_sandbox_ran(report: dict[str, Any]) -> bool:
    """Whether ``report`` is one no sandbox produced: the mock's stand-in."""
    return sandbox_status(report).status == NOT_RUN


def _no_report(report: dict[str, Any] | None) -> dict[str, Any]:
    """The answer every tool gives where no sandbox ran, saying which absence it is.

    The mock sandbox's stand-in has well-formed empty sections, and a tool
    that read them would answer "0 processes" about a detonation that never
    happened.
    """
    if report is None:
        return dict(_NO_REPORT)
    return {"error": sandbox_status(report).statement, "tool": "sandbox"}


def _report_of(container: Any) -> dict[str, Any] | None:
    """The job's sandbox report as the neutral report's document every reader reads.

    ``container.sandbox_report`` is set by ``app.arun`` alongside
    ``sample_format``, for the same reason: agents are built lazily, from nodes
    that do not all carry the graph state. A ``SandboxReport`` assigned there
    instead of its document is laid out (``schemas.sandbox_document``) so both
    forms read identically here.
    """
    report = getattr(container, "sandbox_report", None)
    if report is None:
        return None
    if isinstance(report, dict):
        return report
    try:
        from maljan.schemas.sandbox_document import sandbox_document

        return sandbox_document(report)
    except Exception as exc:  # noqa: BLE001 — an unreadable report is an empty one
        logger.warning("sandbox tools: could not lay out the report (%s).", type(exc).__name__)
        return None


def _list_at(report: dict[str, Any], name: str) -> list[Any] | None:
    """The part ``name`` of the report where it is a list, else ``None``."""
    value = place(report, name)
    return value if isinstance(value, list) else None


# What a view says of a part the report does not hold. An empty list says the
# sandbox watched and saw nothing; a part that is not there says nothing
# either way, and answering it as ``[]`` read as "no network activity".
_ABSENT_STATEMENT = (
    "The report does not hold this part, so whether there was any is not known. "
    "This is not the same as none."
)


def _absent(*parts: str) -> dict[str, Any]:
    """The answer for parts the report does not hold: named absent, with no empty list."""
    return {"absent": list(parts), "statement": _ABSENT_STATEMENT}


def _unavailable(report: dict[str, Any]) -> frozenset[str]:
    """The report's own ``unavailable`` list, each name as the platform's section id.

    A reader lays every part out, as an empty list where its sandbox could not
    give it, and names those parts here; read alone, the empty list would say
    "none observed".
    """
    from maljan.schemas.sandbox_report import section_id

    named = place(report, "unavailable")
    return frozenset(section_id(n) for n in named) if isinstance(named, list) else frozenset()


def _fills(normalised_by: Sequence[str] | None) -> frozenset[str] | None:
    """The list fields the job's reader declares it fills, or ``None`` when it is not known.

    ``normalised_by`` is ``(provider, source_format[, read_from])``
    (``normalised_by_of``); the declaration is the reader's own
    (``schemas.sandbox_report.normaliser_reading``), the one the sandbox
    sections read too.
    """
    if not normalised_by or len(normalised_by) not in (2, 3):
        return None
    from maljan.schemas.sandbox_report import normaliser_reading

    provider, source_format, *rest = (str(part or "").strip() for part in normalised_by)
    reading = normaliser_reading(source_format, provider, rest[0] if rest else "")
    return reading.fills if reading is not None else None


# A view's source under the reader's word for it, where the two differ
# (``schemas.sandbox_report.REPORT_LIST_FIELDS``); every other source is its own.
_FILL_NAMES: dict[str, str] = {"calls": "processes.calls"}


def _held(
    report: dict[str, Any],
    part: str,
    unavailable: frozenset[str],
    fills: frozenset[str] | None = None,
) -> bool:
    """Whether the report holds ``part``: present, filled by its reader, not named unavailable.

    A part the job's reader declares it never fills (``fills``) is laid out
    empty whatever the sandbox saw, and is not held. A part is named
    unavailable by its own name, by its last component (``dns`` for
    ``network.dns``, ``mutexes`` for ``summary.mutexes``), or, for a network
    kind, by ``network``. ``calls`` is held where the flat call list or any
    process's own call list is present (``api_calls`` names it).
    """
    from maljan.schemas.sandbox_report import section_id

    if fills is not None and _FILL_NAMES.get(part, part) not in fills:
        return False
    leaf = part.rsplit(".", 1)[-1]
    names = {section_id(part), section_id(leaf)}
    if part.startswith("network."):
        names.add("network")
    if names & unavailable:
        return False
    if part == "calls":
        if isinstance(place(report, "calls"), list):
            return True
        return any(
            isinstance(proc, dict) and isinstance(proc.get("calls"), list)
            for proc in _list_at(report, "processes") or []
        )
    return place(report, part) is not None


def _absent_of(
    report: dict[str, Any], *sources: str, normalised_by: Sequence[str] | None = None
) -> dict[str, Any] | None:
    """``_absent`` naming ``sources`` when the report holds none of them, else ``None``."""
    unavailable, fills = _unavailable(report), _fills(normalised_by)
    if any(_held(report, source, unavailable, fills) for source in sources):
        return None
    return _absent(*sources)


def sandbox_report_section(
    report: dict[str, Any] | None, section: str, offset: int = 0, limit: int = 0
) -> dict[str, Any]:
    """One top-level section of the report, bounded.

    The escape hatch for a section the other tools do not model — ``target``,
    ``cti``, ``extracted``, ``memory``, ``ids`` or any block a sandbox published
    with no place of its own, under its own name. The section names are listed
    in the answer when the requested one is absent, so a model that guessed
    wrong can correct itself in one turn instead of guessing again.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    key = str(section).strip()
    if key not in report:
        return {
            "error": f"no section {key!r} in the report",
            "sections": sorted(str(k) for k in report),
        }
    value = report[key]
    if isinstance(value, list):
        rows, meta = _page(value, offset, limit)
        return {"section": key, "rows": rows, "total": len(value), **meta}
    return {"section": key, "value": _without_host_paths(value)}


# Where the platform recorded the capture it fetched beside the report. A host
# path, written by the platform and not by the sandbox, and a section answer is
# read by a model: it is named the way the job's capture tools take it back.
_CAPTURE_KEY = "pcap_local_path"


def _without_host_paths(value: Any) -> Any:
    if not isinstance(value, dict) or not value.get(_CAPTURE_KEY):
        return value
    from maljan.tools.staging import job_relative

    return {**value, _CAPTURE_KEY: job_relative(str(value[_CAPTURE_KEY]))}


def sandbox_processes(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The process tree: pid, parent, name and command line, one row each.

    Without the API calls. The call list is where a behaviour report's bulk
    is, and a process tree is the thing an analyst reads first — they are two
    different questions and answering both at once makes the cheap one
    expensive.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    processes = place(report, "processes")
    if not isinstance(processes, list) or _absent_of(
        report, "processes", normalised_by=normalised_by
    ):
        return _absent("processes")
    rows: list[dict[str, Any]] = []
    page, meta = _page(processes, offset, limit)
    if page:
        for proc in page:
            if not isinstance(proc, dict):
                continue
            rows.append(
                {
                    "pid": proc.get("pid"),
                    "ppid": proc.get("ppid") or proc.get("parent_id"),
                    "name": proc.get("process_name") or proc.get("name") or "",
                    "command_line": proc.get("command_line") or proc.get("cmd") or "",
                    "first_seen": proc.get("first_seen"),
                    "call_count": len(proc.get("calls") or []),
                }
            )
    return {"processes": rows, "total": len(processes), **meta}


def sandbox_network(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """DNS lookups, hosts, HTTP requests, TCP/UDP endpoints and TLS, per kind.

    Every row of every kind. A page (``offset``/``limit``) is taken per kind, so
    a sample that made a thousand DNS lookups cannot push its two HTTP requests
    off the page, and a kind cut short says ``<kind>_total`` and
    ``<kind>_next_offset``.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    unavailable, fills = _unavailable(report), _fills(normalised_by)
    if not isinstance(report.get("network"), dict) or "network" in unavailable:
        return _absent("network")
    out: dict[str, Any] = {}
    absent: list[str] = []
    for key in NETWORK_VIEW_KINDS:
        rows = _list_at(report, f"network.{key}")
        if rows is None or not _held(report, f"network.{key}", unavailable, fills):
            absent.append(f"network.{key}")
        else:
            page, meta = _page(rows, offset, limit)
            out[key] = [_with_resolver_fact(row) for row in page]
            if meta:
                out[f"{key}_total"] = len(rows)
                if "next_offset" in meta:
                    out[f"{key}_next_offset"] = meta["next_offset"]
    if absent:
        out.update(_absent(*absent))
    return out


# The kinds the network view lists, in its order; the sandbox sections number
# their network items in this same order (``analysis.sandbox_sections``).
NETWORK_VIEW_KINDS: tuple[str, ...] = (
    "dns",
    "hosts",
    "http",
    "tcp",
    "udp",
    "domains",
    "icmp",
    "tls",
)


def _with_resolver_fact(row: Any) -> Any:
    """A flow or host row, marked ``public_resolver`` when it names a public DNS resolver.

    A platform fact beside the sandbox's own: a sandbox's guest resolves
    through a public resolver whatever the sample does, so an analyst reading
    a row to one is told what the address is before it reads it as a contact.
    """
    if not isinstance(row, dict):
        return row
    from maljan.extractors.network_extractor import is_public_resolver

    address = row.get("dst") or row.get("ip") or row.get("address")
    if isinstance(address, str) and is_public_resolver(address):
        return {**row, "public_resolver": True}
    return row


def _signature_techniques(sig: Mapping[str, Any]) -> list[str]:
    """The ATT&CK ids a sandbox tags one signature with, read from any field it uses.

    The normalised report's ``ttp_tags`` and the raw shapes it is read from
    (``ttp``, ``ttps``, ``attck_id``, ``technique_ids``), each read as the ids
    it writes (``analysis.technique_ids.technique_ids_in``); never the
    signature's name.
    """
    from maljan.analysis.technique_ids import technique_ids_in

    found: dict[str, None] = {}
    for key in ("ttp_tags", "ttp", "ttps", "attck_id", "technique_ids"):
        value = sig.get(key)
        for item in value if isinstance(value, list) else [value]:
            if item:
                found.update(dict.fromkeys(technique_ids_in(item)))
    return list(found)


def sandbox_signatures(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The sandbox's own signature hits, with their severity.

    Reported as what they are — one detection engine's opinion — not folded
    into the verdict. A sandbox signature firing is evidence the agent weighs
    alongside everything else it found.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    signatures = place(report, "signatures")
    if not isinstance(signatures, list) or _absent_of(
        report, "signatures", normalised_by=normalised_by
    ):
        return _absent("signatures")
    rows: list[dict[str, Any]] = []
    page, meta = _page(signatures, offset, limit)
    if page:
        for sig in page:
            if not isinstance(sig, dict):
                continue
            row = {
                "name": sig.get("name") or sig.get("signature") or "",
                "description": sig.get("description") or "",
                "severity": sig.get("severity"),
                "confidence": sig.get("confidence"),
                "references": list(sig.get("references") or [])[:5],
            }
            # The technique ids the sandbox itself tags the signature with, as
            # its report declares them, under the key the tool's declaration
            # reads technique ids from (``technique_ids``). Left out where the
            # sandbox declares none, so an answer without tags is as it was.
            tags = _signature_techniques(sig)
            if tags:
                row["technique_ids"] = tags
            rows.append(row)
    return {"signatures": rows, "total": len(signatures), **meta}


def sandbox_dropped_files(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Files the sample wrote, with the hashes the sandbox computed for them."""
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    dropped = place(report, "dropped_files")
    if not isinstance(dropped, list):
        # A document written before the parts were declared named the list so.
        dropped = report.get("dropped_files")
    if (
        not isinstance(dropped, list)
        or {"dropped_files", "dropped"} & _unavailable(report)
        or "dropped_files" not in (_fills(normalised_by) or {"dropped_files"})
    ):
        return _absent("dropped_files")
    rows: list[dict[str, Any]] = []
    page, meta = _page(dropped, offset, limit)
    if page:
        for entry in page:
            if not isinstance(entry, dict):
                continue
            rows.append(
                {
                    "name": entry.get("name") or entry.get("filepath") or "",
                    "path": entry.get("filepath") or entry.get("guest_paths") or "",
                    "size": entry.get("size"),
                    "sha256": entry.get("sha256"),
                    "type": entry.get("type"),
                }
            )
    return {"dropped": rows, "total": len(dropped), **meta}


# Registry APIs, and what each one does to the key it names. A call the table
# does not know is still reported, as ``access`` — the key it touched is the
# fact, and guessing the verb would be worse than saying the honest word.
_REGISTRY_OPS: dict[str, str] = {
    "regsetvalueexa": "modify",
    "regsetvalueexw": "modify",
    "ntsetvaluekey": "modify",
    "regcreatekeyexa": "create",
    "regcreatekeyexw": "create",
    "ntcreatekey": "create",
    "regdeletekeya": "delete",
    "regdeletekeyw": "delete",
    "regdeletekeyexa": "delete",
    "regdeletekeyexw": "delete",
    "regdeletevaluea": "delete",
    "regdeletevaluew": "delete",
    "ntdeletekey": "delete",
    "ntdeletevaluekey": "delete",
    "regqueryvalueexa": "query",
    "regqueryvalueexw": "query",
    "ntqueryvaluekey": "query",
    "regopenkeyexa": "query",
    "regopenkeyexw": "query",
    "ntopenkey": "query",
    "ntopenkeyex": "query",
}

# What a call says it did, where the operation its API names is only what it
# may do: for each such operation, the argument the outcome is filed under and
# what each recorded value means. A create call opens the key when it already
# exists and says so in its disposition (1 created a new key, 2 opened an
# existing one), and a key only opened was read, not created. A call that
# records no outcome, or one this table does not know, keeps its API's
# operation.
_REGISTRY_OUTCOMES: dict[str, tuple[str, dict[int, str]]] = {
    "create": ("Disposition", {1: "create", 2: "query"}),
}

# A write the call itself reports as failed (``status`` false) changed
# nothing: the key was reached and that is all, so it is recorded as bare
# access, which any read or write of the key replaces.
_FAILED_WRITE = "access"

# What one operation on a key says, against another on the same key: the bare
# fact of access least, a read more, a write most.
_REGISTRY_OP_WEIGHT: dict[str, int] = {
    "access": 0,
    "query": 1,
    "create": 2,
    "modify": 2,
    "delete": 2,
}

# The argument names each reader takes its value from, most wanted first: a
# call's own argument order never decides. A registry key is a full path before
# a subkey and a subkey before the bare hive handle (``Registry``), which is
# the key only for a call that names nothing else; a value is what was written
# or, for a query, what was read (``Data``, or ``Information`` for the native
# value query); a service is its name, under either spelling, before its
# display name or the binary it runs.
_REGISTRY_KEY_ARGS = ("FullName", "KeyName", "ObjectAttributes", "SubKey", "Registry")
_REGISTRY_VALUE_ARGS = ("Buffer", "Data", "ValueData", "Value", "Information")
_MUTEX_APIS = frozenset({"ntcreatemutant", "ntopenmutant", "createmutexa", "createmutexw"})
_MUTEX_ARGS = ("MutexName", "lpName", "ObjectAttributes", "Name")
_SERVICE_APIS = frozenset({"createservicea", "createservicew", "startservicea", "startservicew"})
_SERVICE_ARGS = ("ServiceName", "lpServiceName", "DisplayName", "BinaryPathName")


def _calls(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every API call the report recorded, however it filed them.

    A report may carry a flat call list and also one list per process; a
    report that has both would double-count, so the flat list wins when it is
    there.
    """
    flat = place(report, "calls")
    if isinstance(flat, list) and flat:
        return [row for row in flat if isinstance(row, dict)]
    out: list[dict[str, Any]] = []
    for proc in _list_at(report, "processes") or []:
        if isinstance(proc, dict):
            out.extend(row for row in (proc.get("calls") or []) if isinstance(row, dict))
    return out


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _argument(call: dict[str, Any], names: tuple[str, ...]) -> str:
    """The text of the first of ``names``, in that order, this call carries.

    Whichever shape the call filed its arguments in; see ``call_arguments``.
    """
    value = pick_argument(call.get("arguments"), names, accept=_text)
    return value.strip() if isinstance(value, str) else ""


def _summary_list(report: dict[str, Any], name: str) -> list[str]:
    """The text entries of the behaviour summary's part ``name``."""
    values = place(report, name)
    return [str(v) for v in values if isinstance(v, str)] if isinstance(values, list) else []


def _registry_operation(call: dict[str, Any], operation: str) -> str:
    """What ``call`` did to its key: its API's operation, as the call's own outcome refines it."""
    if operation != "query" and call.get("status") is False:
        return _FAILED_WRITE
    outcome = _REGISTRY_OUTCOMES.get(operation)
    if outcome is None:
        return operation
    name, meanings = outcome
    code = _outcome_code(pick_argument(call.get("arguments"), (name,)))
    return operation if code is None else meanings.get(code, operation)


def _outcome_code(recorded: Any) -> int | None:
    """An outcome a call recorded, as the number it is: filed as an integer or as text.

    Text is read as written, a ``0x`` prefix as hexadecimal and leading zeros
    as decimal (``"02"`` is 2); anything else is no outcome.
    """
    if isinstance(recorded, bool):
        return None
    if isinstance(recorded, int):
        return recorded
    if not isinstance(recorded, str):
        return None
    text = recorded.strip()
    for base in (0, 10):
        try:
            return int(text, base)
        except ValueError:
            continue
    return None


def sandbox_registry_ops(
    report: dict[str, Any] | None,
    limit: int = 0,
    offset: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Registry keys the sample touched, with the operation and the value written.

    Two sources, because sandboxes fill them unevenly: the behaviour summary's
    key list, which says a key was touched and nothing else, and the registry
    API calls themselves, which say what was done and what was written. The
    call wins where both name the same key — an operation is worth more than
    the bare fact of access — and for the same reason a read never replaces a
    write: a key created, modified or deleted and then read stays the write,
    with what was written, and a read that saw no value leaves an earlier
    read's value standing. Between writes the later one in the report's order
    stands; that order is the report's process by process, not time.

    A call's own outcome refines what its API may do (``_REGISTRY_OUTCOMES``):
    a create that opened an existing key is a read. A write the call reports as
    failed is bare access, without the value it did not write.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(report, "registry", "calls", normalised_by=normalised_by)
    if missing is not None:
        return missing
    rows: dict[str, dict[str, Any]] = {}
    for key in _summary_list(report, "registry"):
        rows.setdefault(key, {"key": key, "operation": "access", "value": None})
    for call in _calls(report):
        api = str(call.get("api") or "")
        # Zw* and Nt* are the same native call; the table lists the Nt name.
        name = api.lower()
        if name.startswith("zw"):
            name = "nt" + name[2:]
        listed = _REGISTRY_OPS.get(name)
        if listed is None:
            continue
        key = _argument(call, _REGISTRY_KEY_ARGS)
        if not key:
            continue
        operation = _registry_operation(call, listed)
        value = _argument(call, _REGISTRY_VALUE_ARGS) or None
        if operation == _FAILED_WRITE:
            value = None
        before = rows.get(key)
        if before is not None:
            if _REGISTRY_OP_WEIGHT[operation] < _REGISTRY_OP_WEIGHT[before["operation"]]:
                continue
            if operation == before["operation"] == "query" and value is None:
                continue
        rows[key] = {"key": key, "operation": operation, "value": value}
    ordered = list(rows.values())
    page, meta = _page(ordered, offset, limit)
    return {"registry": page, "total": len(ordered), **meta}


# How many of an API's calling processes one row names, in name order.
_CALLERS_PER_API = 8
# How much of one call's arguments a row quotes; a longer one ends in the cut mark.
_FIRST_ARGS_CHARS = 400


def _calls_by_process(report: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Every API call with the pid that made it, ``""`` when the report lost it.

    The same walk as :func:`_calls`, keeping the process each nested list
    belongs to; a flat call list carries its pid on the row or not at all.
    """
    flat = place(report, "calls")
    if isinstance(flat, list) and flat:
        return [(str(row.get("pid") or ""), row) for row in flat if isinstance(row, dict)]
    out: list[tuple[str, dict[str, Any]]] = []
    for proc in _list_at(report, "processes") or []:
        if isinstance(proc, dict):
            pid = str(proc.get("pid") or "")
            out.extend((pid, row) for row in (proc.get("calls") or []) if isinstance(row, dict))
    return out


def sandbox_api_calls(
    report: dict[str, Any] | None,
    process: str | None = None,
    name: str | None = None,
    limit: int = 0,
    offset: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The API-call histogram, with the first call of each API.

    The call stream itself is where a behaviour report's bulk is, so what comes
    back is one row per API rather than one per call: the name, the module the
    sandbox resolved it from when it recorded one, the first eight processes
    that made it by name, how often, and the arguments and time of the first
    call, which is usually the one that says what the sample was after.
    ``process`` narrows by pid or process name, ``name`` by a substring of the
    API name.

    What the sandbox recorded and nothing else. The rows used to carry a
    behaviour category and a suspicious flag copied from the import table,
    which was this tool doing the analysis; what an API is used for is the
    knowledge server's ``api_capability`` question, asked when the model
    decides the answer matters.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(report, "apistats", "calls", normalised_by=normalised_by)
    if missing is not None:
        return missing

    names_by_pid = {
        str(proc.get("pid")): str(proc.get("process_name") or proc.get("name") or "")
        for proc in _list_at(report, "processes") or []
        if isinstance(proc, dict)
    }
    wanted_process = (process or "").strip().lower()
    wanted_name = (name or "").strip().lower()

    def _is_wanted(pid: str) -> bool:
        if not wanted_process:
            return True
        return wanted_process in {pid.lower(), names_by_pid.get(pid, "").lower()}

    def _label(pid: str) -> str:
        return names_by_pid.get(pid) or pid

    counts: dict[str, int] = {}
    callers: dict[str, set[str]] = {}
    apistats = place(report, "apistats")
    if isinstance(apistats, dict):
        for pid, stats in apistats.items():
            if not _is_wanted(str(pid)) or not isinstance(stats, dict):
                continue
            for api, count in stats.items():
                try:
                    counts[str(api)] = counts.get(str(api), 0) + int(count)
                except (TypeError, ValueError):
                    continue
                if _label(str(pid)):
                    callers.setdefault(str(api), set()).add(_label(str(pid)))

    first_call: dict[str, dict[str, Any]] = {}
    left_out = 0
    for pid, call in _calls_by_process(report):
        api = str(call.get("api") or "")
        if api and not pid and wanted_process:
            left_out += 1
        # With a process asked for, a call the report gave no pid cannot be
        # said to be that process's: it is left out rather than listed under it.
        if not api or (not pid and wanted_process) or (pid and not _is_wanted(pid)):
            continue
        counts.setdefault(api, 0)
        if pid and _label(pid):
            callers.setdefault(api, set()).add(_label(pid))
        if api not in first_call:
            first_call[api] = call

    rows: list[dict[str, Any]] = []
    for api, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        if wanted_name and wanted_name not in api.lower():
            continue
        call = first_call.get(api, {})
        arguments = call.get("arguments")
        module = call.get("dll") or call.get("module")
        seen = call.get("timestamp") or call.get("time")
        rows.append(
            {
                "api": api,
                "dll": str(module) if module else None,
                "processes": sorted(callers.get(api, set()))[:_CALLERS_PER_API],
                # How many processes called it, beside the few named.
                "process_count": len(callers.get(api, set())),
                "count": count,
                "first_args": marked_cut(str(arguments), _FIRST_ARGS_CHARS) if arguments else "",
                "first_seen": str(seen) if seen not in (None, "") else None,
            }
        )
    page, meta = _page(rows, offset, limit)
    answer: dict[str, Any] = {"apis": page, "total": len(rows), **meta}
    if left_out:
        # Said, not dropped: these calls may be the asked process's.
        answer["left_out_without_pid"] = left_out
    return answer


def sandbox_mutexes(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """The named mutexes the sample created or opened.

    A mutex name is often the one durable string a family carries across
    builds, which is why it gets a tool of its own rather than a filter over
    the call stream.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(report, "summary.mutexes", "calls", normalised_by=normalised_by)
    if missing is not None:
        return missing
    names: list[str] = list(_summary_list(report, "summary.mutexes"))
    for call in _calls(report):
        if str(call.get("api") or "").lower() not in _MUTEX_APIS:
            continue
        name = _argument(call, _MUTEX_ARGS)
        if name and name not in names:
            names.append(name)
    page, meta = _page(names, offset, limit)
    return {"mutexes": page, "total": len(names), **meta}


def sandbox_services_and_tasks(
    report: dict[str, Any] | None,
    offset: int = 0,
    limit: int = 0,
    *,
    normalised_by: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Services installed or started, scheduled tasks, and the commands run.

    Three answers in one call because they are one question — what did the
    sample arrange to happen again — and an agent that had to make three calls
    to ask it would routinely make one and miss the other two.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    missing = _absent_of(
        report,
        "summary.created_services",
        "summary.started_services",
        "summary.executed_commands",
        "calls",
        normalised_by=normalised_by,
    )
    if missing is not None:
        return missing
    services: list[str] = [
        *_summary_list(report, "summary.created_services"),
        *_summary_list(report, "summary.started_services"),
    ]
    commands: list[str] = list(_summary_list(report, "summary.executed_commands"))
    tasks: list[str] = [cmd for cmd in commands if "schtasks" in cmd.lower()]
    for call in _calls(report):
        api = str(call.get("api") or "").lower()
        if api in _SERVICE_APIS:
            name = _argument(call, _SERVICE_ARGS)
            if name and name not in services:
                services.append(name)
    deduped_services = list(dict.fromkeys(services))
    out: dict[str, Any] = {"total": len(deduped_services) + len(tasks) + len(commands)}
    for key, rows in (("services", deduped_services), ("tasks", tasks), ("commands", commands)):
        page, meta = _page(rows, offset, limit)
        out[key] = page
        if meta:
            out[f"{key}_total"] = len(rows)
            if "next_offset" in meta:
                out[f"{key}_next_offset"] = meta["next_offset"]
    return out


def sandbox_channels(
    report: dict[str, Any] | None, name: str = "", offset: int = 0, limit: int = 0
) -> dict[str, Any]:
    """The platform-namespaced channels a non-Windows guest publishes.

    ``android.permissions``, ``linux.systemd``, ``macos.launchd`` and whatever
    else a sandbox has to say that the report's other parts have no home for.
    Called with no name it lists what exists, which is how an agent discovers a
    channel it did not know to ask for.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    channels = place(report, "channels")
    if not isinstance(channels, dict):
        return {"channels": [], "rows": []}
    available = sorted(str(k) for k in channels)
    key = str(name).strip()
    if not key:
        return {"channels": available, "rows": []}
    if key not in channels:
        return {"error": f"no channel {key!r}", "channels": available}
    from maljan.schemas.sandbox_document import channel_rows

    # A kept block's items are each a row, built only for the page asked.
    rows = channel_rows(channels[key]) or []
    page, meta = _page(rows, offset, limit)
    return {"channel": key, "rows": page, "total": len(rows), **meta}


def sandbox_items(
    report: dict[str, Any] | None,
    section: str,
    pid: Any = None,
    contains: str = "",
    signature: str = "",
    ids: list[str] | str | None = None,
    *,
    sections: Any = None,
    normalised_by: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    """The items of one section of the report, whole, each with its id and its report fields.

    Read-only over the report the job holds (``analysis.sandbox_sections``):
    no sandbox is asked anything. The filters combine; with none, every item
    of the section is answered. ``matched`` is how many items the filters
    keep, so an answer the guardrail shortens still says how many there are,
    and ``ids_not_read`` how many asked ids past the section's own size were
    not read. Nothing is summarised, ranked or labelled. ``sections`` is the
    report read once for the job (``items_tool`` holds it); without it the
    report is read for this call, as ``normalised_by`` produced it.
    """
    if report is None or _no_sandbox_ran(report):
        return _no_report(report)
    from maljan.analysis.sandbox_sections import (
        NO_PID_ROWS,
        SECTION_PREFIXES,
        Sections,
        names_processes,
        pid_of,
    )

    name = str(section or "").strip().lower()
    if name not in SECTION_PREFIXES:
        return {"error": ITEMS_NO_SECTION, "sections": list(SECTION_PREFIXES)}
    found = sections if isinstance(sections, Sections) else Sections(report, normalised_by)
    held = found.sections[name]
    if held.no:
        return {"section": name, "no": held.no}
    wanted_pid = None
    if pid not in (None, ""):
        if not names_processes(name):
            return {"section": name, "no": NO_PID_ROWS.format(section=name)}
        wanted_pid = pid_of(pid.strip() if isinstance(pid, str) else pid)
        if wanted_pid is None:
            return {"error": ITEMS_BAD_PID, "section": name}
    if str(signature or "").strip() and name != "signatures":
        return {"error": ITEMS_SIGNATURE_SECTION, "section": name}
    listed = re.split(r"[\s,;]+", ids) if isinstance(ids, str) else ids
    asked = [i for i in listed if i] if isinstance(listed, list) else []
    kept = found.query(
        name,
        pid=wanted_pid,
        contains=str(contains or ""),
        signature=str(signature or ""),
        ids=asked,
    )
    answer: dict[str, Any] = {"section": name, "matched": len(kept.items), "items": kept.items}
    if kept.missing:
        answer["not_in_section"] = kept.missing
    if kept.missing_more:
        answer["more_not_in_section"] = kept.missing_more
    if kept.not_read:
        answer["ids_not_read"] = kept.not_read
    return answer


# What ``sandbox_items`` answers for an argument it cannot read.
ITEMS_NO_SECTION = "no such section in the sandbox report; the sections are listed"
ITEMS_BAD_PID = "pid is not a process id in digits"
ITEMS_SIGNATURE_SECTION = "the signature filter reads the signatures section only"

# The arguments that narrow a ``sandbox_items`` answer, named in the notice a
# shortened answer carries.
_ITEM_FILTERS = ("pid", "contains", "signature", "ids")


def sandbox_tools(container: Any) -> list[BaseTool]:
    """The sandbox tools, each closed over this job's report.

    Built per resolution rather than once per process: the report is the job's,
    and a tool cached across jobs would answer the previous sample's questions.
    """
    from langchain_core.tools import StructuredTool

    report = _report_of(container)
    normalised_by = normalised_by_of(container)

    def _report_section(section: str, offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """Read one top-level section of the sandbox report by name.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_report_section(report, section, offset, limit)

    def _processes(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the processes the sandbox observed, with their command lines.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_processes(report, offset, limit, normalised_by=normalised_by)

    def _network(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the DNS lookups, hosts, HTTP requests and endpoints observed.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_network(report, offset, limit, normalised_by=normalised_by)

    def _signatures(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the sandbox's own signature hits and their severity.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_signatures(report, offset, limit, normalised_by=normalised_by)

    def _dropped_files(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the files the sample wrote, with their hashes.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_dropped_files(report, offset, limit, normalised_by=normalised_by)

    def _channels(name: str = "", offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the platform channels, or read one of them by name.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_channels(report, name, offset, limit)

    def _registry_ops(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the registry keys the sample touched, with what it did to each.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_registry_ops(report, limit, offset, normalised_by=normalised_by)

    def _api_calls(
        process: str = "", name: str = "", offset: int = 0, limit: int = 0
    ) -> dict[str, Any]:
        """List the API calls observed, by frequency, with each API's first call.

        ``process`` narrows to one pid or process name, ``name`` to APIs whose
        name contains the text. Rows carry what the sandbox recorded; ask
        api_capability what an API is used for.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_api_calls(
            report, process or None, name or None, limit, offset, normalised_by=normalised_by
        )

    def _mutexes(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List the named mutexes the sample created or opened.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_mutexes(report, offset, limit, normalised_by=normalised_by)

    def _services_and_tasks(offset: int = 0, limit: int = 0) -> dict[str, Any]:
        """List services installed or started, scheduled tasks, and commands run.

        ``offset`` and ``limit`` ask for one page (0 = every row); a page that
        stops short names the next offset.
        """
        return sandbox_services_and_tasks(report, offset, limit, normalised_by=normalised_by)

    sizer = _answer_sizer(container)
    return [
        *(
            StructuredTool.from_function(func=_sized(func, sizer), name=name)
            for func, name in (
                (_report_section, "sandbox_report_section"),
                (_processes, "sandbox_processes"),
                (_network, "sandbox_network"),
                (_signatures, "sandbox_signatures"),
                (_dropped_files, "sandbox_dropped_files"),
                (_registry_ops, "sandbox_registry_ops"),
                (_api_calls, "sandbox_api_calls"),
                (_mutexes, "sandbox_mutexes"),
                (_services_and_tasks, "sandbox_services_and_tasks"),
                (_channels, "sandbox_channels"),
            )
        ),
        items_tool(report, sizer, normalised_by),
    ]


def normalised_by_of(container: Any) -> tuple[str, ...] | None:
    """``(provider, source_format, read_from)`` of the reader behind the job's report, if said."""
    value = getattr(container, "sandbox_normalised", None)
    if isinstance(value, tuple) and len(value) in (2, 3):
        return tuple(str(part) for part in value)
    return None


def items_tool(
    report: dict[str, Any] | None,
    sizer: Any = None,
    normalised_by: tuple[str, ...] | None = None,
) -> BaseTool:
    """The ``sandbox_items`` tool, closed over one job's report and the reader that produced it."""
    from langchain_core.tools import StructuredTool

    from maljan.analysis.sandbox_sections import ITEMS_TOOL, Sections

    # The report read into sections once for the job, on the first call, and
    # held by this closure only: never cached across jobs.
    held: list[Sections] = []

    def _sections() -> Sections | None:
        if report is None or _no_sandbox_ran(report):
            return None
        if not held:
            held.append(Sections(report, normalised_by))
        return held[0]

    def _items(
        section: str,
        pid: int | str | None = None,
        contains: str = "",
        signature: str = "",
        ids: list[str] | str | None = None,
    ) -> dict[str, Any]:
        """Read items of one section of the job's sandbox report, whole.

        ``section`` is one of ``processes``, ``api_calls``, ``files``,
        ``registry``, ``network``, ``signatures``, ``dropped``, ``mutexes``,
        ``commands``, ``services``, ``events``, ``apistats``, ``channels``,
        ``screenshots``, ``extracted`` (the configurations and payloads the
        sandbox extracted), ``resolved_apis``, ``alerts`` (an intrusion
        detection engine's) or ``procdumps``; the pack's sandbox section index
        gives each one's item count, or why the report does not carry it. Each item comes
        with its id (proc:<pid> for a process, <prefix>:<n> for the n-th item
        of any other section), the report list it came from and the report's
        own fields. ``pid`` (a number) keeps the items of that process id, in
        the sections whose rows name a process; ``contains``
        keeps the items one of whose text values contains the text (a path,
        key, host, URL or command line), case not counted; ``signature`` keeps
        the signature with that item id or name; ``ids`` keeps the items with
        those ids, a list or one text of ids separated by commas or spaces. The
        filters combine; with none, every item of the section
        is answered, and ``matched`` counts the items kept. A process's API
        calls are the api_calls items whose process is its id. A claim may
        cite an item by its id.
        """
        return sandbox_items(report, section, pid, contains, signature, ids, sections=_sections())

    return StructuredTool.from_function(func=_sized(_items, sizer, _ITEM_FILTERS), name=ITEMS_TOOL)


def _answer_sizer(container: Any) -> Any:
    """The job's answer guardrail (``ServerRegistry.answer_sizer``), or ``None`` without one."""
    get_registry = getattr(container, "get_server_registry", None)
    if not callable(get_registry):
        return None
    try:
        return get_registry().answer_sizer()
    except Exception as exc:  # noqa: BLE001 — a view answered unsized is still an answer
        logger.warning("sandbox tools: no answer guardrail for this job (%s).", exc)
        return None


# The arguments every view pages by, named in the notice a shortened answer
# carries so the rows it left out are one call away.
_PAGING = ("offset", "limit")


def _sized(func: Any, sizer: Any, narrowing: tuple[str, ...] = _PAGING) -> Any:
    """``func``, its answer sent through the MCP toolkit's guardrail when there is one.

    The same sizing an MCP tool's answer gets: measured against the room the
    conversation has, shortened as a JSON document whose bookkeeping says what
    was left out, the budget charged. The recorder's notice then names the
    arguments in ``narrowing`` (``offset`` and ``limit`` for the paged views),
    so every row stays reachable.
    """
    import functools

    from maljan.core.safe_json import dumps

    if sizer is None:
        return func

    @functools.wraps(func)
    def _answer(*args: Any, **kwargs: Any) -> Any:
        value = func(*args, **kwargs)
        text = dumps(value, default=str)
        return sizer._apply_output_guardrail(text, narrowing)

    return _answer
