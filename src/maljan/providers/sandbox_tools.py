"""The job's sandbox report, as tools instead of one wall of JSON.

The dynamic analyst has always been handed the whole report as text, chunked
to fit and truncated where it did not. That is the wrong shape for a model
that wants three specific things: what ran, what it talked to, and what the
sandbox's own signatures said. These tools let it ask.

In-process on purpose — there is no server to open, no transport to bind and
nothing to time out, because the report is already in the container. That is
what ``ToolRef(kind="sandbox")`` resolves to: a tool set built from the report
the job already downloaded.

A report the container does not have yields the same tools, each answering
``{"error": "no sandbox report for this job"}``. The agent then knows the
channel is empty rather than silently seeing tools that return nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

# How many rows one tool call returns. A busy CAPE report holds tens of
# thousands of API calls; a tool that returned them all would blow the context
# it was meant to save.
_ROW_LIMIT = 200

_NO_REPORT = {"error": "no sandbox report for this job", "tool": "sandbox"}


def _report_of(container: Any) -> dict[str, Any] | None:
    """The job's sandbox report as the CAPE-shaped dict every reader expects.

    ``container.sandbox_report`` is set by ``app.arun`` alongside
    ``sample_format``, for the same reason: agents are built lazily, from nodes
    that do not all carry the graph state. A ``SandboxReport`` model assigned
    there instead of a dict is rendered through ``cape_view`` so both forms
    read identically here.
    """
    report = getattr(container, "sandbox_report", None)
    if report is None:
        return None
    if isinstance(report, dict):
        return report
    try:
        from maljan.providers.cape_view import to_cape_shaped_dict

        return to_cape_shaped_dict(report)
    except Exception as exc:  # noqa: BLE001 — an unreadable report is an empty one
        logger.warning("sandbox tools: could not render the report (%s).", exc)
        return None


def _behavior(report: dict[str, Any]) -> dict[str, Any]:
    behavior = report.get("behavior")
    return behavior if isinstance(behavior, dict) else {}


def sandbox_report_section(report: dict[str, Any] | None, section: str) -> dict[str, Any]:
    """One top-level section of the report, bounded.

    The escape hatch for a section the other tools do not model — ``target``,
    ``static``, ``cti``, whatever a particular sandbox publishes. The section
    names are listed in the answer when the requested one is absent, so a model
    that guessed wrong can correct itself in one turn instead of guessing again.
    """
    if report is None:
        return dict(_NO_REPORT)
    key = str(section).strip()
    if key not in report:
        return {
            "error": f"no section {key!r} in the report",
            "sections": sorted(str(k) for k in report),
        }
    value = report[key]
    if isinstance(value, list):
        return {"section": key, "rows": value[:_ROW_LIMIT], "total": len(value)}
    return {"section": key, "value": value}


def sandbox_processes(report: dict[str, Any] | None) -> dict[str, Any]:
    """The process tree: pid, parent, name and command line, one row each.

    Without the API calls. The call list is where a behaviour report's bulk
    is, and a process tree is the thing an analyst reads first — they are two
    different questions and answering both at once makes the cheap one
    expensive.
    """
    if report is None:
        return dict(_NO_REPORT)
    processes = _behavior(report).get("processes")
    rows: list[dict[str, Any]] = []
    if isinstance(processes, list):
        for proc in processes[:_ROW_LIMIT]:
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
    return {"processes": rows, "total": len(processes) if isinstance(processes, list) else 0}


def sandbox_network(report: dict[str, Any] | None) -> dict[str, Any]:
    """DNS lookups, hosts, HTTP requests, TCP/UDP endpoints and TLS, per kind.

    Per-kind bounds rather than one shared budget: a sample that made a
    thousand DNS lookups must not push its two HTTP requests out of the answer.
    """
    if report is None:
        return dict(_NO_REPORT)
    network = report.get("network")
    if not isinstance(network, dict):
        return {"dns": [], "hosts": [], "http": [], "tcp": [], "udp": []}
    out: dict[str, Any] = {}
    for key in ("dns", "hosts", "http", "tcp", "udp", "domains", "icmp", "tls"):
        rows = network.get(key)
        if isinstance(rows, list):
            out[key] = rows[:_ROW_LIMIT]
            if len(rows) > _ROW_LIMIT:
                out[f"{key}_total"] = len(rows)
    return out


def sandbox_signatures(report: dict[str, Any] | None) -> dict[str, Any]:
    """The sandbox's own signature hits, with their severity.

    Reported as what they are — one detection engine's opinion — not folded
    into the verdict. A CAPE signature firing is evidence the agent weighs
    alongside everything else it found.
    """
    if report is None:
        return dict(_NO_REPORT)
    signatures = report.get("signatures")
    rows: list[dict[str, Any]] = []
    if isinstance(signatures, list):
        for sig in signatures[:_ROW_LIMIT]:
            if not isinstance(sig, dict):
                continue
            rows.append(
                {
                    "name": sig.get("name") or sig.get("signature") or "",
                    "description": sig.get("description") or "",
                    "severity": sig.get("severity"),
                    "confidence": sig.get("confidence"),
                    "references": list(sig.get("references") or [])[:5],
                }
            )
    return {"signatures": rows, "total": len(signatures) if isinstance(signatures, list) else 0}


def sandbox_dropped_files(report: dict[str, Any] | None) -> dict[str, Any]:
    """Files the sample wrote, with the hashes the sandbox computed for them."""
    if report is None:
        return dict(_NO_REPORT)
    dropped = report.get("dropped")
    if not isinstance(dropped, list):
        dropped = report.get("dropped_files")
    rows: list[dict[str, Any]] = []
    if isinstance(dropped, list):
        for entry in dropped[:_ROW_LIMIT]:
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
    return {"dropped": rows, "total": len(dropped) if isinstance(dropped, list) else 0}


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
    "regdeletevaluea": "delete",
    "regdeletevaluew": "delete",
    "ntdeletekey": "delete",
    "ntdeletevaluekey": "delete",
    "regqueryvalueexa": "query",
    "regqueryvalueexw": "query",
    "ntquueryvaluekey": "query",
    "regopenkeyexa": "query",
    "regopenkeyexw": "query",
    "ntopenkey": "query",
}

_REGISTRY_KEY_ARGS = ("FullName", "KeyName", "ObjectAttributes", "SubKey", "Registry")
_REGISTRY_VALUE_ARGS = ("Buffer", "Data", "ValueData", "Value")
_MUTEX_APIS = frozenset({"ntcreatemutant", "ntopenmutant", "createmutexa", "createmutexw"})
_MUTEX_ARGS = ("MutexName", "lpName", "ObjectAttributes", "Name")
_SERVICE_APIS = frozenset({"createservicea", "createservicew", "startservicea", "startservicew"})
_SERVICE_ARGS = ("ServiceName", "DisplayName", "BinaryPathName", "lpServiceName")


def _calls(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Every API call the report recorded, however it filed them.

    CAPE publishes a flat ``behavior.calls`` and also one list per process;
    a report that has both would double-count, so the flat list wins when it
    is there.
    """
    behavior = _behavior(report)
    flat = behavior.get("calls")
    if isinstance(flat, list) and flat:
        return [row for row in flat if isinstance(row, dict)]
    out: list[dict[str, Any]] = []
    for proc in behavior.get("processes") or []:
        if isinstance(proc, dict):
            out.extend(row for row in (proc.get("calls") or []) if isinstance(row, dict))
    return out


def _argument(call: dict[str, Any], names: tuple[str, ...]) -> str:
    """The first of ``names`` this call carries, whichever shape it filed them in."""
    arguments = call.get("arguments")
    if isinstance(arguments, dict):
        pools: list[dict[str, Any]] = [arguments]
    elif isinstance(arguments, list):
        pools = [row for row in arguments if isinstance(row, dict)]
    else:
        pools = []
    for pool in pools:
        for key in names:
            value = pool.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        # Cuckoo's older shape files each argument as {"name": ..., "value": ...}.
        if pool.get("name") in names and isinstance(pool.get("value"), str):
            return str(pool["value"]).strip()
    return ""


def _summary_list(report: dict[str, Any], key: str) -> list[str]:
    rows = _behavior(report).get("summary")
    values = rows.get(key) if isinstance(rows, dict) else None
    return [str(v) for v in values if isinstance(v, str)] if isinstance(values, list) else []


def sandbox_registry_ops(report: dict[str, Any] | None, limit: int = _ROW_LIMIT) -> dict[str, Any]:
    """Registry keys the sample touched, with the operation and the value written.

    Two sources, because sandboxes fill them unevenly: the behaviour summary's
    key list, which says a key was touched and nothing else, and the registry
    API calls themselves, which say what was done and what was written. The
    call wins where both name the same key — an operation is worth more than
    the bare fact of access.
    """
    if report is None:
        return dict(_NO_REPORT)
    bound = max(0, int(limit))
    rows: dict[str, dict[str, Any]] = {}
    for key in _summary_list(report, "keys"):
        rows.setdefault(key, {"key": key, "operation": "access", "value": None})
    for call in _calls(report):
        api = str(call.get("api") or "")
        operation = _REGISTRY_OPS.get(api.lower())
        if operation is None:
            continue
        key = _argument(call, _REGISTRY_KEY_ARGS)
        if not key:
            continue
        value = _argument(call, _REGISTRY_VALUE_ARGS)
        rows[key] = {"key": key, "operation": operation, "value": value or None}
    ordered = list(rows.values())
    return {"registry": ordered[:bound], "total": len(ordered)}


def sandbox_api_calls(
    report: dict[str, Any] | None,
    process: str | None = None,
    category: str | None = None,
    limit: int = 300,
) -> dict[str, Any]:
    """The API-call histogram, categorised, with the first arguments of each call.

    The call stream itself is where a behaviour report's bulk is, so what comes
    back is one row per API rather than one per call: the name, how often it was
    called, the behaviour category it belongs to, and the arguments of the first
    call, which is usually the one that says what the sample was after.
    ``process`` narrows by pid or process name, ``category`` by behaviour.
    """
    if report is None:
        return dict(_NO_REPORT)
    from maljan.extractors.pe_extractor import classify_import

    behavior = _behavior(report)
    names_by_pid = {
        str(proc.get("pid")): str(proc.get("process_name") or proc.get("name") or "")
        for proc in behavior.get("processes") or []
        if isinstance(proc, dict)
    }
    wanted_process = (process or "").strip().lower()
    wanted_category = (category or "").strip().lower()

    counts: dict[str, int] = {}
    apistats = behavior.get("apistats")
    if isinstance(apistats, dict):
        for pid, stats in apistats.items():
            if wanted_process and wanted_process not in {
                str(pid).lower(),
                names_by_pid.get(str(pid), "").lower(),
            }:
                continue
            if isinstance(stats, dict):
                for api, count in stats.items():
                    try:
                        counts[str(api)] = counts.get(str(api), 0) + int(count)
                    except (TypeError, ValueError):
                        continue

    first_args: dict[str, str] = {}
    for call in _calls(report):
        api = str(call.get("api") or "")
        if not api:
            continue
        counts.setdefault(api, 0)
        if api not in first_args:
            arguments = call.get("arguments")
            first_args[api] = str(arguments)[:400] if arguments else ""

    rows: list[dict[str, Any]] = []
    for api, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        api_category, suspicious = classify_import(api)
        if wanted_category and (api_category or "").lower() != wanted_category:
            continue
        rows.append(
            {
                "api": api,
                "count": count,
                "category": api_category,
                "suspicious": bool(suspicious),
                "first_args": first_args.get(api, ""),
            }
        )
    return {"apis": rows[: max(0, int(limit))], "total": len(rows)}


def sandbox_mutexes(report: dict[str, Any] | None) -> dict[str, Any]:
    """The named mutexes the sample created or opened.

    A mutex name is often the one durable string a family carries across
    builds, which is why it gets a tool of its own rather than a filter over
    the call stream.
    """
    if report is None:
        return dict(_NO_REPORT)
    names: list[str] = list(_summary_list(report, "mutexes"))
    for call in _calls(report):
        if str(call.get("api") or "").lower() not in _MUTEX_APIS:
            continue
        name = _argument(call, _MUTEX_ARGS)
        if name and name not in names:
            names.append(name)
    return {"mutexes": names[:_ROW_LIMIT], "total": len(names)}


def sandbox_services_and_tasks(report: dict[str, Any] | None) -> dict[str, Any]:
    """Services installed or started, scheduled tasks, and the commands run.

    Three answers in one call because they are one question — what did the
    sample arrange to happen again — and an agent that had to make three calls
    to ask it would routinely make one and miss the other two.
    """
    if report is None:
        return dict(_NO_REPORT)
    services: list[str] = [
        *_summary_list(report, "created_services"),
        *_summary_list(report, "started_services"),
    ]
    commands: list[str] = list(_summary_list(report, "executed_commands"))
    tasks: list[str] = [cmd for cmd in commands if "schtasks" in cmd.lower()]
    for call in _calls(report):
        api = str(call.get("api") or "").lower()
        if api in _SERVICE_APIS:
            name = _argument(call, _SERVICE_ARGS)
            if name and name not in services:
                services.append(name)
    deduped_services = list(dict.fromkeys(services))
    return {
        "services": deduped_services[:_ROW_LIMIT],
        "tasks": tasks[:_ROW_LIMIT],
        "commands": commands[:_ROW_LIMIT],
        "total": len(deduped_services) + len(tasks) + len(commands),
    }


def sandbox_channels(report: dict[str, Any] | None, name: str = "") -> dict[str, Any]:
    """The platform-namespaced channels a non-Windows guest publishes.

    ``android.permissions``, ``linux.systemd``, ``macos.launchd`` and whatever
    else a sandbox has to say that the CAPE-shaped fields have no home for.
    Called with no name it lists what exists, which is how an agent discovers a
    channel it did not know to ask for.
    """
    if report is None:
        return dict(_NO_REPORT)
    channels = report.get("channels")
    if not isinstance(channels, dict):
        return {"channels": [], "rows": []}
    available = sorted(str(k) for k in channels)
    key = str(name).strip()
    if not key:
        return {"channels": available, "rows": []}
    rows = channels.get(key)
    if not isinstance(rows, list):
        return {"error": f"no channel {key!r}", "channels": available}
    return {"channel": key, "rows": rows[:_ROW_LIMIT], "total": len(rows)}


def sandbox_tools(container: Any) -> list[BaseTool]:
    """The sandbox tools, each closed over this job's report.

    Built per resolution rather than once per process: the report is the job's,
    and a tool cached across jobs would answer the previous sample's questions.
    """
    from langchain_core.tools import StructuredTool

    report = _report_of(container)

    def _report_section(section: str) -> dict[str, Any]:
        """Read one top-level section of the sandbox report by name."""
        return sandbox_report_section(report, section)

    def _processes() -> dict[str, Any]:
        """List the processes the sandbox observed, with their command lines."""
        return sandbox_processes(report)

    def _network() -> dict[str, Any]:
        """List the DNS lookups, hosts, HTTP requests and endpoints observed."""
        return sandbox_network(report)

    def _signatures() -> dict[str, Any]:
        """List the sandbox's own signature hits and their severity."""
        return sandbox_signatures(report)

    def _dropped_files() -> dict[str, Any]:
        """List the files the sample wrote, with their hashes."""
        return sandbox_dropped_files(report)

    def _channels(name: str = "") -> dict[str, Any]:
        """List the platform channels, or read one of them by name."""
        return sandbox_channels(report, name)

    def _registry_ops(limit: int = _ROW_LIMIT) -> dict[str, Any]:
        """List the registry keys the sample touched, with what it did to each."""
        return sandbox_registry_ops(report, limit)

    def _api_calls(process: str = "", category: str = "", limit: int = 300) -> dict[str, Any]:
        """List the API calls observed, by frequency, optionally narrowed."""
        return sandbox_api_calls(report, process or None, category or None, limit)

    def _mutexes() -> dict[str, Any]:
        """List the named mutexes the sample created or opened."""
        return sandbox_mutexes(report)

    def _services_and_tasks() -> dict[str, Any]:
        """List services installed or started, scheduled tasks, and commands run."""
        return sandbox_services_and_tasks(report)

    return [
        StructuredTool.from_function(func=_report_section, name="sandbox_report_section"),
        StructuredTool.from_function(func=_processes, name="sandbox_processes"),
        StructuredTool.from_function(func=_network, name="sandbox_network"),
        StructuredTool.from_function(func=_signatures, name="sandbox_signatures"),
        StructuredTool.from_function(func=_dropped_files, name="sandbox_dropped_files"),
        StructuredTool.from_function(func=_registry_ops, name="sandbox_registry_ops"),
        StructuredTool.from_function(func=_api_calls, name="sandbox_api_calls"),
        StructuredTool.from_function(func=_mutexes, name="sandbox_mutexes"),
        StructuredTool.from_function(func=_services_and_tasks, name="sandbox_services_and_tasks"),
        StructuredTool.from_function(func=_channels, name="sandbox_channels"),
    ]
