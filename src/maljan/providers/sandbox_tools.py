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
    """The six sandbox tools, each closed over this job's report.

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

    return [
        StructuredTool.from_function(func=_report_section, name="sandbox_report_section"),
        StructuredTool.from_function(func=_processes, name="sandbox_processes"),
        StructuredTool.from_function(func=_network, name="sandbox_network"),
        StructuredTool.from_function(func=_signatures, name="sandbox_signatures"),
        StructuredTool.from_function(func=_dropped_files, name="sandbox_dropped_files"),
        StructuredTool.from_function(func=_channels, name="sandbox_channels"),
    ]
