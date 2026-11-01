"""What a tool server can do on the host it runs on, computed rather than claimed.

A sidecar's manifest lists every tool whether or not its optional library is
installed, so a model learns why an answer is empty instead of never seeing
the capability. That leaves the operator learning the same thing one failed
call at a time, mid-run. The capability manifest says it up front::

    {"server": "analysis", "version": "0.9.0",
     "tools": [{"name": "document_info", "optional_dependency": "olefile",
                "available": false, "reason": "olefile is not installed",
                "timeout_s": null}, ...]}

Each sidecar declares which tool needs which optional module, binary,
setting or data path, and ``manifest`` probes each of them on the server's own interpreter
and host — an import, a ``which``, an environment variable — when the server
starts. Nothing is hard-coded as present: a manifest that drifted from the
host would be worse than none. The registry reads it once per job through the
sidecar's ``capabilities`` tool, the settings probe returns it to the console,
and a stage that binds a tool the manifest marks unavailable records the
degradation when it starts, with the reason and the remedy.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import importlib.util
import os
import shutil
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from maljan.tools.errors import MISSING_DEPENDENCY, NOT_CONFIGURED, REMEDIATIONS

# The tool a server answers this with. Named once, so the registry and the
# probe look for the same thing every sidecar offers.
CAPABILITIES_TOOL = "capabilities"


@dataclass(frozen=True)
class Requirement:
    """One thing a tool needs on the host: a module, a binary, a setting or data."""

    kind: str  # "module" | "binary" | "env" | "data"
    name: str
    # For a binary found somewhere other than ``PATH`` alone: the lookup that
    # answers ``None`` when it is present, else the reason it is not. Called
    # with no argument inside the server, and with the server's environment
    # when the check is made from outside it (``installed``).
    locate: Callable[..., str | None] | None = field(default=None, compare=False)
    # For data (a rule corpus, a signature set): the core setting whose value
    # is the path a caller hands the tool, as a dotted path
    # (``static.capa.rules_dir``), and the server environment variable that
    # overrides ``name``, the default path, where the tool reads one instead.
    # Either may be empty. ``pattern`` is what a file in a directory must match
    # for the directory to hold the data.
    setting: str = ""
    override: str = ""
    pattern: str = "*"

    def probe(self) -> str | None:
        """``None`` when present, else the reason it is not.

        A missing module says so in the import's own words, which name the
        module and nothing else. Anything further — a broken install, a shared
        library that will not load — is reported by exception type alone: those
        messages carry absolute paths off the host, and this reason travels to
        a probe response, the console, the run summary and the judge's prompt.
        The type is what a reader acts on; the path is what they must not be
        handed.
        """
        if self.kind == "module":
            try:
                importlib.import_module(self.name)
            except ModuleNotFoundError as exc:
                detail = str(exc).strip()
                return f"{self.name} is not installed" + (f" ({detail})" if detail else "")
            except Exception as exc:  # noqa: BLE001 — a broken import is as absent as a missing one
                return f"{self.name} is not installed ({type(exc).__name__})"
            return None
        if self.kind == "binary":
            if self.locate is not None:
                return self.locate()
            return None if shutil.which(self.name) else f"{self.name} is not on PATH"
        if self.kind == "env":
            return None if os.environ.get(self.name) else f"{self.name} is not configured"
        if self.kind == "data":
            # The path a tool is handed is the caller's setting, which the
            # server does not read: the check before a job does (``installed``).
            return None
        return f"unknown requirement kind {self.kind!r}"

    def installed(
        self, environ: Mapping[str, str] | None = None, settings: Any = None
    ) -> str | None:
        """``None`` when the module, binary or data is on this host, else the reason.

        The check made before a job, from outside the server: nothing is
        imported and nothing is run. A module is looked up on the import path
        (a library uninstalled under a running process is noticed, where a
        module that process imported once would still answer), and a binary is
        looked for as ``probe`` looks for it, in ``environ`` (the environment
        the server is started with) rather than this process's. A setting is
        no install: an ``env`` requirement answers ``None`` here, since the
        value is handed to the server by its own settings, which this
        process's environment does not show.

        A data path is read where the tool reads it. ``settings`` is given
        only by a caller that hands the tool the declared setting's value (the
        worker's own reading): the setting is then the path. Otherwise, as for
        a tool a server runs with its own defaults, the path is the override
        in ``environ`` (this process's environment when ``None``), else the
        default. It is missing when nothing is there, a file is empty or a
        directory holds no file matching ``pattern``. The reason names what
        named the path, and the path itself only relative to the project root:
        the answer is read by any signed-in user, and a path outside the
        project is the host's, not theirs.

        The import path looked on is this process's: a server started with a
        ``PYTHONPATH`` of its own can import what this answers is missing, so
        a caller leaves a module of such a server unchecked.
        """
        if self.kind == "module":
            try:
                found = importlib.util.find_spec(self.name)
            except (ImportError, ValueError):
                found = None
            if found is None:
                return f"{self.name} is not installed (No module named '{self.name}')"
            return None
        if self.kind == "binary":
            if self.locate is not None:
                return self.locate(environ)
            path = None if environ is None else environ.get("PATH")
            return None if shutil.which(self.name, path=path) else f"{self.name} is not on PATH"
        if self.kind == "data":
            return self._data_missing(environ, settings)
        return None

    def _data_missing(self, environ: Mapping[str, str] | None, settings: Any) -> str | None:
        value, named_by = self.name, "the default"
        held = _setting_value(settings, self.setting) if self.setting else None
        if held is not None:
            value, named_by = str(held), self.setting
        elif self.override:
            given = (os.environ if environ is None else environ).get(self.override, "")
            if given.strip():
                value, named_by = given, self.override
        if not value.strip():
            return f"{named_by} names no path"
        base = _data_root()
        target = Path(value)
        target = target if target.is_absolute() else base / target
        if data_held(target, self.pattern):
            return None
        try:
            shown = target.relative_to(base).as_posix()
        except ValueError:
            return f"the path {named_by} names is missing or empty"
        return f"{shown} is missing or empty (named by {named_by})"

    def handed(self, settings: Any) -> dict[str, str]:
        """The server environment that hands the tool this data path's setting.

        ``{override: value}`` for data declaring both a core setting and a
        server override, when ``settings`` names a path other than the
        default: the server's tool then reads the path a caller handing the
        setting reads. Empty otherwise, so a launch under the defaults is
        given nothing it was not given before.
        """
        if self.kind != "data" or not self.setting or not self.override:
            return {}
        held = _setting_value(settings, self.setting)
        value = "" if held is None else str(held).strip()
        if not value:
            return {}
        from maljan.core.paths import resolve_data

        # Absolute, as the caller's own reading resolves it: a server started
        # in another working directory or tree reads the same path.
        path = resolve_data(value)
        if path == resolve_data(self.name):
            return {}
        return {self.override: str(path)}

    @property
    def remedy(self) -> str:
        """What puts a missing data path in place, in words naming no one tool."""
        named = " or ".join(name for name in (self.setting, self.override) if name)
        point = f", or point {named} at a populated copy" if named else ""
        return (
            f"put the data in {self.name}{point}: it is not in version control, so a "
            "fresh clone or git worktree has it only once make external has fetched it "
            "or the main checkout's copy is linked in"
        )


def _setting_value(settings: Any, dotted: str) -> Any:
    """The value at ``dotted`` in ``settings``, or ``None`` when there is none to read."""
    node = settings
    for part in dotted.split("."):
        if node is None:
            return None
        node = node.get(part) if isinstance(node, Mapping) else getattr(node, part, None)
    return node


def _data_root() -> Path:
    """The directory a relative data path is read against (``core.paths.resolve_data``)."""
    from maljan.core.paths import get_project_root

    return get_project_root()


def data_held(path: str | os.PathLike[str], pattern: str = "*") -> bool:
    """Whether ``path`` holds data: a non-empty file, or a directory with a file of ``pattern``."""
    target = Path(path)
    try:
        if target.is_file():
            return target.stat().st_size > 0
        return target.is_dir() and any(entry.is_file() for entry in target.rglob(pattern))
    except OSError:
        return False


def module(name: str) -> Requirement:
    return Requirement("module", name)


def binary(name: str, locate: Callable[..., str | None] | None = None) -> Requirement:
    """A tool that shells out to an executable.

    Found on ``PATH`` by default. ``locate`` is for an executable looked for in
    more places than that, or checked for more than presence — the analysis
    server's ``floss`` looks at a configured path and a user tools directory
    and runs only the pinned build — and answers the reason it is absent.
    """
    return Requirement("binary", name, locate)


def env(name: str) -> Requirement:
    return Requirement("env", name)


def data(default: str, *, setting: str = "", override: str = "", pattern: str = "*") -> Requirement:
    """A file or directory the tool reads its rules or signatures from.

    ``default`` is the path the tool reads when nothing names another;
    ``setting`` the core setting whose value a caller that reads it hands the
    tool instead (a server running the tool with its own defaults does not,
    unless ``override`` is declared too: its launch is then handed the
    setting's value under it, ``handed``),
    ``override`` the server environment variable that replaces the default,
    and ``pattern`` what a file of a directory must match to count. A path
    that is missing or holds nothing is named before a job (``installed``)
    with what named it: a tool reading an empty corpus answers nothing, and
    says so only once the run has paid for it.
    """
    return Requirement("data", default, setting=setting, override=override, pattern=pattern)


@dataclass(frozen=True)
class ToolNeeds:
    """A tool and what it needs. No requirement means it always answers."""

    name: str
    requires: tuple[Requirement, ...] = ()
    timeout_s: float | None = None
    # What the tool still does without the requirement, when it does
    # something: ``apk_info`` answers the zip-level facts without androguard.
    without: str = ""
    # The routed formats only the missing requirement reads, for a tool that
    # still answers without it: a sample of another known format loses
    # nothing (``archive_list`` without py7zr on a zip), and one of these
    # formats loses what it would have read. Empty when that cannot be said,
    # and the partial answer is then a loss for every sample.
    without_reads: tuple[str, ...] = ()
    # The remedy when the requirement is missing, where the code's general one
    # names the wrong thing: an executable is not installed by ``uv sync``.
    remediation: str = ""
    # A tool whose work grows with the sample and has no wall clock of its own
    # (capa, FLOSS): a caller waits for it with no deadline unless its operator
    # set one, and its caller giving up is not the server failing.
    long_running: bool = False
    # What the tool takes and does, in plain facts, for a tool whose arguments
    # its name does not say (the operations of ``transform_bytes``).
    facts: str = ""


def _cell(tool: ToolNeeds) -> dict[str, Any]:
    # Probed once per requirement. The reason and the code both need the
    # answer, and probing twice re-runs an import, a ``which`` and a read of
    # the environment for every cell of every manifest.
    probed = [(req, req.probe()) for req in tool.requires]
    missing = [(req, reason) for req, reason in probed if reason]
    # A data path is never probed here (``Requirement.probe``), so not listed.
    dependency = ", ".join(req.name for req in tool.requires if req.kind != "data") or None
    cell: dict[str, Any] = {
        "name": tool.name,
        "optional_dependency": dependency,
        "available": not missing,
        "reason": "; ".join(reason for _req, reason in missing) if missing else None,
        "timeout_s": tool.timeout_s,
    }
    if tool.long_running:
        cell["long_running"] = True
    if tool.facts:
        cell["facts"] = tool.facts
    if missing:
        kinds = {req.kind for req, _reason in missing}
        code = NOT_CONFIGURED if kinds == {"env"} else MISSING_DEPENDENCY
        # Kept on the cell: a setting left unset is the operator's choice and a
        # library missing is a loss, and the code, not the reason's words, is
        # what tells them apart (``pipeline.operator_choice``).
        cell["code"] = code
        cell["remediation"] = remedy_for(tool, [req for req, _reason in missing])
        if tool.without:
            cell["without"] = tool.without
            if tool.without_reads:
                cell["without_reads"] = list(tool.without_reads)
    return cell


def package_version(distribution: str = "maljan") -> str:
    """The installed version of ``distribution``, or ``"unknown"``."""
    try:
        return str(importlib.metadata.version(distribution))
    except Exception:  # noqa: BLE001 — a version is a label, never a failure
        return "unknown"


def manifest(server: str, tools: list[ToolNeeds], *, version: str | None = None) -> dict[str, Any]:
    """The capability manifest for ``server``, probed now on this host."""
    return {
        "server": server,
        "version": version if version is not None else package_version(),
        "tools": [_cell(tool) for tool in tools],
    }


def remedy_for(tool: ToolNeeds, missing: list[Requirement]) -> str:
    """The remedy for ``missing``: the tool's for what is not data, each data path's own."""
    remedies = []
    other = {req.kind for req in missing if req.kind != "data"}
    if other or not missing:
        code = NOT_CONFIGURED if other == {"env"} else MISSING_DEPENDENCY
        remedies.append(tool.remediation or REMEDIATIONS[code])
    remedies.extend(req.remedy for req in missing if req.kind == "data")
    return "; ".join(dict.fromkeys(remedies))


@dataclass
class Unavailable:
    """One tool a manifest marks unavailable, as a degradation reason reads it."""

    server: str
    tool: str
    reason: str
    remediation: str | None = None
    without: str = ""
    # The manifest's code for why (``not_configured``, ``missing_dependency``),
    # ``None`` for a manifest written before cells carried one.
    code: str | None = None
    # What the tool needs, by name, as its cell lists it (``optional_dependency``).
    requires: tuple[str, ...] = ()

    @property
    def degradation_reason(self) -> str:
        """``server.<key>.<tool>_unavailable(<reason>)``, with what it still does and the remedy.

        A tool that answers less is not a tool that does not answer, and the
        difference is what a reader of the degraded block needs: ``apk_info``
        without androguard still reads the zip, and saying only that it is
        unavailable overstates what was lost.
        """
        text = f"server.{self.server}.{self.tool}_unavailable({self.reason})"
        if self.without:
            text += f"; still answers {self.without}"
        if self.remediation:
            text += f"; {self.remediation}"
        return text


@dataclass
class ServerCapabilities:
    """A manifest as the registry keeps it, indexed by tool."""

    server: str
    version: str = "unknown"
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_payload(cls, server: str, payload: Any) -> ServerCapabilities | None:
        """Read a ``capabilities()`` answer; ``None`` for anything that is not one."""
        if isinstance(payload, str):
            import json

            try:
                payload = json.loads(payload)
            except (ValueError, TypeError):
                return None
        if not isinstance(payload, dict) or not isinstance(payload.get("tools"), list):
            return None
        tools: dict[str, dict[str, Any]] = {}
        for cell in payload["tools"]:
            if isinstance(cell, dict) and cell.get("name"):
                tools[str(cell["name"])] = dict(cell)
        return cls(
            server=str(payload.get("server") or server),
            version=str(payload.get("version") or "unknown"),
            tools=tools,
        )

    def unavailable(self, names: list[str] | None = None) -> list[Unavailable]:
        """The tools marked unavailable, all of them or only ``names``."""
        wanted = set(names) if names is not None else set(self.tools)
        out: list[Unavailable] = []
        for name in sorted(wanted):
            cell = self.tools.get(name)
            if cell is None or cell.get("available", True):
                continue
            out.append(
                Unavailable(
                    server=self.server,
                    tool=name,
                    reason=str(cell.get("reason") or "unavailable"),
                    remediation=(str(cell["remediation"]) if cell.get("remediation") else None),
                    without=str(cell.get("without") or ""),
                    code=str(cell["code"]) if cell.get("code") else None,
                    requires=tuple(
                        name.strip()
                        for name in str(cell.get("optional_dependency") or "").split(",")
                        if name.strip()
                    ),
                )
            )
        return out

    def unusable(self) -> frozenset[str]:
        """The tools this host cannot run, and which answer nothing without it.

        A tool the model is offered is a tool the model will spend a step on.
        One run was handed four of them, got four failures back, and the
        degradation that explained why went to the log and the run summary
        rather than to the agent holding the tool. So these are kept off the
        list the model is given — they stay in the manifest, with the reason
        and the remedy, which is what an operator needs and what the degraded
        block prints.

        A tool that declares what it still answers is not one of them:
        ``archive_list`` without py7zr still lists a zip, and withholding it
        would cost a whole archive analysis to save a 7z failure.
        """
        return frozenset(
            name
            for name, cell in self.tools.items()
            if not cell.get("available", True) and not cell.get("without")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "version": self.version,
            "tools": [dict(cell) for cell in self.tools.values()],
        }
