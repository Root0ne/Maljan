"""What a tool server can do on the host it runs on, computed rather than claimed.

A sidecar's manifest lists every tool whether or not its optional library is
installed, so a model learns why an answer is empty instead of never seeing
the capability. That leaves the operator learning the same thing one failed
call at a time, mid-run. The capability manifest says it up front::

    {"server": "analysis", "version": "0.9.0",
     "tools": [{"name": "document_info", "optional_dependency": "olefile",
                "available": false, "reason": "olefile is not installed",
                "timeout_s": null}, ...]}

Each sidecar declares which tool needs which optional module, binary or
setting, and ``manifest`` probes each of them on the server's own interpreter
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
import os
import shutil
from dataclasses import dataclass, field
from typing import Any

from maljan.tools.errors import MISSING_DEPENDENCY, NOT_CONFIGURED, REMEDIATIONS

# The tool a server answers this with. Named once, so the registry and the
# probe look for the same thing every sidecar offers.
CAPABILITIES_TOOL = "capabilities"


@dataclass(frozen=True)
class Requirement:
    """One thing a tool needs on the host: a module, a binary or a setting."""

    kind: str  # "module" | "binary" | "env"
    name: str

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
            return None if shutil.which(self.name) else f"{self.name} is not on PATH"
        if self.kind == "env":
            return None if os.environ.get(self.name) else f"{self.name} is not configured"
        return f"unknown requirement kind {self.kind!r}"


def module(name: str) -> Requirement:
    return Requirement("module", name)


def binary(name: str) -> Requirement:
    """A tool that shells out to something on PATH.

    No built-in sidecar needs one — capa is a Python API here, not a command —
    but the kind is part of the vocabulary ``docs/configuration.md`` publishes
    for a server somebody else writes, and a kind with no way to declare it is
    a kind nobody can use.
    """
    return Requirement("binary", name)


def env(name: str) -> Requirement:
    return Requirement("env", name)


@dataclass(frozen=True)
class ToolNeeds:
    """A tool and what it needs. No requirement means it always answers."""

    name: str
    requires: tuple[Requirement, ...] = ()
    timeout_s: float | None = None
    # What the tool still does without the requirement, when it does
    # something: ``apk_info`` answers the zip-level facts without androguard.
    without: str = ""


def _cell(tool: ToolNeeds) -> dict[str, Any]:
    # Probed once per requirement. The reason and the code both need the
    # answer, and probing twice re-runs an import, a ``which`` and a read of
    # the environment for every cell of every manifest.
    probed = [(req, req.probe()) for req in tool.requires]
    missing = [(req, reason) for req, reason in probed if reason]
    dependency = ", ".join(req.name for req in tool.requires) or None
    cell: dict[str, Any] = {
        "name": tool.name,
        "optional_dependency": dependency,
        "available": not missing,
        "reason": "; ".join(reason for _req, reason in missing) if missing else None,
        "timeout_s": tool.timeout_s,
    }
    if missing:
        kinds = {req.kind for req, _reason in missing}
        code = NOT_CONFIGURED if kinds == {"env"} else MISSING_DEPENDENCY
        cell["remediation"] = REMEDIATIONS[code]
        if tool.without:
            cell["without"] = tool.without
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


@dataclass
class Unavailable:
    """One tool a manifest marks unavailable, as a degradation reason reads it."""

    server: str
    tool: str
    reason: str
    remediation: str | None = None
    without: str = ""

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
                )
            )
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server,
            "version": self.version,
            "tools": [dict(cell) for cell in self.tools.values()],
        }
