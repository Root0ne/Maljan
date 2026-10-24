"""Name, before a job starts, the tools it would call that this host cannot run.

A tool server's manifest says which of its tools are unavailable and why, but
a run reads it only once it has attached the server: a run whose analysis
server had lost capa was accepted, paid for, and said ``DEGRADED RUN``
afterwards. This reads the same declarations without starting anything.

Two places a job runs a tool on this host are checked, each against the
declared needs of the repository's sidecar the tool belongs to
(``tools.sidecar_needs``), with ``Requirement.installed``: a module looked up
on the import path, an executable looked for where it would be looked for.
Nothing is imported, started or run on a sample, so the check is cheap enough
for every submit and every status read, and linear in the tools declared.

* **The servers the job calls** (``composition.servers_a_job_calls``: its
  team's, the triage pack's, the static provider's) that are switched on and
  are one of those sidecars launched over stdio on this interpreter. A tool
  the server's block does not offer is not named.
* **The triage pack's own readings** (``tools.readers``): every enabled
  in-process step whose reading stands in for a sidecar's tool runs in the
  worker's own process unless the server declaring that tool is switched on
  and reached at an address (``pipeline.nodes._reader_servers``). Those are
  checked whatever the declaring server's block says (switched off, another
  command, a narrowed tool list), because none of it changes where the
  reading runs. A tool already named for its server is not named twice.

A server reached at an address, or launched on another interpreter, is not
checked here: its own manifest, read when a run attaches it and by the
settings connection test, is what says what it can do on its host. A server
whose block sets ``PYTHONPATH`` has its modules left unchecked, since a
library reachable only through it is not on this process's import path.

The default is to warn, not refuse (there is no setting that refuses a job on
an unavailable tool): the job is accepted and the answer names each tool, the
reason and the remedy, in the run's own degradation wording.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.tools.capabilities import ToolNeeds, Unavailable

from app.logsafe import log_safe


def _same_interpreter(command: str) -> bool:
    """Whether ``command`` is this process's interpreter, as written (links not followed).

    Two virtual environments share the base interpreter a link resolves to,
    and differ in exactly what this check is about.
    """
    return bool(command) and os.path.abspath(command) == os.path.abspath(sys.executable)


def _sidecar_directory(config: Any) -> str | None:
    """The ``services/<dir>`` whose ``server.py`` ``config`` launches, or ``None``."""
    from maljan.core.paths import get_project_root, resolve_mcp_args

    args = resolve_mcp_args([str(a) for a in getattr(config, "args", None) or []])
    if not args:
        return None
    script = Path(args[0])
    services = Path(get_project_root()) / "services"
    if script.name != "server.py" or script.parent.parent != services:
        return None
    return script.parent.name


def _sidecar_needs(config: Any) -> list[ToolNeeds] | None:
    """The declared needs of the sidecar ``config`` launches here, or ``None``.

    ``None`` for anything this host cannot check without starting it: a
    server reached at an address, another interpreter, another program.
    """
    from maljan.tools.sidecar_needs import BY_DIRECTORY

    if str(getattr(config, "transport", "")) != "stdio":
        return None
    if not _same_interpreter(str(getattr(config, "command", "") or "")):
        return None
    directory = _sidecar_directory(config)
    return BY_DIRECTORY.get(directory) if directory else None


def _environ(key: str, config: Any) -> dict[str, str]:
    """The environment the server is started with, which is where it looks for an executable."""
    from maljan.agents.subprocess_env import child_env

    return child_env(
        dict(getattr(config, "env", None) or {}),
        allow=tuple(getattr(config, "env_allow", None) or ()),
        server=key,
    )


def _reading_needs(config: Any, tool: str) -> tuple[str, ToolNeeds] | None:
    """The sidecar and declaration of ``tool`` a pack reading stands in for, or ``None``.

    The declaring server's own sidecar when its launch names one, else the
    sidecar that declares the tool: the reading runs the same code either way.
    """
    from maljan.tools.sidecar_needs import BY_DIRECTORY

    directory = _sidecar_directory(config) if config is not None else None
    candidates = [directory] if directory in BY_DIRECTORY else list(BY_DIRECTORY)
    for name in candidates:
        for need in BY_DIRECTORY[str(name)]:
            if need.name == tool:
                return str(name), need
    return None


def _in_process_readings(
    settings: Any, *, level: int = logging.INFO
) -> Iterable[tuple[str, ToolNeeds, Mapping[str, str] | None]]:
    """``(server, declaration, environment)`` of each pack reading this worker runs itself.

    The readings of every enabled in-process step, each but the ones whose
    declaring server is switched on and reached at an address, where the
    reading runs instead (``pipeline.nodes._reader_servers``). ``server`` is
    the declaring server's key, else the sidecar's name; the environment is
    the declaring server's, which the pack lends its in-process steps, else
    ``None`` (this process's own); one mapping per server, so a reading's
    answer can be kept per environment. ``level`` is what the choice of a
    switched-off or one of several declaring servers is logged at.
    """
    from maljan.agents.sample_staging import REMOTE_TRANSPORTS
    from maljan.core.pack_servers import _declaring_server_key
    from maljan.core.pack_steps import effective_steps, steps_on_servers
    from maljan.providers.servers import READER_DELIVERY_KIND
    from maljan.tools.readers import READERS

    servers = settings.mcp.servers
    steps, _off = steps_on_servers(
        effective_steps(getattr(settings.triage, "steps", None) or ()), servers
    )
    run = {step.called for step in steps if step.enabled and step.builtin}
    runners = {
        key: server
        for key, server in servers.items()
        if any(
            getattr(facts, "kind", None) == READER_DELIVERY_KIND
            for facts in (getattr(server, "tool_facts", None) or {}).values()
        )
    }
    lent: dict[str, Mapping[str, str]] = {}
    for tool in dict.fromkeys(spec.stands_for for spec in READERS.values()):
        if tool not in run:
            continue
        key = _declaring_server_key(runners, tool, purpose=f"the reading of {tool}", level=level)
        config = runners.get(key) if key else None
        transport = str(getattr(config, "transport", "stdio") or "stdio").lower()
        if config is not None and config.enabled and transport in REMOTE_TRANSPORTS:
            continue
        held = _reading_needs(config, tool)
        if held is None:
            continue
        directory, need = held
        label = key or directory.removesuffix("-mcp")
        if config is not None and key not in lent:
            lent[key] = _environ(key, config)
        yield label, need, lent.get(key) if config is not None else None


def _missing(
    need: ToolNeeds,
    environ: Mapping[str, str] | None,
    answered: dict[Any, str | None],
    *,
    modules: bool = True,
) -> Unavailable | None:
    """``need`` as unavailable when one of its requirements is absent, else ``None``.

    ``answered`` keeps each requirement's answer for ``environ``: an
    executable is looked for in it, so another environment is asked again.
    """
    reasons = []
    for req in need.requires:
        if req.kind == "module" and not modules:
            continue
        held = (req, id(environ))
        if held not in answered:
            answered[held] = req.installed(environ)
        if answered[held]:
            reasons.append(str(answered[held]))
    if not reasons:
        return None
    return Unavailable(
        server="",
        tool=need.name,
        reason="; ".join(reasons),
        remediation=need.remediation or _general_remedy(),
        without=need.without,
    )


def unavailable_tools(
    settings: Any,
    *,
    profile: str | None = None,
    global_provider: str | None = None,
    level: int = logging.DEBUG,
) -> list[Unavailable]:
    """Each tool a job under ``settings`` can call that this host lacks, by server and tool.

    ``profile`` and ``global_provider`` are what the job names, when it
    names them. Empty when everything checked is here, and when the job's
    servers cannot be read (an unknown profile is the caller's refusal).
    What is found is logged at ``level``: a warning for a job being accepted,
    a debug line for a status read.
    """
    from maljan.agents.composition import servers_a_job_calls

    if profile and profile != str(settings.agents.profile):
        agents = settings.agents.model_copy(update={"profile": profile})
        settings = settings.model_copy(update={"agents": agents})
    try:
        used = servers_a_job_calls(settings, global_provider=global_provider)
    except Exception as exc:  # noqa: BLE001 — what the job calls is unknown: nothing to name
        logger.debug("tool availability: servers not read (%s)", type(exc).__name__)
        return []
    found: list[Unavailable] = []
    for key in sorted(used):
        config = settings.mcp.servers.get(key)
        if config is None or not config.enabled:
            continue
        needs = _sidecar_needs(config)
        if needs is None:
            continue
        offered = None if config.tools is None else set(config.tools)
        modules = "PYTHONPATH" not in (config.env or {})
        if not modules:
            logger.debug(
                "tool availability: %s sets PYTHONPATH; its modules are not checked here",
                log_safe(key),
            )
        environ = _environ(key, config)
        # One answer per requirement: two tools needing one module ask once.
        answered: dict[Any, str | None] = {}
        for need in needs:
            if offered is not None and need.name not in offered:
                continue
            missing = _missing(need, environ, answered, modules=modules)
            if missing is not None:
                missing.server = key
                found.append(missing)
    named = {(u.server, u.tool) for u in found}
    try:
        # The status read asks often: its choice of server is a debug line.
        chosen_at = logging.DEBUG if level <= logging.DEBUG else logging.INFO
        readings = list(_in_process_readings(settings, level=chosen_at))
    except Exception as exc:  # noqa: BLE001 — the pack's steps unread: the servers' answer stands
        logger.debug("tool availability: pack readings not read (%s)", type(exc).__name__)
        readings = []
    answered = {}
    for server, need, lent in readings:
        if (server, need.name) in named:
            continue
        missing = _missing(need, lent, answered)
        if missing is not None:
            missing.server = server
            named.add((server, need.name))
            found.append(missing)
    if found:
        logger.log(
            level,
            "tools a job would call are unavailable on this host: %s",
            log_safe("; ".join(u.degradation_reason for u in found)),
        )
    return found


def _general_remedy() -> str:
    from maljan.tools.errors import MISSING_DEPENDENCY, REMEDIATIONS

    return REMEDIATIONS[MISSING_DEPENDENCY]


def as_rows(found: list[Unavailable]) -> list[dict[str, Any]]:
    """The API's rows: server, tool, reason, remedy, what it still answers, and the run's words."""
    return [
        {
            "server": u.server,
            "tool": u.tool,
            "reason": u.reason,
            "remediation": u.remediation or "",
            "still_answers": u.without,
            "degradation_reason": u.degradation_reason,
        }
        for u in found
    ]
