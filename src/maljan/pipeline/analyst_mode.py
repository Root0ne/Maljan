"""Whether one job's analysts run at once or one after another, and why.

``llm.parallel_analysts`` is ``auto``, ``true`` or ``false``. The two explicit
values are used as set. ``auto`` is decided per job from the endpoints of the
models the analysts call:

* Ollama is a runtime somebody runs, taken to serve one request at a time.
* An OpenAI-compatible endpoint's host is resolved. A loopback, private,
  link-local or shared-range (``100.64.0.0/10``) address — written as a
  literal, or what the name resolves to — and a name that only a local
  resolver answers (``localhost``, ``*.local``, ``host.docker.internal`` and
  its kin) is a local server. A local server's ``/props`` is asked for its
  slot count (the window probe's own request): more than one slot runs the
  analysts in parallel, one slot or no answer runs them one after another.
* A host that resolves only to public addresses is a hosted API and runs them
  in parallel — unless its ``/props`` reported exactly one slot.
* A host that cannot be resolved runs them one after another: it could not be
  told whether the endpoint is hosted.
* A vendor API (Anthropic, Gemini) is hosted.

One model taken to serve one request at a time makes the whole job
sequential: concurrent analysts on it would clobber each other's per-slot
state. Every model an analyst may call is asked about, its fallbacks
included, because a fallback is a model the run calls. The reason names the
fact that decided.

Resolving names and asking ``/props`` are network round trips, so the worker
resolves the mode on a thread before it builds the job (:func:`resolve_for`).

A stage whose ``mode`` the operator set keeps it. A stage with no mode of its
own follows the job's mode (:func:`with_resolved_modes`), except one a debate
hands over to, which stays one node. A debate's revision round follows the
stages it revises (:func:`revision_mode`). What every analysis stage and
every revision round ran in, and why, is logged once per job and carried in
the run summary's ``profile.analyst_mode``.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from maljan.core.config import explicit_parallel
from maljan.core.logger import logger

SETTING = "llm.parallel_analysts"

# Names only a local resolver answers: a container runtime's name for the host
# it runs on, and the machine's own.
LOCAL_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "host.docker.internal",
        "gateway.docker.internal",
        "host.containers.internal",
        "host.lima.internal",
    }
)

# How long one name may take to resolve before it is taken as unresolvable.
RESOLVE_SECONDS = 3.0

# Where a stage's mode came from, as the run summary says it.
FROM_STAGE = "stage"
FROM_JOB = "job"
FROM_HANDOVER = "debate handover"
FROM_REVISED = "the stages it revises"

_SHARED_RANGE = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class AnalystMode:
    """The run mode one job resolved, what the setting said, and why."""

    parallel: bool
    setting: str
    reason: str
    stages: tuple[dict[str, Any], ...] = field(default=())

    @property
    def mode(self) -> str:
        return "parallel" if self.parallel else "sequential"

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mode": self.mode, "setting": self.setting, "reason": self.reason}
        if self.stages:
            out["stages"] = [dict(row) for row in self.stages]
        return out

    def sentence(self) -> str:
        how = "in parallel" if self.parallel else "one after another"
        return f"Analysts run {how} by default for this job: {self.reason}."


def _setting_of(settings: Any) -> tuple[bool | None, str]:
    value = getattr(getattr(settings, "llm", None), "parallel_analysts", None)
    explicit = explicit_parallel(value)
    if explicit is None:
        return None, "auto"
    return explicit, "true" if explicit else "false"


def _local_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return bool(
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or (isinstance(address, ipaddress.IPv4Address) and address in _SHARED_RANGE)
    )


def _addresses(host: str) -> list[str]:
    """Every address ``host`` resolves to, or ``[]`` when it does not resolve in time."""
    found: list[str] = []

    def _resolve() -> None:
        try:
            for row in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP):
                found.append(str(row[4][0]))
        except (OSError, UnicodeError):
            return

    worker = threading.Thread(target=_resolve, name="analyst-mode-resolve", daemon=True)
    worker.start()
    worker.join(RESOLVE_SECONDS)
    return [] if worker.is_alive() else list(dict.fromkeys(found))


def locality(endpoint: str) -> tuple[str, str]:
    """``("local" | "hosted" | "unknown", the fact that decided)`` for one endpoint's host."""
    host = (urlparse(endpoint).hostname or "").strip().lower().rstrip(".")
    if not host:
        return "unknown", f"{endpoint!r} names no host"
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _local_address(literal):
            return "local", f"{host} is a loopback, private, link-local or shared-range address"
        return "hosted", f"{host} is a public address"
    if host in LOCAL_NAMES or host.endswith((".localhost", ".local", ".internal")):
        return "local", f"{host} is a name only a local resolver answers"
    resolved = _addresses(host)
    if not resolved:
        return "unknown", f"{host} did not resolve, so it could not be told whether it is hosted"
    parsed = []
    for text in resolved:
        try:
            parsed.append(ipaddress.ip_address(text.split("%", 1)[0]))
        except ValueError:
            continue
    if not parsed:
        return "unknown", f"{host} did not resolve, so it could not be told whether it is hosted"
    local = [str(a) for a in parsed if _local_address(a)]
    if local:
        return "local", (
            f"{host} resolves to {', '.join(local)}, a loopback, private, link-local or "
            "shared-range address"
        )
    return "hosted", f"{host} resolves only to public addresses"


def _serves_concurrently(settings: Any, assignment: Any, *, probe: bool) -> tuple[bool, str]:
    """Whether one model's endpoint serves concurrent requests, and the fact that decided."""
    from maljan.core.model_assignments import endpoint_label
    from maljan.llm.context_window import reported_slots, window_for_assignment

    provider = str(assignment.provider)
    endpoint = str(assignment.endpoint or "")
    where = endpoint_label(endpoint) or provider
    named = f"{provider}/{assignment.model}"
    if provider == "ollama":
        return False, (
            f"{named} is served by Ollama at {where}, a runtime taken to serve one request "
            "at a time"
        )
    if provider != "openai":
        return True, f"{named} is served by the hosted {provider} API"
    kind, fact = locality(endpoint)
    if probe and kind != "unknown":
        # The window probe reads ``/props``, where a llama.cpp server says how
        # many slots it serves; asked once per endpoint and cached.
        try:
            window_for_assignment(settings, assignment, probe=True)
        except Exception as exc:  # noqa: BLE001 — a probe never fails a job
            logger.debug("analyst mode: the window probe of %s failed (%s)", where, exc)
    slots = reported_slots(endpoint)
    if kind == "unknown":
        return False, f"{named} is served at {where}: {fact}"
    if slots > 1:
        return True, f"{named} is served at {where} ({fact}), whose /props reports {slots} slots"
    if slots == 1:
        return False, f"{named} is served at {where} ({fact}), whose /props reports one slot"
    if kind == "local":
        return False, (
            f"{named} is served at {where} ({fact}), which reported no slot count, so it is "
            "taken to serve one request at a time"
        )
    return True, f"{named} is served at {where}, a hosted API ({fact})"


def resolve_analyst_mode(settings: Any, agents: list[str], *, probe: bool = True) -> AnalystMode:
    """The run mode ``llm.parallel_analysts`` gives the job whose analysts are ``agents``.

    ``probe=False`` asks no server for its slot count; names are still
    resolved. Never raises: a mode that cannot be worked out is sequential,
    and says so. Blocking: call it from a thread, not an event loop.
    """
    explicit, setting = _setting_of(settings)
    if explicit is not None:
        return AnalystMode(explicit, setting, f"{SETTING} is {setting}")
    try:
        from maljan.core.model_assignments import assignments_for

        assignments = assignments_for(settings, list(agents))
    except Exception as exc:  # noqa: BLE001 — a mode is never worth a failed job
        return AnalystMode(
            False, setting, f"{SETTING} is auto and the analysts' models could not be read ({exc})"
        )
    seen: dict[tuple[str, str, str], Any] = {}
    for assignment in assignments:
        seen.setdefault(
            (str(assignment.provider), str(assignment.endpoint), str(assignment.model)), assignment
        )
    if not seen:
        return AnalystMode(False, setting, f"{SETTING} is auto and no analyst names a model")
    said: list[str] = []
    for assignment in seen.values():
        concurrent, why = _serves_concurrently(settings, assignment, probe=probe)
        if not concurrent:
            return AnalystMode(False, setting, f"{SETTING} is auto and {why}")
        said.append(why)
    return AnalystMode(True, setting, f"{SETTING} is auto and " + "; ".join(said))


def resolve_for(settings: Any, *, mock: bool = False) -> AnalystMode:
    """The mode of the job ``settings`` describe: the active team's analysts, probed.

    What the worker runs on a thread before it builds the job. A mock job asks
    nothing of any server.
    """
    if mock:
        return mock_mode(settings)
    from maljan.agents.composition import analyst_keys

    return resolve_analyst_mode(settings, analyst_keys(settings), probe=True)


def mock_mode(settings: Any) -> AnalystMode:
    """The run mode of a mock job: the setting where it is explicit, else sequential."""
    explicit, setting = _setting_of(settings)
    if explicit is not None:
        return AnalystMode(explicit, setting, f"{SETTING} is {setting}")
    return AnalystMode(
        False,
        setting,
        f"{SETTING} is auto and a mock run calls no model, so its analysts run one after another",
    )


def analyst_mode_of(container: Any) -> AnalystMode:
    """The job's resolved mode, from ``container.analyst_mode()`` where it has one.

    A stand-in container without one is read from its settings: an explicit
    value as set, ``auto`` as sequential, because nothing resolved it.
    """
    getter = getattr(container, "analyst_mode", None)
    if callable(getter):
        try:
            found = getter()
        except Exception as exc:  # noqa: BLE001 — a mode is never worth a failed node
            logger.debug("analyst mode: the container's could not be read (%s)", exc)
            found = None
        if isinstance(found, AnalystMode):
            return found
    explicit, setting = _setting_of(getattr(container, "config", None))
    if explicit is not None:
        return AnalystMode(explicit, setting, f"{SETTING} is {setting}")
    return AnalystMode(False, setting, f"{SETTING} is auto and was not resolved for this job")


def with_resolved_modes(profile: Any, mode: AnalystMode) -> Any:
    """``profile`` with every analysis stage that sets no mode given the job's.

    A stage whose own mode is set is left as it is. A stage the team cannot
    run in parallel — a parallel stage with two agents is two nodes, and a
    debate hands over to exactly one — stays sequential. The profile is
    copied; the stored one is never changed.
    """
    from maljan.core.config import stage_list_problems

    stages = list(getattr(profile, "stages", None) or [])
    if not any(stage.kind == "analysis" and stage.mode is None for stage in stages):
        return profile
    for index, stage in enumerate(stages):
        if stage.kind != "analysis" or stage.mode is not None:
            continue
        stages[index] = stage.model_copy(update={"mode": mode.mode})
        if mode.parallel and stage_list_problems(stages):
            stages[index] = stage.model_copy(update={"mode": "sequential"})
    return profile.model_copy(update={"stages": stages})


def _upstream_analysis(profile: Any, debate: Any) -> list[Any]:
    """The analysis stages a debate stage argues over: every one upstream of it."""
    by_key = {stage.key: stage for stage in profile.stages}
    upstream: set[str] = set()
    pending = [key for key in debate.depends_on if key in by_key]
    while pending:
        current = pending.pop()
        if current in upstream:
            continue
        upstream.add(current)
        pending.extend(key for key in by_key[current].depends_on if key in by_key)
    return [s for s in profile.stages if s.kind == "analysis" and s.key in upstream]


def revision_mode(resolved: Any, debate: Any, job: AnalystMode) -> tuple[bool, str]:
    """``(parallel, where it came from)`` for a debate's revision round.

    The mode of the stages it revises: parallel only when every one of them
    runs in parallel. With none found, the job's.
    """
    revised = _upstream_analysis(resolved, debate) if debate is not None else []
    if not revised:
        return job.parallel, FROM_JOB
    return all(stage.mode == "parallel" for stage in revised), FROM_REVISED


def stage_modes(stored: Any, resolved: Any, job: AnalystMode) -> tuple[dict[str, Any], ...]:
    """What every analysis stage and every revision round runs in, and where it came from."""
    rows: list[dict[str, Any]] = []
    original = {stage.key: stage for stage in stored.stages}
    for stage in resolved.stages:
        if stage.kind == "analysis":
            own = getattr(original.get(stage.key), "mode", None)
            mode = stage.mode or "sequential"
            if own is not None:
                source = FROM_STAGE
            elif mode != job.mode:
                source = FROM_HANDOVER
            else:
                source = FROM_JOB
            rows.append({"stage": stage.key, "round": "analysis", "mode": mode, "from": source})
        elif stage.kind == "debate":
            parallel, source = revision_mode(resolved, stage, job)
            rows.append(
                {
                    "stage": stage.key,
                    "round": "revision",
                    "mode": "parallel" if parallel else "sequential",
                    "from": source,
                }
            )
    return tuple(rows)


def stage_sentences(rows: tuple[dict[str, Any], ...]) -> list[str]:
    """One log line per row of :func:`stage_modes`."""
    said = {
        FROM_STAGE: "set on the stage",
        FROM_JOB: "the job's mode",
        FROM_HANDOVER: "a debate hands over to it, so it stays one node",
        FROM_REVISED: "the mode of the stages it revises",
    }
    out = []
    for row in rows:
        what = "its agents" if row["round"] == "analysis" else "its revision round"
        how = "in parallel" if row["mode"] == "parallel" else "one after another"
        out.append(
            f"Stage {row['stage']!r} runs {what} {how} ({said.get(row['from'], row['from'])})."
        )
    return out
