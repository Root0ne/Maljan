"""Whether one job's analysts run at once or one after another, and why.

``llm.parallel_analysts`` is ``auto``, ``true`` or ``false``. The two explicit
values are used as set. ``auto`` is decided per job from what the platform
already knows about the models the analysts call:

* a model served by Ollama, or by an OpenAI-compatible server at a loopback,
  link-local or private address, is a runtime somebody runs on one machine,
  and it is taken to serve one request at a time — unless it is a llama.cpp
  server whose ``/props`` reported more than one slot (read from the answer
  the window probe already asks for, so it costs no request of its own);
* any other endpoint is a hosted API, which serves requests concurrently —
  unless its ``/props`` reported exactly one slot.

One model of the job that is taken to serve one request at a time makes the
whole job sequential: concurrent analysts on it would clobber each other's
per-slot state. Every model an analyst may call is asked about, its fallbacks
included, because a fallback is a model the run calls.

A stage whose ``mode`` the operator set keeps it. A stage with no mode of its
own follows the resolved value (:func:`with_resolved_modes`), and so does the
revision round. The mode and its reason are logged once per job and carried
in the run summary's ``profile.analyst_mode``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from maljan.core.config import explicit_parallel
from maljan.core.logger import logger

SETTING = "llm.parallel_analysts"


@dataclass(frozen=True)
class AnalystMode:
    """The run mode one job resolved, what the setting said, and why."""

    parallel: bool
    setting: str
    reason: str

    @property
    def mode(self) -> str:
        return "parallel" if self.parallel else "sequential"

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "setting": self.setting, "reason": self.reason}

    def sentence(self) -> str:
        how = "in parallel" if self.parallel else "one after another"
        return f"Analysts run {how}: {self.reason}."


def _setting_of(settings: Any) -> tuple[bool | None, str]:
    value = getattr(getattr(settings, "llm", None), "parallel_analysts", None)
    explicit = explicit_parallel(value)
    if explicit is None:
        return None, "auto"
    return explicit, "true" if explicit else "false"


def _serves_concurrently(settings: Any, assignment: Any, *, probe: bool) -> tuple[bool, str]:
    """Whether one model's endpoint serves concurrent requests, and the words for why."""
    from maljan.core.model_assignments import endpoint_label
    from maljan.llm.context_window import reported_slots, window_for_assignment
    from maljan.llm.openai_provider import is_local_endpoint

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
    local = is_local_endpoint(endpoint)
    if local and probe:
        # The window probe reads ``/props``, where a llama.cpp server says how
        # many slots it serves; asked once per endpoint and cached.
        try:
            window_for_assignment(settings, assignment, probe=True)
        except Exception as exc:  # noqa: BLE001 — a probe never fails a job
            logger.debug("analyst mode: the window probe of %s failed (%s)", where, exc)
    slots = reported_slots(endpoint)
    if slots > 1:
        return True, f"the llama.cpp server at {where} serving {named} reports {slots} slots"
    if slots == 1:
        return False, f"the llama.cpp server at {where} serving {named} reports one slot"
    if local:
        return False, (
            f"{named} is served at {where}, a loopback, link-local or private address, and "
            "the server reported no slot count, so it is taken to serve one request at a time"
        )
    return True, f"{named} is served by a hosted API at {where}"


def resolve_analyst_mode(settings: Any, agents: list[str], *, probe: bool = True) -> AnalystMode:
    """The run mode ``llm.parallel_analysts`` gives the job whose analysts are ``agents``.

    ``probe=False`` decides from what is already known, without a request.
    Never raises: a mode that cannot be worked out is sequential, and says so.
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
    debate hands over to exactly one — stays sequential, and the log says why.
    The profile is copied; the stored one is never changed.
    """
    from maljan.core.config import stage_list_problems

    stages = list(getattr(profile, "stages", None) or [])
    if not any(stage.kind == "analysis" and stage.mode is None for stage in stages):
        return profile
    for index, stage in enumerate(stages):
        if stage.kind != "analysis" or stage.mode is not None:
            continue
        stages[index] = stage.model_copy(update={"mode": mode.mode})
        if not mode.parallel:
            continue
        problems = stage_list_problems(stages)
        if problems:
            stages[index] = stage.model_copy(update={"mode": "sequential"})
            logger.info(
                "Stage %r runs its agents one after another, not in parallel as the job's "
                "analyst mode says: %s",
                stage.key,
                problems[0].message,
            )
    return profile.model_copy(update={"stages": stages})
