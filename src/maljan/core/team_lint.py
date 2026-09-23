"""Everything wrong with a team, found before it is saved rather than during a job.

A team is operator text: stages, what each depends on, when each runs and who
is in it. A malformed one used to be found in one of two places, both late —
the save that refused it with the first problem the settings model met, or a
job that failed deep in the graph builder after the sample had been uploaded.
This module reads a team the way the settings model does and reports every
problem at once, located on the stage it concerns.

It adds no rule of its own to what save refuses. Every error comes from the
functions the settings model itself raises from (``stage_list_problems``,
``stage_member_problems``, ``stage_condition_problem``, the built-in identity
check and pydantic's own field messages), so what the editor shows and what
save refuses are the same sentences. The one error it words itself is a
cycle, which save refuses as a dependency on a later stage; naming the loop
is what tells the operator which edge to cut.

Warnings are the other half: a team that saves and runs, and will not do what
it looks like it does. A warning never blocks a save, and each one is decided
from the team as written — nothing here guesses what a sample will be.

The lint never changes a team. It reports.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import ValidationError

from maljan.core.config import (
    _AGENT_KEY_RE,
    _KEY_RULE,
    BUILTIN_PROFILES,
    JUDGE_AGENT_KEY,
    REPORTER_AGENT_KEY,
    ProfileDefinition,
    StageDefinition,
    TeamProblem,
    _builtin_profiles,
    _definition_field,
    analysts_become_stages,
    builtin_profile_changed,
    builtin_profile_message,
    convert_builtin_profile_document,
    stage_condition_problem,
    stage_list_problems,
    stage_member_problems,
)
from maljan.pipeline.conditions import constant_truth, stage_references
from maljan.pipeline.topology import adopted_roots

__all__ = ["TeamFinding", "lint_team", "lint_teams", "team_stages"]

Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class TeamFinding:
    """One problem with a team, where it sits, and whether it blocks a save.

    ``team`` is empty for a finding about the agent map rather than one team;
    ``agent`` then names the agent it concerns. ``stage`` and ``field`` locate
    a stage finding on its card.
    """

    severity: Severity
    code: str
    message: str
    team: str = ""
    stage: str | None = None
    field: str | None = None
    agent: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "team": self.team,
            "stage": self.stage,
            "field": self.field,
            "agent": self.agent,
        }


def _error(team: str, problem: TeamProblem) -> TeamFinding:
    return TeamFinding("error", problem.code, problem.message, team, problem.stage, problem.field)


def _stage_label(raw: Any, index: int) -> str:
    """The name a stage goes by in a finding: its key when it has one."""
    if isinstance(raw, dict) and isinstance(raw.get("key"), str) and raw["key"]:
        return str(raw["key"])
    return str(index)


def _placeholder(raw: Any, label: str) -> StageDefinition:
    """A stand-in for a stage pydantic refused, so the graph rules still see it.

    Built without validation, from whatever of the raw stage has the right
    type. A kind that is not a kind stays as written: no kind rule matches it,
    so the stand-in adds no finding the stage did not earn.
    """
    data = raw if isinstance(raw, dict) else {}

    def strings(value: Any) -> list[str]:
        return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []

    kind = data.get("kind", "analysis")
    return StageDefinition.model_construct(
        key=label,
        label=data.get("label") if isinstance(data.get("label"), str) else "",
        kind=kind if isinstance(kind, str) else "",
        agents=strings(data.get("agents")),
        depends_on=strings(data.get("depends_on")),
        when=data.get("when") if isinstance(data.get("when"), str) else "",
        mode="parallel" if data.get("mode") == "parallel" else "sequential",
        inject_upstream="findings",
        debate=None,
        builtin_tools=True,
    )


def _prepared(name: str, entry: dict[str, Any]) -> dict[str, Any]:
    """``entry`` as the settings model reads it: a built-in's pack choice, analysts as stages."""
    converted = convert_builtin_profile_document(name, entry)
    prepared = analysts_become_stages(converted)
    return prepared if isinstance(prepared, dict) else entry


def team_stages(name: str, entry: Any) -> tuple[list[StageDefinition], list[TeamFinding]]:
    """Every stage of ``entry``, typed where pydantic accepts it, and its field errors.

    A stage pydantic refuses is replaced by a stand-in built from its raw
    values, so a key typed wrong on one card does not hide a dangling
    dependency on another. The condition is checked apart from the other
    fields, by the same function the stage model raises from, so it is
    reported under ``when`` in the model's own words.
    """
    findings: list[TeamFinding] = []
    if isinstance(entry, dict):
        entry = _prepared(name, entry)
    raw_stages = entry.get("stages") if isinstance(entry, dict) else None
    if not isinstance(raw_stages, list):
        return [], findings
    typed: list[StageDefinition] = []
    for index, raw in enumerate(raw_stages):
        label = _stage_label(raw, index)
        when = raw.get("when", "") if isinstance(raw, dict) else ""
        candidate = {**raw, "when": ""} if isinstance(raw, dict) and isinstance(when, str) else raw
        try:
            stage = StageDefinition.model_validate(candidate)
        except ValidationError as exc:
            for err in exc.errors():
                field = str(err["loc"][0]) if err["loc"] else None
                findings.append(TeamFinding("error", "field", err["msg"], name, label, field))
            stage = _placeholder(raw, label)
        else:
            stage = stage.model_copy(update={"when": when})
        if isinstance(when, str):
            problem = stage_condition_problem(stage.key, when)
            if problem:
                findings.append(TeamFinding("error", "condition", problem, name, label, "when"))
        typed.append(stage)
    return typed, findings


def _profile_field_errors(name: str, entry: dict[str, Any]) -> list[TeamFinding]:
    """Pydantic's refusals of the team's own fields, the stage list aside."""
    try:
        ProfileDefinition.model_validate(entry)
    except ValidationError as exc:
        return [
            TeamFinding("error", "field", err["msg"], name, None, str(err["loc"][0]))
            for err in exc.errors()
            if err["loc"] and err["loc"][0] != "stages"
        ]
    return []


def _cycles(stages: list[StageDefinition]) -> list[list[str]]:
    """Every loop of two or more stages through ``depends_on``, each in stage order.

    A stage that depends on itself is already refused in those words, so a
    loop of one is left to that rule.
    """
    order = {stage.key: i for i, stage in enumerate(stages)}
    edges = {
        stage.key: [d for d in stage.depends_on if d in order and d != stage.key]
        for stage in stages
    }
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    found: list[list[str]] = []
    counter = 0

    def visit(key: str) -> None:
        nonlocal counter
        index[key] = low[key] = counter
        counter += 1
        stack.append(key)
        on_stack.add(key)
        for nxt in edges.get(key, []):
            if nxt not in index:
                visit(nxt)
                low[key] = min(low[key], low[nxt])
            elif nxt in on_stack:
                low[key] = min(low[key], index[nxt])
        if low[key] == index[key]:
            component: list[str] = []
            while True:
                top = stack.pop()
                on_stack.discard(top)
                component.append(top)
                if top == key:
                    break
            if len(component) > 1:
                found.append(sorted(component, key=order.__getitem__))

    for stage in stages:
        if stage.key not in index:
            visit(stage.key)
    return found


def _upstream(stages: list[StageDefinition]) -> dict[str, set[str]]:
    """Every stage each stage runs after, the triage pack's adoption included."""
    keys = {stage.key for stage in stages}
    first, adopted = adopted_roots(stages)
    direct: dict[str, list[str]] = {
        stage.key: [d for d in stage.depends_on if d in keys] for stage in stages
    }
    if first is not None:
        for key in adopted:
            direct[key] = [*direct.get(key, []), first]
    out: dict[str, set[str]] = {}
    for stage in stages:
        seen: set[str] = set()
        pending = list(direct.get(stage.key, []))
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            pending.extend(direct.get(current, []))
        out[stage.key] = seen
    return out


def _warnings(name: str, stages: list[StageDefinition]) -> list[TeamFinding]:
    """What is legal about ``stages`` and still not what it looks like.

    Only what the team itself decides. A condition that names a field of the
    sample may be false for every sample this deployment will ever see, and
    saying so would be a guess; one that reads a stage the team does not have
    always reads "did not run", and that is a fact about the team.
    """
    findings: list[TeamFinding] = []
    keys = [stage.key for stage in stages]
    if len(set(keys)) != len(keys) or _cycles(stages):
        return findings
    upstream = _upstream(stages)

    verdicts = [stage.key for stage in stages if stage.kind == "verdict"]
    if len(verdicts) == 1:
        verdict = verdicts[0]
        for stage in stages:
            if stage.kind in ("verdict", "report"):
                continue
            if verdict in upstream[stage.key]:
                message = (
                    f"stage {stage.key!r} runs after the verdict stage {verdict!r}, so "
                    "nothing it finds reaches the verdict"
                )
                findings.append(
                    TeamFinding("warning", "after_verdict", message, name, stage.key, "depends_on")
                )
            elif stage.key not in upstream[verdict]:
                message = (
                    f"stage {stage.key!r} is not upstream of the verdict stage {verdict!r}: "
                    "the judge does not wait for it, so what it finds may not reach the verdict"
                )
                findings.append(
                    TeamFinding("warning", "unreachable", message, name, stage.key, "depends_on")
                )

    for stage in stages:
        if not stage.when.strip() or stage_condition_problem(stage.key, stage.when):
            continue
        if constant_truth(stage.when) is False:
            findings.append(
                TeamFinding(
                    "warning",
                    "never_runs",
                    f"stage {stage.key!r}: the condition is false for every sample, so the "
                    "stage never runs",
                    name,
                    stage.key,
                    "when",
                )
            )
        for read in stage_references(stage.when):
            if read not in keys:
                message = (
                    f"stage {stage.key!r}: the condition reads stages.{read}, and this team "
                    f"has no stage {read!r}; it always reads as a stage that did not run"
                )
                code = "condition_unknown_stage"
            elif read not in upstream[stage.key]:
                message = (
                    f"stage {stage.key!r}: the condition reads stages.{read}, which this "
                    "stage does not run after; it may not have run when the condition is "
                    "evaluated"
                )
                code = "condition_not_upstream"
            else:
                continue
            findings.append(TeamFinding("warning", code, message, name, stage.key, "when"))
    return findings


def lint_team(
    name: str,
    entry: Any,
    *,
    definitions: Mapping[str, Any],
    active: str = "default",
) -> list[TeamFinding]:
    """Every error and warning about one team, errors first, each located.

    ``definitions`` is the agent map the team is checked against — models or
    stored dicts — and ``active`` the profile that would run, which is what
    decides whether a built-in team may keep a disabled member.
    """
    findings: list[TeamFinding] = []
    if not _AGENT_KEY_RE.match(str(name)):
        findings.append(TeamFinding("error", "team_key", f"{name!r}: {_KEY_RULE}", name))
    if not isinstance(entry, dict):
        findings.append(TeamFinding("error", "field", "a profile entry must be an object", name))
        return findings

    prepared = _prepared(name, entry)
    stages, field_errors = team_stages(name, prepared)
    findings.extend(_profile_field_errors(name, prepared))
    findings.extend(field_errors)

    shape = stage_list_problems(stages)
    findings.extend(_error(name, problem) for problem in shape)
    for loop in _cycles(stages):
        path = " → ".join([*loop, loop[0]])
        message = f"stages {', '.join(repr(k) for k in loop)} depend on each other: {path}"
        findings.extend(
            TeamFinding("error", "cycle", message, name, key, "depends_on") for key in loop
        )

    exempt = name in BUILTIN_PROFILES and name != active
    findings.extend(
        _error(name, problem)
        for problem in stage_member_problems(name, stages, definitions, exempt=exempt)
    )

    if name in _builtin_profiles():
        # A seed is a valid team, so a built-in the profile model refuses has
        # been edited. One it accepts is compared field by field; a disabled
        # member is a problem with the agent map, not an edit to the team.
        try:
            changed = builtin_profile_changed(name, ProfileDefinition.model_validate(prepared))
        except ValidationError:
            changed = True
        if changed:
            findings.append(TeamFinding("error", "builtin", builtin_profile_message(name), name))

    findings.extend(_warnings(name, stages))
    return findings


def _named_in_teams(profiles: Mapping[str, Any]) -> set[str]:
    named: set[str] = set()
    for entry in profiles.values():
        if not isinstance(entry, dict):
            continue
        for stage in entry.get("stages") or []:
            if isinstance(stage, dict):
                named.update(a for a in stage.get("agents") or [] if isinstance(a, str))
        named.update(a for a in entry.get("analysts") or [] if isinstance(a, str))
    return named


def _asked_by_agents(definitions: Mapping[str, Any]) -> set[str]:
    asked: set[str] = set()
    for definition in definitions.values():
        tools = (
            definition.get("tools")
            if isinstance(definition, dict)
            else [ref.model_dump() for ref in getattr(definition, "tools", [])]
        )
        for ref in tools or []:
            if isinstance(ref, dict) and ref.get("kind") == "agent" and ref.get("agent"):
                asked.add(str(ref["agent"]))
    return asked


def lint_teams(
    profiles: Mapping[str, Any],
    *,
    definitions: Mapping[str, Any],
    active: str = "default",
) -> list[TeamFinding]:
    """Every team in ``profiles``, then what only the whole map can say.

    The one map-wide warning is an unused agent: enabled, able to be an
    analyst, and named by no stage of any team and asked by no agent. It
    costs nothing at run time, which is why it is a warning; it is usually
    an agent someone meant to put in a team.
    """
    findings: list[TeamFinding] = []
    for name, entry in profiles.items():
        findings.extend(lint_team(str(name), entry, definitions=definitions, active=active))

    in_use = _named_in_teams(profiles) | _asked_by_agents(definitions)
    for key, definition in definitions.items():
        if key in (JUDGE_AGENT_KEY, REPORTER_AGENT_KEY) or key in in_use:
            continue
        if _definition_field(definition, "role") in ("judge", "report"):
            continue
        if _definition_field(definition, "enabled", True) is False:
            continue
        findings.append(
            TeamFinding(
                "warning",
                "unused_agent",
                f"agent {key!r} is enabled, and no team names it and no agent asks it",
                agent=str(key),
            )
        )
    return findings
