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

    ``team`` is ``None`` for a finding about the agent map rather than one team;
    ``agent`` then names the agent it concerns. ``stage`` and ``field`` locate
    a stage finding on its card.
    """

    severity: Severity
    code: str
    message: str
    team: str | None = None
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


def _dependency_edges(stages: list[StageDefinition]) -> dict[str, list[str]]:
    """Each key's dependencies among the team's keys, itself left out, first declaration's."""
    keys = {stage.key for stage in stages}
    edges: dict[str, list[str]] = {}
    for stage in stages:
        if stage.key in edges:
            continue
        edges[stage.key] = [
            d for d in dict.fromkeys(stage.depends_on) if d in keys and d != stage.key
        ]
    return edges


def _strongly_connected(edges: dict[str, list[str]]) -> list[list[str]]:
    """Every group of two or more keys that reach each other, by Tarjan's method.

    Iterative, with an explicit stack of (key, position in its edge list), so
    a chain of any length costs its keys plus its edges and never the
    interpreter's recursion depth.
    """
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    found: list[list[str]] = []
    counter = 0
    for root in edges:
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            key, position = work[-1]
            targets = edges.get(key, [])
            if position < len(targets):
                work[-1] = (key, position + 1)
                nxt = targets[position]
                if nxt not in index:
                    index[nxt] = low[nxt] = counter
                    counter += 1
                    stack.append(nxt)
                    on_stack.add(nxt)
                    work.append((nxt, 0))
                elif nxt in on_stack:
                    low[key] = min(low[key], index[nxt])
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[key])
            if low[key] == index[key]:
                component: list[str] = []
                while True:
                    top = stack.pop()
                    on_stack.discard(top)
                    component.append(top)
                    if top == key:
                        break
                if len(component) > 1:
                    found.append(component)
    return found


def _cycles(stages: list[StageDefinition]) -> list[list[str]]:
    """One real loop through ``depends_on`` in every tangle of stages, in dependency order.

    Each group of stages that depend on each other yields one loop through it,
    starting at the group's first-declared stage and following dependencies
    inside the group until a stage repeats: a path an operator can walk on the
    cards, not merely the list of stages involved. A stage that depends on
    itself is already refused in those words, so a loop of one is left to
    that rule. Linear in stages plus edges.
    """
    order: dict[str, int] = {}
    for i, stage in enumerate(stages):
        order.setdefault(stage.key, i)
    edges = _dependency_edges(stages)
    loops: list[list[str]] = []
    for component in _strongly_connected(edges):
        members = set(component)
        start = min(component, key=order.__getitem__)
        path: list[str] = []
        position: dict[str, int] = {}
        current = start
        while current not in position:
            position[current] = len(path)
            path.append(current)
            current = next(d for d in edges[current] if d in members)
        loops.append(path[position[current] :])
    loops.sort(key=lambda loop: order[loop[0]])
    return loops


def _graph(stages: list[StageDefinition]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Dependencies and dependents per key, the triage pack's adoption included."""
    edges = _dependency_edges(stages)
    first, adopted = adopted_roots(stages)
    if first is not None:
        for key in adopted:
            edges[key] = [*edges.get(key, []), first]
    reverse: dict[str, list[str]] = {}
    for key, targets in edges.items():
        for target in targets:
            reverse.setdefault(target, []).append(key)
    return edges, reverse


def _reach(start: str, edges: dict[str, list[str]]) -> set[str]:
    """Every key reachable from ``start`` in one or more steps. Iterative."""
    seen: set[str] = set()
    pending = list(edges.get(start, []))
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        pending.extend(edges.get(current, []))
    return seen


def _read_upstream(
    stages: list[StageDefinition], edges: dict[str, list[str]], bit: dict[str, int]
) -> dict[str, int]:
    """For each stage, which of the keys in ``bit`` it runs after, as a bit mask.

    One pass in dependency order (Kahn's method over ``edges``, which the
    caller has checked hold no loop): a stage's mask is its dependencies'
    masks with each dependency's own bit added. Only keys some condition
    reads get a bit, so the cost is the stages plus the edges, times the
    number of distinct stages conditions read, over the machine word, and a
    stage's answer to "has ``x`` run before me" is one bit test.
    """
    waiting = {stage.key: len(edges.get(stage.key, [])) for stage in stages}
    dependents: dict[str, list[str]] = {}
    for key, targets in edges.items():
        for target in targets:
            dependents.setdefault(target, []).append(key)
    mask: dict[str, int] = {key: 0 for key in waiting}
    ready = [key for key, count in waiting.items() if count == 0]
    while ready:
        key = ready.pop()
        carried = mask[key] | bit.get(key, 0)
        for dependent in dependents.get(key, []):
            mask[dependent] |= carried
            waiting[dependent] -= 1
            if waiting[dependent] == 0:
                ready.append(dependent)
    return mask


def _warnings(name: str, stages: list[StageDefinition]) -> list[TeamFinding]:
    """What is legal about ``stages`` and still not what it looks like.

    Only what the team itself decides. A condition that names a field of the
    sample may be false for every sample this deployment will ever see, and
    saying so would be a guess; one that reads a stage the team does not have
    always reads "did not run", and that is a fact about the team.

    Nothing here holds a set per stage. The verdict warnings are two walks from
    the verdict stage, one up and one down; a condition that reads another
    stage is one walk from the stage that carries it, stopped when it arrives.
    """
    findings: list[TeamFinding] = []
    keys = [stage.key for stage in stages]
    known = set(keys)
    if len(known) != len(keys) or _cycles(stages):
        return findings
    edges, reverse = _graph(stages)

    verdicts = [stage.key for stage in stages if stage.kind == "verdict"]
    if len(verdicts) == 1:
        verdict = verdicts[0]
        before = _reach(verdict, edges)
        after = _reach(verdict, reverse)
        for stage in stages:
            if stage.kind in ("verdict", "report"):
                continue
            if stage.key in after:
                message = (
                    f"stage {stage.key!r} runs after the verdict stage {verdict!r}, so "
                    "nothing it finds reaches the verdict"
                )
                findings.append(
                    TeamFinding("warning", "after_verdict", message, name, stage.key, "depends_on")
                )
            elif stage.key not in before:
                message = (
                    f"stage {stage.key!r} is not upstream of the verdict stage {verdict!r}: "
                    "the judge does not wait for it, so what it finds may not reach the verdict"
                )
                findings.append(
                    TeamFinding("warning", "unreachable", message, name, stage.key, "depends_on")
                )

    conditioned = [
        stage
        for stage in stages
        if stage.when.strip() and not stage_condition_problem(stage.key, stage.when)
    ]
    references = {stage.key: stage_references(stage.when) for stage in conditioned}
    wanted = {read for reads in references.values() for read in reads if read in known}
    bit = {key: 1 << i for i, key in enumerate(sorted(wanted))}
    before_me = _read_upstream(stages, edges, bit) if bit else {}
    for stage in conditioned:
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
        for read in references[stage.key]:
            if read not in known:
                message = (
                    f"stage {stage.key!r}: the condition reads stages.{read}, and this team "
                    f"has no stage {read!r}; it always reads as a stage that did not run"
                )
                code = "condition_unknown_stage"
            elif not before_me.get(stage.key, 0) & bit[read]:
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
        # The whole loop is written out once, on its first-declared stage; the
        # other stages on it point there, so a loop of n stages is n findings
        # of constant length rather than n copies of an n-stage path.
        head = loop[0]
        path = " → ".join([*loop, head])
        findings.append(
            TeamFinding(
                "error",
                "cycle",
                f"stages depend on each other in a loop: {path}",
                name,
                head,
                "depends_on",
            )
        )
        findings.extend(
            TeamFinding(
                "error",
                "cycle",
                f"stage {key!r} is on the loop of stages written out on stage {head!r}",
                name,
                key,
                "depends_on",
            )
            for key in loop[1:]
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
