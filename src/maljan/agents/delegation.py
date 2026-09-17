"""One agent asking another, as a tool call.

A lead analyst gives work to specialists; a specialist checks a point with a
colleague. Both are the same act here: ``ToolRef(kind="agent", agent=<key>)``
on a definition puts a tool named ``ask_<key>`` in that agent's toolbox, and
calling it runs the named agent under the same job — the same container, the
same sample paths, the same pack and run state — with the task as its human
turn, and hands its answer back as the tool's result.

Expressing delegation as a tool is the whole design. Nothing about it is a
second mechanism: the ask is a ledger entry (``server="team"``,
``tool="ask_<key>"``) recorded by the same wrapper as every other call, with
the callee's wall clock as its duration; the callee's own tool calls are
ledger entries under the callee's key, written to the caller's evidence buffer
so the stage node that drains the caller writes them all; the callee's turns
come out of the ask's own budget and are counted under the callee; and the ask
and the answer are two
``agent_message`` events with ``addressed_to`` set, so the transcript shows
who asked whom and what came back.

The answer is the callee's ISR text, verbatim. The caller reads it as a tool
result and decides what to make of it; nothing here edits a claim, a
confidence or a technique id on the way through.

Four guards, each a tool error the model reads rather than a job failure:
a callee that is not defined or is disabled is refused by name; an ask that
would nest deeper than ``core.agents.delegation_depth`` is refused with the
chain that reached it; an ask back up the chain — the callee asking its
caller, or anyone already waiting on this answer — is refused as a cycle; and
an ask that would come back with a server the asking stage withholds is
refused naming the stage and the servers, because a callee's effective tool
set is its own definition narrowed by the tool policy of the stage asking.

One agent does one thing at a time, on both sides. A caller's asks take its
own ``asks_lock``, so two ``ask_*`` calls in one turn — which langgraph
gathers — run one after the other rather than putting two nested loops on one
llama-server slot. An ask of an agent, a second ask of it and its own stage
run take *its* lock, because all three drive the same buffers and the same
call chain. The two locks are different objects, which is what lets an ask
made from inside an ask still nest. A caller waits only as long as it can
still read an answer in, and a callee that does not free up in that time is a
refusal like the others.

An ask has a budget of its own: ``core.agents.delegation_steps`` and
``core.agents.delegation_timeout_seconds``, cut to the time the caller has
left and to nothing else. A callee derived from its caller's remaining steps
ran out before it had made a tool call, and the caller's own budget is not
spent by its specialists' work — only by the wall clock it waits through.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

from maljan.agents.tool_pinning import SERVER_METADATA_KEY
from maljan.core.logger import logger
from maljan.pipeline.events import claims_to_payload, emit_agent_message, summarize_claims
from maljan.pipeline.validation import Violation

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool

    from maljan.schemas.isr_models import AgentISR

# The server a delegation entry is recorded under. Not a tool server: the
# name says the call went to a member of the team.
TEAM_SERVER = "team"

# An ask that would leave its caller with less than this cannot be answered
# in the time: the callee's loop needs a first model turn and the caller a
# last one to read the answer. There is no matching step floor — an ask has a
# step budget of its own, so the caller's remaining steps say nothing about
# whether a specialist can still do a piece of work.
MIN_SECONDS_TO_ASK = 20.0
# Kept back from what the caller has left, so the callee's hard cap fires
# before the caller's own does and the caller still reads the answer.
SECONDS_KEPT_FOR_THE_CALLER = 15.0
# How long an ask made outside a tool loop — a script, a test harness — waits
# for a busy callee. A caller inside a loop waits what its own budget allows.
SECONDS_WAITING_OUTSIDE_A_LOOP = 300.0

# How much of a callee's raw answer is shown when it carried no claim.
_ANSWER_WITHOUT_CLAIMS_CHARS = 2000


class DelegationRefused(Exception):
    """An ask that is not made, with the reason in the words the model reads."""


# How a refusal reads in a ledger entry's error, since the recorder writes an
# exception as ``<type>: <message>``. Named here rather than spelled at the
# reader, so the two cannot drift: the report header uses it to leave a guard
# that worked out of its list of broken tools, while a callee that raised or
# ran out of time stays in.
REFUSAL_PREFIX = f"{DelegationRefused.__name__}:"


class AskArguments(BaseModel):
    """What one ask carries. ``task`` is the question; ``context`` is optional."""

    task: str = Field(
        description=(
            "What this agent should establish or check: one focused question it can "
            "answer with its own tools over this sample."
        )
    )
    context: str = Field(
        default="",
        description=(
            "Facts, ledger ids or findings the agent should start from, when the task needs them."
        ),
    )


def tool_name(agent_key: str) -> str:
    """The name the tool carries in a caller's toolbox."""
    return f"ask_{agent_key}"


def ask_tool(container: Any, caller_key: str, callee_key: str) -> BaseTool:
    """The ``ask_<callee>`` tool for ``caller_key``, described from the callee.

    A synchronous function on purpose: the ReAct executor runs a sync tool on
    a worker thread, which is the one place a nested tool loop may block on
    the shared agent loop without deadlocking it.
    """
    from langchain_core.tools import StructuredTool

    definition = container.config.agents.definitions.get(callee_key)
    label = str(getattr(definition, "label", "") or "") or callee_key
    role = str(getattr(definition, "role", "") or "agent")
    steps, seconds = ask_budget(container)
    description = (
        f"Ask {label} ({callee_key}, role {role}) to work on one focused task with its "
        "own tools over this sample. Its answer comes back as its own claims, each with "
        "the ledger ids it cited, exactly as it gave them. It gets "
        f"{steps} steps and up to {seconds} s of its own, and they do not come out of "
        f"your step budget — your wall clock is what they cost, so about "
        f"{_asks_that_fit(caller_key, seconds)} of these fit in your time. Ask one at a "
        "time and read each answer before the next."
    )

    def _ask(task: str, context: str = "") -> str:
        return ask(
            container, caller_key=caller_key, callee_key=callee_key, task=task, context=context
        )

    return StructuredTool.from_function(
        func=_ask,
        name=tool_name(callee_key),
        description=description,
        args_schema=AskArguments,
        infer_schema=False,
        metadata={SERVER_METADATA_KEY: TEAM_SERVER},
    )


def _asks_that_fit(caller_key: str, seconds: int) -> int:
    """Roughly how many asks the caller's own stage timeout has room for.

    A number the model can plan against. Rough on purpose: an ask that
    finishes early gives its remainder back, so this is a floor rather than a
    quota, and the refusal is what actually stops the last one.
    """
    from maljan.agents.base_agent import loop_limits

    try:
        timeout, _steps = loop_limits(caller_key)
    except Exception:  # noqa: BLE001 — a sentence is never worth a failed resolution
        return 1
    return max(1, int(timeout // max(1, seconds)))


def refusal(container: Any, caller: Any, callee_key: str) -> str | None:
    """Why this ask is not made, or ``None`` when it may be.

    The definition and the enabled flag are read from the job's settings; the
    depth and the cycle are read from the caller's own call chain, which is
    the list of agents whose asks it is itself answering.
    """
    definitions = container.config.agents.definitions
    definition = definitions.get(callee_key)
    if definition is None:
        available = ", ".join(sorted(definitions)) or "(none)"
        return f"there is no agent named {callee_key!r} to ask. Available: {available}"
    if not getattr(definition, "enabled", True):
        return f"agent {callee_key!r} is disabled in this deployment and cannot be asked"
    beyond = _servers_the_caller_may_not_reach(container, caller, callee_key)
    if beyond:
        return (
            f"asking {callee_key!r} would reach {', '.join(beyond)}, which "
            f"{_where_the_caller_runs(container, caller)} withholds from the agents in it; "
            "work from the tools you were given"
        )
    chain = (*tuple(getattr(caller, "call_chain", ()) or ()), str(caller.name))
    if callee_key in chain:
        path = " -> ".join((*chain, callee_key))
        return (
            f"asking {callee_key!r} would be a cycle: it is already waiting on this answer ({path})"
        )
    limit = int(getattr(container.config.agents, "delegation_depth", 2) or 2)
    if len(chain) > limit:
        path = " -> ".join(chain)
        return (
            f"asking {callee_key!r} would nest deeper than the delegation depth of "
            f"{limit} ({path}); answer from what you have or ask through your caller"
        )
    budget = getattr(caller, "loop_budget", None)
    if budget is not None:
        # Time, and only time. An ask has a step budget of its own, so the
        # caller having spent its steps says nothing about whether a
        # specialist can still do a piece of work — but the caller waits
        # inside its own wall clock, so its remaining seconds are real.
        seconds = budget.seconds_left() - SECONDS_KEPT_FOR_THE_CALLER
        if seconds < MIN_SECONDS_TO_ASK:
            return (
                f"not enough time left to ask {callee_key!r}: {max(0, int(seconds))} s "
                f"remain and an ask needs at least {int(MIN_SECONDS_TO_ASK)} s; "
                "write your answer from what you have"
            )
    return None


def _servers_the_caller_may_not_reach(container: Any, caller: Any, callee_key: str) -> list[str]:
    """The callee's servers the stage this chain started in withholds, or nothing."""
    from maljan.agents.composition import servers_withheld_from

    try:
        return servers_withheld_from(
            container.config,
            str(caller.name),
            callee_key,
            also=frozenset(getattr(caller, "withheld_by_the_chain", ()) or ()),
        )
    except Exception as exc:  # noqa: BLE001 — a guard never costs a run
        logger.debug("delegation: the caller's tool policy could not be read (%s).", exc)
        return []


def _the_chain_s_tool_policy(caller: Any) -> frozenset[str]:
    """Every server the stage that started this chain withholds, for the callee.

    Carried rather than recomputed, because a callee that no stage names
    withholds nothing of its own: without this the policy would hold for the
    first ask and lapse for the one that ask makes in turn.
    """
    from maljan.agents.composition import _withheld_servers

    inherited = frozenset(getattr(caller, "withheld_by_the_chain", ()) or ())
    try:
        return inherited | frozenset(_withheld_servers(caller._container.config, str(caller.name)))
    except Exception as exc:  # noqa: BLE001 — the inherited set still holds
        logger.debug("delegation: the caller's tool policy could not be read (%s).", exc)
        return inherited


def _where_the_caller_runs(container: Any, caller: Any) -> str:
    """The stage the caller is in, named the way the refusal reads best."""
    from maljan.agents.composition import stage_for_agent

    try:
        stage = stage_for_agent(container.config, str(caller.name))
    except Exception:  # noqa: BLE001 — the sentence still reads without it
        stage = None
    return f"stage {str(stage.key)!r}" if stage is not None else "this profile"


def ask(container: Any, *, caller_key: str, callee_key: str, task: str, context: str = "") -> str:
    """Run ``callee_key`` on ``task`` for ``caller_key`` and return its ISR text.

    Raises ``DelegationRefused`` for a guarded ask and whatever the callee's
    loop raises for one that failed; the recorder turns either into a failed
    ledger entry whose message the caller reads.
    """
    caller = container.get_agent(caller_key)
    why = refusal(container, caller, callee_key)
    if why is not None:
        logger.info("delegation refused (%s -> %s): %s", caller_key, callee_key, why)
        raise DelegationRefused(why)
    callee = container.get_agent(callee_key)
    wait = _seconds_to_wait_for(caller)
    # One ask at a time per caller. A model that emits two ``ask_*`` calls in
    # one turn has them run concurrently — langgraph gathers a turn's tool
    # calls — and two nested loops against one llama-server slot is the
    # re-prefill failure this project has already diagnosed once: the slot's
    # recurrent state is clobbered, every step re-processes the whole prompt,
    # and the run times out looking like a model problem. The caller's own
    # lock is a different object from any callee's, so an ask made from inside
    # an ask still nests.
    if not _held(caller.asks_lock, wait):
        raise DelegationRefused(
            f"another of your asks is still running and did not finish within {int(wait)} s; "
            "ask one agent at a time, or answer from what you have"
        )
    try:
        # One thing at a time per callee, too. The instance is the job's, so a
        # second caller asking it and the callee's own stage run drive the
        # same buffers, the same budget and the same call chain; both take
        # this lock, and the one that arrives second waits.
        #
        # Bounded, for two reasons. A caller must not spend more waiting than
        # it has left to read the answer with, and two agents in one parallel
        # stage that reference each other would otherwise each hold what the
        # other wants. What the wait buys is an answer; what it costs is
        # refused in words the model can act on.
        if not _held(callee.delegation_lock, _seconds_to_wait_for(caller)):
            raise DelegationRefused(
                f"agent {callee_key!r} is busy with its own work and did not free up in time; "
                "answer from what you have or ask someone else"
            )
        try:
            # Asked again now the waiting is done: the second ask of a turn
            # can have spent the caller's clock queueing, and an ask made with
            # no time left runs a one-second loop that fails where the refusal
            # is a sentence the model can act on.
            why = refusal(container, caller, callee_key)
            if why is not None:
                logger.info("delegation refused (%s -> %s): %s", caller_key, callee_key, why)
                raise DelegationRefused(why)
            return _ask(
                container, caller, callee, str(task or "").strip(), str(context or "").strip()
            )
        finally:
            callee.delegation_lock.release()
    finally:
        caller.asks_lock.release()


def _held(lock: Any, wait: float) -> bool:
    """Take ``lock`` within ``wait`` seconds, or say it could not be taken."""
    return bool(lock.acquire(timeout=max(0.0, float(wait))))


def _seconds_to_wait_for(caller: Any) -> float:
    """How long a caller may wait for a busy callee: what it can spare, at most."""
    budget = getattr(caller, "loop_budget", None)
    if budget is None:
        return SECONDS_WAITING_OUTSIDE_A_LOOP
    return max(1.0, float(budget.seconds_left()) - SECONDS_KEPT_FOR_THE_CALLER)


def _ask(container: Any, caller: Any, callee: Any, task: str, context: str) -> str:
    stage = str(getattr(caller, "pipeline_stage", "") or "analysis")
    round_index = int(getattr(caller, "current_round", 0) or 0)
    sink = getattr(container, "event_sink", None)
    emit_agent_message(
        sink,
        speaker=str(caller.name),
        role="analyst",
        text=task,
        round_index=round_index,
        report=context or None,
        stage=stage,
        addressed_to=str(callee.name),
    )

    # What the callee cannot have on this host, recorded once, the way the
    # stage node records it for an agent it is about to run. In the one team
    # where the specialists hold the tools, the specialists are in no stage,
    # so without this no unavailable tool of theirs is ever written down.
    _note_what_the_callee_cannot_have(container, callee)
    its_own = _what_the_callee_had(callee)
    _brief_callee(caller, callee, stage=stage, round_index=round_index)
    budget = getattr(caller, "loop_budget", None)
    callee._budget_ceiling = _what_this_ask_gets(container, budget)
    spent_before = int(getattr(callee, "steps_spent", 0) or 0)
    started = time.monotonic()
    try:
        text, isr = callee.answer_task(_task_turn(str(caller.name), task, context, callee))
    finally:
        callee._budget_ceiling = None
        callee.call_chain = ()
        _give_the_callee_back_what_it_had(callee, its_own)
        spent = int(getattr(callee, "steps_spent", 0) or 0) - spent_before
        if budget is not None:
            # Noted, not charged: the caller's own step budget is its own.
            budget.note_delegated(spent)
        _hand_over_the_record(
            caller, callee, still_running=getattr(caller, "loop_budget", None) is budget
        )
        logger.info(
            "delegation %s -> %s: %d step(s), %.1f s",
            caller.name,
            callee.name,
            spent,
            time.monotonic() - started,
        )

    _hand_over_the_structured_channel(caller, callee, isr)
    answer = _answer_text(isr, text)
    emit_agent_message(
        sink,
        speaker=str(callee.name),
        role="analyst",
        text=summarize_claims(isr.claims, speaker=str(callee.name)),
        round_index=round_index,
        status=_status(isr),
        claims=claims_to_payload(isr.claims),
        dissent=list(isr.dissent_items or []),
        report=answer,
        stage=stage,
        addressed_to=str(caller.name),
    )
    return answer


def _note_what_the_callee_cannot_have(container: Any, callee: Any) -> None:
    """Run the stage-start manifest check for an agent no stage will start."""
    try:
        from maljan.pipeline.nodes import note_unavailable_tools

        note_unavailable_tools(container, callee)
    except Exception as exc:  # noqa: BLE001 — a record is never worth a run
        logger.debug("delegation: the callee's manifest check was skipped (%s).", exc)


def ask_budget(container: Any) -> tuple[int, int]:
    """``(steps, seconds)`` one ask gets, from the job's settings."""
    agents = container.config.agents
    steps = int(getattr(agents, "delegation_steps", 12) or 12)
    seconds = int(getattr(agents, "delegation_timeout_seconds", 300) or 300)
    return max(2, steps), max(1, seconds)


def _what_this_ask_gets(container: Any, budget: Any) -> Any:
    """The callee's ceiling: the delegation's own budget, cut to the caller's clock.

    The steps are the delegation's, whole. The seconds are the delegation's or
    what the caller has left, whichever is less, because the caller is waiting
    inside its own timeout and an ask that outlived it would answer an agent
    whose node has already failed.
    """
    from maljan.agents.base_agent import BudgetCeiling

    steps, seconds = ask_budget(container)
    wall = float(seconds)
    if budget is not None:
        wall = max(1.0, budget.seconds_left() - SECONDS_KEPT_FOR_THE_CALLER)
        seconds = int(min(seconds, wall))
    return BudgetCeiling(steps=steps, seconds=float(seconds), wall=wall)


def _brief_callee(caller: Any, callee: Any, *, stage: str, round_index: int) -> None:
    """Give the callee what the node gave the caller: the same job, the same view.

    The pack, the run state, the format and the round come from the caller
    as it stands. The sample path is chosen for the callee the way the node
    chooses it for a stage agent — its own provider's mirror first — from the
    choices the node kept on the caller; a caller outside a staged run has
    none, and the callee then shares the caller's pinned path.
    """
    callee.pipeline_stage = stage
    callee.current_round = round_index
    callee.facts_block = str(getattr(caller, "facts_block", "") or "")
    callee.pack_ledger_ids = list(getattr(caller, "pack_ledger_ids", None) or [])
    callee.run_state_block = str(getattr(caller, "run_state_block", "") or "")
    callee.sample_format = tuple(getattr(caller, "sample_format", ("unknown", "unknown")))
    callee.call_chain = (*tuple(getattr(caller, "call_chain", ()) or ()), str(caller.name))
    callee.withheld_by_the_chain = _the_chain_s_tool_policy(caller)
    choices = getattr(caller, "sample_path_choices", None) or {}
    resolved = getattr(callee, "_resolved", None)
    provider_id = str(getattr(resolved, "static_provider_id", "") or "")
    callee._analysis_file_path = (
        (choices.get("by_provider") or {}).get(provider_id)
        or choices.get("static")
        or choices.get("host")
        or getattr(caller, "_analysis_file_path", None)
        or None
    )
    callee._path_by_server = dict(getattr(resolved, "path_by_server", {}) or {})


# What ``_brief_callee`` writes onto the callee, and so what is given back to
# it when the ask is over. A callee that runs a stage of its own later in the
# run must not still be holding the caller's pack or the caller's path: the
# node re-pins a sandbox-fed role and nothing re-pins the rest.
_BRIEFED_STATE = (
    "pipeline_stage",
    "current_round",
    "facts_block",
    "pack_ledger_ids",
    "run_state_block",
    "sample_format",
    "_analysis_file_path",
    "_path_by_server",
    "withheld_by_the_chain",
)


def _what_the_callee_had(callee: Any) -> dict[str, Any]:
    """The state the brief is about to write over, kept to be put back."""
    return {name: getattr(callee, name, None) for name in _BRIEFED_STATE}


def _give_the_callee_back_what_it_had(callee: Any, its_own: dict[str, Any]) -> None:
    """Undo the brief, so the ask leaves nothing behind on the callee."""
    for name, value in its_own.items():
        setattr(callee, name, value)


def _hand_over_the_structured_channel(caller: Any, callee: Any, isr: AgentISR) -> None:
    """Move the callee's findings and artifacts onto the caller's own buffers.

    ``answer_task`` drains them onto the ISR the delegation holds, and only
    the text of that ISR crosses back to the model — so without this a
    specialist's artifacts would reach no report. They travel unedited; an
    artifact that did not say which agent established it is marked with the
    callee's name, because on the caller's buffer it would otherwise read as
    the caller's.
    """
    for artifact in list(isr.artifacts or []):
        if not str(getattr(artifact, "source", "") or "").strip():
            artifact.source = str(callee.name)
        caller._artifacts_buffer.append(artifact)
    for finding in list(isr.findings or []):
        caller._findings_buffer.append(finding)


def _task_turn(caller_name: str, task: str, context: str, callee: Any) -> str:
    """The callee's human turn: where the sample is, the task, the context, the shape.

    The pack is not here; ``frame_messages`` puts it at the head of this turn
    inside the loop, the same way it does for a stage agent's first turn.
    """
    from maljan.agents.configurable_analyst import _ISR_FORMAT_INSTRUCTION, _PATH_HEADER

    parts: list[str] = []
    path = getattr(callee, "_analysis_file_path", None)
    if path:
        parts.append(_PATH_HEADER.format(path=path).rstrip())
    parts.append(f"Task from {caller_name}:\n{task}")
    if context:
        parts.append(f"Context from {caller_name}:\n{context}")
    parts.append(
        "Answer the task and nothing wider. Cite the ledger id of every tool call and "
        "every fact you rely on.\n\n" + _ISR_FORMAT_INSTRUCTION.rstrip()
    )
    return "\n\n".join(parts)


def _hand_over_the_record(caller: Any, callee: Any, *, still_running: bool = True) -> None:
    """Move what the callee recorded onto the caller, so one node writes it all.

    The ledger entries keep the callee's key; the stage node that drains the
    caller writes them to the run's ledger with everything else. The
    validation findings are carried the same way, each naming the callee, so
    a callee that never runs a stage of its own still has its check counted.

    ``still_running`` is false when the caller's loop ended while this ask was
    in flight. Its node has already failed it and drained it, so anything
    appended now would either be lost or re-emitted in a later round. The
    callee is drained all the same — its buffers must not carry into its next
    run — and what could not be handed over is logged and counted.
    """
    try:
        entries = callee.drain_evidence_entries()
    except Exception as exc:  # noqa: BLE001 — the record is handed over best-effort
        logger.debug("delegation: the callee's ledger could not be read (%s).", exc)
        entries = []
    rows = _drain_budget_rows(callee)
    if not still_running:
        logger.warning(
            "delegation %s -> %s: the caller's loop ended first; %d ledger entr(y/ies), "
            "%d budget row(s) and the callee's validation state are dropped.",
            caller.name,
            callee.name,
            len(entries),
            len(rows),
        )
        _drop_the_callee_s_validation_state(callee)
        return
    if entries:
        caller._evidence_entries.extend(entries)
    # The callee's loop spent a budget too, and a callee that runs no stage of
    # its own is drained by nobody else: its rows would stay on it until its
    # next loop and then be counted in whichever stage drained it.
    for row in rows:
        caller._note_budget(dict(row, agent=str(callee.name)))
    try:
        rows, retries, fed_back = callee.drain_validation_findings()
        not_run = callee.drain_validation_not_run()
    except Exception as exc:  # noqa: BLE001
        logger.debug("delegation: the callee's validation state could not be read (%s).", exc)
        return
    for row in rows:
        caller.validation_findings.append(
            Violation(
                code=str(row.get("code", "")),
                message=f"{callee.name}: {row.get('message', '')}",
                path=str(row.get("path", "")),
            )
        )
    # The two counters are read-modify-write and this runs on an executor
    # thread, so they go under the caller's own lock — the same one the meter's
    # rows take.
    with _the_caller_s_lock(caller):
        caller.validation_retries += int(retries or 0)
        for code, count in (fed_back or {}).items():
            caller.validation_fed_back[code] = caller.validation_fed_back.get(code, 0) + int(count)
    for code in not_run:
        if code not in caller.validation_not_run:
            caller.validation_not_run.append(code)


def _the_caller_s_lock(caller: Any) -> Any:
    """The caller's lock for its read-modify-write counters, or nothing."""
    import contextlib

    return getattr(caller, "_meter_lock", None) or contextlib.nullcontext()


def _drain_budget_rows(callee: Any) -> list[dict[str, Any]]:
    """What the callee's loops spent, handed over once. Never raises."""
    drain = getattr(callee, "drain_budget_records", None)
    if not callable(drain):
        return []
    try:
        return list(drain() or [])
    except Exception as exc:  # noqa: BLE001 — the meter never costs a run
        logger.debug("delegation: the callee's budget rows could not be read (%s).", exc)
        return []


def _drop_the_callee_s_validation_state(callee: Any) -> None:
    """Empty the callee's checks without folding them anywhere, and never raise."""
    try:
        callee.drain_validation_findings()
        callee.drain_validation_not_run()
    except Exception as exc:  # noqa: BLE001
        logger.debug("delegation: the callee's validation state could not be read (%s).", exc)


def _answer_text(isr: AgentISR, text: str) -> str:
    """The callee's ISR text, verbatim, with its raw answer after it when it had no claim.

    The summary is what the caller cites from. An answer that parsed to no
    claim still said something, and the caller is better placed to read it
    than to be told only that nothing was claimed.
    """
    summary = isr.to_text_summary()
    if isr.claims:
        return summary
    reason = str(getattr(isr, "status_reason", "") or "").strip()
    note = f" ({reason})" if reason else ""
    body = (text or "").strip()
    if not body:
        return f"{summary}\n  No claim in the CLAIM format{note}."
    if len(body) > _ANSWER_WITHOUT_CLAIMS_CHARS:
        body = body[:_ANSWER_WITHOUT_CLAIMS_CHARS] + "…"
    return f"{summary}\n  No claim in the CLAIM format{note}. The agent's answer follows.\n{body}"


def _status(isr: AgentISR) -> str:
    declared = str(getattr(isr, "status", "") or "").strip()
    if declared:
        return declared
    return "complete" if list(isr.claims or []) else "no_claims"
