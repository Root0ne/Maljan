"""Routing strategies for the negotiation loop.

Determines whether to continue iterating (revision) or proceed to the judge.

Decision priority (highest to lowest), in ``debate_route``:
  1. Hard iteration limit — unconditional judge.
  2. A mediation that failed, one whose mediator wrote no answer (empty, or
     cut at the output cap before any text), or consensus that does not
     apply — judge.
  3. Convergence — every revision of the round right before this mediation is
     the answer in force again, whitespace aside: another round would argue
     over the same answers. Judge.
     No change — no analyst was revised in that round (every revision failed,
     wrote nothing, carried no structured report or was not asked): judge, by
     consensus where the mediator stated one, otherwise ``not_revised``.
     Points unchanged — analysts were revised in that round, and this
     mediation's blocking lines are the same contested points as the last
     mediation's (``debate_facts.same_points``: none resolved, none new):
     another round would argue the same points. Judge
     (``contested_points_unchanged``); no consensus is claimed. The same end
     when the mediator marked every blocking line carried from a line of the
     last mediation (``[carried: L<n>]``) and the round's record shows no
     analyst the line names changed a claim on that earlier line
     (``debate_facts.carried_unmoved``); a line not marked is read as before.
     Ledger stated — every blocking line of this mediation states only counts
     the ledger states, and an earlier mediation told the analysts those
     counts (``debate_facts.ledger_stated``): another round would argue
     counts already told. Judge (``ledger_stated``); no consensus is claimed,
     and the lines stay standing disagreements for the judge and the report.
  4. Sycophancy is a fact told to the mediator, never a route of its own.
  5. Genuine LLM consensus (no listed line the mediator marked blocking, or
     left unmarked) — judge.
     Reworded — no consensus, and every revision of the round right before
     this mediation states the claims in force again, wording aside (the same
     values, entry ids, techniques, negators, confidence step and technical
     terms, ``claim_drops.unchanged_in_substance``):
     another round would argue over wording. Judge (``reworded``); no
     consensus is claimed.
  6. Adaptive termination — statistical confidence convergence, with no
     contradiction standing → judge.
     No contested point — the mediator's final block was read and lists no
     blocking line, so it names no analyst to revise: judge
     (``no_contested_point``). A round would ask nobody.
  7. Default → revision.

The run summary reads its termination reason from the same function, so the
reason it records is the rule that ended the debate. At the hard limit the
reason is the rule that would have ended it there anyway, and ``hard_limit``
only when the debate would have gone on.

Convergence criterion:
  - Window: last CONFIDENCE_WINDOW finite values.
  - Sample std (n-1 in denominator) < CONVERGENCE_STD_THRESHOLD.
  - Mean(window) >= MIN_CONVERGENCE_CONFIDENCE.
  - NaN / inf values are filtered out before computation; if the resulting
    window is too short, the loop continues.

Rationale: SELENE (arXiv) showed adaptive stopping reduces token cost ~50%
without sacrificing accuracy. Sample std (Bessel-corrected) is the standard
statistical estimator for small windows.
"""

from __future__ import annotations

import math
from typing import Any

from maljan.core.config import MEDIATOR_AGENT_NAME, Settings
from maljan.core.logger import logger
from maljan.pipeline.state import AnalysisState

CONFIDENCE_WINDOW: int = 3
CONVERGENCE_STD_THRESHOLD: float = 0.04
MIN_CONVERGENCE_CONFIDENCE: float = 0.70


def _sample_std(values: list[float]) -> float:
    """Sample (Bessel-corrected) standard deviation. ``inf`` if n<2."""
    n = len(values)
    if n < 2:
        return float("inf")
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / (n - 1)
    return math.sqrt(variance)


def _finite(values: list[float]) -> list[float]:
    return [v for v in values if math.isfinite(v)]


def is_confidence_stable(
    confidence_history: list[float],
    window: int = CONFIDENCE_WINDOW,
    std_threshold: float = CONVERGENCE_STD_THRESHOLD,
    min_confidence: float = MIN_CONVERGENCE_CONFIDENCE,
) -> bool:
    """Return True if recent confidence values have statistically stabilized.

    NaN / inf entries are dropped before assessment. Requires at least
    ``window`` finite values.
    """
    finite_history = _finite(confidence_history)
    if len(finite_history) < window:
        return False

    recent = finite_history[-window:]
    std = _sample_std(recent)
    mean = sum(recent) / len(recent)

    stable = std < std_threshold and mean >= min_confidence
    if stable:
        logger.info(
            "Adaptive termination: confidence stable (std=%.4f < %.2f, mean=%.3f >= %.2f).",
            std,
            std_threshold,
            mean,
            min_confidence,
        )
    else:
        logger.debug(
            "Adaptive termination: not yet stable "
            "(std=%.4f, std_threshold=%.2f, mean=%.3f, min=%.2f, n=%d).",
            std,
            std_threshold,
            mean,
            min_confidence,
            len(finite_history),
        )
    return stable


# Why a debate ended, as the run summary records it.
HARD_LIMIT = "hard_limit"
CONSENSUS = "consensus"
CONVERGED = "converged"
CONVERGENCE = "convergence"
MEDIATION_FAILED = "mediation_failed"
# The last mediation's mediator wrote no answer: the round was not mediated.
NOT_MEDIATED = "not_mediated"
NOT_APPLICABLE = "not_applicable"
# No analyst was revised in the round before this mediation: the round made no
# change, and the answers in force go to the judge.
NOT_REVISED = "not_revised"
# The last mediation's final block was read and lists no blocking line: it
# names no analyst to revise, so no revision round is held.
NO_CONTESTED_POINT = "no_contested_point"
# The round before this mediation revised analysts, and this mediation's
# blocking lines are the last mediation's contested points, none resolved and
# none new: the round changed none of them.
POINTS_UNCHANGED = "contested_points_unchanged"
# Every revision of the round before this mediation states the claims in
# force again, wording aside: the round changed no value, entry id, technique,
# negation, confidence step or technical term.
REWORDED = "reworded"
# Every blocking line of this mediation states only counts the ledger states,
# and the analysts were told them by an earlier mediation.
LEDGER_STATED = "ledger_stated"
# Why a revision round opens.
NO_CONSENSUS = "no_consensus"


def _quiet(*_args: Any, **_kwargs: Any) -> None:
    """A log call that says nothing."""


def debate_start(state: Any, stage: str | None = None) -> tuple[str, dict[str, int]]:
    """``(stage key, where it began)`` for debate ``stage``, or ``("", {})`` when unrecorded.

    ``stage`` ``None`` is the debate the state was last in: the one whose first
    mediation came latest. A state written before debates recorded their start
    has none, and is read as one debate from the run's first mediation, as it
    always was.
    """
    starts = state.get("debate_starts") or {}
    if not isinstance(starts, dict):
        return "", {}
    if stage is not None:
        row = starts.get(stage)
        return (stage, row) if isinstance(row, dict) else ("", {})
    rows = [(key, row) for key, row in starts.items() if isinstance(row, dict)]
    if not rows:
        return "", {}
    return max(rows, key=lambda item: int(item[1].get("mediations") or 0))


def with_debate_start(state: Any, stage: str | None, update: dict[str, Any]) -> dict[str, Any]:
    """``update`` with where debate ``stage`` began, on the first mediation it holds.

    Recorded once per stage, from the state the mediation read: the run's
    mediation count, the length of its confidence series and of its
    discussion. A node output that held no mediation (no ``iteration_count``)
    records nothing.
    """
    if not stage or "iteration_count" not in update:
        return update
    if stage in (state.get("debate_starts") or {}):
        return update
    start = {
        "mediations": int(state.get("iteration_count") or 0),
        "confidences": len(state.get("confidence_history") or []),
        "arguments": len(state.get("discussion_history") or []),
    }
    return {**update, "debate_starts": {stage: start}}


def debate_rounds(state: Any, stage: str | None = None) -> int:
    """The mediations debate ``stage`` has held: the run's count less where it began."""
    _key, start = debate_start(state, stage)
    held = int(state.get("iteration_count", 0) or 0)
    return max(0, held - int(start.get("mediations") or 0))


def rounds_held_before(state: Any, stage: str | None) -> int:
    """The mediations debate ``stage`` held before the one now being held.

    A stage with no recorded start, in a state where another debate recorded
    its own, is opening: it has held none, whatever the run's count. A state
    where no debate recorded a start reads the run's count, as it always did.
    """
    starts = state.get("debate_starts") or {}
    if stage and isinstance(starts, dict) and starts and stage not in starts:
        return 0
    return debate_rounds(state, stage) if stage else int(state.get("iteration_count", 0) or 0)


def debate_view(state: Any, stage: str | None = None) -> Any:
    """``state`` as debate ``stage`` reads it: its own confidence series and discussion.

    An earlier debate's numbers and mediations are not this debate's: read
    with them, a second debate ended on the first one's stable confidence or
    paired its first mediation with the first debate's last.
    """
    _key, start = debate_start(state, stage)
    if not start:
        return state
    view = dict(state)
    view["confidence_history"] = list(state.get("confidence_history") or [])[
        int(start.get("confidences") or 0) :
    ]
    view["discussion_history"] = list(state.get("discussion_history") or [])[
        int(start.get("arguments") or 0) :
    ]
    return view


def revision_round_before(
    state: Any, *, mediations: int | None = None, stage: str | None = None
) -> dict[str, Any] | None:
    """The record of the revision round right before mediation ``mediations``, or ``None``.

    ``mediations`` counts the mediations held with that one included; it is
    the state's ``iteration_count`` once the mediation has run, which is what
    the router reads. That round recorded the mediation count it followed, one
    less. A record of any other round (the last round of an earlier debate
    stage of the same run) is not this debate's, and neither is one another
    debate ``stage`` recorded.
    """
    held = int(state.get("iteration_count", 0)) if mediations is None else int(mediations)
    rounds = state.get("revision_rounds") or []
    last = rounds[-1] if rounds else None
    if not isinstance(last, dict):
        return None
    if int(last.get("round", -1)) != held - 1:
        return None
    if stage and last.get("stage") and str(last.get("stage")) != stage:
        return None
    return last


def revised_in(record: dict[str, Any] | None) -> set[str] | None:
    """The analysts revised in a revision round's record, or ``None`` when it names none.

    A record written before the round named its revised analysts says nothing
    about who was revised; the sycophancy check then judges every pair, as it
    did.
    """
    if not isinstance(record, dict):
        return None
    names = record.get("revised")
    if not isinstance(names, list):
        return None
    return {str(name) for name in names}


def last_two_mediations(history: Any) -> tuple[Any, Any] | None:
    """The two latest mediator contributions of ``history``, earlier first, or ``None``."""
    found: list[Any] = []
    for argument in reversed(list(history or [])):
        if getattr(argument, "agent_name", "") == MEDIATOR_AGENT_NAME:
            found.append(argument)
            if len(found) == 2:
                return found[1], found[0]
    return None


def points_unchanged(state: Any, record: dict[str, Any] | None = None) -> bool:
    """Whether the last mediation's blocking lines are the one before's contested points.

    Read from the two mediations' structured answers (``contradictions``,
    the lines each marked blocking or left unmarked), and only where both
    were made (``status`` complete): the same points by their keys
    (``debate_facts.same_points``), or every blocking line marked carried by
    the mediator from a line of the one before on which the revision round
    in between (``record``) shows no analyst the line names changed a claim
    (``debate_facts.carried_unmoved``).
    """
    from maljan.pipeline.debate_facts import carried_unmoved, same_points

    pair = last_two_mediations(state.get("discussion_history") or [])
    if pair is None:
        return False
    before, after = pair
    if any(getattr(a, "status", "complete") != "complete" for a in pair):
        return False
    lines = list(getattr(after, "contradictions", None) or [])
    if same_points(list(getattr(before, "contradictions", None) or []), lines):
        return True
    return carried_unmoved(
        lines,
        dict(getattr(after, "carried", None) or {}),
        record,
        [str(f) for f in getattr(after, "place_facts", None) or []],
    )


def only_ledger_stated(state: Any) -> bool:
    """Whether every blocking line of the last mediation is one the ledger states, told before.

    Read from the mediation's own record (``AgentArgument.ledger_stated``,
    one sentence per distinct blocking line it holds), and only where the
    mediation was made (``status`` complete) and lists a blocking line.
    """
    history = state.get("discussion_history") or []
    last = history[-1] if history else None
    if last is None or getattr(last, "agent_name", "") != MEDIATOR_AGENT_NAME:
        return False
    if getattr(last, "status", "complete") != "complete":
        return False
    lines = {str(line) for line in getattr(last, "contradictions", None) or []}
    stated = list(getattr(last, "ledger_stated", None) or [])
    return bool(lines) and len(stated) == len(lines)


def route_within_limit(
    state: Any, *, sycophancy_check: bool = True, log: bool = True, stage: str | None = None
) -> tuple[str, str]:
    """The decision with the round limit left aside: ``(route, reason)``.

    ``sycophancy_check`` is accepted for the callers that pass the stage's
    option; sycophancy decides no route (``sycophancy_detector``).

    ``log=False`` is the run summary reading the reason after the fact: the
    decision was logged when the router made it.

    ``stage`` is the debate stage deciding (``None``: the debate the state was
    last in). Its rounds, confidence series and mediations are its own; an
    earlier debate's are not read.
    """
    say = logger.info if log else _quiet
    key, _start = debate_start(state, stage)
    iteration = debate_rounds(state, stage)
    revised = revision_round_before(state, stage=key or None)
    state = debate_view(state, stage)
    consensus = state.get("is_consensus", False)
    confidence_history: list[float] = state.get("confidence_history") or []

    # A mediation round that ERRORED (a transient blip or a timeout) is not a
    # substantive "no consensus": a revision round would make every analyst
    # call the model again just to retry mediation. The ISRs already populated
    # go to the judge. ``AgentArgument.status`` carries it; the prose prefix is
    # kept for state persisted before that field existed.
    history = state.get("discussion_history") or []
    last = history[-1] if history else None
    errored = bool(last) and (
        getattr(last, "status", "complete") in ("failed", "timeout")
        or str(getattr(last, "finding", "")).startswith("[ERROR] Mediation")
    )
    if errored:
        say(
            "Mediation errored at round %d — routing to judge with current "
            "ISRs instead of a wasteful revision round.",
            iteration,
        )
        return "judge", MEDIATION_FAILED

    # The mediator wrote no answer (``mediation_models.MEDIATOR_NO_ANSWER``):
    # it stated neither agreement nor a contradiction, so there is nothing for
    # a revision round to answer. The answers in force go to the judge.
    if bool(last) and getattr(last, "status", "complete") == "no_answer":
        say(
            "The mediator wrote no answer at round %d — routing to judge with the "
            "answers in force.",
            iteration,
        )
        return "judge", NOT_MEDIATED

    # Fewer than two analysts produced claims, or the debate did not run:
    # there is no agreement to reach, and a revision round would ask the
    # same analysts to argue with nobody.
    if state.get("consensus_applicable") is False:
        say("Consensus not applicable at round %d. Proceeding to judge.", iteration)
        return "judge", NOT_APPLICABLE

    # Every revision of the round before is the answer in force again,
    # whitespace aside: the answers the next mediation would read are the
    # ones this one read. A fact, not a reading of meaning. A round in which
    # no revision stood (every one failed or was not made) is not convergence.
    if revised is not None and int(revised.get("made") or 0) > 0 and revised.get("identical"):
        say(
            "Debate converged at round %d: every revision of the last round is the "
            "answer in force again.",
            iteration,
        )
        return "judge", CONVERGED

    # No analyst was revised in the round before: every answer this mediation
    # read is the one the last mediation read. The round made no change, and
    # another round is not opened because of it. A consensus the mediator
    # stated over those answers stands as consensus (the sycophancy check
    # judged no revised answer in it); otherwise the answers in force go to
    # the judge as they are, and no agreement is claimed.
    if revised is not None and "made" in revised and int(revised.get("made") or 0) == 0:
        if consensus:
            say("Consensus at round %d over answers the last round did not revise.", iteration)
            return "judge", CONSENSUS
        say(
            "No analyst was revised in the round before round %d; the round made no change. "
            "Routing to judge with the answers in force.",
            iteration,
        )
        return "judge", NOT_REVISED

    # Analysts were revised in the round before, and the contested points this
    # mediation lists are the ones the last listed, none resolved and none new:
    # the round changed no point, and another would argue the same ones. The
    # answers in force go to the judge, and no agreement is claimed.
    if (
        revised is not None
        and int(revised.get("made") or 0) > 0
        and points_unchanged(state, revised)
    ):
        say(
            "The round before round %d revised analysts and left the contested points as they "
            "were; routing to judge with the answers in force.",
            iteration,
        )
        return "judge", POINTS_UNCHANGED

    # Every blocking line of this mediation states only counts the ledger
    # states, and the analysts it names were told them by an earlier
    # mediation: another round would argue counts already told. The lines
    # stand as disagreements; no agreement is claimed.
    if only_ledger_stated(state):
        say(
            "Every blocking line of round %d states only counts the ledger states and the "
            "analysts were told; routing to judge with the answers in force.",
            iteration,
        )
        return "judge", LEDGER_STATED

    # Sycophancy is a fact told to the mediator (``sycophancy_detector``); it
    # never overrides the mediator's consensus or a block with no contested
    # point, and never opens a round of its own.
    if consensus:
        say("Genuine consensus reached at round %d.", iteration)
        return "judge", CONSENSUS

    # Every revision of the round before states the claims in force again,
    # wording aside: what the analysts claim, cite and map did not move, and a
    # round more would argue over words. The answers in force go to the judge.
    if revised is not None and int(revised.get("made") or 0) > 0 and revised.get("reworded"):
        say(
            "Every revision of the round before round %d states the claims in force again, "
            "wording aside; routing to judge with the answers in force.",
            iteration,
        )
        return "judge", REWORDED

    # Adaptive termination on the confidence series, unless the last
    # mediation lists contradictions still standing: a number that stopped
    # moving is not agreement while the mediator says what is disputed. The
    # round limit still bounds the debate.
    standing = bool(getattr(last, "contradictions", None)) and (
        getattr(last, "agent_name", "") == MEDIATOR_AGENT_NAME
    )
    if not standing and is_confidence_stable(confidence_history):
        say("Adaptive termination triggered at round %d (stable confidence).", iteration)
        return "judge", CONVERGENCE

    # The mediator's block was read and names nobody in a contested point
    # (``AgentArgument.revise == []``): a revision round asks only the analysts
    # it names, so it would ask nobody. Not read (``None``) is not this.
    if (
        bool(last)
        and getattr(last, "agent_name", "") == MEDIATOR_AGENT_NAME
        and getattr(last, "revise", None) == []
    ):
        say(
            "The mediator names no analyst in a contested point at round %d; no revision "
            "round is held. Routing to judge with the answers in force.",
            iteration,
        )
        return "judge", NO_CONTESTED_POINT

    return "revision", NO_CONSENSUS


def debate_route(
    state: Any, *, max_rounds: int, sycophancy_check: bool = True, stage: str | None = None
) -> tuple[str, str]:
    """``(route, reason)`` for the state a mediation round left.

    ``route`` is ``"judge"`` or ``"revision"``. For ``"judge"`` the reason is
    what ended the debate; at the round limit it is the rule that would have
    ended the debate there anyway, and ``hard_limit`` when it would have gone
    on. The limit counts the rounds of debate ``stage`` alone.
    """
    at_limit = debate_rounds(state, stage) >= max_rounds
    # At the limit the decision is read quietly: the limit is what is logged.
    route, reason = route_within_limit(
        state, sycophancy_check=sycophancy_check, log=not at_limit, stage=stage
    )
    if at_limit:
        logger.info("Hard iteration limit (%d) reached. Proceeding to judge.", max_rounds)
        return "judge", reason if route == "judge" else HARD_LIMIT
    return route, reason


class ConsensusRouter:
    """Routes the workflow based on consensus detection and iteration limits."""

    def __init__(self, config: Settings, *, stage: Any = None) -> None:
        self._config = config
        # The debate stage this router belongs to. Its ``DebateOptions`` are
        # what the round limit and the sycophancy check come from; a profile
        # with two debates gives each of them its own. ``None`` — the shape
        # every test that builds a router by hand uses — falls back to the
        # global negotiation settings, which is what those options were seeded
        # from in the first place.
        self._stage = stage

    @property
    def _max_rounds(self) -> int:
        options = getattr(self._stage, "debate", None)
        if options is not None:
            return int(options.max_rounds)
        return int(self._config.negotiation.max_iterations)

    @property
    def _consensus_threshold(self) -> float:
        """The bar this debate calls agreement at.

        Read by nothing in ``should_continue`` — the mediator applies it when
        it sets ``is_consensus`` — and exposed here so a caller that wants the
        stage's effective value has one place to ask, rather than reaching into
        ``stage.debate`` and re-deciding the fallback.
        """
        options = getattr(self._stage, "debate", None)
        if options is not None:
            return float(options.consensus_threshold)
        return float(self._config.negotiation.consensus_threshold)

    @property
    def _sycophancy_check(self) -> bool:
        options = getattr(self._stage, "debate", None)
        if options is not None:
            return bool(options.sycophancy_check)
        return True

    def should_continue(self, state: AnalysisState) -> str:
        """Conditional router for LangGraph.

        Returns:
            "judge" to finalize, "revision" to continue negotiating.
        """
        route, _reason = debate_route(
            state,
            max_rounds=self._max_rounds,
            sycophancy_check=self._sycophancy_check,
            stage=getattr(self._stage, "key", None),
        )
        return route
