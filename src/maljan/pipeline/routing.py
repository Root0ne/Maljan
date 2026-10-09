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
  4. Sycophancy override — if sycophancy AND consensus, force revision.
  5. Genuine LLM consensus (no listed line the mediator marked blocking, or
     left unmarked) — judge.
  6. Adaptive termination — statistical confidence convergence, with no
     contradiction standing → judge.
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

from maljan.core.config import Settings
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
# Why a revision round opens.
SYCOPHANCY = "sycophancy"
NO_CONSENSUS = "no_consensus"


def _quiet(*_args: Any, **_kwargs: Any) -> None:
    """A log call that says nothing."""


def _round_before(state: Any) -> dict[str, Any] | None:
    """The record of the revision round right before this mediation, or ``None``.

    That round recorded the mediation count it followed, one less than now. A
    record of any other round — the last round of an earlier debate stage of
    the same run — is not this debate's.
    """
    rounds = state.get("revision_rounds") or []
    last = rounds[-1] if rounds else None
    if not isinstance(last, dict):
        return None
    if int(last.get("round", -1)) != int(state.get("iteration_count", 0)) - 1:
        return None
    return last


def route_within_limit(
    state: Any, *, sycophancy_check: bool = True, log: bool = True
) -> tuple[str, str]:
    """The decision with the round limit left aside: ``(route, reason)``.

    ``log=False`` is the run summary reading the reason after the fact: the
    decision was logged when the router made it.
    """
    say = logger.info if log else _quiet
    iteration = state.get("iteration_count", 0)
    consensus = state.get("is_consensus", False)
    syco = state.get("sycophancy_detected", False)
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
    revised = _round_before(state)
    if revised is not None and int(revised.get("made") or 0) > 0 and revised.get("identical"):
        say(
            "Debate converged at round %d: every revision of the last round is the "
            "answer in force again.",
            iteration,
        )
        return "judge", CONVERGED

    # A "consensus" that comes with sycophancy is treated as premature: force
    # another revision.
    if syco and consensus and sycophancy_check:
        say(
            "Sycophancy override: consensus premature at round %d. Forcing revision.",
            iteration,
        )
        return "revision", SYCOPHANCY

    if consensus:
        say("Genuine consensus reached at round %d.", iteration)
        return "judge", CONSENSUS

    # Adaptive termination on the confidence series, unless the last
    # mediation lists contradictions still standing: a number that stopped
    # moving is not agreement while the mediator says what is disputed. The
    # round limit still bounds the debate.
    standing = bool(getattr(last, "contradictions", None)) and (
        getattr(last, "agent_name", "") == "Mediator"
    )
    if not standing and is_confidence_stable(confidence_history):
        say("Adaptive termination triggered at round %d (stable confidence).", iteration)
        return "judge", CONVERGENCE

    return "revision", NO_CONSENSUS


def debate_route(state: Any, *, max_rounds: int, sycophancy_check: bool = True) -> tuple[str, str]:
    """``(route, reason)`` for the state a mediation round left.

    ``route`` is ``"judge"`` or ``"revision"``. For ``"judge"`` the reason is
    what ended the debate; at the round limit it is the rule that would have
    ended the debate there anyway, and ``hard_limit`` when it would have gone
    on.
    """
    at_limit = state.get("iteration_count", 0) >= max_rounds
    # At the limit the decision is read quietly: the limit is what is logged.
    route, reason = route_within_limit(state, sycophancy_check=sycophancy_check, log=not at_limit)
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
            state, max_rounds=self._max_rounds, sycophancy_check=self._sycophancy_check
        )
        return route
