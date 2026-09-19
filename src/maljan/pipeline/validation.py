"""What a model got wrong, said back to the model, once.

Every layer this module replaces used to do the same thing silently: read an
agent's answer, decide it was wrong, and write a different answer in its place.
The claim in the report was then nobody's — not the analyst's, because it had
been overwritten, and not the pipeline's, because the pipeline never said so.

Here the finding is a :class:`Violation` instead of an edit. The producer is
told what is wrong in the same conversation that produced the answer and gets
one more turn to fix it. What is still wrong after that turn stays wrong, on
the record, under ``run_summary.validation.unresolved`` — an unfixed claim that
says it is unfixed is worth more than a corrected claim nobody can attribute.

This module and ``schemas``/``tools`` are the only places allowed to write a
claim's ``technique_id`` or ``confidence``, or a report's ``severity``,
``malware_category`` or ``family``; ``tests/unit/test_no_silent_overrides.py``
enforces that. Even here the writes are narrow: the technique-id validity flag
and the drop of an indicator that named a value no tool ever saw.
"""

from __future__ import annotations

import json
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, get_args, get_origin

from pydantic import ValidationError

# The row helpers live with the shape (``analysis.corroboration``) and are
# re-exported here, where every reader of a run's validation looks for them.
from maljan.agents.run_evidence_corpus import CorpusState, both_searched
from maljan.analysis.corroboration import corroboration_row as corroboration_row
from maljan.analysis.corroboration import corroboration_sources as corroboration_sources
from maljan.analysis.technique_ids import TECHNIQUE_ID_EXACT_RE
from maljan.core.logger import logger
from maljan.pipeline.events import (
    VALIDATION_RESOLVED,
    VALIDATION_RETRIED,
    VALIDATION_SURVIVED,
    EventSink,
    emit_validation_feedback,
    safe_finding_value,
)
from maljan.schemas.evidence import entry_ids_in
from maljan.schemas.judgement import SEVERITY_RATINGS, VERDICT_VALUES
from maljan.schemas.stix_pattern import read_comparisons

# How many alternatives a suggestion list carries. Three is what fits in one
# line of feedback; a longer list reads as a menu and the model picks from the
# middle of it.
MAX_SUGGESTIONS = 3

# How far a candidate has to beat the claimed id's own score before the gate
# says anything. The index scores a *correct* id near zero often enough that a
# bare threshold questioned almost every claim: 81 of the 92 feedback rows in
# one audited run, 33 of 33 in another. The default is the measured one — see
# ``tests/fixtures/attck_alignment_recorded.json`` and docs/architecture.md.
ALIGNMENT_MARGIN = 0.20

# How many schema complaints one feedback turn carries. A model that answered
# with the wrong shape produces one error per field, and a wall of them reads
# as noise rather than as a correction.
MAX_SCHEMA_VIOLATIONS = 6


# The sentence the retry turn opens with. A constant because two call sites
# send it and a test reads it.
FEEDBACK_PREAMBLE = "Your previous answer had these problems:"
FEEDBACK_CLOSING = "Fix them and answer again in the same format."


# What joins the agents of a route inside one serialised row. A unit separator
# rather than a comma: an agent key is an operator's word and a comma in one
# would split a name in half on the way back.
ROUTE_SEPARATOR = "\x1f"


@dataclass(frozen=True)
class Violation:
    """One thing wrong with an answer, in the words the producer will read."""

    code: str
    message: str
    path: str = ""
    # A finding the producer is shown and asked about, that nothing acts on by
    # removing something. It exists for one situation: the check could not
    # search this run's whole record — the grounding corpus hit its ceiling,
    # or there is no corpus and the stored entries it fell back to had been
    # blanked by the evidence byte budget — so "this value is in no tool
    # output" is not a statement the platform is entitled to make. The row
    # says what was searched and what was not; the object stays.
    advisory: bool = False
    # The agents this row was handed through, outermost first, and the
    # finding's own words. Two values rather than one string: a hand-over adds
    # a name in front of the sentence and the whole is bounded, and a bound
    # applied to one string has to work out where the route ends — which it
    # cannot do, and which cost a sentence opening ``T1055: `` its identifier.
    # Carried apart, the bound can only ever shorten the route.
    route: tuple[str, ...] = ()
    sentence: str = ""

    def __post_init__(self) -> None:
        # A row written by a validator has no route, and its message is its
        # sentence. Everything downstream may then read either.
        if not self.sentence:
            object.__setattr__(self, "sentence", self.message)

    def to_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "path": self.path,
            # Strings, because every other value in the row is one and the
            # channel that carries it is ``dict[str, list[dict[str, str]]]``.
            "advisory": "true" if self.advisory else "",
            "sentence": self.sentence,
            "route": ROUTE_SEPARATOR.join(self.route),
        }


@dataclass
class ValidationTally:
    """How much correction one producer needed, by code.

    ``run_summary.validation.by_code`` used to be built from the unresolved
    list alone, so a run whose judge was corrected once and answered properly
    the second time reported ``retries: 1`` beside an empty ``by_code`` and
    nothing said what the retry had been about. Every violation a producer is
    *shown* is counted here, and so is every one it never fixed, which is the
    only reading under which the two numbers agree.
    """

    retries: int = 0
    by_code: dict[str, int] = field(default_factory=dict)
    # What this producer was told and did not fix, with the producer's name, in
    # the shape ``run_summary.validation.unresolved`` carries. The report
    # stage's two rounds run after the summary is built and have nowhere else
    # to put theirs.
    unresolved: list[dict[str, str]] = field(default_factory=list)

    def count(self, violations: Sequence[Violation]) -> None:
        """Count a set of violations. The shape ``on_feedback`` is called with."""
        for violation in violations:
            self.by_code[violation.code] = self.by_code.get(violation.code, 0) + 1

    def record_unresolved(self, producer: str, violations: Sequence[Violation]) -> None:
        """Keep what survived the retry, as a row naming who was told.

        ``advisory`` travels with it. Rebuilt without the flag, a row the
        platform explicitly declined to act on was stored, printed and drawn as
        an ordinary unfixed finding, and an operator had to read inside the
        message to learn that nothing had been dropped for it.
        """
        self.unresolved.extend(
            {
                "agent": producer,
                "code": v.code,
                "message": v.message,
                **({"advisory": "true"} if v.advisory else {}),
            }
            for v in violations
        )

    def merge(self, other: ValidationTally) -> None:
        self.retries += other.retries
        for code, count in other.by_code.items():
            self.by_code[code] = self.by_code.get(code, 0) + count
        self.unresolved.extend(other.unresolved)

    def to_dict(self) -> dict[str, Any]:
        """The tally as the run summary carries it.

        ``unresolved`` is part of it whenever there is any: a serialisation
        that dropped the rows would leave a reader the counts and none of the
        claims they were counted for. An empty list is left out, so a run that
        over-claimed nothing does not carry an empty key saying so.
        """
        out: dict[str, Any] = {
            "retries": int(self.retries),
            "by_code": dict(sorted(self.by_code.items())),
        }
        if self.unresolved:
            out["unresolved"] = [dict(row) for row in self.unresolved]
        return out


# A validator reads a produced object and says what is wrong with it. It never
# changes the object: the whole point of the type is that the caller decides
# what to do with the answer.
Validator = Callable[[Any], list[Violation]]


# ---------------------------------------------------------------------------
# Feedback
# ---------------------------------------------------------------------------


def feedback_text(violations: Sequence[Violation]) -> str:
    """The retry turn's text for a set of violations."""
    lines = [FEEDBACK_PREAMBLE]
    for violation in violations:
        where = f" ({violation.path})" if violation.path else ""
        lines.append(f"- [{violation.code}]{where} {violation.message}")
    lines.append(FEEDBACK_CLOSING)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Analyst ISRs
# ---------------------------------------------------------------------------


UNGROUNDED_TECHNIQUE_CODE = "isr.ungrounded_technique"


def _techniques_cited_by_findings(isr: Any, citable: set[str]) -> set[str]:
    """The techniques the findings block already cites one of this run's entries for.

    The structured channel is where the analyst is asked for ids by machine,
    and an analyst that used it has answered the question the claim line asks
    in prose. Asking it twice for one technique is a feedback turn spent on
    bookkeeping.
    """
    cited: set[str] = set()
    for finding in getattr(isr, "findings", None) or []:
        ids = " ".join(str(value) for value in (getattr(finding, "evidence_ids", None) or []))
        if not entry_ids_in(ids) & citable:
            continue
        for technique in getattr(finding, "technique_ids", None) or []:
            text = str(technique).strip().upper()
            if text:
                cited.add(text)
    return cited


def _cites_a_ledger_entry(claim: Any, cited_by_findings: set[str], citable: set[str]) -> bool:
    """Whether a claim points at something the run actually recorded.

    Two ways, and only two. The evidence line is where the claim format asks
    for the id, and the findings block is where the same analyst may already
    have cited one for this technique. The claim's own prose is deliberately
    not searched: "as ev_0001 does not show, this may be injection" is not a
    citation, and reading it as one is how a validator stops validating.

    The id has to be one this run issued. The feedback names three real ones,
    so the shape of an id is no proof of anything, and an ``ev_9999`` the run
    never recorded is a citation of nothing.
    """
    if entry_ids_in(str(getattr(claim, "evidence_ref", "") or "")) & citable:
        return True
    technique = str(getattr(claim, "technique_id", "") or "").strip().upper()
    return bool(technique and technique in cited_by_findings)


def validate_isr(
    isr: Any,
    *,
    attck: Any = None,
    ledger_ids: Sequence[str] | None = None,
    sample: Mapping[str, Any] | None = None,
    alignment: Any = None,
    alignment_threshold: float = 0.05,
    alignment_margin: float = ALIGNMENT_MARGIN,
    weak_alignment_challenges: bool = False,
) -> list[Violation]:
    """What is wrong with one analyst's structured answer.

    ``attck`` is the knowledge module the technique ids are checked against —
    ``maljan.tools.knowledge`` in production, a stub in a test that must not
    load a fifty-megabyte bundle. Passing ``None`` skips the catalogue check
    rather than failing it: a box that cannot read ATT&CK has a thinner report,
    not a run full of invented violations.

    ``ledger_ids`` are the entries this analyst may cite: what its own tool
    calls produced in this run, and the triage pack's entries, which every
    agent is shown. They decide one thing: a technique claim that cites none
    of them is asked for one. An analyst with nothing citable at all — a
    measurement profile, which has no tools and no pack — is exempt, because
    it has nothing it could cite.

    ``sample`` carries the routed ``platform`` and ``file_type``; a known
    technique whose catalogue domain or platforms cannot apply to them is
    ``attck.platform_mismatch``. ``alignment`` is the gate — a callable of
    ``(claim_text, technique_id)`` answering the index's gate score and
    candidates, or ``None`` when the index is cold or the gate is off. The
    ranking is narrowed to the sample's own domain and platforms and written on
    the claim whatever it says; it becomes ``attck.weak_alignment`` only with
    ``weak_alignment_challenges`` on, and then only for a claimed id that scores
    under ``alignment_threshold`` while an in-scope candidate from another
    tactic beats it by ``alignment_margin``. No id is ever replaced by a
    candidate.
    """
    citable = [str(i) for i in (ledger_ids or []) if str(i).strip()]
    known = {i.strip().lower() for i in citable}
    cited_by_findings = _techniques_cited_by_findings(isr, known)
    violations: list[Violation] = []
    claims = list(getattr(isr, "claims", None) or [])
    agent = str(getattr(isr, "agent_id", "") or "")
    scope = expected_technique_scope(sample)

    for index, claim in enumerate(claims):
        path = f"{agent}.claims[{index}]" if agent else f"claims[{index}]"

        confidence: Any = getattr(claim, "confidence", None)
        try:
            numeric: float | None = float(confidence)
        except (TypeError, ValueError):
            numeric = None
        if numeric is None or not (0.0 <= numeric <= 1.0):
            violations.append(
                Violation(
                    code="isr.confidence_range",
                    message=(
                        f"CONFIDENCE is {safe_finding_value(confidence)!r}; it must be a number "
                        "between 0.0 and 1.0."
                    ),
                    path=path,
                )
            )

        evidence = str(getattr(claim, "evidence_ref", "") or "").strip()
        if not evidence:
            violations.append(
                Violation(
                    code="isr.empty_evidence",
                    message=(
                        "the claim cites no evidence; give the concrete artifact it "
                        "rests on, or drop the claim."
                    ),
                    path=path,
                )
            )

        tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
        # A technique with nothing behind it. A live run on a signed PuTTY
        # produced sixteen of these in one ISR — "may exhibit process injection
        # (T1055) | Evidence: no specific imports were provided; this claim is
        # speculative" — and the judge read them as sixteen techniques and said
        # Malware. The analyst is asked to cite the entry it read the technique
        # from or to drop it; nothing here removes the claim or the id.
        if tid and citable and not _cites_a_ledger_entry(claim, cited_by_findings, known):
            shown = ", ".join(citable[:3])
            violations.append(
                Violation(
                    code=UNGROUNDED_TECHNIQUE_CODE,
                    message=(
                        f"TECHNIQUE {safe_finding_value(tid)} cites no evidence id from this "
                        f"run. Name the ledger entry it was read from, for example {shown}, "
                        "or drop the "
                        "technique: a technique nothing in the run establishes is read "
                        "downstream as a finding."
                    ),
                    path=path,
                )
            )
        if not tid or attck is None:
            continue
        if not _technique_is_known(tid, attck):
            suggestions = _suggest_techniques(str(getattr(claim, "claim", "") or ""), attck)
            hint = (
                f" The closest real techniques are {', '.join(suggestions)}." if suggestions else ""
            )
            violations.append(
                Violation(
                    code="attck.unknown_id",
                    message=(
                        f"TECHNIQUE {safe_finding_value(tid)} is not in the MITRE ATT&CK catalogue"
                        f"{_retired_note(tid, attck)}.{hint} "
                        "Use one of them, or omit the technique id."
                    ),
                    path=path,
                )
            )
            continue
        mismatch = platform_mismatch_message(tid, attck, scope)
        if mismatch:
            violations.append(Violation(code=PLATFORM_MISMATCH_CODE, message=mismatch, path=path))
        weak = _weak_alignment(
            claim,
            tid,
            alignment,
            alignment_threshold,
            attck=attck,
            scope=scope,
            margin=alignment_margin,
            challenge=weak_alignment_challenges,
        )
        if weak:
            violations.append(Violation(code=WEAK_ALIGNMENT_CODE, message=weak, path=path))

    return violations


# ---------------------------------------------------------------------------
# Domain and platform consistency
# ---------------------------------------------------------------------------

PLATFORM_MISMATCH_CODE = "attck.platform_mismatch"

# The ATT&CK domain a routed platform belongs to. A platform this table does
# not name has no domain to check against, and an ``ics`` sample is not a
# thing the router produces.
_DOMAIN_BY_PLATFORM: dict[str, str] = {
    "windows": "enterprise",
    "linux": "enterprise",
    "macos": "enterprise",
    "android": "mobile",
    "ios": "mobile",
}

# The routed file types that settle the platform on their own, in the words
# the catalogue uses. The router's platform is read first; these are for a
# state whose platform is missing but whose format is not.
_PLATFORM_BY_FILE_TYPE: dict[str, str] = {
    "pe": "windows",
    "elf": "linux",
    "mach-o": "macos",
    "apk": "android",
    "dex": "android",
    "ipa": "ios",
}


def expected_technique_scope(
    sample: Mapping[str, Any] | None,
) -> tuple[str | None, tuple[str, ...]]:
    """``(domain, MITRE platforms)`` a technique must fit for this sample.

    ``(None, ())`` for a sample whose platform is unknown or cross-platform,
    which is "do not check": a comparison the router could not make is not
    one a validator should make either.
    """
    from maljan.memory.attck_loader import mitre_platforms

    data = sample if isinstance(sample, Mapping) else {}
    platform = str(data.get("platform") or "").strip().lower()
    file_type = str(data.get("file_type") or "").strip().lower()
    if platform not in _DOMAIN_BY_PLATFORM:
        platform = _PLATFORM_BY_FILE_TYPE.get(file_type, "")
    domain = _DOMAIN_BY_PLATFORM.get(platform)
    if domain is None:
        return None, ()
    return domain, tuple(mitre_platforms(platform))


def platform_mismatch_message(
    technique_id: str, attck: Any, scope: tuple[str | None, tuple[str, ...]]
) -> str:
    """Why ``technique_id`` cannot apply to a sample in ``scope``, or ``""``.

    The catalogue's own domain and platforms for the id, against the routed
    ones. Two ways to miss: the id belongs to another domain, or it declares
    platforms and none of them is the sample's.

    Four things are not a miss, and the function answers ``""`` for each in
    turn before it compares anything. A sample whose platform the router could
    not settle, or that is cross-platform, has no scope to check against. A
    knowledge object with no lookup cannot be asked. A lookup that raises or
    answers something other than a mapping has not answered. And a technique
    whose only platform is ``PRE`` happens before any host is touched, so no
    sample's platform can contradict it — including its *domain*, which is why
    that carve-out is asked before the domain comparison and not after it.
    ATT&CK keeps every PRE technique in the enterprise matrix and mobile has
    none, so asking the domain first made every PRE id cross-domain on an
    Android sample. While this check only annotated, that produced a warning;
    now that the report reads it to decide what to publish, it removed real
    techniques — ``T1583 Acquire Infrastructure`` off an Android infostealer's
    C2 registration — from every published surface.

    A fifth is not a miss on the platform comparison alone: a technique the
    catalogue carries no platforms for is not questioned there, because no
    information is not a mismatch. It is still questioned on its domain, which
    the catalogue did answer.

    ``attck_scope`` is asked first: it answers from the vendored files and
    loads nothing, which is what lets this run inside an analyst's turn.
    ``attck_lookup`` is the fallback for a knowledge object without it.
    """
    expected_domain, expected_platforms = scope
    if expected_domain is None:
        return ""
    lookup = getattr(attck, "attck_scope", None) or getattr(attck, "attck_lookup", None)
    if lookup is None:
        return ""
    try:
        answer = lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — an unanswered lookup is no mismatch
        logger.debug("validation: the ATT&CK lookup for %s failed (%s).", technique_id, exc)
        return ""
    if not isinstance(answer, dict):
        return ""
    domain = str(answer.get("domain") or "").strip().lower()
    platforms = [str(p) for p in (answer.get("platforms") or []) if str(p).strip()]
    if _pre_only(platforms):
        return ""
    sample_words = f"{expected_domain}-domain, {'/'.join(expected_platforms) or 'any platform'}"
    if domain and domain != expected_domain:
        return (
            f"TECHNIQUE {safe_finding_value(technique_id)} belongs to the ATT&CK {domain} domain"
            f"{f' (platforms {", ".join(platforms)})' if platforms else ''}; this sample is "
            f"{sample_words}. Use a technique from the sample's domain, or drop the technique id."
        )
    if expected_platforms and platforms:
        wanted = {p.lower() for p in expected_platforms}
        if not any(p.lower() in wanted for p in platforms):
            return (
                f"TECHNIQUE {safe_finding_value(technique_id)} declares the platforms "
                f"{', '.join(platforms)}; this "
                f"sample is {sample_words}. Use a technique that applies to it, or drop the "
                "technique id."
            )
    return ""


def _pre_only(platforms: Sequence[str]) -> bool:
    """Whether ``PRE`` is the technique's only platform."""
    return len(platforms) == 1 and str(platforms[0]).strip().upper() == "PRE"


# ---------------------------------------------------------------------------
# The alignment gate
# ---------------------------------------------------------------------------

WEAK_ALIGNMENT_CODE = "attck.weak_alignment"

# How many of the index's candidates a claim carries and the feedback names.
ALIGNMENT_CANDIDATES = 5


def _base_id(technique_id: str) -> str:
    """The parent technique of an id: ``T1055.001`` -> ``T1055``."""
    return str(technique_id or "").split(".")[0]


def _catalogue_answer(technique_id: str, attck: Any, question: str) -> dict[str, Any]:
    """One catalogue answer about an id, or ``{}`` when it cannot be had."""
    lookup = getattr(attck, question, None)
    if lookup is None:
        return {}
    try:
        answer = lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — an unanswered lookup narrows nothing
        logger.debug("validation: the %s lookup for %s failed (%s).", question, technique_id, exc)
        return {}
    return answer if isinstance(answer, dict) else {}


def _within_scope(technique_id: str, attck: Any, scope: tuple[str | None, tuple[str, ...]]) -> bool:
    """Whether a technique could apply to a sample in ``scope``.

    The same question ``platform_mismatch_message`` answers about a claimed id,
    asked about a *candidate* before it is proposed. Without it the index
    offered Mobile and ICS techniques as better fits for a Windows PE — the
    ranking is domain-blind, so ``T1406`` and ``T0885`` came back for a claim
    about a PE's imports and the analyst was asked to consider them.
    """
    expected_domain, expected_platforms = scope
    if expected_domain is None:
        return True
    answer = _catalogue_answer(technique_id, attck, "attck_scope") or _catalogue_answer(
        technique_id, attck, "attck_lookup"
    )
    if not answer:
        return True
    domain = str(answer.get("domain") or "").strip().lower()
    if domain and domain != expected_domain:
        return False
    platforms = [str(p) for p in (answer.get("platforms") or []) if str(p).strip()]
    if not platforms or _pre_only(platforms):
        return True
    wanted = {p.lower() for p in expected_platforms}
    return not wanted or any(p.lower() in wanted for p in platforms)


def _tactics(technique_id: str, attck: Any) -> set[str]:
    """The tactics the catalogue gives a technique, lowercased."""
    answer = _catalogue_answer(technique_id, attck, "attck_lookup")
    return {str(t).strip().lower() for t in (answer.get("tactics") or []) if str(t).strip()}


def _disagrees_with(candidate_id: str, tid: str, attck: Any) -> bool:
    """Whether proposing ``candidate_id`` contradicts the claim's own id.

    A candidate from the same technique family (``T1055`` beside ``T1055.001``)
    or from the same tactic is the index naming another rung of the behaviour
    the analyst already named, which is a ranking preference and not a reason
    to spend a model turn. A candidate from another tactic is the index saying
    the claim describes something else.
    """
    if _base_id(candidate_id) == _base_id(tid):
        return False
    claimed = _tactics(tid, attck)
    return not (claimed and claimed & _tactics(candidate_id, attck))


def _weak_alignment(
    claim: Any,
    tid: str,
    alignment: Any,
    threshold: float,
    *,
    attck: Any = None,
    scope: tuple[str | None, tuple[str, ...]] = (None, ()),
    margin: float = ALIGNMENT_MARGIN,
    challenge: bool = False,
) -> str:
    """Record the index's ranking on the claim; the feedback when it disagrees.

    ``alignment(text, tid)`` answers ``{gate_score, candidates: [{technique_id,
    score_gate}, ...]}`` or ``None`` when the index has nothing to say. The
    ranking is written to ``claim.alignment`` whatever it says — narrowed to
    the sample's own ATT&CK domain and platforms, so nothing out of scope is
    ever proposed — and the judge and the report see it beside the analyst's
    choice.

    The feedback is the narrow case: the gate challenges only when it is turned
    on, the claimed id scores under the threshold, the index did not rank the
    claimed id itself among its in-scope candidates, no in-scope candidate
    names the same family or tactic, and the best of the ones that do disagree
    beats the claimed id by ``margin``. Everything else is a ranking the model
    may disagree with, and the id is never replaced either way.
    """
    if alignment is None:
        return ""
    # The claim's own words. ``evidence_ref`` is a ledger id and a quoted
    # fragment, which is noise in the one input the gate score comes from.
    text = str(getattr(claim, "claim", "") or "").strip()
    if not text:
        return ""
    try:
        answer = alignment(text, tid, k=ALIGNMENT_CANDIDATES)
    except Exception as exc:  # noqa: BLE001 — a gate that cannot answer gates nothing
        logger.debug("validation: the alignment gate failed for %s (%s).", tid, exc)
        return ""
    if not isinstance(answer, dict):
        return ""
    candidates: list[dict[str, Any]] = [
        {
            "technique_id": str(c.get("technique_id") or "").strip().upper(),
            "score_gate": float(c.get("score_gate") or 0.0),
        }
        for c in answer.get("candidates") or []
        if isinstance(c, dict) and c.get("technique_id")
    ]
    candidates = [c for c in candidates if _within_scope(str(c["technique_id"]), attck, scope)]
    try:
        gate_score = float(answer.get("gate_score") or 0.0)
    except (TypeError, ValueError):
        gate_score = 0.0
    record = {"gate_score": round(gate_score, 4), "candidates": candidates}
    if hasattr(claim, "alignment"):
        claim.alignment = record
    if not challenge or gate_score >= threshold:
        return ""
    if scope[0] is None:
        # A sample whose domain the router could not settle has no scope to
        # score inside, and a comparison that cannot be made is not one to
        # challenge on.
        return ""
    if any(str(c["technique_id"]) == tid for c in candidates):
        # The index ranked the claimed id itself, in scope. Wherever it put it,
        # it did not fail to think of it, and a candidate it happened to score
        # higher is a preference between two techniques the index considers
        # applicable — not the disagreement this check is for.
        return ""
    disagreeing = [c for c in candidates if _disagrees_with(str(c["technique_id"]), tid, attck)]
    if not disagreeing:
        return ""
    best = max(disagreeing, key=lambda c: float(c["score_gate"]))
    if float(best["score_gate"]) - gate_score < margin:
        return ""
    ranked = ", ".join(f"{c['technique_id']} ({c['score_gate']:.2f})" for c in disagreeing)
    return (
        f"TECHNIQUE {safe_finding_value(tid)} aligns weakly with the claim's own text (gate score "
        f"{gate_score:.2f}, threshold {threshold:.2f}), and the ATT&CK index ranks "
        f"{best['technique_id']} ({best['score_gate']:.2f}) and other techniques from this "
        f"sample's own domain above it: {ranked}. Keep {safe_finding_value(tid)} if the evidence "
        "says so and say "
        "why in the claim, choose one of the ranked techniques, or drop the technique id."
    )


def technique_check_note(findings: Any) -> str:
    """What the judge is told about technique claims the check questioned and the analyst kept.

    The platform mismatches and weak alignments that survived their retry,
    read off the unresolved rows so the judge weighs the same messages the
    analyst was shown — the domain, the platforms, the candidates. Empty when
    there are none.
    """
    rows: list[Any] = []
    if isinstance(findings, dict):
        for entries in findings.values():
            rows.extend(entries or [])
    else:
        rows.extend(findings or [])
    lines: list[str] = []
    for row in rows:
        data = row if isinstance(row, dict) else getattr(row, "__dict__", {}) or {}
        code = str(data.get("code") or "")
        if code not in (PLATFORM_MISMATCH_CODE, WEAK_ALIGNMENT_CODE):
            continue
        message = " ".join(str(data.get("message") or "").split())
        lines.append(f"- {code}: {message}")
    if not lines:
        return ""
    return (
        "TECHNIQUE CHECK — claims the ATT&CK check questioned and the analyst kept. The ids "
        "are the analysts' own; the check names what disagrees with them and nothing here "
        "changed them.\n" + "\n".join(lines)
    )


# The id inside an ``isr.ungrounded_technique`` message, which is where the
# technique the analyst kept is written down.
_TID_IN_MESSAGE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def ungrounded_technique_note(findings: Any) -> str:
    """What the judge is told about technique claims that cite nothing.

    Read off the unresolved rows rather than recomputed: these are the claims
    an analyst was already asked about and kept, and the judge weighing them
    is entitled to know which of the techniques in front of it nothing in the
    run establishes. Empty when there are none, which is the usual case.
    """
    rows: list[Any] = []
    if isinstance(findings, dict):
        for entries in findings.values():
            rows.extend(entries or [])
    else:
        rows.extend(findings or [])
    named: list[str] = []
    for row in rows:
        data = row if isinstance(row, dict) else getattr(row, "__dict__", {}) or {}
        if str(data.get("code") or "") != UNGROUNDED_TECHNIQUE_CODE:
            continue
        match = _TID_IN_MESSAGE_RE.search(str(data.get("message") or ""))
        if match and match.group(0) not in named:
            named.append(match.group(0))
    if not named:
        return ""
    return "technique claims citing no evidence from this run: " + ", ".join(named)


VALIDITY_CODE = "attck.unknown_id"

# A technique named with no id. Its own code because the answer is different
# from an id that does not resolve: there is nothing to look up, and a
# behaviour the model could not map is still a behaviour the report can carry.
MISSING_ID_CODE = "attck.missing_id"


# What the run-quality note says for a check that could not run, per code.
# A code this table does not know is still named rather than described as
# something it is not.
NOT_RUN_SENTENCES: dict[str, str] = {
    "attck.unknown_id": (
        "the ATT&CK catalogue could not be read; technique ids were not checked (attck.unknown_id)"
    ),
}


def not_run_sentence(code: str) -> str:
    """The run-quality sentence for one check that could not run."""
    return NOT_RUN_SENTENCES.get(code, f"a validation check could not run ({code})")


def validity_check_available(attck: Any) -> bool:
    """Whether the validity check can run at all on this box.

    ``unknown_technique_ids`` answers "nothing unknown" when the catalogue
    cannot be read, which is the right thing to *return* and the wrong thing
    to *report*: a run that checked nothing has to say so. A knowledge module
    without the question is read as available, so a stub in a test is not
    told it is broken.
    """
    probe = getattr(attck, "catalogue_available", None)
    if attck is None or probe is None:
        return attck is not None
    try:
        return bool(probe())
    except Exception as exc:  # noqa: BLE001 — a probe that raises is a catalogue that is not there
        logger.debug("validation: the catalogue probe failed (%s).", exc)
        return False


def unknown_technique_ids(ids: Sequence[str], attck: Any) -> set[str]:
    """Which of ``ids`` the ATT&CK catalogue has no entry for, across all domains.

    The single place that answers "is this a real technique", so the analyst
    loop, the judge's bundle check and the report's capability matrix cannot
    disagree about one id. A lookup that fails is not a verdict: an unreachable
    catalogue returns nothing unknown rather than calling everything invented.

    ``attck_validate`` is the cheap question — it answers from the vendored id
    universe and only touches the fifty-megabyte catalogue once an id has
    already failed — and every id is asked in one call, so a report with forty
    techniques costs one lookup rather than forty.
    """
    wanted = [str(i).strip().upper() for i in ids if str(i).strip()]
    if not wanted or attck is None:
        return set()

    check = getattr(attck, "attck_validate", None)
    if check is not None:
        try:
            answer = check(wanted)
        except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
            logger.debug("validation: the ATT&CK check failed (%s).", exc)
            return set()
        return {
            str(row.get("id") or "").strip().upper()
            for row in (answer or {}).get("invalid") or []
            if row.get("id")
        }

    lookup = getattr(attck, "attck_lookup", None)
    if lookup is None:
        return set()
    unknown: set[str] = set()
    for tid in wanted:
        try:
            answer = lookup(tid)
        except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
            logger.debug("validation: the ATT&CK lookup for %s failed (%s).", tid, exc)
            continue
        if isinstance(answer, dict) and not answer.get("valid"):
            unknown.add(tid)
    return unknown


def _technique_is_known(technique_id: str, attck: Any) -> bool:
    """Whether the id is a real technique."""
    return not unknown_technique_ids([technique_id], attck)


def _retired_note(technique_id: str, attck: Any) -> str:
    """`` (retired in ATT&CK 19.2)`` when a previous vendored catalogue had the id."""
    ask = getattr(attck, "attck_retired_in", None)
    if ask is None:
        return ""
    try:
        release = ask(technique_id)
    except Exception as exc:  # noqa: BLE001 — a note, not a check
        logger.debug("validation: the retired-id lookup for %s failed (%s).", technique_id, exc)
        return ""
    return f" (retired in ATT&CK {release})" if release else ""


def _suggest_techniques(claim_text: str, attck: Any) -> list[str]:
    """Up to :data:`MAX_SUGGESTIONS` real ids for what the claim describes."""
    resolve = getattr(attck, "resolve_technique", None)
    if resolve is None or not claim_text.strip():
        return []
    try:
        answer = resolve(claim_text, MAX_SUGGESTIONS)
    except Exception as exc:  # noqa: BLE001 — a suggestion is a courtesy, not a contract
        logger.debug("validation: technique suggestions unavailable (%s).", exc)
        return []
    candidates = (answer or {}).get("candidates") if isinstance(answer, dict) else None
    out: list[str] = []
    for candidate in candidates or []:
        tid = str((candidate or {}).get("technique_id") or "").strip().upper()
        if tid and tid not in out:
            out.append(tid)
        if len(out) >= MAX_SUGGESTIONS:
            break
    return out


def mark_invalid_technique_ids(isr: Any, violations: Iterable[Violation]) -> None:
    """Flag the claims whose technique id survived the retry unresolved.

    The id itself is left exactly as the analyst wrote it. What changes is the
    report's description of it: ``technique_id_valid=False`` is how a reader,
    the STIX minting step and the FP linter learn that this one is not real.
    """
    claims = list(getattr(isr, "claims", None) or [])
    for violation in violations:
        if violation.code != "attck.unknown_id":
            continue
        index = _claim_index(violation.path)
        if index is None or index >= len(claims):
            continue
        claim = claims[index]
        if hasattr(claim, "technique_id_valid"):
            claim.technique_id_valid = False


def _claim_index(path: str) -> int | None:
    match = re.search(r"claims\[(\d+)\]", path or "")
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# Anything with a pydantic schema
# ---------------------------------------------------------------------------


def keep_known_keys(model: Any, payload: Any) -> tuple[Any, list[str]]:
    """``payload`` narrowed to the fields ``model`` declares, and what was dropped.

    The report sections forbid unknown keys, deliberately: a model that invents
    a field has invented its content too. But refusing the whole object over
    one extra key cost two reports their conclusion and their technical
    analysis — ``sophistication_rating`` and ``text`` beside fields that were
    all correct — and the report then simply had no conclusion, with nothing
    saying why. The known subset is kept, the extra keys are named, and the
    caller records them as a degradation reason.

    Recursive through the declared sub-models, because the keys the models
    invented were nested inside the section objects rather than beside them.
    Paths come back dotted, as a reader of the reason reads them.
    """
    dropped: list[str] = []

    def _walk(target: Any, value: Any, path: str) -> Any:
        fields = getattr(target, "model_fields", None)
        if not isinstance(value, dict) or not isinstance(fields, dict):
            return value
        kept: dict[str, Any] = {}
        for key, item in value.items():
            if key not in fields:
                dropped.append(f"{path}{key}")
                continue
            kept[key] = _walk_field(fields[key], item, f"{path}{key}.")
        return kept

    def _walk_field(field: Any, value: Any, path: str) -> Any:
        annotation = getattr(field, "annotation", None)
        origin = get_origin(annotation)
        nested = [
            arg
            for arg in ([annotation, *get_args(annotation)])
            if isinstance(arg, type) and hasattr(arg, "model_fields")
        ]
        if not nested:
            return value
        if isinstance(value, list):
            return [_walk(nested[0], item, f"{path}{index}.") for index, item in enumerate(value)]
        if origin in (dict, Mapping) and isinstance(value, dict):
            # A mapping of models: the keys are the caller's own, not fields,
            # so the sub-model is asked about each *value*. Walked as the
            # dict itself, every key would be reported dropped and the field
            # would come back empty.
            return {key: _walk(nested[-1], item, f"{path}{key}.") for key, item in value.items()}
        return _walk(nested[0], value, path)

    return _walk(model, payload, ""), dropped


def schema_violations(model: Any, payload: Any, *, code: str) -> list[Violation]:
    """Pydantic's complaints about ``payload``, in words the model can act on.

    The narrative and the report composer answer against a schema with real
    constraints — three to five capability paragraphs, an executive summary
    between 120 and 1200 characters, six required fields per recommendation —
    and the constraints are exactly the things a model gets wrong. Before this
    the whole answer was discarded on the first one and the report shipped the
    deterministic template instead, with nothing telling anyone which rule was
    broken. Each pydantic error becomes one violation naming the field and the
    rule, which is what the retry turn shows the model.
    """
    if payload is None:
        return [Violation(code=code, message="the answer was not JSON at all.")]
    try:
        model.model_validate(payload)
    except ValidationError as exc:
        return [
            Violation(
                code=code,
                message=_schema_message(model, error),
                path=".".join(str(part) for part in error.get("loc") or ()),
            )
            for error in exc.errors()
        ][:MAX_SCHEMA_VIOLATIONS]
    except Exception as exc:  # noqa: BLE001 — a coercion failure is still a finding
        return [Violation(code=code, message=safe_finding_value(exc))]
    return []


# ---------------------------------------------------------------------------
# The report's prose
# ---------------------------------------------------------------------------

UNGROUNDED_CAPABILITY_CODE = "narrative.ungrounded_capability"

# The capability each term claims, and what in a run would establish it: an
# ATT&CK technique (matched on the base id, so a sub-technique counts), or an
# evidence section / typed block whose presence means the run looked at that
# behaviour and found something.
#
# The list is fixed rather than derived, and short rather than exhaustive.
# These are the words that turn a thin run into a confident-sounding report:
# run 3's executive summary asserted "active command-and-control
# communication", "data exfiltration" and "persistent backdoor access" for a
# sample whose whole analysis was one technique (T1027) and no network or
# sandbox data at all. A term nobody over-claims does not need to be here.
CAPABILITY_TERMS: tuple[tuple[str, str, tuple[str, ...], tuple[str, ...]], ...] = (
    (
        "command and control",
        r"command[\s-]and[\s-]control|\bc2\b|\bc&c\b|\bcnc\b",
        ("T1071", "T1090", "T1095", "T1102", "T1104", "T1105", "T1132", "T1571", "T1573"),
        ("network", "c2", "connections", "http", "dns"),
    ),
    (
        "exfiltration",
        r"exfiltrat\w*",
        ("T1020", "T1029", "T1041", "T1048", "T1030", "T1567"),
        ("network", "exfiltration", "connections"),
    ),
    (
        "backdoor",
        r"backdoor\w*",
        ("T1071", "T1219", "T1505", "T1546", "T1543", "T1547"),
        ("network", "persistence", "services"),
    ),
    (
        "keylogging",
        r"keylog\w*|keystroke\w*",
        ("T1056",),
        ("dynamic", "hooks", "input"),
    ),
    (
        "ransomware",
        r"ransom\w*",
        ("T1486", "T1490", "T1491", "T1485"),
        ("ransom_note", "encryption_scheme"),
    ),
    (
        "encryption",
        r"encrypt\w*|cryptograph\w*",
        ("T1027", "T1022", "T1486", "T1573", "T1140"),
        ("encryption_scheme", "crypto", "strings"),
    ),
    (
        "persistence",
        r"persist\w*",
        ("T1053", "T1136", "T1197", "T1505", "T1543", "T1546", "T1547", "T1574"),
        ("persistence", "registry", "services", "scheduled_tasks"),
    ),
    (
        "process injection",
        r"inject\w*",
        ("T1055", "T1620", "T1106"),
        ("dynamic", "processes", "imports"),
    ),
    (
        "lateral movement",
        r"lateral[\s-]movement",
        ("T1021", "T1080", "T1210", "T1534", "T1570"),
        ("network", "smb", "connections"),
    ),
    (
        "credential theft",
        r"credential\w*|password[\s-]steal\w*|\bstealer\b",
        ("T1003", "T1552", "T1555", "T1056", "T1539"),
        ("credentials", "browser", "files_read"),
    ),
    (
        "downloader or dropper",
        r"\bdownloader\b|\bdropper\b|\bloader\b",
        ("T1105", "T1204", "T1608", "T1027"),
        ("network", "dropped_files", "files_written"),
    ),
    (
        "rootkit",
        r"rootkit\w*",
        ("T1014", "T1215", "T1542", "T1564"),
        ("drivers", "kernel"),
    ),
    (
        "spyware",
        r"spyware|surveillance",
        ("T1056", "T1113", "T1123", "T1125"),
        ("dynamic", "screenshots"),
    ),
)

_COMPILED_CAPABILITY_TERMS = tuple(
    (label, re.compile(pattern, re.IGNORECASE), techniques, keys)
    for label, pattern, techniques, keys in CAPABILITY_TERMS
)


@dataclass(frozen=True)
class CapabilityGrounding:
    """What a run established, in the three shapes the terms are checked against.

    Built once per report and handed to the validator, so the narrative round
    and each of the composer's sections ask the same question of the same run.
    """

    technique_ids: frozenset[str] = frozenset()
    evidence_keys: frozenset[str] = frozenset()
    evidence_text: str = ""

    def grounds(
        self, techniques: Sequence[str], keys: Sequence[str], pattern: re.Pattern[str]
    ) -> bool:
        """Whether the run supports a term by technique, by section, or by word.

        The third is not a loophole. An analyst that wrote "the sample resolves
        a hard-coded C2 host from its strings" has grounded the phrase whether
        or not anybody mapped it to T1071, and a report is allowed to repeat
        what its own evidence says. What is forbidden is the report being the
        first place the word appears.
        """
        if any(base in self.technique_ids for base in techniques):
            return True
        if any(key in self.evidence_keys for key in keys):
            return True
        return bool(self.evidence_text and pattern.search(self.evidence_text))

    def summary(self) -> str:
        """What the run does have, for the feedback turn to offer instead."""
        techniques = ", ".join(sorted(self.technique_ids)) or "no ATT&CK techniques"
        keys = ", ".join(sorted(self.evidence_keys)) or "no evidence sections"
        return f"This run established {techniques}, and has {keys}."

    @classmethod
    def from_report(cls, report: Any, isr_reports: Any = None) -> CapabilityGrounding:
        """Read a ``MalwareReport`` (and optionally the analysts' ISRs).

        Never raises: a grounding that cannot be read is an empty one, and an
        empty one grounds nothing — which would fail every term — so a read
        that finds nothing at all returns a grounding that checks nothing. A
        report the validator cannot understand must not become a report full of
        violations.
        """
        techniques: set[str] = set()
        keys: set[str] = set()
        words: list[str] = []
        try:
            for row in list(getattr(report, "ttp_mappings", None) or []) + list(
                getattr(report, "capability_matrix", None) or []
            ):
                base = _base_technique(getattr(row, "technique_id", ""))
                if base:
                    techniques.add(base)
                words.append(str(getattr(row, "technique_name", "") or ""))
            for block in ("static", "dynamic", "network"):
                if getattr(report, block, None) is not None:
                    keys.add(block)
            if list(getattr(report, "persistence", None) or []):
                keys.add("persistence")
            for section in getattr(report, "sections", None) or []:
                key = str(getattr(section, "key", "") or "").strip().lower()
                if key:
                    keys.add(key)
                words.append(str(getattr(section, "title", "") or ""))
                for row in getattr(section, "rows", None) or []:
                    words.extend(str(cell) for cell in row)
                words.append(str(getattr(section, "text", "") or ""))
            values = isr_reports.values() if hasattr(isr_reports, "values") else ()
            for isr in values:
                for claim in getattr(isr, "claims", None) or []:
                    words.append(str(getattr(claim, "claim", "") or ""))
                    base = _base_technique(str(getattr(claim, "technique_id", "") or ""))
                    if base:
                        techniques.add(base)
                for finding in getattr(isr, "findings", None) or []:
                    words.append(str(getattr(finding, "title", "") or ""))
        except Exception as exc:  # noqa: BLE001 — an unreadable run grounds nothing
            logger.debug("validation: the capability grounding could not be read (%s).", exc)
        return cls(
            technique_ids=frozenset(techniques),
            evidence_keys=frozenset(keys),
            evidence_text=" ".join(w for w in words if w).lower(),
        )


# What ends the clause a term was written in. A capability word after one of
# these is a new statement, so a negation before it does not reach it.
#
# A comma is deliberately not one of them. "The loader does not, in any
# sandbox run, establish command-and-control" is one clause with a
# parenthetical in it, and treating the commas as boundaries threw the cue
# away and re-flagged the honest negative. The window below is the limiter.
_CLAUSE_BREAK_RE = re.compile(r"[.;:!?\n]|\bbut\b|\bhowever\b|\bwhereas\b", re.IGNORECASE)

# The cues that turn a capability word into a report of its absence.
#
# ``free`` is not among them. "free of" is the only construction it would have
# earned, and it cost a real claim: "a free dynamic-DNS host for command and
# control" is an over-claim the validator exists to catch.
_NEGATION_RE = re.compile(
    r"\b(?:no|not|never|without|lack(?:s|ed|ing)?|absence|none)\b|n't\b|\bfailed to\b",
    re.IGNORECASE,
)

# The phrases that open with a cue and assert the opposite of one. "There is no
# doubt that the sample exfiltrates data" is a claim, and "not only does it
# persist" is two. Checked at the cue's own position, so a real cue elsewhere
# in the window still counts.
_NOT_A_NEGATION = ("no doubt", "not only")

# How far back a cue is allowed to reach. A negation governs the words next to
# it, not the whole paragraph: "no persistence was observed and the sample
# injects code into explorer.exe" is one honest negative and one real claim,
# and a window this size keeps the second one.
#
# Two known limits, both of them the price of the two rules above, and both
# erring toward the answer that costs a feedback turn rather than the one that
# clears a real over-claim:
#
#   * a comma splice — "No persistence was observed, the sample injects code"
#     — leaves the second claim unflagged, because the comma is not a clause
#     break and the window still reaches the cue;
#   * the last item of a long negative list — "no evidence of keylogging,
#     credential theft, or exfiltration" — is flagged, because the cue is
#     further back than this.
#
# ``TestTheKnownLimitsOfTheWindow`` pins both, so a later change to the break
# set or the window is measured against them rather than discovering them.
_NEGATION_WINDOW = 40


def _is_negated(text: str, start: int) -> bool:
    """Whether the term at ``start`` sits inside a statement of absence.

    Read backwards from the match through at most ``_NEGATION_WINDOW``
    characters, stopping at whatever ended the previous clause. A cue in what
    is left governs this term: "contains no keylogging or credential theft"
    negates both words, while "no persistence was observed; it injects code"
    negates only the first, because the semicolon ends the clause the cue was
    in.
    """
    window = text[max(0, start - _NEGATION_WINDOW) : start]
    breaks = list(_CLAUSE_BREAK_RE.finditer(window))
    if breaks:
        window = window[breaks[-1].end() :]
    lowered = window.lower()
    return any(
        not lowered.startswith(_NOT_A_NEGATION, cue.start())
        for cue in _NEGATION_RE.finditer(window)
    )


def _claimed(pattern: re.Pattern[str], text: str) -> bool:
    """Whether ``text`` claims the capability rather than reporting its absence.

    One surviving match is enough: a report that says the sample does not
    exfiltrate data in one sentence and does exfiltrate it in another has made
    the claim, and it is the claim that has to be grounded.
    """
    return any(not _is_negated(text, match.start()) for match in pattern.finditer(text))


def _base_technique(technique_id: Any) -> str:
    """``T1055.012`` as ``T1055``; anything else as ""."""
    value = str(technique_id or "").strip().upper()
    return value.split(".")[0] if TECHNIQUE_ID_EXACT_RE.match(value) else ""


def ungrounded_capabilities(
    text: str, grounding: CapabilityGrounding, *, code: str = UNGROUNDED_CAPABILITY_CODE
) -> list[Violation]:
    """Capability claims in ``text`` that this run's evidence does not support.

    One violation per term, so the feedback turn names each one and the run
    summary counts them. The prose itself is never edited: what an unresolved
    term buys is a reader who can see that the sentence outran the evidence,
    which is worth more than a summary quietly rewritten by a regular
    expression into something no model wrote.
    """
    if not text or not text.strip():
        return []
    if not grounding.technique_ids and not grounding.evidence_keys and not grounding.evidence_text:
        # Nothing was read, so nothing can be judged ungrounded. See
        # ``CapabilityGrounding.from_report``.
        return []
    violations: list[Violation] = []
    for label, pattern, techniques, keys in _COMPILED_CAPABILITY_TERMS:
        # A report of absence is not a claim. Saying "no command-and-control
        # communication was observed" is the prose a thin run should produce,
        # and flagging it spends the one retry arguing against the honest
        # sentence this validator exists to encourage.
        if not _claimed(pattern, text):
            continue
        if grounding.grounds(techniques, keys, pattern):
            continue
        violations.append(
            Violation(
                code=code,
                message=(
                    f"the text claims {label}, which nothing in this run establishes — "
                    f"no {', '.join(techniques[:3])} technique, no matching evidence "
                    f"section, and no analyst said it. {grounding.summary()} "
                    "Describe what was found, or drop the claim."
                ),
                path=label.replace(" ", "_"),
            )
        )
    return violations


def narrative_capability_violations(
    payload: Any, grounding: CapabilityGrounding
) -> list[Violation]:
    """:func:`ungrounded_capabilities` over a narrative answer's prose fields."""
    if payload is None:
        return []
    data = payload if isinstance(payload, dict) else getattr(payload, "__dict__", {}) or {}
    parts: list[str] = [str(data.get("executive_summary") or "")]
    parts.extend(str(item) for item in (data.get("capabilities_narrative") or []))
    return ungrounded_capabilities("\n".join(parts), grounding)


def section_capability_violations(payload: Any, grounding: CapabilityGrounding) -> list[Violation]:
    """:func:`ungrounded_capabilities` over every string a section answer carries."""
    if payload is None:
        return []
    parts: list[str] = []

    def _walk(value: Any, depth: int = 0) -> None:
        if depth > 4:
            return
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for item in value.values():
                _walk(item, depth + 1)
        elif isinstance(value, list | tuple):
            for item in value:
                _walk(item, depth + 1)

    _walk(payload)
    return ungrounded_capabilities("\n".join(parts), grounding, code=UNGROUNDED_CAPABILITY_CODE)


# ---------------------------------------------------------------------------
# The judge's bundle
# ---------------------------------------------------------------------------


# The identity fields whose values count as grounded without a ledger entry.
_IDENTITY_INDICATOR_KEYS = ("sha256", "sha1", "md5", "file_name")


def sample_identity_values(sample: Any) -> set[str]:
    """The sample's own identity values, as grounded as anything a tool saw.

    They come from the router rather than from a tool the model chose, and the
    judge is shown them in its identity block. A run that never called
    ``hashes`` has no ledger entry carrying the sha256 the job was queued
    under, and an indicator naming that hash was flagged as invented.
    """
    data = sample if isinstance(sample, dict) else {}
    values = {str(data.get(key) or "").strip() for key in _IDENTITY_INDICATOR_KEYS}
    return {value for value in values if value}


INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE = "stix.indicator_type_contradicts_verdict"

# The word this export will not let a Benign verdict publish unasked, and the
# rest of the STIX indicator-type vocabulary the judge may reach for instead.
_MALICIOUS_ACTIVITY = "malicious-activity"
_MILDER_INDICATOR_TYPES = ("benign", "anomalous-activity", "unknown")


def _is_the_samples_own_indicator(pattern: str, identity: set[str]) -> bool:
    """Whether this indicator names the sample rather than something it touched.

    The export mints one indicator for the sample's own hash and types it with
    the verdict, so an indicator quoting an identity value is that statement
    and not a claim about a third party.
    """
    return any(literal.lower() in identity for _path, literal in _comparisons(pattern))


def indicator_type_contradicts_verdict(
    obj: Any, *, verdict: str | None, identity: set[str], path: str
) -> list[Violation]:
    """A judge-written indicator that says the opposite of the judge's verdict.

    The type is the judge's to give: nothing rewrites it and nothing drops the
    object. On a Benign verdict an indicator typed ``malicious-activity``
    publishes the sample's own vendor domain to a blocklist as malicious
    activity, so the judge is asked about it once, with the vocabulary's milder
    words named and its own answer published whichever way it goes.

    One direction only. A Malware verdict beside an indicator typed ``benign``
    is not the same statement: an indicator is a claim about the value it
    names, and a malicious sample may well touch something harmless.
    """
    if verdict != "Benign":
        return []
    types = [str(t).strip().lower() for t in (getattr(obj, "indicator_types", None) or [])]
    if _MALICIOUS_ACTIVITY not in types:
        return []
    pattern = str(getattr(obj, "pattern", "") or "")
    if _is_the_samples_own_indicator(pattern, identity):
        return []
    named = str(getattr(obj, "name", "") or "").strip() or pattern
    return [
        Violation(
            code=INDICATOR_TYPE_CONTRADICTS_VERDICT_CODE,
            message=(
                f"the indicator {safe_finding_value(named)!r} is typed "
                f"{_MALICIOUS_ACTIVITY!r} while the verdict you stated is Benign, so this "
                "bundle publishes the value as malicious activity to whoever consumes it. "
                f"The indicator-type vocabulary also has {', '.join(_MILDER_INDICATOR_TYPES)}. "
                "Retype it, or restate the verdict, or keep the type as it is — whichever "
                "you answer is what this run publishes, and a type you keep is recorded "
                "beside the bundle as raised and kept."
            ),
            path=path,
        )
    ]


def validate_verdict_bundle(
    bundle: Any,
    evidence_corpus: set[str] | None = None,
    *,
    attck: Any = None,
    sample: Any = None,
    shortened_tools: Iterable[str] = (),
    searched: Iterable[str] = (),
    corpus_state: CorpusState | None = None,
) -> list[Violation]:
    """What is wrong with the judge's answer, in the judge's own terms.

    ``attck`` is the same knowledge module the analyst loop consults, and it is
    the same check: an id is unresolvable when the catalogue does not have it,
    not when it fails a regex. ``T7777`` is well-formed and imaginary, which is
    exactly the case this violation exists for. Passing ``None`` skips the
    catalogue question rather than answering it wrongly.

    ``sample`` is the identity block's dict; a quoted value equal to one of
    its hashes or its file name counts as found, the way a corpus hit does.
    They are kept out of the corpus haystack, which is searched by substring:
    the file name is whatever the submitter typed, and a name carrying an
    address would otherwise ground an indicator for it. A pattern is grounded
    when one of its quoted values is found, in the corpus or in the identity,
    as it always was for the corpus alone; the denylists run first either way.

    ``shortened_tools`` names the tools whose answers reached the corpus with
    rows missing. It changes no verdict: it is one sentence added to an
    absence, so a judge reading one knows which call to narrow.

    ``searched`` is what the run's own tools answered, each answer as itself
    and already lower-cased by the corpus that kept it. It is passed beside
    ``evidence_corpus`` rather than inside it because joining the run's whole
    record into one token copied it twice more for nothing.

    ``corpus_state`` says whether the evidence searched is this run's whole
    record. When it is not — the in-memory corpus hit its ceiling, or there is
    no corpus and the stored entries fell back on had been blanked by the byte
    budget — an absence is written as an **advisory** row: the judge is told
    once, in a sentence that says what was searched and what was not, and
    nothing drops its object for it. Passing ``None`` means the caller knows
    the corpus was whole, which is the default every existing caller had.
    """
    violations: list[Violation] = []
    objects = list(getattr(bundle, "objects", None) or [])
    scope = expected_technique_scope(sample)

    # The token corpus and the run's own answers, each as itself. The tokens
    # are short and are joined once; the answers are searched where they are.
    haystack = Haystack(
        [
            " ".join(sorted(evidence_corpus)).lower() if evidence_corpus else "",
            *(str(part) for part in searched),
        ]
    )
    identity = {value.lower() for value in sample_identity_values(sample)}
    # The verdict as the judge stated it, read the one way every reader of a
    # verdict reads it, so an indicator is weighed against the word that will
    # be published rather than against the object set.
    from maljan.pipeline.outcome import read_stated_verdict

    stated_verdict = read_stated_verdict(bundle).recognised
    runtime_paths = _runtime_paths(evidence_corpus)
    partial = shortened_evidence_note(shortened_tools)
    how_whole = corpus_state or CorpusState()
    # Neither source. The token corpus holds the sandbox report's network
    # entries and the run's own answers travel beside it, so a run with no
    # sandbox block and no answers searched nothing at all — and a check that
    # searched nothing may not conclude from it. It says so instead: the row is
    # written, it is advisory, and the judge keeps its object. Gating the whole
    # branch on the token corpus alone skipped the check outright on mock mode,
    # a static-only team, a failed submission and any sample that made no
    # network call, and an invented indicator was exported with nothing said.
    if not haystack:
        how_whole = both_searched(how_whole, NOTHING_SEARCHED)
    not_searched = partial_evidence_note(how_whole)
    for index, obj in enumerate(objects):
        kind = str(getattr(obj, "type", "") or "")
        if kind == "indicator":
            pattern = str(getattr(obj, "pattern", "") or "")
            violations.extend(
                indicator_type_contradicts_verdict(
                    obj,
                    verdict=stated_verdict,
                    identity=identity,
                    path=f"objects[{index}]",
                )
            )
            problem = _indicator_problem(pattern, haystack, runtime_paths, identity)
            if problem:
                absent = _is_an_absence(problem)
                caveat = f"{partial}{not_searched}" if absent else ""
                violations.append(
                    Violation(
                        code="stix.ungrounded_indicator",
                        message=(
                            f"{safe_finding_value(problem)} Emit indicators only for values a "
                            "tool in this run actually saw, and prefer zero indicators to an "
                            f"invented one.{caveat}"
                        ),
                        path=f"objects[{index}]",
                        # Only an absence goes advisory, and only when the
                        # evidence searched was partial. A denylisted host or a
                        # malformed digest is refused on its own account and no
                        # amount of evidence would change it.
                        advisory=absent and how_whole.partial,
                    )
                )
        elif kind == "attack-pattern":
            tid = _attack_pattern_technique_id(obj)
            if not tid:
                # A technique with a name and no id used to skip every check
                # below, because all of them key on the id — which is how an
                # Android sample's attack-patterns reached a report with the
                # Mobile-domain check never having run on them, and how three
                # of them were published as ATT&CK techniques with an empty
                # `technique_id`. It is asked for once here; if it survives,
                # the report carries it as an unmapped behaviour.
                name = str(getattr(obj, "name", "") or "").strip()
                violations.append(
                    Violation(
                        code=MISSING_ID_CODE,
                        message=(
                            f"the attack-pattern {safe_finding_value(name)!r} names no MITRE "
                            "ATT&CK technique id. "
                            "Give its external_references a mitre-attack entry with the "
                            "external_id (T#### or T####.###), or drop the object and say "
                            "what was observed in the assessment: a behaviour with no "
                            "technique id is reported as a behaviour, not as a technique."
                        ),
                        path=f"objects[{index}]",
                    )
                )
                continue
            if not TECHNIQUE_ID_EXACT_RE.match(tid):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {safe_finding_value(tid)}, which is "
                            "not shaped like a MITRE ATT&CK technique id (T#### or T####.###)."
                        ),
                        path=f"objects[{index}]",
                    )
                )
            elif attck is not None and not _technique_is_known(tid, attck):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {safe_finding_value(tid)}, which the "
                            "MITRE ATT&CK catalogue has no entry for in any domain"
                            f"{_retired_note(tid, attck)}. Use a real technique id or "
                            "drop the attack-pattern."
                        ),
                        path=f"objects[{index}]",
                    )
                )
            elif attck is not None:
                mismatch = platform_mismatch_message(tid, attck, scope)
                if mismatch:
                    violations.append(
                        Violation(
                            code=PLATFORM_MISMATCH_CODE,
                            message=mismatch,
                            path=f"objects[{index}]",
                        )
                    )

    assessment = getattr(bundle, "x_maljan_assessment", None)
    severity = getattr(assessment, "severity", None) if assessment is not None else None
    rating = str(getattr(severity, "rating", "") or "") if severity is not None else ""
    if rating and rating not in SEVERITY_RATINGS:
        violations.append(
            Violation(
                code="verdict.severity_enum",
                message=(
                    f"severity.rating is {safe_finding_value(rating)!r}; it must be one of "
                    f"{', '.join(SEVERITY_RATINGS)}."
                ),
                path="severity.rating",
            )
        )

    family = getattr(assessment, "family", None) if assessment is not None else None
    if family is not None and str(getattr(family, "name", "") or "").strip():
        if not list(getattr(family, "evidence_ids", None) or []):
            violations.append(
                Violation(
                    code="attribution.ungrounded_family",
                    message=(
                        f"family {safe_finding_value(family.name)!r} cites no evidence ids; list "
                        "the ledger entries the name came from, or drop the attribution."
                    ),
                    path="family.evidence_ids",
                )
            )

    return violations


def _model_at(model: Any, loc: Sequence[Any]) -> Any:
    """The model that owns the field ``loc`` points at, or ``model`` itself.

    Walks the named steps of a pydantic error location, stepping through list
    and optional annotations on the way. Anything it cannot follow — a union
    with two model members, a dict of models — ends the walk at the last model
    it was sure about, which is a less specific answer rather than a wrong one.
    """
    import typing

    current = model
    for step in loc[:-1] if loc else ():
        if not isinstance(step, str):
            continue
        field = (getattr(current, "model_fields", {}) or {}).get(step)
        if field is None:
            return current
        annotation = field.annotation
        for _ in range(3):
            args = [a for a in typing.get_args(annotation) if a is not type(None)]
            if len(args) != 1:
                break
            annotation = args[0]
        if isinstance(annotation, type) and hasattr(annotation, "model_fields"):
            current = annotation
        else:
            return current
    return current


def _schema_message(model: Any, error: Mapping[str, Any]) -> str:
    """Pydantic's complaint, with the schema's keys added when it is about a key.

    ``extra="forbid"`` answers "Extra inputs are not permitted", which names
    neither the key that was rejected nor the ones that would have been
    accepted; "Field required" names the one that is absent and nothing else.
    A live report composer spent both of its turns on the first sentence and
    the ``conclusion`` section was dropped from the delivered report. The field
    list is short, it is exactly what the model needs to answer again, and it
    costs one line of the feedback turn.
    """
    # Pydantic's own sentence about the field. It does not normally echo the
    # value, and a finding row is not the place to find out that it sometimes
    # does.
    message = safe_finding_value(error.get("msg") or "is not valid")
    kind = str(error.get("type") or "")
    if kind not in ("extra_forbidden", "missing"):
        return message
    # The keys of the object that rejected the field, which for a nested error
    # is not the answer's own: a bad key inside
    # ``defensive_recommendations[0]`` was answered with the narrative's three
    # top-level keys, none of which belong there.
    owner = _model_at(model, error.get("loc") or ())
    keys = ", ".join(sorted(getattr(owner, "model_fields", {}) or {}))
    if not keys:
        return message
    if kind == "extra_forbidden":
        return (
            f"{message}: this object accepts only these keys and rejects every other one — {keys}."
        )
    return f"{message}: this object's keys are {keys}."


ASSESSMENT_MISSING_CODE = "verdict.assessment_missing"

# What the judge is told to add, in the shape the bundle reads it in.
ASSESSMENT_MISSING_MESSAGE = (
    'Add x_maljan_assessment at the top level of the bundle, as a sibling of "objects" '
    "and not inside it, with verdict, severity {rating, rationale}, malware_category, "
    "family {name, confidence, evidence_ids} and confidence. "
    "Omit only a field the evidence cannot support."
)

# The fields whose presence means the block said something. A block carrying
# only the verdict has still answered the question the report leads with, and a
# judge that abstained on the other four has answered too.
_ASSESSMENT_FIELDS: tuple[str, ...] = (
    "verdict",
    "severity",
    "malware_category",
    "family",
    "confidence",
)


def assessment_violations(bundle: Any) -> list[Violation]:
    """Whether the judge said what it thinks, beyond the STIX objects.

    The message names the top level of the bundle because that is where
    ``Bundle.x_maljan_assessment`` is read from. A block the judge placed
    inside ``objects`` instead is lifted to the top level before validation
    (``agents.judge_postprocess.lift_misplaced_extensions``) and the lift is
    recorded; this check then sees the block where the bundle keeps it. Only a
    bundle that carries no assessment at all reaches the violation below.

    Severity, category, family and the judge's own confidence are the judge's
    to decide and nothing downstream computes them, so a bundle without them
    produces a report that reads "not assessed" from top to bottom. That used
    to happen in silence. It is one feedback turn now, and an unresolved
    finding when the retry omits the block as well.

    A judge that abstains on one field has answered; a block with nothing in it
    has not, and counts as absent.
    """
    assessment = getattr(bundle, "x_maljan_assessment", None)
    if assessment is not None and any(
        getattr(assessment, field, None) is not None for field in _ASSESSMENT_FIELDS
    ):
        return []
    return [
        Violation(
            code=ASSESSMENT_MISSING_CODE,
            message=ASSESSMENT_MISSING_MESSAGE,
            path="x_maljan_assessment",
        )
    ]


UNSTATED_VERDICT_CODE = "verdict.unstated"
UNRECOGNISED_VERDICT_CODE = "verdict.unrecognised"


def stated_verdict_violations(bundle: Any) -> list[Violation]:
    """Whether the judge stated a verdict, and whether it can be read.

    Two different faults with two different consequences, so two codes.

    The field is **absent**: the object set decides, because there is nothing
    else to go on. A ``malware`` object written "strictly as a container for
    the object type in STIX" then becomes a Malware verdict, which is the
    fail-safe and not an answer — so `verdict.unstated` records that it was
    used. The fallback stays for stored runs and for a model that omitted the
    field.

    The field **says something this pipeline cannot read**: the objects decide
    nothing. The run publishes the inconclusive verdict, the judge's own word
    travels to the report beside it, and `verdict.unrecognised` asks once for a
    word from the vocabulary — quoting what the judge wrote, because a
    correction that does not repeat the mistake is one the model cannot locate.

    A bundle this pipeline built out of text states its own verdict in
    ``x_maljan_fallback_verdict`` and is not asked for a second one.
    """
    if getattr(bundle, "x_maljan_fallback_verdict", None) is not None:
        return []
    from maljan.pipeline.outcome import INCONCLUSIVE_VERDICT, read_stated_verdict

    stated = read_stated_verdict(bundle)
    if stated.recognised is not None:
        return []
    listed = ", ".join(VERDICT_VALUES)
    if stated.unrecognised:
        return [
            Violation(
                code=UNRECOGNISED_VERDICT_CODE,
                message=(
                    f"x_maljan_assessment.verdict says {safe_finding_value(stated.written)!r}, "
                    f"which is not one of {listed}. Answer with exactly one of those three words "
                    "and nothing else — no qualifier, no parenthesis, no sentence; put anything "
                    "you want to qualify it with in severity.rationale. Until it is one of them "
                    f"this run publishes {INCONCLUSIVE_VERDICT} and no confidence, and your own "
                    "answer is printed beside it."
                ),
                path="x_maljan_assessment.verdict",
            )
        ]
    return [
        Violation(
            code=UNSTATED_VERDICT_CODE,
            message=(
                "x_maljan_assessment states no verdict. State it: set "
                f"x_maljan_assessment.verdict to one of {listed}, and set "
                "x_maljan_assessment.confidence to how sure you are of it. Write a malware "
                "object only for a sample you conclude is malware; without the field the "
                "verdict is read off the objects, which is a guess at what you meant."
            ),
            path="x_maljan_assessment.verdict",
        )
    ]


ASSESSMENT_CONFLICT_CODE = "verdict.assessment_conflict"

# The pairs that cannot both be meant. A malicious verdict whose severity is
# Informational, and a clean verdict rated High or Critical, are two answers to
# one question: a live run said Malware at 0.6 while its own rationale read
# "there is no evidence of malicious functionality", and the report printed
# both without a word about the contradiction.
_CONFLICTING_RATINGS: dict[str, frozenset[str]] = {
    "Malware": frozenset({"Informational"}),
    "Benign": frozenset({"High", "Critical"}),
}

# The words a category uses to say the sample is not malware. Checked against a
# Malware verdict only, and against this short list only: a category is free
# text, and the mirrored rule — deciding that some word in it means malicious —
# would be this module classifying the sample. PuTTY's was
# ``legitimate-utility`` beside a Malware verdict and an Informational rating.
_BENIGN_CATEGORY_WORDS: tuple[str, ...] = (
    "legitimate",
    "benign",
    "clean",
    "harmless",
    "not malware",
    "no malware",
    "non malicious",
    "not malicious",
)


def _category_says_benign(category: str) -> bool:
    """Whether a free-text category asserts the sample is not malware."""
    words = re.sub(r"[^a-z0-9]+", " ", category.lower()).strip()
    return any(word in words for word in _BENIGN_CATEGORY_WORDS)


def assessment_conflict_violations(bundle: Any) -> list[Violation]:
    """Whether the judge's stated verdict and the rest of its answer agree.

    Three comparisons, all of them against the verdict the judge stated: the
    severity rating, the malware category, and whether a ``malware`` object is
    in the bundle. Every field is the judge's and none is touched here — what
    the judge gets is one turn in which both sides are named and it is asked
    which it meant. A contradiction that survives the turn is recorded rather
    than resolved, because picking one of the two for the judge would be
    exactly the silent override this module exists to replace. The verdict is
    then published as stated, and the STIX export declines to carry a malware
    object under a Benign one.

    One row per disagreeing fact, each with its own path, so the console folds
    them apart and the judge reads what each one is about.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    verdict = decide_from_bundle(bundle)
    assessment = getattr(bundle, "x_maljan_assessment", None)
    found: list[Violation] = []

    rating = str(getattr(getattr(assessment, "severity", None), "rating", "") or "").strip()
    if rating and rating in _CONFLICTING_RATINGS.get(verdict, frozenset()):
        found.append(
            Violation(
                code=ASSESSMENT_CONFLICT_CODE,
                message=(
                    f"This bundle's verdict is {verdict} and "
                    f"x_maljan_assessment.severity.rating says {rating}; those are two "
                    "different answers about the same sample. Reconcile them: either the "
                    "verdict or the rating is what you meant, and the rationale should "
                    "support whichever it is."
                ),
                path="x_maljan_assessment.severity.rating",
            )
        )

    category = str(getattr(assessment, "malware_category", "") or "").strip()
    if verdict == "Malware" and category and _category_says_benign(category):
        found.append(
            Violation(
                code=ASSESSMENT_CONFLICT_CODE,
                message=(
                    f"This bundle's verdict is Malware and x_maljan_assessment."
                    f"malware_category says {safe_finding_value(category)!r}, which says it is "
                    "not. Reconcile them: give the verdict the category describes, or a category "
                    "that describes the verdict."
                ),
                path="x_maljan_assessment.malware_category",
            )
        )

    if verdict == "Benign" and _malware_object_index(bundle) is not None:
        found.append(
            Violation(
                code=ASSESSMENT_CONFLICT_CODE,
                message=(
                    "This bundle's verdict is Benign and it carries a malware object. A "
                    "malware object is written for a sample you conclude is malware; under "
                    "a Benign verdict it is not published and the report says so. Drop the "
                    "object, or state the verdict it belongs to."
                ),
                path="objects",
            )
        )
    return found


def _malware_object_index(bundle: Any) -> int | None:
    """Where the bundle's first ``malware`` object sits, or ``None``."""
    for index, obj in enumerate(getattr(bundle, "objects", None) or []):
        if str(getattr(obj, "type", "") or "") == "malware":
            return index
    return None


UNSUPPORTED_BENIGN_CODE = "verdict.unsupported_benign"


def unsupported_benign_violations(
    bundle: Any, *, analyst_claims: int, ledger_ids: Sequence[str] | None = None
) -> list[Violation]:
    """Whether a Benign verdict on a run with no analysis cites anything.

    A live sample that 31 of 75 engines called malicious ended Benign at 0.1
    after every analyst reported no claims: the judge had seven tool results in
    front of it and no analysis of them, and "nothing was said about this
    sample" became "this sample is clean".

    Benign is a finding, so it needs something behind it. Either the bundle
    cites an entry from this run — a valid Authenticode signature out of
    ``signing_info`` is the usual one, which is how a signed PuTTY still ends
    Benign — or the verdict gives way to Suspicious with a rationale that says
    the run was inconclusive. Which of the two it is stays the judge's
    decision: this asks once and records what survives.

    Any cited entry clears it, not only a signature. The validator's business
    is whether the verdict points at the run's own evidence; grading that
    evidence is the judge's, and a validator that ranked it would be making the
    call it is here to ask for.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    if analyst_claims > 0 or decide_from_bundle(bundle) != "Benign":
        return []
    known = {str(entry).strip().lower() for entry in (ledger_ids or []) if str(entry).strip()}
    # A run with nothing recorded has nothing to cite, and ``verdict_for_run``
    # already calls it inconclusive: the retry could not be satisfied and could
    # not change the reported verdict.
    if not known:
        return []
    try:
        text = json.dumps(bundle.model_dump(mode="json"), default=str)
    except Exception as exc:  # noqa: BLE001 — an unreadable bundle cites nothing
        logger.debug("validation: the bundle could not be read for citations (%s).", exc)
        text = ""
    if entry_ids_in(text) & known:
        return []
    listed = ", ".join(sorted(known)[:3])
    return [
        Violation(
            code=UNSUPPORTED_BENIGN_CODE,
            message=(
                "This verdict is Benign and no analyst made a single claim about the "
                "sample, so nothing examined it. Benign is a finding and needs evidence: "
                "cite the ledger entry that establishes it — a valid signature from "
                "signing_info is the usual one — or return Suspicious and say in the "
                f"rationale that the run was inconclusive. The entries this run recorded "
                f"include {listed}."
            ),
            path="objects",
        )
    ]


def _runtime_paths(evidence_corpus: set[str] | None) -> set[str]:
    """The corpus entries that look like a path something really touched."""
    from maljan.agents._indicator_denylists import IOC_OS_RESOURCE_PREFIXES

    found: set[str] = set()
    for token in evidence_corpus or ():
        value = str(token).strip()
        if any(value.startswith(prefix.lower()) for prefix in IOC_OS_RESOURCE_PREFIXES):
            found.add(value)
    return found


# The root a path on this machine is written from: a POSIX slash, a drive with
# either separator, a UNC share, an environment variable, a home tilde, or a
# registry hive — which ``directory:path`` carries about as often as the
# registry's own object type does.
_DIRECTORY_ROOT_RE = re.compile(
    r"^(?:/"
    # The separator after a drive is required. ``C:Windows`` is drive-relative
    # — it names whatever directory that drive is currently in, which is not a
    # place on the analysed machine that anything could be checked against.
    r"|[A-Za-z]:[\\/]"
    # One backslash or two. Two are a UNC share; one is what a UNC share
    # written the way a judge writes it becomes, because a STIX literal
    # ``'\\server\share'`` is unescaped by the reader to ``\server\share``
    # before any of this sees it. Refusing it told the judge its own valid
    # path could not be a place.
    r"|\\\\?"
    r"|%[A-Za-z_][A-Za-z0-9_]*%[\\/]?"
    r"|\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)[\\/]?"
    r"|~[\\/]?"
    r"|(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)[\\/]"
    r")",
    re.IGNORECASE,
)

# A step that is a placeholder rather than a name. A strings table is full of
# them — a format string the sample was compiled with, read out of the bytes as
# though it were a path somebody visited. A step opening with ``#`` or ``?`` is
# the last one too: it is a URL's fragment or query, and ``/#frag`` read as a
# directory is a URL cut at its path.
_PLACEHOLDER_STEP_RE = re.compile(r"^(?:%[-+ #0-9.]*[a-zA-Z]|%\d+|\{[^}]*\}|<[^>]*>|\$\d+|[#?].*)$")

# What a step must carry to read as a name rather than as punctuation: two
# characters somebody could have typed as part of one.
_NAME_RUN_RE = re.compile(r"[A-Za-z0-9]{2}")

# A character no path on any of these filesystems carries.
_CONTROL_CHARACTERS = frozenset(chr(code) for code in range(0x20)) | {chr(0x7F)}

# A run of hexadecimal on its own, and the lengths a digest this project can
# name comes in. Anything else quoted in a pattern is asked the corpus question
# as it always was.
_HEX_TOKEN_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_LENGTHS = frozenset({32, 40, 56, 64, 96, 128})

# What separates one token from the next in the evidence corpus. A digest is
# found when it stands alone between two of them, never when it is the first
# half of a longer one.
_TOKEN_BOUNDARY_RE = re.compile(r"[0-9a-f]", re.IGNORECASE)


def _comparisons(pattern: str) -> list[tuple[str, str]]:
    """Every ``(object path, quoted literal)`` the pattern compares, in order.

    :func:`~maljan.schemas.stix_pattern.read_comparisons` is the one reader of
    a pattern this repository has; the STIX renderer asks it the same question
    about the same syntax, and two readers of one pattern is how one of them
    publishes what the other vetoes. What is kept here is this caller's own
    filter: a value that is only whitespace is not a value to ask about.
    """
    return [
        (comparison.path, comparison.literal.strip())
        for comparison in read_comparisons(pattern)
        if comparison.literal.strip()
    ]


def reads_as_a_place(value: str) -> bool:
    """Whether this literal is written the way a directory on a machine is.

    The validity half of the directory question, and only that: it removes what
    could not be a place, and says nothing about whether this run saw one. A
    place has a root and at least one named step under it — ``/tmp`` is a
    directory, ``/`` and ``C:\\`` are roots and nothing under them — and every
    step is written the way a name is: not empty, not whitespace, no control
    character, not a format specifier a sample was compiled with, and at least
    one of them carrying two characters running that somebody could have typed.
    A strings table produces ``/%s/%s`` and ``/ /`` by the dozen.
    """
    text = str(value or "")
    root = _DIRECTORY_ROOT_RE.match(text)
    if root is None:
        return False
    steps = [step for step in re.split(r"[\\/]", text[root.end() :]) if step != ""]
    if not steps or text[root.end() :].startswith(("/", "\\")):
        return False
    for step in steps:
        if not step.strip() or _PLACEHOLDER_STEP_RE.match(step):
            return False
        if any(character in _CONTROL_CHARACTERS for character in step):
            return False
    return any(_NAME_RUN_RE.search(step) for step in steps)


def _place_in_the_evidence(
    literal: str, haystack: Haystack, runtime_paths: set[str], own: set[str]
) -> bool:
    """Whether the run recorded this place, however either side spelled it.

    The grounding half. A path is written with whichever separator the writer's
    platform uses and with a trailing one as often as without, so the literal is
    asked under the spellings that mean the same location — the normalisation
    the report's own path rows go through — and each is asked as a whole value
    rather than as a substring.
    """
    from maljan.reporting.dedupe import canonical_path

    lowered = literal.lower()
    spellings = {
        lowered,
        canonical_path(literal).lower(),
        lowered.replace("\\", "/"),
        lowered.replace("/", "\\"),
    }
    spellings |= {spelling.rstrip("/\\") for spelling in spellings if len(spelling) > 1}
    return any(
        spelling in own or spelling in runtime_paths or haystack.holds_value(spelling)
        for spelling in spellings
        if spelling
    )


class Haystack:
    """The evidence a grounding check searches, as the parts it came in.

    Never one joined string. A value never spans two tool answers — joining
    them put a space between them and a space bounds a value — so asking each
    part is exactly the search the joined string performed. Joining was not
    free: on 400 answers of 6 000 characters the run's record was copied on the
    way into the corpus's cache, again as an element of the token set, and a
    third time into the string that was finally searched.

    Everything here is compared lower-cased, which is the corpus's own rule and
    is why the run's answers are folded once, at the moment they are recorded.
    """

    __slots__ = ("parts",)

    def __init__(self, parts: Iterable[str]) -> None:
        self.parts: tuple[str, ...] = tuple(part for part in parts if part)

    def __contains__(self, needle: str) -> bool:
        return any(needle in part for part in self.parts)

    def __bool__(self) -> bool:
        return bool(self.parts)

    def holds_value(self, value: str) -> bool:
        """Whether the evidence holds ``value`` as a value of its own."""
        from maljan.agents._indicator_denylists import whole_value_in

        return any(whole_value_in(value, part) for part in self.parts)

    def holds_token(self, value: str) -> bool:
        """Whether ``value`` stands between two boundaries rather than inside a run."""
        return any(_token_in(value, part) for part in self.parts)


def _token_in(lowered: str, part: str) -> bool:
    """Whether ``lowered`` is a whole token of ``part``."""
    start = part.find(lowered)
    while start != -1:
        before = part[start - 1] if start else ""
        after = part[start + len(lowered) : start + len(lowered) + 1]
        if not _TOKEN_BOUNDARY_RE.match(before or " ") and not _TOKEN_BOUNDARY_RE.match(
            after or " "
        ):
            return True
        start = part.find(lowered, start + 1)
    return False


def _whole_token_in(literal: str, haystack: Haystack, own: set[str]) -> bool:
    """Whether ``literal`` appears in the corpus as a value rather than a prefix."""
    lowered = literal.lower()
    if lowered in own:
        return True
    return haystack.holds_token(lowered)


# What a check that had nothing to search says about what it searched. Not the
# same as a corpus that lost answers — there were none to lose — but the same
# conclusion: an absence measured over nothing is a note, never a reason to
# remove a model's object.
NOTHING_SEARCHED = CorpusState(complete=False, why="no evidence was searched")

# The words every corpus-miss sentence in :func:`_indicator_problem` shares.
# Kept for readers grepping for the phrase; nothing decides anything by it.
ABSENT_FROM_THE_EVIDENCE = "appears nowhere"


class _Problem(str):
    """A refusal sentence, and whether the refusal is an absence.

    A ``str``, so the sentence is still just the sentence everywhere it is
    read. The flag rides on the object rather than in its text because what
    the caveat and the advisory rule key on is *what the check concluded*, and
    keying on the words would let a model-written indicator value carrying the
    phrase attract a caveat it did not earn.
    """

    absent: bool = False


def _an_absence(sentence: str) -> _Problem:
    """A refusal whose whole content is that the evidence does not hold it."""
    found = _Problem(sentence)
    found.absent = True
    return found


def _is_an_absence(problem: str) -> bool:
    """Whether this refusal is "the evidence does not hold it" and nothing else."""
    return bool(getattr(problem, "absent", False))


def shortened_evidence_note(tools: Iterable[str]) -> str:
    """What to add to an absence when part of the evidence searched was shortened.

    A shortened answer is still the answer the model read — the shortener hands
    one string to both the model and the ledger — so "this value is in no tool
    output" stays true and the grounding rule is unchanged. What is not true is
    that the search was over everything the tool found: a shortened document
    handed over fewer rows than the call produced. Naming the tools lets the
    judge ask one of them again with a narrower argument instead of guessing
    whether its value was in the part that did not fit.

    Empty when nothing was shortened, so a clean run's feedback is unchanged.
    """
    named = sorted({str(tool).strip() for tool in tools if str(tool).strip()})
    if not named:
        return ""
    return (
        " The evidence searched includes shortened answers from "
        f"{safe_finding_value(', '.join(named))}: those calls did not fit and were "
        "handed over with rows missing. Narrow one of them and ask again before "
        "withdrawing a value on this."
    )


def partial_evidence_note(state: CorpusState) -> str:
    """What an absence may say when the evidence searched was not the whole run.

    The platform does not assert an absence over evidence it knows is partial.
    When the run's in-memory corpus hit its ceiling, or there is no corpus and
    the stored entries fell back on had been blanked by the byte budget, the
    row says how much was not searched and whose it was — counts and tool
    names only, because a sentence naming a value would put a tool's output
    back into the row the value was withheld from — and says that nothing is
    dropped for it.

    Empty when the corpus was whole, so an ordinary absence reads as it did.
    """
    if state.complete:
        return ""
    if not state.missing_tools:
        # No tool to name — the corpus is gone, or there was never anything to
        # search — so the reason is what the sentence carries instead. One of
        # this module's own words either way, never a producer's.
        return (
            f" The evidence searched is not this run's whole record ({state.why}), so this is a "
            "note rather than a finding and nothing is dropped for it."
        )
    named = safe_finding_value(", ".join(state.missing_tools))
    answers = "answer" if state.missing_answers == 1 else "answers"
    return (
        f" The evidence searched is not this run's whole record: {state.missing_answers} "
        f"{answers} from {named} were not kept. This is a note rather than a finding, and "
        "nothing is dropped for it."
    )


def partial_grounding_reason(state: CorpusState) -> str:
    """One sentence saying grounding was advisory in this run, or ``""``.

    A degradation reason rather than a finding: it is a fact about the run's
    record, not about the sample. It names the remedy — which of the three
    reasons it is — because an operator who set the ceiling and an operator
    whose run was resumed have different things to do about it.
    """
    if state.complete:
        return ""
    reason = state.why or "the evidence searched was not this run's whole record"
    named = f" ({', '.join(state.missing_tools)})" if state.missing_tools else ""
    return (
        f"grounding searched less than this run produced — {reason}: "
        f"{state.missing_answers} answer(s) not kept{named}. "
        "An absence measured against it is recorded as a note and drops nothing."
    )


def _indicator_problem(
    pattern: str, haystack: Haystack, runtime_paths: set[str], identity: Iterable[str] = ()
) -> str:
    """Why this indicator is not grounded, in words the judge can act on, or "".

    The rules are the ones the post-processor used to apply silently, said out
    loud instead: the denylists in ``agents._indicator_denylists`` are what a
    URL host, a compile artefact and a foreign class reference are checked
    against, and here they become the sentence the judge reads rather than a
    log line nobody sees.

    ``identity`` is the sample's own lowercased hashes and file name. A literal
    equal to one of them counts as found wherever the haystack is consulted; a
    literal merely contained in one does not, so neither a slice of the sha256
    nor a value written inside the submitted name passes.
    """
    from maljan.agents._indicator_denylists import (
        COMPILE_ARTIFACT_RE,
        FOREIGN_CLASS_REF_RE,
        HASH_HEX_LENGTHS,
        IOC_FILE_EXTENSIONS,
        IOC_OS_RESOURCE_PREFIXES,
        URL_DENY_HOSTS,
        malformed_hash_in,
    )

    if not pattern.strip():
        return "the indicator has an empty pattern."
    # Raw here, deliberately: these are what the denylists and the corpus are
    # matched against, and a scrubbed path would answer a different question
    # from the one this check asks. The sentence they end up in is what the
    # caller wraps, because that is what is stored and shown.
    comparisons = _comparisons(pattern)
    literals = [literal for _path, literal in comparisons]
    if not literals:
        return "the indicator pattern quotes no value."
    own = set(identity)

    def _found(literal: str) -> bool:
        return literal.lower() in haystack or literal.lower() in own

    # A hash literal answers to its algorithm before it answers to the corpus.
    # Sixteen of the thirty-two characters of an MD5 are a prefix of one, and a
    # substring search over the evidence finds a prefix every time — one run
    # exported ``32066ff6369a7bd7`` as an indicator no consumer matching on MD5
    # can ever match. The length question is asked first because a truncated
    # digest is not "present in the evidence" whatever the haystack says.
    malformed = malformed_hash_in(pattern)
    if malformed is not None:
        algorithm, literal = malformed
        named = safe_finding_value(algorithm)
        expected = HASH_HEX_LENGTHS.get(algorithm)
        return (
            f"{safe_finding_value(literal)!r} is not a {named} digest: "
            f"{named} is {expected} hexadecimal characters."
        )

    # Every comparison in the pattern, asked in turn, and each check below is a
    # veto rather than an acceptance. A pattern is not one comparison —
    # ``[a] AND [b]``, an ``IN`` list, a compound the judge writes — and these
    # branches used to key on what the *pattern* started with, so a URL beside
    # a hash was never asked the denylist question and a grounded digest
    # answered for the whole expression. What one comparison establishes is
    # that *it* raised no problem; the others are still asked.
    grounded = False
    for path, literal in comparisons:
        if path.startswith("file:hashes") or path.endswith("imphash"):
            if _HEX_TOKEN_RE.match(literal) and len(literal) in _DIGEST_LENGTHS:
                if not _whole_token_in(literal, haystack, own):
                    return _an_absence(
                        f"the indicator pattern names {safe_finding_value(literal)}, which "
                        "appears nowhere in the evidence this run collected as a value of its "
                        "own."
                    )
                grounded = True
                continue
            # A fuzzy hash is not a run of hex and has no length this code
            # knows — an ssdeep carries block sizes and slashes, a TLSH opens
            # with its version — so the prefix question the whole-token rule
            # answers does not arise for it. It is asked the corpus question
            # every other value is asked, and skipping it told a judge that the
            # ssdeep the ``hashes`` tool had just reported "appears nowhere in
            # the evidence", spent the one retry on that and dropped the
            # object.
            grounded = grounded or _found(literal)
            continue
        if path.startswith("url:"):
            host = _url_host(literal)
            if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
                return (
                    f"the URL host in {safe_finding_value(literal)!r} is documentation or "
                    "vendor infrastructure."
                )
            if not _found(literal):
                return _an_absence(
                    f"the URL {safe_finding_value(literal)!r} appears nowhere in this run's "
                    "evidence."
                )
            grounded = True
            continue
        if path.startswith("file:name") or path.startswith("directory:path"):
            if COMPILE_ARTIFACT_RE.search(literal):
                return (
                    f"{safe_finding_value(literal)!r} is a compiler or toolchain artefact, "
                    "not an indicator."
                )
            if FOREIGN_CLASS_REF_RE.match(literal):
                return (
                    f"{safe_finding_value(literal)!r} is a class reference from a library, "
                    "not a file on disk."
                )
            lowered = literal.lower()
            anchored = (
                any(literal.startswith(prefix) for prefix in IOC_OS_RESOURCE_PREFIXES)
                or lowered in runtime_paths
                or lowered in own
            )
            if path.startswith("directory:path"):
                # Two questions, and a directory is asked both. A directory has
                # no extension to answer the first with, and telling the judge
                # its own row "has no file extension … so nothing says it is a
                # real path" was untrue of the thing it had written.
                if not reads_as_a_place(literal):
                    return (
                        f"{safe_finding_value(literal)!r} is not written as a directory: a "
                        "path on this machine has a root — a drive, a share, a POSIX slash, "
                        "an environment variable or a registry hive — and at least one named "
                        "step under it."
                    )
                if not _place_in_the_evidence(literal, haystack, runtime_paths, own):
                    return _an_absence(
                        f"{safe_finding_value(literal)!r} appears nowhere in the evidence "
                        "this run collected as a value of its own."
                    )
                grounded = True
                continue
            if not (anchored or any(lowered.endswith(ext) for ext in IOC_FILE_EXTENSIONS)):
                return (
                    f"{safe_finding_value(literal)!r} has no file extension, no filesystem "
                    "anchor and was not "
                    "observed at runtime, so nothing says it is a real path."
                )
            grounded = True
            continue
        # A digest-shaped literal under a path this does not model is still a
        # digest: it is asked as a whole token wherever it is written.
        if _HEX_TOKEN_RE.match(literal) and len(literal) in _DIGEST_LENGTHS:
            if not _whole_token_in(literal, haystack, own):
                return (
                    f"the indicator pattern names {safe_finding_value(literal)}, which appears "
                    "nowhere in the evidence this run collected as a value of its own."
                )
            grounded = True
            continue
        grounded = grounded or _found(literal)

    # One comparison is enough to ground the pattern. ``[file:hashes.'SHA-256'
    # = '<hex>']`` quotes the hash algorithm as well as the hash, and requiring
    # every quoted string to appear in the corpus would reject the digest for
    # the company it keeps.
    if grounded:
        return ""
    return _an_absence(
        f"the indicator pattern names {safe_finding_value(', '.join(literals))}, which "
        "appears nowhere "
        "in the evidence this run collected."
    )


def _url_host(raw_url: str) -> str | None:
    """Best-effort host extraction without a full URL parser."""
    from urllib.parse import urlparse

    try:
        return (urlparse(raw_url).hostname or "").lower() or None
    except (ValueError, TypeError):
        return None


# The ``source_name`` values that mean "this external_id is an ATT&CK id".
# Only these are read: an attack-pattern may legitimately carry a Sigma rule id
# or a CVE first in its reference list, and holding the judge to the ATT&CK
# vocabulary for one of those would burn the single retry on nothing.
_MITRE_SOURCES = frozenset({"mitre-attack", "mitre attack"})


def _attack_pattern_technique_id(obj: Any) -> str:
    """The ATT&CK id an attack-pattern declares, from its MITRE ref or its name."""
    for ref in getattr(obj, "external_references", None) or []:
        if not isinstance(ref, dict):
            continue
        if str(ref.get("source_name") or "").strip().lower() not in _MITRE_SOURCES:
            continue
        external_id = ref.get("external_id")
        if external_id:
            return str(external_id).strip().upper()
    name = str(getattr(obj, "name", "") or "").strip().upper()
    first = name.split()[0].rstrip(":") if name else ""
    return first if first.startswith("T") else ""


def drop_ungrounded_indicators(bundle: Any, violations: Sequence[Violation]) -> int:
    """Remove the indicators still ungrounded after the retry; return how many.

    An unresolved technique id can stay on a claim and be labelled; an
    unresolved indicator cannot stay in a STIX bundle, because a bundle is
    consumed by detection tooling that has no way to read a label. It is
    dropped here and recorded in ``run_summary.validation.unresolved``, so the
    false positive is visible as a run fact rather than as a blocking rule.

    An **advisory** row drops nothing. The platform states an absence only over
    evidence it searched whole; when it could not, the judge is told so and
    keeps its object.
    """
    indices = {
        index
        for index in (
            _object_index(v.path)
            for v in violations
            # Never on an advisory row. An advisory absence is one the platform
            # measured against evidence it knows is partial, and dropping the
            # judge's object over it is exactly the wrong statement made
            # expensive: the value may well be in the part that was not kept.
            if v.code == "stix.ungrounded_indicator" and not v.advisory
        )
        if index is not None
    }
    if not indices:
        return 0
    objects = list(getattr(bundle, "objects", None) or [])
    kept = [obj for index, obj in enumerate(objects) if index not in indices]
    dropped = len(objects) - len(kept)
    if dropped:
        bundle.objects = kept
        logger.warning("validation: dropped %d ungrounded indicator(s) from the bundle.", dropped)
    return dropped


def _object_index(path: str) -> int | None:
    match = re.search(r"objects\[(\d+)\]", path or "")
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# The retry loop
# ---------------------------------------------------------------------------


def _collect(parsed: Any, validators: Sequence[Validator]) -> list[Violation]:
    found: list[Violation] = []
    for validator in validators:
        try:
            found.extend(validator(parsed) or [])
        except Exception as exc:  # noqa: BLE001 — a broken validator must not fail a run
            logger.warning("validation: a validator raised (%s); its findings are skipped.", exc)
    return found


def _with_feedback(messages: list[Any], answer: Any, violations: Sequence[Violation]) -> list[Any]:
    """The conversation plus the model's answer plus the correction turn."""
    from langchain_core.messages import AIMessage, HumanMessage

    content = getattr(answer, "content", None)
    turns = list(messages)
    turns.append(AIMessage(content=str(content if content is not None else answer)))
    turns.append(HumanMessage(content=feedback_text(violations)))
    return turns


def _announce_feedback(
    violations: Sequence[Violation],
    on_feedback: Callable[[Sequence[Violation]], None] | None,
    feed: _FeedbackFeed | None = None,
    retry_index: int = 0,
) -> None:
    """Log the correction turn, publish it, and hand it to the run's tally."""
    logger.info(
        "validation: retrying after %d violation(s): %s.",
        len(violations),
        ", ".join(sorted({v.code for v in violations})),
    )
    if feed is not None:
        feed.announce(violations, retry_index)
    if on_feedback is None:
        return
    try:
        on_feedback(violations)
    except Exception as exc:  # noqa: BLE001 — a metric is never worth a lost run
        logger.debug("validation: the feedback tally was not updated (%s).", exc)


class _FeedbackFeed:
    """Who is being corrected and where to say so, for one retry loop.

    A tuple of three arguments repeated across two nearly identical loops and
    their four call sites is a tuple somebody eventually passes in the wrong
    order. The producer names itself once and the loops carry one object.
    """

    def __init__(self, sink: EventSink | None, agent: str, stage: str) -> None:
        self.sink = sink
        self.agent = str(agent)
        self.stage = str(stage)

    def announce(self, violations: Sequence[Violation], retry_index: int) -> None:
        for violation in violations:
            self._emit(violation, retry_index, VALIDATION_RETRIED)

    def outcome(
        self,
        shown: Sequence[Violation],
        remaining: Sequence[Violation],
        retry_index: int,
    ) -> None:
        """What became of every violation this loop saw.

        One line per violation, and the ones that were never fed back are here
        too: a retry introduces violations of its own, and a reader of the
        conversation used to see only the batch that triggered the retry —
        two lines beside a run whose summary recorded ten unresolved findings.
        """
        left = {(v.code, v.path) for v in remaining}
        seen: set[tuple[str, str]] = set()
        for violation in shown:
            key = (violation.code, violation.path)
            if key in left or key in seen:
                continue
            seen.add(key)
            self._emit(violation, retry_index, VALIDATION_RESOLVED)
        for violation in remaining:
            self._emit(violation, retry_index, VALIDATION_SURVIVED)

    def _emit(self, violation: Violation, retry_index: int, state: str) -> None:
        emit_validation_feedback(
            self.sink,
            stage=self.stage,
            agent=self.agent,
            code=str(violation.code),
            message=str(violation.message),
            retry_index=retry_index,
            state=state,
            # The producer's own locator, so the two lines about one violation
            # fold together and two violations of one code on different claims
            # do not.
            path=str(violation.path),
        )


def announce_unresolved(
    sink: EventSink | None,
    *,
    agent: str,
    stage: str,
    violations: Sequence[Violation],
    retry_index: int = 0,
) -> None:
    """Publish findings nobody was shown, as findings that survived.

    For a producer that records a violation outside the retry loop — the judge
    appends the timeout, the fallback and its two verdict checks after it —
    where the run summary carried a row the conversation never showed.
    """
    feed = _feed(sink, agent, stage)
    if feed is not None and violations:
        feed.outcome([], violations, retry_index)


def announce_resolved(
    sink: EventSink | None,
    *,
    agent: str,
    stage: str,
    violations: Sequence[Violation],
    retry_index: int = 0,
) -> None:
    """Publish findings the pipeline settled itself, as findings that are settled.

    For an act this pipeline is allowed to perform without asking — moving the
    judge's own assessment block to the property the schema reads it from,
    unchanged. Nobody is corrected and no turn is spent, and the line says so
    rather than leaving a reader to find out from a bundle that parsed.
    """
    feed = _feed(sink, agent, stage)
    if feed is not None and violations:
        feed.outcome(violations, [], retry_index)


def _feed(sink: EventSink | None, agent: str, stage: str) -> _FeedbackFeed | None:
    """The feed for a caller that named a sink, or nothing for one that did not.

    A loop run from the CLI, a test or the report composer has nobody to tell,
    and an object that emits into ``None`` on every violation is cheaper to
    skip than to build.
    """
    return _FeedbackFeed(sink, agent, stage) if sink is not None else None


async def retry_with_feedback[T](
    run: Callable[[list[Any]], Awaitable[Any]],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
    on_feedback: Callable[[Sequence[Violation]], None] | None = None,
    sink: EventSink | None = None,
    agent: str = "",
    stage: str = "",
) -> tuple[T, list[Violation], int]:
    """Run, validate, and give the model one chance to fix what it got wrong.

    Returns the last answer, whatever is still wrong with it, and how many
    retries were spent. Remaining violations are returned rather than raised:
    the caller decides whether an unresolved finding is a label on a claim or a
    dropped object, and neither of those is this function's call to make.

    ``on_feedback`` is handed every violation the producer is shown, before it
    is shown. A violation the retry fixes leaves no other trace, and a run
    summary that counts only the leftovers cannot say what the retry was for
    — :class:`ValidationTally` is what the callers pass.

    ``sink``, ``agent`` and ``stage`` put the same correction into the live
    conversation, as one ``validation_feedback`` per violation — ``retried``
    where the producer is shown it, then ``resolved`` or ``survived`` once this
    loop knows which, including for the violations the retry itself introduced.
    A caller with nobody to tell — the CLI, a test, the report composer —
    passes no sink and nothing is emitted.
    """
    feed = _feed(sink, agent, stage)
    turns = list(messages)
    answer = await run(turns)
    parsed = parse(answer)
    violations = _collect(parsed, validators)
    retries = 0
    shown: list[Violation] = []
    while violations and retries < max_retries:
        _announce_feedback(violations, on_feedback, feed, retries + 1)
        shown.extend(violations)
        turns = _with_feedback(turns, answer, violations)
        retries += 1
        answer = await run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    if feed is not None:
        feed.outcome(shown, violations, retries)
    return parsed, violations, retries


def retry_with_feedback_sync[T](
    run: Callable[[list[Any]], Any],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
    on_feedback: Callable[[Sequence[Violation]], None] | None = None,
    sink: EventSink | None = None,
    agent: str = "",
    stage: str = "",
) -> tuple[T, list[Violation], int]:
    """:func:`retry_with_feedback` for the analysts, whose loop is synchronous.

    The analyst tool loop is sync all the way down (``execute_tool_loop`` bridges
    to the shared agent loop itself), so an async-only helper would force every
    analyst call site through a second bridge for no gain. The two functions
    share the feedback turn and the collection rule and differ only in the await.
    """
    feed = _feed(sink, agent, stage)
    turns = list(messages)
    answer = run(turns)
    parsed = parse(answer)
    violations = _collect(parsed, validators)
    retries = 0
    shown: list[Violation] = []
    while violations and retries < max_retries:
        _announce_feedback(violations, on_feedback, feed, retries + 1)
        shown.extend(violations)
        turns = _with_feedback(turns, answer, violations)
        retries += 1
        answer = run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    if feed is not None:
        feed.outcome(shown, violations, retries)
    return parsed, violations, retries


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def validation_metrics(
    retries: int,
    unresolved: Sequence[tuple[str, Violation]],
    fed_back: Mapping[str, int] | None = None,
    not_run: Sequence[str] | None = None,
) -> dict[str, Any]:
    """``run_summary.validation`` from the run's retries, corrections and leftovers.

    ``fed_back`` is what the producers were told, by code (see
    :class:`ValidationTally`). It is added to the leftovers rather than
    replacing them: a code that was fed back once and never fixed is two
    facts about the run, and ``by_code`` is the count of both. ``not_run``
    names the checks that could not run at all — the validity check on a box
    with no catalogue — which is a different fact from a check that ran and
    found nothing.
    """
    by_code: dict[str, int] = {code: int(count) for code, count in (fed_back or {}).items()}
    rows: list[dict[str, str]] = []
    for agent, violation in unresolved:
        by_code[violation.code] = by_code.get(violation.code, 0) + 1
        rows.append(
            {
                "agent": agent,
                "code": violation.code,
                "message": violation.message,
                # The second place a row is rebuilt for the record. A row the
                # platform declined to act on, stored without the flag, reads
                # downstream as a producer's own unfixed finding.
                **({"advisory": "true"} if violation.advisory else {}),
            }
        )
    return {
        "retries": int(retries),
        "by_code": dict(sorted(by_code.items())),
        "unresolved": rows,
        "not_run": sorted({str(code) for code in (not_run or []) if str(code).strip()}),
    }


# What the deterministic sources are called in a corroboration row. The
# tools that carry their own ATT&CK ids: capa's ``attck`` field, a Sigma rule's
# tags, a YARA TTP rule's ``meta.technique_id``, ``lolbin_lookup``'s technique
# id.
# A tool this table does not name is listed under its own name.
ASSERTING_SOURCES: dict[str, str] = {
    "capa": "capa",
    "sigma_match": "sigma",
    "sigma_match_sandbox": "sigma",
    "lolbin_lookup": "lolbin",
    # Our own YARA TTP rules carry ``meta.technique_id``; a match asserts it.
    "yara_scan": "yara",
}
# ``api_capability`` is deliberately absent: the API catalogue associates a
# technique with an import set, it does not observe one. Its associations
# travel under ``associated_by`` and never count as a source.


def corroboration(
    isrs: dict[str, Any] | None, ledger: Sequence[Any] | None
) -> dict[str, dict[str, Any]]:
    """Per technique id, who asserted it and who claimed it, by name.

    ``asserted_by`` is the deterministic sources that carry their own ATT&CK
    ids — a rule that fired names its technique — and ``claimed_by`` is the
    agents. Two flat lists, no weights, no score: the number that used to
    live here was a weighted sum over layer weights and cross-layer
    multipliers, and its inputs were constants nobody could derive from
    anything. Two agents and a capa rule naming ``T1055`` is a fact; 0.87 was
    an opinion with a decimal point. A technique nothing asserted is not
    penalised anywhere; the reader sees the empty list.

    The same collection feeds the judge's evidence-summary block, so the metric
    the report carries and the block the judge read cannot disagree.
    """
    from maljan.pipeline.evidence_summary import catalogue_associations, collect

    agents = {str(getattr(isr, "agent_id", "") or name) for name, isr in (isrs or {}).items()}
    associations = catalogue_associations(ledger)
    out: dict[str, dict[str, list[str]]] = {}
    collected = collect(isrs, ledger)
    for tid in associations:
        collected.setdefault(tid, [])
    for tid, sources in sorted(collected.items()):
        asserted: list[str] = []
        claimed: list[str] = []
        for source, _confidence in sources:
            if source in agents:
                if source not in claimed:
                    claimed.append(source)
            else:
                label = ASSERTING_SOURCES.get(source, source)
                if label not in asserted:
                    asserted.append(label)
        row: dict[str, Any] = {"asserted_by": sorted(asserted), "claimed_by": sorted(claimed)}
        if tid in associations:
            row["associated_by"] = list(associations[tid])
        # Upstream Sigma rules and the case corpus still name ids the
        # catalogue retired; the row says so, the way the validity message does.
        retired = _retired_release(tid)
        if retired:
            row["retired_in"] = retired
        out[tid] = row
    return out


def _retired_release(technique_id: str) -> str | None:
    try:
        from maljan.memory.attck_loader import retired_in

        return retired_in(technique_id)
    except Exception:  # noqa: BLE001 — a note, not a check
        return None


UNSUPPORTED_MALWARE_CODE = "verdict.unsupported_malware"


def unsupported_malware_violations(
    bundle: Any, *, analyst_claims: int, ledger_ids: Sequence[str] | None = None
) -> list[Violation]:
    """Whether a Malware verdict on a run with no analysis cites anything.

    The mirror of ``unsupported_benign_violations``, and for the same reason:
    a verdict is a finding. Malware over zero analyst claims can stand on the
    run's own record — a reputation entry, a rule hit, a signature the pack
    established — and the bundle then cites that entry; or it gives way to
    Suspicious with a rationale that says the run was inconclusive. Which of
    the two stays the judge's call. This asks once and records what survives,
    and it grades nothing: any cited entry from this run clears it.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    if analyst_claims > 0 or decide_from_bundle(bundle) != "Malware":
        return []
    known = {str(entry).strip().lower() for entry in (ledger_ids or []) if str(entry).strip()}
    if not known:
        return []
    try:
        text = json.dumps(bundle.model_dump(mode="json"), default=str)
    except Exception as exc:  # noqa: BLE001 — an unreadable bundle cites nothing
        logger.debug("validation: the bundle could not be read for citations (%s).", exc)
        text = ""
    if entry_ids_in(text) & known:
        return []
    listed = ", ".join(sorted(known)[:3])
    return [
        Violation(
            code=UNSUPPORTED_MALWARE_CODE,
            message=(
                "This verdict is Malware and no analyst made a single claim about the "
                "sample, so nothing examined it. Malware is a finding and needs evidence: "
                "cite the ledger entries that establish it — a reputation entry, a YARA or "
                "capa hit, a Sigma match — or return Suspicious and say in the rationale "
                f"that the run was inconclusive. The entries this run recorded include {listed}."
            ),
            path="objects",
        )
    ]
