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

import re
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.core.logger import logger

# How many alternatives a suggestion list carries. Three is what fits in one
# line of feedback; a longer list reads as a menu and the model picks from the
# middle of it.
MAX_SUGGESTIONS = 3

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# The literals a STIX pattern quotes, e.g. ``[file:name = 'x.exe']`` -> ``x.exe``.
_PATTERN_LITERAL_RE = re.compile(r"'([^']*)'")

# The sentence the retry turn opens with. A constant because two call sites
# send it and a test reads it.
FEEDBACK_PREAMBLE = "Your previous answer had these problems:"
FEEDBACK_CLOSING = "Fix them and answer again in the same format."


@dataclass(frozen=True)
class Violation:
    """One thing wrong with an answer, in the words the producer will read."""

    code: str
    message: str
    path: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "path": self.path}


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


def validate_isr(isr: Any, *, attck: Any = None) -> list[Violation]:
    """What is wrong with one analyst's structured answer.

    ``attck`` is the knowledge module the technique ids are checked against —
    ``maljan.tools.knowledge`` in production, a stub in a test that must not
    load a fifty-megabyte bundle. Passing ``None`` skips the catalogue check
    rather than failing it: a box that cannot read ATT&CK has a thinner report,
    not a run full of invented violations.
    """
    violations: list[Violation] = []
    claims = list(getattr(isr, "claims", None) or [])
    agent = str(getattr(isr, "agent_id", "") or "")

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
                        f"CONFIDENCE is {confidence!r}; it must be a number between 0.0 and 1.0."
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
        if not tid or attck is None:
            continue
        if _technique_is_known(tid, attck):
            continue
        suggestions = _suggest_techniques(str(getattr(claim, "claim", "") or ""), attck)
        hint = f" The closest real techniques are {', '.join(suggestions)}." if suggestions else ""
        violations.append(
            Violation(
                code="attck.unknown_id",
                message=(
                    f"TECHNIQUE {tid} is not in the MITRE ATT&CK catalogue.{hint} "
                    "Use one of them, or omit the technique id."
                ),
                path=path,
            )
        )

    return violations


def _technique_is_known(technique_id: str, attck: Any) -> bool:
    """Whether the catalogue has this id. A lookup that fails is not a verdict."""
    lookup = getattr(attck, "attck_lookup", None)
    if lookup is None:
        return True
    try:
        answer = lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
        logger.debug("validation: the ATT&CK lookup for %s failed (%s).", technique_id, exc)
        return True
    if not isinstance(answer, dict):
        return True
    # An id the catalogue could not be consulted about is not an invalid id.
    if answer.get("reason") and not answer.get("name"):
        return bool(answer.get("valid"))
    return bool(answer.get("valid"))


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
# The judge's bundle
# ---------------------------------------------------------------------------

_SEVERITY_RATINGS = ("Critical", "High", "Medium", "Low", "Informational")


def validate_verdict_bundle(
    bundle: Any, evidence_corpus: set[str] | None = None
) -> list[Violation]:
    """What is wrong with the judge's answer, in the judge's own terms."""
    violations: list[Violation] = []
    objects = list(getattr(bundle, "objects", None) or [])

    haystack = " ".join(sorted(evidence_corpus)).lower() if evidence_corpus else ""
    for index, obj in enumerate(objects):
        kind = str(getattr(obj, "type", "") or "")
        if kind == "indicator" and evidence_corpus is not None:
            ungrounded = _ungrounded_literals(str(getattr(obj, "pattern", "") or ""), haystack)
            if ungrounded:
                violations.append(
                    Violation(
                        code="stix.ungrounded_indicator",
                        message=(
                            f"the indicator pattern names {', '.join(ungrounded)}, which "
                            "appears nowhere in the evidence this run collected. Emit "
                            "indicators only for values a tool actually saw, and prefer "
                            "zero indicators to an invented one. Compiler artefacts, "
                            "example domains and the analyst's own scratch paths are "
                            "not evidence."
                        ),
                        path=f"objects[{index}]",
                    )
                )
        elif kind == "attack-pattern":
            tid = _attack_pattern_technique_id(obj)
            if tid and not _TID_RE.match(tid):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {tid}, which is not a MITRE "
                            "ATT&CK technique id (T#### or T####.###)."
                        ),
                        path=f"objects[{index}]",
                    )
                )

    assessment = getattr(bundle, "x_maljan_assessment", None)
    severity = getattr(assessment, "severity", None) if assessment is not None else None
    rating = str(getattr(severity, "rating", "") or "") if severity is not None else ""
    if rating and rating not in _SEVERITY_RATINGS:
        violations.append(
            Violation(
                code="verdict.severity_enum",
                message=(
                    f"severity.rating is {rating!r}; it must be one of "
                    f"{', '.join(_SEVERITY_RATINGS)}."
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
                        f"family {family.name!r} cites no evidence ids; list "
                        "the ledger entries the name came from, or drop the attribution."
                    ),
                    path="family.evidence_ids",
                )
            )

    return violations


def _ungrounded_literals(pattern: str, haystack: str) -> list[str]:
    """The literals of a STIX pattern that the evidence corpus never mentions."""
    if not pattern:
        return []
    missing: list[str] = []
    for literal in _PATTERN_LITERAL_RE.findall(pattern):
        value = str(literal).strip()
        if not value:
            continue
        if value.lower() in haystack:
            continue
        if value not in missing:
            missing.append(value)
    return missing


def _attack_pattern_technique_id(obj: Any) -> str:
    """The technique id an attack-pattern declares, from refs or from its name."""
    for ref in getattr(obj, "external_references", None) or []:
        external_id = (ref or {}).get("external_id") if isinstance(ref, dict) else None
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
    """
    indices = {
        index
        for index in (
            _object_index(v.path) for v in violations if v.code == "stix.ungrounded_indicator"
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


async def retry_with_feedback[T](
    run: Callable[[list[Any]], Awaitable[Any]],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
) -> tuple[T, list[Violation], int]:
    """Run, validate, and give the model one chance to fix what it got wrong.

    Returns the last answer, whatever is still wrong with it, and how many
    retries were spent. Remaining violations are returned rather than raised:
    the caller decides whether an unresolved finding is a label on a claim or a
    dropped object, and neither of those is this function's call to make.
    """
    turns = list(messages)
    answer = await run(turns)
    parsed = parse(answer)
    violations = _collect(parsed, validators)
    retries = 0
    while violations and retries < max_retries:
        logger.info(
            "validation: retrying after %d violation(s): %s.",
            len(violations),
            ", ".join(sorted({v.code for v in violations})),
        )
        turns = _with_feedback(turns, answer, violations)
        retries += 1
        answer = await run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    return parsed, violations, retries


def retry_with_feedback_sync[T](
    run: Callable[[list[Any]], Any],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
) -> tuple[T, list[Violation], int]:
    """:func:`retry_with_feedback` for the analysts, whose loop is synchronous.

    The analyst tool loop is sync all the way down (``execute_tool_loop`` bridges
    to the shared agent loop itself), so an async-only helper would force every
    analyst call site through a second bridge for no gain. The two functions
    share the feedback turn and the collection rule and differ only in the await.
    """
    turns = list(messages)
    answer = run(turns)
    parsed = parse(answer)
    violations = _collect(parsed, validators)
    retries = 0
    while violations and retries < max_retries:
        logger.info(
            "validation: retrying after %d violation(s): %s.",
            len(violations),
            ", ".join(sorted({v.code for v in violations})),
        )
        turns = _with_feedback(turns, answer, violations)
        retries += 1
        answer = run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    return parsed, violations, retries


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def validation_metrics(retries: int, unresolved: Sequence[tuple[str, Violation]]) -> dict[str, Any]:
    """``run_summary.validation`` from the run's retries and leftovers."""
    by_code: dict[str, int] = {}
    rows: list[dict[str, str]] = []
    for agent, violation in unresolved:
        by_code[violation.code] = by_code.get(violation.code, 0) + 1
        rows.append({"agent": agent, "code": violation.code, "message": violation.message})
    return {
        "retries": int(retries),
        "by_code": dict(sorted(by_code.items())),
        "unresolved": rows,
    }


def corroboration(
    isrs: dict[str, Any] | None, ledger: Sequence[Any] | None
) -> dict[str, list[str]]:
    """Which sources cite each technique id, by name.

    A count of distinct sources, not a combined confidence. The number that
    used to live here was a weighted sum over layer weights and cross-layer
    multipliers, and its inputs were constants nobody could derive from
    anything. Two agents and a capa rule naming ``T1055`` is a fact; 0.87 was
    an opinion with a decimal point.

    The same collection feeds the judge's evidence-summary block, so the metric
    the report carries and the block the judge read cannot disagree.
    """
    from maljan.pipeline.evidence_summary import collect

    return {
        tid: sorted(source for source, _confidence in sources)
        for tid, sources in sorted(collect(isrs, ledger).items())
    }
