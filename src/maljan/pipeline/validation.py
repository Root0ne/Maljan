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

from pydantic import ValidationError

from maljan.core.logger import logger
from maljan.schemas.judgement import SEVERITY_RATINGS

# How many alternatives a suggestion list carries. Three is what fits in one
# line of feedback; a longer list reads as a menu and the model picks from the
# middle of it.
MAX_SUGGESTIONS = 3

# How many schema complaints one feedback turn carries. A model that answered
# with the wrong shape produces one error per field, and a wall of them reads
# as noise rather than as a correction.
MAX_SCHEMA_VIOLATIONS = 6

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
    """Whether the id is a real technique. A lookup that fails is not a verdict.

    ``attck_validate`` is the cheap question: it answers from the vendored id
    universe and only touches the fifty-megabyte catalogue once an id has
    already failed. That is what lets this run inside every analyst's loop
    rather than once per job.
    """
    check = getattr(attck, "attck_validate", None)
    if check is not None:
        try:
            answer = check([technique_id])
        except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
            logger.debug("validation: the ATT&CK check for %s failed (%s).", technique_id, exc)
            return True
        return not (answer or {}).get("invalid")

    lookup = getattr(attck, "attck_lookup", None)
    if lookup is None:
        return True
    try:
        answer = lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — a knowledge failure is not a violation
        logger.debug("validation: the ATT&CK lookup for %s failed (%s).", technique_id, exc)
        return True
    return not isinstance(answer, dict) or bool(answer.get("valid"))


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
                message=str(error.get("msg") or "is not valid"),
                path=".".join(str(part) for part in error.get("loc") or ()),
            )
            for error in exc.errors()
        ][:MAX_SCHEMA_VIOLATIONS]
    except Exception as exc:  # noqa: BLE001 — a coercion failure is still a finding
        return [Violation(code=code, message=str(exc))]
    return []


# ---------------------------------------------------------------------------
# The judge's bundle
# ---------------------------------------------------------------------------


def validate_verdict_bundle(
    bundle: Any, evidence_corpus: set[str] | None = None, *, attck: Any = None
) -> list[Violation]:
    """What is wrong with the judge's answer, in the judge's own terms.

    ``attck`` is the same knowledge module the analyst loop consults, and it is
    the same check: an id is unresolvable when the catalogue does not have it,
    not when it fails a regex. ``T7777`` is well-formed and imaginary, which is
    exactly the case this violation exists for. Passing ``None`` skips the
    catalogue question rather than answering it wrongly.
    """
    violations: list[Violation] = []
    objects = list(getattr(bundle, "objects", None) or [])

    haystack = " ".join(sorted(evidence_corpus)).lower() if evidence_corpus else ""
    runtime_paths = _runtime_paths(evidence_corpus)
    for index, obj in enumerate(objects):
        kind = str(getattr(obj, "type", "") or "")
        if kind == "indicator" and evidence_corpus is not None:
            pattern = str(getattr(obj, "pattern", "") or "")
            problem = _indicator_problem(pattern, haystack, runtime_paths)
            if problem:
                violations.append(
                    Violation(
                        code="stix.ungrounded_indicator",
                        message=(
                            f"{problem} Emit indicators only for values a tool in this run "
                            "actually saw, and prefer zero indicators to an invented one."
                        ),
                        path=f"objects[{index}]",
                    )
                )
        elif kind == "attack-pattern":
            tid = _attack_pattern_technique_id(obj)
            if not tid:
                continue
            if not _TID_RE.match(tid):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {tid}, which is not shaped like a "
                            "MITRE ATT&CK technique id (T#### or T####.###)."
                        ),
                        path=f"objects[{index}]",
                    )
                )
            elif attck is not None and not _technique_is_known(tid, attck):
                violations.append(
                    Violation(
                        code="stix.unknown_technique",
                        message=(
                            f"the attack-pattern names {tid}, which the MITRE ATT&CK "
                            "catalogue has no entry for in any domain. Use a real "
                            "technique id or drop the attack-pattern."
                        ),
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
                    f"severity.rating is {rating!r}; it must be one of "
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
                        f"family {family.name!r} cites no evidence ids; list "
                        "the ledger entries the name came from, or drop the attribution."
                    ),
                    path="family.evidence_ids",
                )
            )

    return violations


def _runtime_paths(evidence_corpus: set[str] | None) -> set[str]:
    """The corpus entries that look like a path something really touched."""
    from maljan.agents._indicator_denylists import IOC_OS_RESOURCE_PREFIXES

    found: set[str] = set()
    for token in evidence_corpus or ():
        value = str(token).strip()
        if any(value.startswith(prefix.lower()) for prefix in IOC_OS_RESOURCE_PREFIXES):
            found.add(value)
    return found


def _indicator_problem(pattern: str, haystack: str, runtime_paths: set[str]) -> str:
    """Why this indicator is not grounded, in words the judge can act on, or "".

    The rules are the ones the post-processor used to apply silently, said out
    loud instead: the denylists in ``agents._indicator_denylists`` are what a
    URL host, a compile artefact and a foreign class reference are checked
    against, and here they become the sentence the judge reads rather than a
    log line nobody sees.
    """
    from maljan.agents._indicator_denylists import (
        COMPILE_ARTIFACT_RE,
        FOREIGN_CLASS_REF_RE,
        IOC_FILE_EXTENSIONS,
        IOC_OS_RESOURCE_PREFIXES,
        URL_DENY_HOSTS,
    )

    if not pattern.strip():
        return "the indicator has an empty pattern."
    literals = [str(v).strip() for v in _PATTERN_LITERAL_RE.findall(pattern) if str(v).strip()]
    if not literals:
        return "the indicator pattern quotes no value."
    stripped = pattern.lstrip()

    if stripped.startswith("[url:value"):
        for literal in literals:
            host = _url_host(literal)
            if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
                return f"the URL host in {literal!r} is documentation or vendor infrastructure."
        if not any(literal.lower() in haystack for literal in literals):
            return f"the URL {literals[0]!r} appears nowhere in this run's evidence."
        return ""

    if stripped.startswith("[file:name"):
        for literal in literals:
            if COMPILE_ARTIFACT_RE.search(literal):
                return f"{literal!r} is a compiler or toolchain artefact, not an indicator."
            if FOREIGN_CLASS_REF_RE.match(literal):
                return f"{literal!r} is a class reference from a library, not a file on disk."
        for literal in literals:
            lowered = literal.lower()
            if (
                any(lowered.endswith(ext) for ext in IOC_FILE_EXTENSIONS)
                or any(literal.startswith(prefix) for prefix in IOC_OS_RESOURCE_PREFIXES)
                or lowered in runtime_paths
            ):
                return ""
        return (
            f"{literals[0]!r} has no file extension, no filesystem anchor and was not "
            "observed at runtime, so nothing says it is a real path."
        )

    # One literal is enough. A pattern like ``[file:hashes.'SHA-256' = '<hex>']``
    # quotes the hash algorithm as well as the hash, and requiring every quoted
    # string to appear in the corpus would reject the digest for the company it
    # keeps.
    if any(literal.lower() in haystack for literal in literals):
        return ""
    return (
        f"the indicator pattern names {', '.join(literals)}, which appears nowhere "
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
