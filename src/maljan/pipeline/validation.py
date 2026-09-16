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
from typing import Any

from pydantic import ValidationError

from maljan.core.logger import logger
from maljan.schemas.evidence import entry_ids_in
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
        """Keep what survived the retry, as a row naming who was told."""
        self.unresolved.extend(
            {"agent": producer, "code": v.code, "message": v.message} for v in violations
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
    isr: Any, *, attck: Any = None, ledger_ids: Sequence[str] | None = None
) -> list[Violation]:
    """What is wrong with one analyst's structured answer.

    ``attck`` is the knowledge module the technique ids are checked against —
    ``maljan.tools.knowledge`` in production, a stub in a test that must not
    load a fifty-megabyte bundle. Passing ``None`` skips the catalogue check
    rather than failing it: a box that cannot read ATT&CK has a thinner report,
    not a run full of invented violations.

    ``ledger_ids`` are the entries this analyst's own tool calls produced in
    this run. They decide one thing: a technique claim that cites none of them
    is asked for one. An analyst with an empty ledger — a measurement profile
    with no tools at all — is exempt, because it has nothing it could cite.
    """
    citable = [str(i) for i in (ledger_ids or []) if str(i).strip()]
    known = {i.strip().lower() for i in citable}
    cited_by_findings = _techniques_cited_by_findings(isr, known)
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
                        f"TECHNIQUE {tid} cites no evidence id from this run. Name the "
                        f"ledger entry it was read from, for example {shown}, or drop the "
                        "technique: a technique nothing in the run establishes is read "
                        "downstream as a finding."
                    ),
                    path=path,
                )
            )
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
                message=_schema_message(model, error),
                path=".".join(str(part) for part in error.get("loc") or ()),
            )
            for error in exc.errors()
        ][:MAX_SCHEMA_VIOLATIONS]
    except Exception as exc:  # noqa: BLE001 — a coercion failure is still a finding
        return [Violation(code=code, message=str(exc))]
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
    return value.split(".")[0] if _TID_RE.match(value) else ""


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


def validate_verdict_bundle(
    bundle: Any,
    evidence_corpus: set[str] | None = None,
    *,
    attck: Any = None,
    sample: Any = None,
) -> list[Violation]:
    """What is wrong with the judge's answer, in the judge's own terms.

    ``attck`` is the same knowledge module the analyst loop consults, and it is
    the same check: an id is unresolvable when the catalogue does not have it,
    not when it fails a regex. ``T7777`` is well-formed and imaginary, which is
    exactly the case this violation exists for. Passing ``None`` skips the
    catalogue question rather than answering it wrongly.

    ``sample`` is the identity block's dict; its hashes and file name ground
    an indicator the way a ledger entry does, and only when the indicator's
    value is one of them exactly. They are kept out of the corpus haystack,
    which is searched by substring: the file name is whatever the submitter
    typed, and a name carrying an address would otherwise ground an indicator
    for it. Every other indicator value still needs a ledger entry.
    """
    violations: list[Violation] = []
    objects = list(getattr(bundle, "objects", None) or [])

    haystack = " ".join(sorted(evidence_corpus)).lower() if evidence_corpus else ""
    identity = {value.lower() for value in sample_identity_values(sample)}
    runtime_paths = _runtime_paths(evidence_corpus)
    for index, obj in enumerate(objects):
        kind = str(getattr(obj, "type", "") or "")
        if kind == "indicator" and evidence_corpus is not None:
            pattern = str(getattr(obj, "pattern", "") or "")
            problem = _indicator_problem(pattern, haystack, runtime_paths, identity)
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
    message = str(error.get("msg") or "is not valid")
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
    "and not inside it, with severity {rating, rationale}, malware_category, "
    "family {name, confidence, evidence_ids} and confidence. "
    "Omit only a field the evidence cannot support."
)


def assessment_violations(bundle: Any) -> list[Violation]:
    """Whether the judge said what it thinks, beyond the STIX objects.

    The message names the top level of the bundle because that is where
    ``Bundle.x_maljan_assessment`` is read from. A block placed inside
    ``objects`` instead is discarded by ``Bundle.model_validate`` and the
    report says "not assessed" — the very failure the retry exists to fix.

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
        getattr(assessment, field, None) is not None
        for field in ("severity", "malware_category", "family", "confidence")
    ):
        return []
    return [
        Violation(
            code=ASSESSMENT_MISSING_CODE,
            message=ASSESSMENT_MISSING_MESSAGE,
            path="x_maljan_assessment",
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


def assessment_conflict_violations(bundle: Any) -> list[Violation]:
    """Whether the judge's verdict and its own severity say the same thing.

    Both fields are the judge's, and neither is touched here: what the judge
    gets is one turn in which both are named and it is asked which it meant.
    A contradiction that survives the turn is recorded rather than resolved,
    because picking one of the two for the judge would be exactly the silent
    override this module exists to replace.
    """
    from maljan.pipeline.outcome import decide_from_bundle

    verdict = decide_from_bundle(bundle)
    conflicting = _CONFLICTING_RATINGS.get(verdict)
    if not conflicting:
        return []
    assessment = getattr(bundle, "x_maljan_assessment", None)
    rating = str(getattr(getattr(assessment, "severity", None), "rating", "") or "").strip()
    if rating not in conflicting:
        return []
    return [
        Violation(
            code=ASSESSMENT_CONFLICT_CODE,
            message=(
                f"The bundle's objects say {verdict} and x_maljan_assessment.severity.rating "
                f"says {rating}; those are two different answers about the same sample. "
                "Reconcile them: either the objects or the rating is what you meant, and "
                "the rationale should support whichever it is."
            ),
            path="x_maljan_assessment.severity.rating",
        )
    ]


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


def _indicator_problem(
    pattern: str, haystack: str, runtime_paths: set[str], identity: Iterable[str] = ()
) -> str:
    """Why this indicator is not grounded, in words the judge can act on, or "".

    The rules are the ones the post-processor used to apply silently, said out
    loud instead: the denylists in ``agents._indicator_denylists`` are what a
    URL host, a compile artefact and a foreign class reference are checked
    against, and here they become the sentence the judge reads rather than a
    log line nobody sees.

    ``identity`` is the sample's own lowercased hashes and file name. A literal
    equal to one of them is grounded whatever the pattern's type; a literal
    merely contained in one is not, so neither a slice of the sha256 nor a
    value written inside the submitted name passes.
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
    own = set(identity)
    if any(literal.lower() in own for literal in literals):
        return ""
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


def _announce_feedback(
    violations: Sequence[Violation],
    on_feedback: Callable[[Sequence[Violation]], None] | None,
) -> None:
    """Log the correction turn and hand its violations to the run's tally."""
    logger.info(
        "validation: retrying after %d violation(s): %s.",
        len(violations),
        ", ".join(sorted({v.code for v in violations})),
    )
    if on_feedback is None:
        return
    try:
        on_feedback(violations)
    except Exception as exc:  # noqa: BLE001 — a metric is never worth a lost run
        logger.debug("validation: the feedback tally was not updated (%s).", exc)


async def retry_with_feedback[T](
    run: Callable[[list[Any]], Awaitable[Any]],
    messages: list[Any],
    validators: Sequence[Validator],
    *,
    max_retries: int = 1,
    parse: Callable[[Any], T],
    on_feedback: Callable[[Sequence[Violation]], None] | None = None,
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
    """
    turns = list(messages)
    answer = await run(turns)
    parsed = parse(answer)
    violations = _collect(parsed, validators)
    retries = 0
    while violations and retries < max_retries:
        _announce_feedback(violations, on_feedback)
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
    on_feedback: Callable[[Sequence[Violation]], None] | None = None,
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
        _announce_feedback(violations, on_feedback)
        turns = _with_feedback(turns, answer, violations)
        retries += 1
        answer = run(turns)
        parsed = parse(answer)
        violations = _collect(parsed, validators)
    return parsed, violations, retries


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def validation_metrics(
    retries: int,
    unresolved: Sequence[tuple[str, Violation]],
    fed_back: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """``run_summary.validation`` from the run's retries, corrections and leftovers.

    ``fed_back`` is what the producers were told, by code (see
    :class:`ValidationTally`). It is added to the leftovers rather than
    replacing them: a code that was fed back once and never fixed is two
    facts about the run, and ``by_code`` is the count of both.
    """
    by_code: dict[str, int] = {code: int(count) for code, count in (fed_back or {}).items()}
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
