"""Build the MITRE ATT&CK capability matrix (tactic x technique heatmap).

A projection, and only a projection. Two inputs:

  - the judge's STIX bundle — the attack-patterns it emitted and the confidence
    it put on each relationship;
  - ``isr_reports`` — the analysts' own claims, which add the technique ids and
    the evidence quotes the judge did not carry over.

An id the ATT&CK catalogue does not have is carried through to the matrix and
marked (``technique_id_valid``), not dropped: it is the producer's answer, and
the report is where a reader is told it does not resolve. That holds for the
judge as much as for an analyst — the judge's ids are checked here because the
judge has no later loop to be told in. It does not reach ``ttp_mappings``,
which is the *published* technique list every other technique surface of the
report is built from, and which therefore names only techniques this run
found.

Neither input is adjusted here. The cap this module used to apply — halving the
confidence of an obfuscation or injection claim whose supporting static
evidence the module could not find — is gone: the analyst's number is the
analyst's, and an unsupported claim is now something the analyst is told about
in its own loop, not something a matrix builder quietly discounts.

The vendored technique table gives the name and the tactic phases for any
ATT&CK id — a file read, not an index build.

The output is two complementary structures:
  - ``CapabilityCell[]`` — one row per (tactic, technique) pair for the
    heatmap UI.
  - ``TTPMapping[]`` — one row per technique with all the evidence quotes,
    confidence, contributing layers; this is what the narrative agent reads.

The mapping ``technique_phase_slug -> (tactic_id, tactic_name)`` is resolved
from the vendored tactic catalogue, which the ATT&CK update script writes from
the same bundles (so new releases map with no code change). The inlined
``_TACTIC_TABLE`` below is kept only as a fallback for when that file cannot be
read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.technique_ids import attack_reference_id, says_no_technique
from maljan.core.logger import logger
from maljan.reporting.models import CapabilityCell, TTPMapping
from maljan.schemas.evidence import ENTRY_ID_RE
from maljan.schemas.isr_models import (
    ABSENCE_TECHNIQUE_MARKER,
    JUDGE_ONLY_TECHNIQUE_MARKER,
    JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
    judge_and_findings_note,
    judge_dropped_reason,
    judge_kept_note,
)
from maljan.schemas.stix_models import (
    TECHNIQUE_REVIEW_PROPERTY,
    TechniqueReview,
    stated_confidence,
)

# Fallback MITRE ATT&CK Enterprise tactic catalogue (pre-v19 names). Used only
# when the live bundle's tactic catalogue is unavailable. ``kill_chain_phases``
# in the STIX bundle uses the slug form ("defense-evasion"); we map each slug
# to the canonical TA-id and the human-readable name.
_TACTIC_TABLE: tuple[tuple[str, str, str], ...] = (
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
)

_TACTIC_BY_SLUG: dict[str, tuple[str, str]] = {
    slug: (tid, name) for tid, slug, name in _TACTIC_TABLE
}

# Canonical Enterprise tactic name per TA-id. Used to pin the display name even
# when the live ATT&CK bundle renames a tactic (v19 relabelled TA0005
# "Defense Evasion" -> "Stealth"). The frontend pins the same table.
_TACTIC_NAME_BY_ID: dict[str, str] = {tid: name for tid, _slug, name in _TACTIC_TABLE}


def build_capability_matrix(
    *,
    stix_output: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
    sample: dict[str, Any] | None = None,
) -> tuple[list[CapabilityCell], list[TTPMapping]]:
    """Return ``(capability_cells, ttp_mappings)`` for the report.

    Both lists are sorted by descending confidence so the UI renders the
    most relevant rows first.

    ``sample`` is the routed platform and file type. With it, a technique from
    an ATT&CK domain the sample cannot host — two enterprise-only ids on an
    Android package, in the run that made the case — joins the rule an
    unresolvable id already follows: kept in the matrix with the reason
    written beside it, and out of the published list. Without it the question
    is not asked, which is the same fall-open answer the validator gives.
    """
    techniques = _collect_techniques(stix_output, isr_reports)
    if not techniques:
        return [], []

    out_of_scope = _out_of_scope(list(techniques), sample)
    review = technique_review(stix_output)

    cells: list[CapabilityCell] = []
    mappings: list[TTPMapping] = []
    for tid, info in techniques.items():
        (name, tactic_slug), tactic_domain = _resolve_technique_meta(tid)
        evidence = info["evidence"]
        # The highest number any source put on this technique. Taken once, here,
        # rather than accumulated into the row as it was collected, and
        # ``None`` when no source gave one: a technique the judge named with no
        # number — every one it names alone under a verdict with no malware
        # object to hang an edge on — is not a technique at confidence zero.
        confidence = max((float(c) for c in info.get("confidences") or ()), default=None)
        # Who stated that number: the first source whose number it is. The two
        # lists are appended together, so a source that stated no number is
        # never named as the producer of someone else's.
        stated_by = next(
            (
                who
                for c, who in zip(
                    info.get("confidences") or (), info.get("stated_by") or (), strict=True
                )
                if float(c) == confidence
            ),
            "",
        )
        layers = info.get("layers") or []
        valid = bool(info.get("valid", True))

        # Never emit a zero-confidence cell with no evidence and no contributing
        # source — it is an empty claim the UI would render as a "verified"
        # capability and the narrative agent would expand into prose. A
        # technique the judge named always has a source (the judge), so this
        # only catches a row nothing actually asserted.
        if not confidence and not evidence and not layers:
            continue

        tactic_id, tactic_name = _resolve_tactic(tactic_slug, tactic_domain)
        domain, platforms = _catalogue_scope(tid)
        # The cell keeps an id the catalogue rejected or the sample cannot
        # host, with the reason written beside it: it is the producer's answer
        # and deleting it would delete the record of it. The mapping does not,
        # because ``ttp_mappings`` is the published technique list — the
        # report's ATT&CK section, its References, the STIX attack-patterns and
        # ``/reports/{id}/mitre`` are all built from it — and a technique a
        # check rejected is not one this run found.
        # The judge's word on a technique it was asked about after its verdict
        # (``techniques_for_the_judge``): one it dropped is not published and
        # says so in the judge's words, one it kept is published — a finding's
        # technique included, since the judge is the check that asked about
        # it — and one it gave no answer for is what it would have been
        # without the question, marked as not confirmed.
        asked = review is not None and tid in review.asked
        decided = review.decision_for(tid) if review is not None and asked else None
        if not valid:
            not_published = "the ATT&CK catalogue has no entry for this id in any domain"
        elif out_of_scope.get(tid):
            not_published = out_of_scope[tid]
        elif decided is not None and decided.decision == "drop":
            not_published = judge_dropped_reason(decided.reason)
        elif not info.get("claimed") and not (decided is not None and decided.decision == "keep"):
            not_published = FINDING_ONLY_REASON
        else:
            not_published = ""
        notes: list[str] = []
        if info.get("noted") and all(info["noted"]):
            # Every analyst claim naming it reads as absence and was kept
            # when asked. Published all the same: the analyst decided.
            notes.append(ABSENCE_TECHNIQUE_MARKER)
        elif info.get("judge_named") and not info.get("analyst_claimed") and not not_published:
            # The judge named it and no analyst claim carries it: published by
            # the rule for a technique the judge states, and the row says so —
            # naming the analysts that named it on a finding, where any did,
            # since the run's corroboration record lists them as its sources.
            on_findings = info.get("finding_named_by") or []
            notes.append(
                judge_and_findings_note(on_findings) if on_findings else JUDGE_ONLY_TECHNIQUE_MARKER
            )
        if decided is not None and decided.decision == "keep":
            notes.append(judge_kept_note(decided.reason))
        elif asked and decided is None and not not_published:
            notes.append(JUDGE_UNCONFIRMED_TECHNIQUE_MARKER)
        cells.append(
            CapabilityCell(
                tactic=tactic_id or "TA0000",
                tactic_name=tactic_name or "Unknown",
                technique_id=tid,
                technique_name=name,
                # Every statement whole: the matrix may wrap, never cut.
                evidence=list(evidence),
                confidence=confidence,
                confidence_source=stated_by,
                contributing_layers=layers,
                technique_id_valid=valid,
                platforms=platforms,
                domain=domain,
                not_published=not_published,
                note="; ".join(notes),
                # Each analyst statement naming it, verbatim, by analyst: what
                # the analysts said is theirs to weigh, never classified here.
                statements=[f"{who}: {text}" for who, text in info.get("statements") or [] if text],
            )
        )
        if not_published:
            logger.info(
                "capability_matrix: %s stays in the matrix marked and out of the published "
                "technique list; %s.",
                tid,
                not_published,
            )
            continue
        mappings.append(
            TTPMapping(
                technique_id=tid,
                technique_name=name,
                tactic=tactic_id,
                tactic_name=tactic_name,
                evidence_quotes=list(evidence),
                confidence=confidence,
                contributing_layers=layers,
                is_corroborated=len([lyr for lyr in layers if lyr != _JUDGE_SOURCE]) >= 2,
                technique_id_valid=valid,
            )
        )

    cells.sort(key=lambda c: -1.0 if c.confidence is None else c.confidence, reverse=True)
    mappings.sort(key=lambda m: -1.0 if m.confidence is None else m.confidence, reverse=True)
    logger.info("capability_matrix: %d cells, %d ttp mappings", len(cells), len(mappings))
    return cells, mappings


# What the judge is called in ``contributing_layers``. It is listed, because a
# technique the judge named and no analyst claimed should say where it came
# from — but it is left out of the corroboration count: the judge read the
# analysts rather than the sample, so counting it would turn one analyst's
# claim into two agreeing sources.
_JUDGE_SOURCE = "judge"
# The layer name the judge contributes under, for renderers that count analyst layers.
JUDGE_SOURCE = _JUDGE_SOURCE

# Why an id that reached the report on a finding alone is not published. A
# claim is questioned in its analyst's own loop — its technique id is asked
# whether the catalogue has it, whether the sample's domain can host it and
# whether any evidence grounds it, and the analyst is shown the answer and
# given a turn. A finding's ``technique_ids`` are read by the corroboration
# metric and the report's Findings table and by nothing that asks a question,
# so a finding citing no evidence at all and carrying no confidence would
# otherwise publish a technique. It is printed everywhere, with this beside it,
# and published nowhere.
FINDING_ONLY_REASON = (
    "it was named on a finding rather than on a claim, so no check asked what evidence holds it up"
)


def _out_of_scope(ids: list[str], sample: dict[str, Any] | None) -> dict[str, str]:
    """Per technique the sample cannot host, why — in the check's own words.

    The same function the analyst loop and the judge's bundle check ask
    (``pipeline.validation.platform_mismatch_message``), over the same
    catalogue, so the sentence the report carries is the one the producer was
    shown. It runs here rather than reading the surviving violations back
    because this is after the feedback turn by construction: a technique the
    retry replaced is not in the matrix to be asked about.

    Never raises, and answers nothing for a sample whose platform is unknown or
    cross-domain — the check falls open, so a question nobody can answer is not
    counted as a mismatch.
    """
    if not sample:
        return {}
    try:
        from maljan.pipeline.validation import expected_technique_scope, platform_mismatch_message
        from maljan.tools import knowledge
    except Exception as exc:  # noqa: BLE001 — a knowledge lookup degrades, never raises
        logger.debug("capability_matrix: the platform check is unavailable (%s)", exc)
        return {}
    scope = expected_technique_scope(sample)
    if scope[0] is None:
        return {}
    found: dict[str, str] = {}
    for tid in ids:
        try:
            message = platform_mismatch_message(tid, knowledge, scope)
        except Exception as exc:  # noqa: BLE001 — an unanswered lookup is no mismatch
            logger.debug("capability_matrix: no platform answer for %s (%s)", tid, exc)
            continue
        if message:
            found[tid] = " ".join(message.split())
    return found


def _catalogue_scope(technique_id: str) -> tuple[str, list[str]]:
    """``(domain, platforms)`` the catalogue declares for the id; empty when it cannot say.

    The FP linter's platform check reads these off the cell. Never raises:
    a catalogue that cannot be read leaves the cell without a scope, which
    the linter reads as nothing to check rather than as a mismatch.
    """
    try:
        from maljan.tools import knowledge

        answer = knowledge.attck_lookup(technique_id)
    except Exception as exc:  # noqa: BLE001 — a knowledge lookup degrades, never raises
        logger.debug("capability_matrix: no catalogue scope for %s (%s)", technique_id, exc)
        return "", []
    if not isinstance(answer, dict):
        return "", []
    return (
        str(answer.get("domain") or ""),
        [str(p) for p in (answer.get("platforms") or []) if str(p).strip()],
    )


def _unknown_to_the_catalogue(ids: list[str]) -> set[str]:
    """Which of ``ids`` the ATT&CK catalogue has no entry for.

    The judge's ids go through the same check the analysts' do
    (``pipeline.validation.unknown_technique_ids``), and for the same reason: an
    id nothing can resolve is the producer's answer either way, and the report
    marks it rather than deleting it. Without this a judge that emitted
    ``T0000`` reached the matrix unmarked while an analyst that did the same was
    labelled — one rule for the model that had the last word.

    Never raises. An unreachable catalogue marks nothing rather than marking
    everything, and records nothing here: ``run_summary.validation.not_run``
    is written by the analyst loop and the judge node, which are the two
    places a check that did not run is a fact about the run.
    """
    try:
        from maljan.pipeline.validation import unknown_technique_ids
        from maljan.tools import knowledge
    except Exception as exc:  # noqa: BLE001 — a knowledge lookup degrades, never raises
        logger.debug("capability_matrix: the ATT&CK check is unavailable (%s)", exc)
        return set()
    return unknown_technique_ids(ids, knowledge)


def _collect_techniques(
    stix_output: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Merge the judge's technique list and the analysts' claims, by technique.

    Each row collects what every source said — the evidence quotes, the source
    names, and every confidence — without deciding anything. The caller reduces
    the confidences to one number, once.
    """
    techniques: dict[str, dict[str, Any]] = {}

    def _row(tid: str) -> dict[str, Any]:
        # ``confidences`` is every number a source put on this technique, kept
        # as a list rather than folded into a running maximum. The projection
        # takes the max once, where a reader can see it happen; a row that
        # rewrites its own ``confidence`` key as it goes reads like the thing
        # this phase removed even when it is only accumulating.
        # ``claimed`` is whether any producer put this id somewhere a check
        # was asked about it: a judge attack-pattern, a judge relationship, an
        # analyst claim. A finding's technique ids reach the report through a
        # path no check has ever seen, so they leave this false and the caller
        # marks the row unpublished.
        # ``stated_by`` names the producer of each confidence, index for index.
        return techniques.setdefault(
            tid,
            {
                "evidence": [],
                "confidences": [],
                "stated_by": [],
                "layers": [],
                "valid": True,
                "claimed": False,
            },
        )

    # 1. The judge's bundle. An attack-pattern says the technique is in the
    # verdict; a relationship's annotation says how sure the judge was. Its ids
    # are checked against the catalogue here, the
    # same way an analyst's were checked in the analyst's own loop.
    judge_ids = _judge_technique_ids(stix_output)
    judge_relationships = _judge_relationship_rows(stix_output)
    unknown = _unknown_to_the_catalogue(judge_ids + [tid for tid, _c in judge_relationships])
    # A bundle this pipeline built because the judge's answer was not one names
    # no technique of the judge's: its attack-patterns are the analysts'
    # claims, carried over, and the analysts are credited below. Crediting the
    # judge there named a source that said nothing.
    judge_spoke = not (stix_output or {}).get("x_maljan_fallback_verdict")
    for tid in judge_ids:
        row = _row(tid)
        row["claimed"] = True
        row["judge_named"] = row.get("judge_named", False) or judge_spoke
        if tid in unknown:
            row["valid"] = False
        # The judge is credited as the source. Without it an attack-pattern the
        # judge emitted with no matching relationship carries no confidence, no
        # evidence and no source, and the zero-signal guard below drops it — so
        # a technique the verdict names would be missing from the report the
        # verdict is printed in, marked or not.
        if judge_spoke and _JUDGE_SOURCE not in row["layers"]:
            row["layers"].append(_JUDGE_SOURCE)
    for tid, confidence in judge_relationships:
        row = _row(tid)
        row["claimed"] = True
        row["judge_named"] = row.get("judge_named", False) or judge_spoke
        if tid in unknown:
            row["valid"] = False
        if confidence is not None:
            row["confidences"].append(confidence)
            row["stated_by"].append("the judge")
        # The relationship is the judge's statement, so the judge is its
        # source. The agents it credits are the judge's words about the
        # evidence and stay on the relationship as written; a layer is a source
        # that named the technique itself, and one analyst's claim credited by
        # the judge to two analysts is still one claim.
        if judge_spoke and _JUDGE_SOURCE not in row["layers"]:
            row["layers"].append(_JUDGE_SOURCE)

    # 2. ISR claims. The analysts carry the evidence quotes and the techniques
    # the judge did not name.
    if isr_reports:
        for agent_name, isr in isr_reports.items():
            for claim in getattr(isr, "claims", None) or []:
                claim_tid = getattr(claim, "technique_id", None)
                if not claim_tid or says_no_technique(claim_tid):
                    continue
                row = _row(str(claim_tid))
                # The same id on a claim and on a finding is judged as the
                # claim's: it was asked the questions, and the finding is a
                # second mention of an answer that already stands.
                row["claimed"] = True
                row["analyst_claimed"] = True
                # Whether each claim naming it reads as absence and was kept
                # when asked: a note on the row, and nothing else.
                row.setdefault("noted", []).append(
                    bool(getattr(claim, "kept_after_absence_question", False))
                )
                # An id the catalogue does not have stays in the matrix and is
                # marked. Dropping it deleted the analyst's answer from the one
                # surface a reader looks at, which is the behaviour this whole
                # phase replaced; the marker is how a reader learns instead.
                if not getattr(claim, "technique_id_valid", True):
                    row["valid"] = False
                row["confidences"].append(float(getattr(claim, "confidence", 0.0) or 0.0))
                layer = getattr(isr, "domain", None) or agent_name or "agent"
                row["stated_by"].append(f"the {layer} analyst")
                if layer and str(layer) not in row["layers"]:
                    row["layers"].append(str(layer))
                quote = getattr(claim, "claim", None) or getattr(claim, "evidence_ref", None) or ""
                if quote and quote not in row["evidence"]:
                    row["evidence"].append(str(quote))
                row.setdefault("statements", []).append((str(layer), str(quote)))
            # 3. The findings' own technique ids. An ISR carries ids in two
            # places, and this was the one no check ever saw: the report's
            # Findings table and the corroboration metric are both built from
            # it, so a run whose final claims carried no id at all still
            # printed three enterprise-only techniques on an Android sample
            # with nothing saying they were not published. Collected here, they
            # are asked the domain question and the catalogue question with
            # every other id. What they are not asked is what a claim is asked
            # in its analyst's own loop — whether any evidence grounds them —
            # so an id that arrived here and nowhere else is printed as claimed
            # and published nowhere; see ``FINDING_ONLY_REASON``.
            for finding in getattr(isr, "findings", None) or []:
                stated = getattr(finding, "confidence", None)
                title = str(getattr(finding, "title", "") or "")
                layer = getattr(isr, "domain", None) or agent_name or "agent"
                for raw in getattr(finding, "technique_ids", None) or []:
                    tid = str(raw or "").strip().upper()
                    if not tid or says_no_technique(tid):
                        continue
                    row = _row(tid)
                    # A finding with no number adds none, and names no one
                    # as its producer: the two lists stay index for index.
                    if isinstance(stated, int | float):
                        row["confidences"].append(float(stated))
                        row["stated_by"].append(f"the {layer} analyst, on a finding")
                    if layer and str(layer) not in row["layers"]:
                        row["layers"].append(str(layer))
                    named_by = str(getattr(isr, "agent_id", "") or agent_name or "")
                    if named_by and named_by not in row.setdefault("finding_named_by", []):
                        row["finding_named_by"].append(named_by)
                    if title and title not in row["evidence"]:
                        row["evidence"].append(title)
                    row.setdefault("statements", []).append((str(layer), title))

    # The catalogue question, asked of every id still standing. A claim was
    # asked it in the analyst's own loop and carries the answer; an id that
    # arrived on a finding was asked it nowhere, and one catalogue giving one
    # answer is the point.
    standing = [tid for tid, row in techniques.items() if row.get("valid", True)]
    for tid in _unknown_to_the_catalogue(standing):
        techniques[tid]["valid"] = False

    return techniques


def _judge_objects(stix_output: dict[str, Any] | None) -> list[dict[str, Any]]:
    objects = (stix_output or {}).get("objects")
    return [obj for obj in objects if isinstance(obj, dict)] if isinstance(objects, list) else []


def _judge_technique_ids(stix_output: dict[str, Any] | None) -> list[str]:
    """The technique ids the judge's attack-patterns name."""
    found: list[str] = []
    for obj in _judge_objects(stix_output):
        if obj.get("type") != "attack-pattern":
            continue
        # Only a reference filed under ATT&CK names a technique: a CAPEC
        # reference listed first was read as technique ``CAPEC-…``.
        tid = attack_reference_id(obj)
        if tid and tid not in found:
            found.append(tid)
    return found


def unmapped_behaviours(stix_output: dict[str, Any] | None) -> list[str]:
    """What the judge named as an attack-pattern without naming a technique.

    The validator asks for the id once; an object that comes back without one
    still describes something the judge observed, and dropping it silently is
    how three of them reached one report's ``/mitre`` as techniques with an
    empty ``technique_id``. They are reported here instead, as behaviours,
    which is what they are — and they are not published as ATT&CK techniques
    on any surface.
    """
    names: list[str] = []
    for obj in _judge_objects(stix_output):
        if obj.get("type") != "attack-pattern":
            continue
        if attack_reference_id(obj):
            continue
        name = str(obj.get("name") or "").strip()
        if name and name.upper().split()[0].rstrip(":").startswith("T"):
            # The id is in the name, which ``_attack_pattern_technique_id``
            # reads; it is a mapped technique and belongs to the matrix.
            continue
        if name and name not in names:
            names.append(name)
    return names


def _judge_relationship_rows(
    stix_output: dict[str, Any] | None,
) -> list[tuple[str, float | None]]:
    """``(technique_id, the judge's confidence or None)`` per annotated relationship.

    The technique is the attack-pattern the relationship points at. It used to
    be read from ``x_maljan_technique_id`` alone, which the prompt never asks
    for and no stored judge relationship carried, so every number the judge put
    on a technique was dropped and a technique only the judge named was
    published at 0.0. The property still wins where it is written. ``None``
    where the judge wrote no number: an absent confidence is not a zero.
    """
    objects = _judge_objects(stix_output)
    technique_of: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        declared = attack_reference_id(obj)
        if declared:
            technique_of[str(obj.get("id") or "")] = declared
    rows: list[tuple[str, float | None]] = []
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        written = obj.get("x_maljan_technique_id")
        tid = (
            written.strip().upper()
            if isinstance(written, str) and written.strip()
            else technique_of.get(str(obj.get("target_ref") or ""))
            or technique_of.get(str(obj.get("source_ref") or ""))
        )
        if not tid:
            continue
        # A number outside 0–1, or no number, is no number: the judge is asked
        # about it (``stix.annotation_out_of_schema``) and nothing here puts it
        # on the scale.
        rows.append((tid, stated_confidence(obj.get("x_maljan_confidence"))))
    return rows


def _resolve_technique_meta(tid: str) -> tuple[tuple[str, str], str]:
    """``((technique_name, tactic_slug), domain)`` for an id, from the vendored table.

    A name and a tactic are dictionary facts about an id, and the vendored
    table carries both; reading them from the ATT&CK index meant building the
    whole catalogue — a fifty-megabyte parse, and on a cold box a download —
    to render a heatmap row. Falls back to ``(tid, "")`` for an id the table
    does not have, as the index did.
    """
    try:
        from maljan.memory.attck_loader import technique_entry
    except Exception as exc:  # noqa: BLE001 — a catalogue lookup degrades, never raises
        logger.debug("capability_matrix: the technique table is unavailable (%s)", exc)
        return (tid, ""), ""
    entry = technique_entry(tid)
    if entry is None and "." in tid:
        # A sub-technique the table does not carry is described by its parent.
        entry = technique_entry(tid.split(".")[0])
    if entry is None:
        return (tid, ""), ""
    return (entry.name or tid, entry.tactics[0] if entry.tactics else ""), entry.domain


def _resolve_tactic(tactic_slug: str, domain: str = "") -> tuple[str, str]:
    """Resolve a kill-chain slug to ``(tactic_id, tactic_name)``.

    The vendored table's tactic catalogue answers, then the *display name* is
    pinned to the canonical Enterprise label for known TA-ids. A v19+ release
    renamed TA0005 "Defense Evasion" to "Stealth", which leaked into the
    markdown export / ``ttp_mappings`` and contradicted the frontend's
    "Defense Evasion"; pinning keeps every surface consistent. Falls back to
    the inlined ``_TACTIC_BY_SLUG`` table when the vendored catalogue cannot be
    read.
    """
    if not tactic_slug:
        return "", ""
    try:
        from maljan.memory.attck_loader import tactic_entry

        tactic = tactic_entry(domain, tactic_slug)
    except Exception as exc:  # noqa: BLE001 — a catalogue lookup degrades, never raises
        logger.debug("capability_matrix: no tactic catalogue for %s (%s)", tactic_slug, exc)
        tactic = None
    if tactic is not None and tactic.tactic_id:
        return tactic.tactic_id, _TACTIC_NAME_BY_ID.get(tactic.tactic_id, tactic.name)
    return _TACTIC_BY_SLUG.get(tactic_slug, ("", tactic_slug))


@dataclass
class TechniqueQuestion:
    """One technique the judge is asked about after its verdict, with what names it.

    ``kind`` is ``claimed`` for a technique an analyst claimed that the judge's
    bundle does not carry, and ``finding`` for one named only on a finding.
    Each mention is ``(agent, the claim's or the finding's text, its evidence
    ids)``, the text as the analyst wrote it.
    """

    technique_id: str
    kind: str
    mentions: list[tuple[str, str, list[str]]] = field(default_factory=list)


def technique_review(stix_output: dict[str, Any] | None) -> TechniqueReview | None:
    """The judge's answer about the techniques it was asked, from its bundle, or ``None``."""
    raw = (stix_output or {}).get(TECHNIQUE_REVIEW_PROPERTY)
    if raw is None:
        return None
    try:
        return raw if isinstance(raw, TechniqueReview) else TechniqueReview.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — an unreadable answer decides nothing
        logger.debug("capability_matrix: the judge's technique answer is unreadable (%s)", exc)
        return None


def bundle_technique_ids(stix_output: dict[str, Any] | None) -> set[str]:
    """Every technique id the judge's bundle carries, on an attack-pattern or an edge."""
    return {tid.upper() for tid in _judge_technique_ids(stix_output)} | {
        tid.upper() for tid, _c in _judge_relationship_rows(stix_output)
    }


# Why a technique the judge's question would name is left out of it: the
# report does not publish it whatever the judge says.
NOT_ASKED_UNKNOWN_ID = "not asked: the ATT&CK catalogue has no entry for this id in any domain"


def judge_questions(
    stix_output: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
    sample: dict[str, Any] | None = None,
) -> tuple[list[TechniqueQuestion], dict[str, str]]:
    """The techniques to put to the judge after its verdict, and the ones left out, with why.

    (a) Each technique an analyst claimed that the judge's bundle carries
    neither as an attack-pattern nor on an edge, and (b) each technique named
    only on a finding — on no claim and not in the bundle; in the order they
    were named. An id the catalogue rejects — on the claim's own flag or asked
    here, as the matrix asks it — or one the routed sample cannot host is not
    asked: the matrix keeps it out of the published list before any answer is
    read. Those come back as ``{id: "not asked: <reason>"}``.
    """
    in_bundle = bundle_technique_ids(stix_output)
    questions: dict[str, TechniqueQuestion] = {}
    claimed: set[str] = set()
    flagged: set[str] = set()
    for agent_name, isr in (isr_reports or {}).items():
        agent = str(getattr(isr, "agent_id", "") or agent_name)
        for claim in getattr(isr, "claims", None) or []:
            tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
            if not tid or says_no_technique(tid):
                continue
            claimed.add(tid)
            if not getattr(claim, "technique_id_valid", True):
                flagged.add(tid)
            if tid in in_bundle:
                continue
            evidence = str(getattr(claim, "evidence_ref", "") or "")
            questions.setdefault(tid, TechniqueQuestion(tid, "claimed")).mentions.append(
                (
                    agent,
                    str(getattr(claim, "claim", "") or ""),
                    list(dict.fromkeys(found.lower() for found in ENTRY_ID_RE.findall(evidence))),
                )
            )
    for agent_name, isr in (isr_reports or {}).items():
        agent = str(getattr(isr, "agent_id", "") or agent_name)
        for finding in getattr(isr, "findings", None) or []:
            title = str(getattr(finding, "title", "") or "")
            detail = str(getattr(finding, "detail", "") or "")
            text = f"{title} — {detail}" if title and detail else title or detail
            ids = [str(i) for i in (getattr(finding, "evidence_ids", None) or []) if str(i)]
            for raw in getattr(finding, "technique_ids", None) or []:
                tid = str(raw or "").strip().upper()
                if not tid or says_no_technique(tid) or tid in claimed or tid in in_bundle:
                    continue
                questions.setdefault(tid, TechniqueQuestion(tid, "finding")).mentions.append(
                    (agent, text, ids)
                )
    ids = list(questions)
    unknown = flagged | _unknown_to_the_catalogue(ids)
    out_of_scope = _out_of_scope(ids, sample)
    not_asked: dict[str, str] = {}
    for tid in ids:
        if tid in unknown:
            not_asked[tid] = NOT_ASKED_UNKNOWN_ID
        elif out_of_scope.get(tid):
            not_asked[tid] = f"not asked: {out_of_scope[tid]}"
    return [q for tid, q in questions.items() if tid not in not_asked], not_asked


def techniques_for_the_judge(
    stix_output: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
    sample: dict[str, Any] | None = None,
) -> list[TechniqueQuestion]:
    """The techniques :func:`judge_questions` puts to the judge."""
    return judge_questions(stix_output, isr_reports, sample)[0]
