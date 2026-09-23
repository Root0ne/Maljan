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

from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import CapabilityCell, TTPMapping

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

    cells: list[CapabilityCell] = []
    mappings: list[TTPMapping] = []
    for tid, info in techniques.items():
        (name, tactic_slug), tactic_domain = _resolve_technique_meta(tid)
        evidence = info["evidence"]
        # The highest number any source put on this technique. Taken once, here,
        # rather than accumulated into the row as it was collected.
        confidence = max((float(c) for c in info.get("confidences") or ()), default=0.0)
        layers = info.get("layers") or []
        valid = bool(info.get("valid", True))

        # Never emit a zero-confidence cell with no evidence and no contributing
        # source — it is an empty claim the UI would render as a "verified"
        # capability and the narrative agent would expand into prose. A
        # technique the judge named always has a source (the judge), so this
        # only catches a row nothing actually asserted.
        if confidence <= 0.0 and not evidence and not layers:
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
        if not valid:
            not_published = "the ATT&CK catalogue has no entry for this id in any domain"
        elif out_of_scope.get(tid):
            not_published = out_of_scope[tid]
        elif not info.get("claimed"):
            not_published = FINDING_ONLY_REASON
        else:
            not_published = ""
        cells.append(
            CapabilityCell(
                tactic=tactic_id or "TA0000",
                tactic_name=tactic_name or "Unknown",
                technique_id=tid,
                technique_name=name,
                evidence=evidence[:6],
                confidence=max(0.0, min(1.0, confidence)),
                contributing_layers=layers,
                technique_id_valid=valid,
                platforms=platforms,
                domain=domain,
                not_published=not_published,
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
                evidence_quotes=evidence[:8],
                confidence=max(0.0, min(1.0, confidence)),
                contributing_layers=layers,
                is_corroborated=len([lyr for lyr in layers if lyr != _JUDGE_SOURCE]) >= 2,
                technique_id_valid=valid,
            )
        )

    cells.sort(key=lambda c: c.confidence, reverse=True)
    mappings.sort(key=lambda m: m.confidence, reverse=True)
    logger.info("capability_matrix: %d cells, %d ttp mappings", len(cells), len(mappings))
    return cells, mappings


# What the judge is called in ``contributing_layers``. It is listed, because a
# technique the judge named and no analyst claimed should say where it came
# from — but it is left out of the corroboration count: the judge read the
# analysts rather than the sample, so counting it would turn one analyst's
# claim into two agreeing sources.
_JUDGE_SOURCE = "judge"

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
        return techniques.setdefault(
            tid,
            {"evidence": [], "confidences": [], "layers": [], "valid": True, "claimed": False},
        )

    # 1. The judge's bundle. An attack-pattern says the technique is in the
    # verdict; a relationship's annotation says how sure the judge was. Its ids
    # are checked against the catalogue here, the
    # same way an analyst's were checked in the analyst's own loop.
    judge_ids = _judge_technique_ids(stix_output)
    judge_relationships = _judge_relationship_rows(stix_output)
    unknown = _unknown_to_the_catalogue(judge_ids + [tid for tid, _c in judge_relationships])
    for tid in judge_ids:
        row = _row(tid)
        row["claimed"] = True
        if tid in unknown:
            row["valid"] = False
        # The judge is credited as the source. Without it an attack-pattern the
        # judge emitted with no matching relationship carries no confidence, no
        # evidence and no source, and the zero-signal guard below drops it — so
        # a technique the verdict names would be missing from the report the
        # verdict is printed in, marked or not.
        if _JUDGE_SOURCE not in row["layers"]:
            row["layers"].append(_JUDGE_SOURCE)
    for tid, confidence in judge_relationships:
        row = _row(tid)
        row["claimed"] = True
        if tid in unknown:
            row["valid"] = False
        if confidence is not None:
            row["confidences"].append(confidence)
        # The relationship is the judge's statement, so the judge is its
        # source. The agents it credits are the judge's words about the
        # evidence and stay on the relationship as written; a layer is a source
        # that named the technique itself, and one analyst's claim credited by
        # the judge to two analysts is still one claim.
        if _JUDGE_SOURCE not in row["layers"]:
            row["layers"].append(_JUDGE_SOURCE)

    # 2. ISR claims. The analysts carry the evidence quotes and the techniques
    # the judge did not name.
    if isr_reports:
        for agent_name, isr in isr_reports.items():
            for claim in getattr(isr, "claims", None) or []:
                claim_tid = getattr(claim, "technique_id", None)
                if not claim_tid:
                    continue
                row = _row(str(claim_tid))
                # The same id on a claim and on a finding is judged as the
                # claim's: it was asked the questions, and the finding is a
                # second mention of an answer that already stands.
                row["claimed"] = True
                # An id the catalogue does not have stays in the matrix and is
                # marked. Dropping it deleted the analyst's answer from the one
                # surface a reader looks at, which is the behaviour this whole
                # phase replaced; the marker is how a reader learns instead.
                if not getattr(claim, "technique_id_valid", True):
                    row["valid"] = False
                row["confidences"].append(float(getattr(claim, "confidence", 0.0) or 0.0))
                layer = getattr(isr, "domain", None) or agent_name or "agent"
                if layer and str(layer) not in row["layers"]:
                    row["layers"].append(str(layer))
                quote = getattr(claim, "claim", None) or getattr(claim, "evidence_ref", None) or ""
                if quote and quote not in row["evidence"]:
                    row["evidence"].append(str(quote)[:200])
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
                confidence = float(getattr(finding, "confidence", 0.0) or 0.0)
                title = str(getattr(finding, "title", "") or "")
                layer = getattr(isr, "domain", None) or agent_name or "agent"
                for raw in getattr(finding, "technique_ids", None) or []:
                    tid = str(raw or "").strip().upper()
                    if not tid:
                        continue
                    row = _row(tid)
                    row["confidences"].append(confidence)
                    if layer and str(layer) not in row["layers"]:
                        row["layers"].append(str(layer))
                    if title and title not in row["evidence"]:
                        row["evidence"].append(title[:200])

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
        for ref in obj.get("external_references") or []:
            external_id = ref.get("external_id") if isinstance(ref, dict) else None
            if isinstance(external_id, str) and external_id.strip():
                tid = external_id.strip().upper()
                if tid not in found:
                    found.append(tid)
                break
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
        refs = obj.get("external_references") or []
        if any(isinstance(ref, dict) and str(ref.get("external_id") or "").strip() for ref in refs):
            continue
        name = str(obj.get("name") or "").strip()
        if name and name.upper().split()[0].rstrip(":").startswith("T"):
            # The id is in the name, which ``_attack_pattern_technique_id``
            # reads; it is a mapped technique and belongs to the matrix.
            continue
        if name and name not in names:
            names.append(name[:200])
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
        for ref in obj.get("external_references") or []:
            external_id = ref.get("external_id") if isinstance(ref, dict) else None
            if isinstance(external_id, str) and external_id.strip():
                technique_of[str(obj.get("id") or "")] = external_id.strip().upper()
                break
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
        raw = obj.get("x_maljan_confidence")
        try:
            confidence = None if raw is None else float(raw)
        except (TypeError, ValueError):
            confidence = None
        rows.append((tid, confidence))
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
