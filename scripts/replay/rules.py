"""The platform's deterministic rules, re-run over one stored run.

Each part calls the rules' own functions over what the run stored, composed
the way the platform composes them:

* **the analysts.** Every answer the run stored as the analyst wrote it is
  parsed by the platform's reader (``BaseAnalyst._text_to_isr``) and checked
  as the analyst's validation turn checks an answer
  (``BaseAnalyst._validate_isr``). The claims in force, the report row's
  ``agent_findings``, are checked by the checks that read claims, and their
  validity and absence notes are reset and decided again from those findings
  (``mark_invalid_technique_ids``).
* **the judge.** Its answer as written (``stix-judge.json``) is parsed as the
  judge parses it (``JudgeAgent._bundle_from_response``) and checked as
  ``JudgeAgent.give_verdict`` checks it, the parse's settled findings kept
  apart as the round keeps them; the indicators it would drop are dropped.
* **the report.** The run summary's validation block is rebuilt from the
  replayed findings, and the deterministic build (``MalwareReportBuilder``),
  the export over the judge's bundle (``ExtendedSTIXRenderer``) and the IOC
  table the export decides follow from it: the published techniques with the
  capability matrix's reasons, each indicator's publish answer, the claims in
  force the composed body leaves undiscussed and the detection rules drafted.
* **the report's two model rounds.** The narrative and each composer section
  as the stored report holds them, checked as each round checks its answer,
  then put on the rebuilt report as each round puts its answer.
* **the tool calls.** Each recorded call's arguments, as the recorder checks
  them before it runs a call.
* **the report linter,** over the finished report.
* **corroboration,** per technique.

What a model would have been asked is what is counted: no model is called.
Output names codes, entry ids and counts; a finding's words and a claim's text
are added only when asked for (``show_text``). Every input the stored record
does not hold is listed in ``not_replayed`` with why, and a part that raised
is listed there marked as an error (``"error": true``): a crash is not a
decision, and the command ends with status 2 on one.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import traceback
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from scripts.replay.guard import ReplayEnvironment, replay_environment
from scripts.replay.record import REPLAY_SCHEMA
from scripts.replay.stored import StoredRun

# What each producer's checks are, as the platform composes them: the
# functions the replay calls for that producer, in the platform's order, and
# the ones it cannot call over a stored run, each with why. A test holds both
# lists to the platform's own call sites (``test_the_replay_knows_every_check``).
ANALYST_CHECKS: tuple[str, ...] = (
    "claims_repeated",
    "analyst_repeated_violation",
    "parse_violations",
    "undescribed_decompiles",
    "decompiled_not_described_violation",
    "library_only_claims_violation",
    "check_function_claims",
    "validate_isr",
)
# Why the output-cap questions cannot be replayed: the record keeps the
# answer, not whether the model's output limit ended it.
_CUT_NOT_STORED = "whether the answer ended at the output cap is not in the stored record"
ANALYST_NOT_REPLAYED: dict[str, str] = {"analyst_cut_violation": _CUT_NOT_STORED}
JUDGE_CHECKS: tuple[str, ...] = (
    "lift_misplaced_extensions",
    "duplicate_label_violations",
    "validate_verdict_bundle",
    "assessment_violations",
    "assessment_conflict_violations",
    "stated_verdict_violations",
    "unsupported_benign_violations",
    "unsupported_malware_violations",
    "unattributed_indicator_violations",
)
JUDGE_NOT_REPLAYED: dict[str, str] = {"verdict_cut_violation": _CUT_NOT_STORED}
NARRATIVE_CHECKS: tuple[str, ...] = (
    "schema_violations",
    "narrative_capability_violations",
    "key_finding_citation_violations",
    "citation_violations",
    "wrong_entry_citations",
    "misstated_entry_contents",
    "ledger_absence_contradictions",
    "technique_name_violations",
    "recommendation_indicator_violations",
    "recommendation_technique_violations",
)
COMPOSER_CHECKS: tuple[str, ...] = (
    "schema_violations",
    "section_capability_violations",
    "citation_violations",
    "wrong_entry_citations",
    "misstated_entry_contents",
    "ledger_absence_contradictions",
    "technique_name_violations",
    "repeated_item_violations",
    "unpublished_value_violations",
    "flow_voice_violations",
    "persistence_not_observed_violations",
    "configuration_citation_violations",
    "identifier_citation_violations",
    "stated_value_violations",
)
COMPOSER_NOT_REPLAYED: dict[str, str] = {"section_cut_violation": _CUT_NOT_STORED}
TOOL_CHECKS: tuple[str, ...] = ("self_named_arguments",)

# Where each composer section's answer stands in a stored report, and how the
# answer the section's schema reads is rebuilt from it: the report field, and
# the key of the schema the field's value is the list (or object) of. ``None``
# is a section whose schema is the stored object itself.
COMPOSER_PLACES: dict[str, tuple[str, str | None]] = {
    "introduction": ("intro_background", "text"),
    "execution_flow": ("technical_analysis.execution_flow", "steps"),
    "configuration": ("technical_analysis.configuration", "items"),
    "host_identifiers": ("technical_analysis.host_identifiers", "identifiers"),
    "commands": ("technical_analysis.commands", "commands"),
    "encryption_scheme": ("technical_analysis.encryption_scheme", None),
    "cli_flags": ("technical_analysis.cli_flags", "flags"),
    "ransom_note": ("technical_analysis.ransom_note", None),
    "communications": ("c2_channels", "channels"),
}

_LOG = logging.getLogger("maljan.replay")


# ---------------------------------------------------------------------------
# What every part reads
# ---------------------------------------------------------------------------


@dataclass
class _Run:
    """The stored run as the rules read it, built once per replay."""

    stored: StoredRun
    show_text: bool
    ledger: list[Any] = field(default_factory=list)
    # The ledger's entries by the agent whose call each is, in ledger order.
    by_agent: dict[str, list[Any]] = field(default_factory=dict)
    pack: list[Any] = field(default_factory=list)
    identity: dict[str, Any] = field(default_factory=dict)
    isrs: dict[str, Any] = field(default_factory=dict)
    # Each analyst's final answer, parsed once: the answer replay and the
    # claims in force (which take its findings) both read it.
    final_isrs: dict[str, Any] = field(default_factory=dict)
    # Each analyst's findings and artifacts as the stored report's tables
    # hold them, for an answer in force whose stored text carries no block.
    stored_findings: dict[str, list[Any]] = field(default_factory=dict)
    stored_artifacts: dict[str, list[Any]] = field(default_factory=dict)
    # What the replay found on each analyst's claims in force, and what the
    # judge's round leaves standing: the run summary's validation block.
    in_force_found: dict[str, list[Any]] = field(default_factory=dict)
    judge_left: list[Any] = field(default_factory=list)
    judge_settled: list[Any] = field(default_factory=list)
    judge_codes: set[str] = field(default_factory=set)
    not_replayed: list[dict[str, Any]] = field(default_factory=list)
    _named: set[tuple[str, str]] = field(default_factory=set)

    def name(self, part: str, why: str, *, error: bool = False) -> None:
        """Say once that ``part`` was not replayed, and why; ``error`` when it raised."""
        if (part, why) in self._named:
            return
        self._named.add((part, why))
        row: dict[str, Any] = {"part": part, "why": why}
        if error:
            row["error"] = True
        self.not_replayed.append(row)


def _where(exc: BaseException) -> str:
    """Where an exception was raised, as ``file:line (function)``: never its message."""
    frames = traceback.extract_tb(exc.__traceback__)
    if not frames:
        return type(exc).__name__
    last = frames[-1]
    return f"{type(exc).__name__} at {Path(last.filename).name}:{last.lineno} ({last.name})"


def _failed(run: _Run, part: str, exc: BaseException) -> dict[str, Any]:
    """A part that raised, named as an error with where it raised; its message only with text."""
    why = _where(exc)
    if run.show_text:
        why = f"{why}: {exc}"
    run.name(part, why, error=True)
    return {"replayed": False, "why": why, "error": True}


def _timestamp(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]


def _read_ledger(run: _Run) -> None:
    from maljan.schemas.evidence import LedgerEntry

    fields = set(LedgerEntry.model_fields)
    unread = 0
    for item in run.stored.evidence:
        row = {k: v for k, v in item.items() if k in fields}
        row["id"] = item.get("entry_id") or item.get("id")
        try:
            run.ledger.append(LedgerEntry.model_validate(row))
        except Exception:  # noqa: BLE001 — counted and named below
            unread += 1
    run.ledger.sort(key=lambda entry: entry.seq)
    for entry in run.ledger:
        run.by_agent.setdefault(str(entry.agent or ""), []).append(entry)
    if unread:
        run.name("ledger", f"{unread} stored ledger row(s) do not read as this tree's LedgerEntry")
    if not run.stored.evidence:
        run.name("ledger", "the stored run holds no evidence ledger")
    try:
        from maljan.pipeline.triage_pack import pack_entries

        run.pack = pack_entries(run.ledger)
    except Exception as exc:  # noqa: BLE001
        _failed(run, "triage pack", exc)


def _read_identity(run: _Run) -> None:
    """The routed identity: the report's identity block, the job's sample row under it."""
    report = run.stored.report or {}
    found = report.get("identity")
    block: dict[str, Any] = found if isinstance(found, dict) else {}
    found = block.get("hashes")
    hashes: dict[str, Any] = found if isinstance(found, dict) else {}
    job = run.stored.job or {}
    identity = {
        "sha256": str(hashes.get("sha256") or job.get("sample_sha256") or ""),
        "file_name": str(block.get("file_name") or job.get("sample_filename") or ""),
        "file_type": str(block.get("file_type") or ""),
        "platform": str(block.get("platform") or ""),
        "md5": str(hashes.get("md5") or ""),
        "sha1": str(hashes.get("sha1") or ""),
    }
    run.identity = {k: v for k, v in identity.items() if v}
    if run.stored.job is not None and not (job.get("sample_sha256") and job.get("sample_filename")):
        run.name(
            "identity",
            "the job record holds no sample hash and name (no sample row joined to it): the "
            "report's identity block is the only source of them",
        )
    if not run.identity.get("sha256"):
        run.name("identity", "neither the report nor the job states the sample's hash")
    if not run.identity.get("file_type") or not run.identity.get("platform"):
        run.name(
            "identity",
            "the stored report states no file type or platform; the routed format is unknown",
        )


def _snapshot_value(run: _Run, key: str, default: Any = None) -> Any:
    return run.stored.settings.get(key, default)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _blocks_read(claims: Sequence[Any]) -> dict[int, tuple[list[str], str]]:
    """Per claim block, the entry ids its claims cite and its sentence: one pass over the claims."""
    from maljan.pipeline.validation import claim_block_indexes
    from maljan.schemas.evidence import entry_ids_in

    ids: dict[int, set[str]] = {}
    sentence: dict[int, str] = {}
    for claim, block in zip(claims, claim_block_indexes(claims), strict=False):
        ids.setdefault(block, set()).update(
            entry_ids_in(str(getattr(claim, "evidence_ref", "") or ""))
        )
        sentence.setdefault(block, str(getattr(claim, "claim", "") or ""))
    return {block: (sorted(found), sentence[block]) for block, found in ids.items()}


def _block_of(path: str) -> int | None:
    marker = ".claims[" if ".claims[" in path else "claims["
    if marker not in path:
        return None
    tail = path.split(marker, 1)[1]
    number = tail.split("]", 1)[0]
    return int(number) if number.isdigit() else None


def _flag(
    violation: Any,
    *,
    show_text: bool,
    ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    """One finding as the replay records it: code, path, subject and entry ids.

    The entry ids are the ones the claim it is about cites (``ids``), or the
    ones the sentences it quotes from the checked text cite. Never ids read out
    of the finding's own message, which may list the ids the answer could have
    cited.
    """
    from maljan.schemas.evidence import entry_ids_in

    row: dict[str, Any] = {"code": str(getattr(violation, "code", "") or "")}
    path = str(getattr(violation, "path", "") or "")
    if path:
        row["path"] = path
    subject = str(getattr(violation, "subject", "") or "")
    if subject:
        row["subject"] = subject
    if getattr(violation, "advisory", False):
        row["advisory"] = True
    if ids is None:
        quoted = " ".join(str(q) for q in (getattr(violation, "quoted", None) or ()))
        ids = sorted(entry_ids_in(quoted))
    listed = sorted(dict.fromkeys(ids))
    if listed:
        row["entries"] = listed
    if show_text:
        row["message"] = str(getattr(violation, "message", "") or "")
    return row


def _tally(flags: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return dict(sorted(Counter(str(f["code"]) for f in flags).items()))


def _claim_flags(violations: Sequence[Any], isr: Any, *, show_text: bool) -> list[dict[str, Any]]:
    """Each finding about an analyst's answer, with the entry ids its claim cites."""
    blocks = _blocks_read(list(getattr(isr, "claims", None) or []))
    out: list[dict[str, Any]] = []
    for violation in violations:
        block = _block_of(str(getattr(violation, "path", "") or ""))
        ids, sentence = blocks.get(block, ([], "")) if block is not None else ([], "")
        row = _flag(violation, show_text=show_text, ids=ids)
        if show_text and sentence:
            row["claim"] = sentence
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# The analysts
# ---------------------------------------------------------------------------


@dataclass
class _Own:
    """What an analyst's answer was checked against: its own entries and the pack's."""

    entries: list[Any]
    ledger_ids: list[str]
    items: Any
    decompiled: list[Any]
    image_bases: tuple[int, ...]
    listed: list[Any]
    facts: Any
    facts_failed: str


def _own(run: _Run, agent: str, before: datetime | None) -> _Own:
    """The analyst's own entries up to ``before`` (all of them when ``None``), and the pack's."""
    from maljan.analysis.sandbox_sections import item_index_of
    from maljan.pipeline.validation import decompiled_functions, image_bases_in

    # An entry started after the answer was written is one the answer could
    # not cite; one with no recorded start is kept.
    until = before.timestamp() if before is not None else None
    own = [
        entry
        for entry in run.by_agent.get(agent, [])
        if until is None or entry.started_at is None or float(entry.started_at) <= until
    ]
    pack = list(run.pack)
    image_bases = tuple(dict.fromkeys([*image_bases_in(own), *image_bases_in(pack)]))
    listed: list[Any] = []
    facts: Any = None
    failed = ""
    from maljan.pipeline.function_claims import facts_unread, function_facts, listed_functions

    listed = listed_functions(own)
    if listed:
        run.name(
            "analysts",
            "the function-claim check reads the triage pack as an analyst was shown it; the "
            "bound the run cut the pack at is not recorded, so the pack is read whole",
        )
        try:
            from maljan.agents.function_map import function_artefacts
            from maljan.pipeline.triage_pack import pack_block

            facts = function_facts(
                own,
                function_artefacts(pack),
                pack_entries=pack,
                facts_block=pack_block(pack, 0),
                bases=image_bases,
            )
        except Exception as exc:  # noqa: BLE001 — the platform's own words for it
            failed = facts_unread(exc)
    return _Own(
        entries=own,
        ledger_ids=[*(str(e.id) for e in own), *(str(e.id) for e in pack)],
        items=item_index_of(pack),
        decompiled=decompiled_functions(own),
        image_bases=image_bases,
        listed=listed,
        facts=facts,
        facts_failed=failed,
    )


def _parse_answer(run: _Run, agent: str, domain: str, text: str, revision_round: int) -> Any:
    """``text`` read the way the analyst's own parser reads an answer."""
    from maljan.agents.base_agent import BaseAnalyst

    class _ReplayAnalyst(BaseAnalyst):
        """The parser's host: an analyst with no model, no tools and no loop."""

        def analyze(self, data: str) -> str:  # pragma: no cover - never called
            return ""

        def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - never called
            return ""

        def _infer_domain(self) -> str:
            return domain

    analyst = _ReplayAnalyst.__new__(_ReplayAnalyst)
    analyst.name = agent
    analyst.logger = _LOG
    analyst._findings_buffer = []
    analyst._artifacts_buffer = []
    prose = analyst._capture_findings(text)
    isr = analyst._text_to_isr(prose, revision_round)
    return analyst._drain_findings(isr)


def _analyst_checks(run: _Run, isr: Any, own: _Own, techniques: bool, *, whole: bool) -> list[Any]:
    """The analyst validation turn's checks over one answer, in the platform's order."""
    from maljan.pipeline import validation as v
    from maljan.tools import knowledge

    found: list[Any] = []
    if whole:
        text = str(getattr(isr, "answer_text", "") or "") or str(
            getattr(isr, "unparsed_answer", "") or ""
        )
        margin = _snapshot_value(run, "validation.claim_repeat_margin")
        repeated = v.claims_repeated(text, None if margin is None else int(margin))
        if repeated is not None:
            found.append(v.analyst_repeated_violation(repeated, techniques=techniques))
        found.extend(v.parse_violations(isr, techniques=techniques))
    undescribed = v.decompiled_not_described_violation(
        v.undescribed_decompiles(isr, own.decompiled, own.image_bases)
    )
    if undescribed is not None:
        found.append(undescribed)
    library = v.library_only_claims_violation(isr)
    if library is not None:
        found.append(library)
    if own.listed:
        from maljan.pipeline.function_claims import FunctionClaimCheck, check_function_claims

        check = (
            FunctionClaimCheck(not_checked=[own.facts_failed])
            if own.facts_failed
            else check_function_claims(isr, own.listed, own.facts, own.image_bases)
        )
        found.extend(check.violations)
    found.extend(
        v.validate_isr(
            isr,
            attck=knowledge,
            ledger_ids=own.ledger_ids,
            sample={
                "file_type": run.identity.get("file_type", "unknown"),
                "platform": run.identity.get("platform", "unknown"),
            },
            alignment=None,
            items=own.items,
        )
    )
    return found


def _answer_record(
    run: _Run,
    agent: str,
    domain: str,
    text: str,
    revision_round: int,
    *,
    source: str,
    before: datetime | None,
    in_force: bool,
) -> dict[str, Any]:
    techniques = bool(_snapshot_value(run, f"agents.definitions.{agent}.attck_techniques", True))
    isr = _parse_answer(run, agent, domain, text, revision_round)
    if in_force:
        run.final_isrs[agent] = isr
        if not isr.findings and not isr.artifacts:
            # The platform stores an answer's prose without its findings
            # block; for the answer in force the report's tables hold it.
            isr.findings = list(run.stored_findings.get(agent) or [])
            isr.artifacts = list(run.stored_artifacts.get(agent) or [])
    own = _own(run, agent, before)
    found = _analyst_checks(run, isr, own, techniques, whole=True)
    flags = _claim_flags(found, isr, show_text=run.show_text)
    record: dict[str, Any] = {
        "answer": f"round {revision_round}",
        "source": source,
        "replayed": True,
        "claims": len(isr.claims),
        "findings": len(isr.findings),
        "codes": _tally(flags),
        "flags": flags,
    }
    if in_force:
        record["in_force"] = True
    if before is None:
        record["own_entries"] = "all of the analyst's entries (the answer's time is not recorded)"
    return record


# A first answer with claims is stored as the platform's summary of them
# (``AgentISR.to_text_summary``), which is not an answer anyone wrote.
_SUMMARY_ONLY = "stored as the platform's summary of its claims, not as the analyst wrote it"


def _not_replayable(answer: str, source: str, why: str) -> dict[str, Any]:
    return {"answer": answer, "source": source, "replayed": False, "why": why}


def _messages_by_speaker(transcript: Iterable[Mapping[str, Any]]) -> dict[str, list[Any]]:
    """The analysts' and revisers' messages, by speaker, in the order they were said: one pass."""
    out: dict[str, list[Any]] = {}
    for message in transcript:
        if str(message.get("role") or "") in ("analyst", "reviser"):
            out.setdefault(str(message.get("speaker") or ""), []).append(message)
    return out


def _message_answers(
    run: _Run,
    agent: str,
    messages: Sequence[Mapping[str, Any]],
    domain: str,
    in_force_round: int,
) -> tuple[list[dict[str, Any]], datetime | None]:
    """The answers the transcript stored for ``agent``, and the time of the one in force."""
    out: list[dict[str, Any]] = []
    final_at: datetime | None = None
    for message in messages:
        role = str(message.get("role") or "")
        rnd = int(message.get("round") or 0)
        report = str(message.get("report") or "")
        at = _timestamp(message.get("ts"))
        source = f"transcript {message.get('seq') or ''}".strip()
        truncated = bool(message.get("report_truncated"))
        if role == "analyst":
            if in_force_round == 0:
                final_at = at
                continue
            if message.get("claims"):
                out.append(_not_replayable("round 0", source, _SUMMARY_ONLY))
                continue
            if not report.strip():
                continue
        elif not report.strip():
            # A revision that was not made: the answer in force stood.
            continue
        if role == "reviser" and rnd == in_force_round:
            # The revision in force: the report row holds it whole.
            final_at = at
            continue
        if truncated:
            out.append(
                _not_replayable(
                    f"round {rnd}",
                    source,
                    f"stored truncated at {len(report):,} characters",
                )
            )
            continue
        out.append(
            _answer_record(
                run, agent, domain, report, rnd, source=source, before=at, in_force=False
            )
        )
    return out, final_at


def _stored_findings(run: _Run) -> dict[str, list[Any]]:
    """Each analyst's findings, read back from the stored report's Findings table.

    The report row keeps an analyst's claims and not its findings; the table is
    their one stored trace: title, techniques, confidence and evidence ids. A
    finding's detail and artifacts are not in it, and a row two analysts reached
    is read as one finding of each.
    """
    from maljan.reporting.ledger_report import NOT_PUBLISHED_MARKER
    from maljan.schemas.evidence import entry_ids_in
    from maljan.schemas.isr_models import Finding

    marker = f" ({NOT_PUBLISHED_MARKER})"
    out: dict[str, list[Any]] = {}
    for section in (run.stored.report or {}).get("sections") or []:
        if not isinstance(section, dict) or section.get("key") != "findings":
            continue
        for row in section.get("rows") or []:
            cells = [str(cell) for cell in row] if isinstance(row, list) else []
            if len(cells) < 5:
                continue
            agents, title, techniques, confidence, evidence = cells[:5]
            ids = [t.strip() for t in techniques.replace(marker, "").split(",")]
            try:
                stated: float | None = float(confidence)
            except ValueError:
                stated = None
            for agent in (a.strip() for a in agents.split(",")):
                if not agent:
                    continue
                out.setdefault(agent, []).append(
                    Finding(
                        title=title,
                        detail="",
                        category="",
                        technique_ids=[t for t in ids if t],
                        confidence=stated,
                        evidence_ids=sorted(entry_ids_in(evidence)),
                    )
                )
    return out


def _stored_artifacts(run: _Run) -> dict[str, list[Any]]:
    """Each analyst's artifacts, read back from the stored report's Appendix A tables.

    Read by the platform's own reader of those tables (``listed_rows``): each
    row with the analyst that listed it and the ids its artifact cites. Rows
    one analyst listed under one kind and one citation are one artifact.
    """
    from types import SimpleNamespace

    from maljan.reporting.ledger_report import (
        EVIDENCE_COLUMN,
        LISTED_BY_COLUMN,
        artifact_sections,
        listed_rows,
    )
    from maljan.schemas.evidence import entry_ids_in
    from maljan.schemas.isr_models import Artifact

    sections = [
        SimpleNamespace(**section)
        for section in (run.stored.report or {}).get("sections") or []
        if isinstance(section, dict)
    ]
    out: dict[str, list[Any]] = {}
    for kind, section in artifact_sections(sections):
        columns = [str(c) for c in getattr(section, "columns", None) or []]
        if columns[:2] == [LISTED_BY_COLUMN, EVIDENCE_COLUMN]:
            columns = columns[2:]
        elif columns[:1] == [LISTED_BY_COLUMN]:
            columns = columns[1:]
        grouped: dict[tuple[str, str], list[list[str]]] = {}
        for analyst, cited, row in listed_rows(section):
            grouped.setdefault((analyst, cited), []).append(list(row))
        for (analyst, cited), rows in grouped.items():
            out.setdefault(analyst, []).append(
                Artifact(
                    kind=kind,
                    label=str(getattr(section, "title", "") or ""),
                    value=None,
                    columns=columns,
                    rows=rows,
                    evidence_ids=sorted(entry_ids_in(cited)),
                    source=analyst,
                )
            )
    return out


def _in_force(run: _Run, agent: str, row: Mapping[str, Any]) -> dict[str, Any]:
    """The claims in force, checked by the checks that read claims, their notes decided again.

    The stored claims carry the run's own decisions about them: whether the
    catalogue knows each technique, whether its analyst kept an absence claim
    when asked, whether it cites only failed calls. Each is reset and decided
    again here, by the platform's own functions over the replayed findings, so
    a change to the rules reaches what the report publishes.
    """
    from maljan.pipeline.validation import mark_invalid_technique_ids
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    claims: list[Any] = []
    unread = 0
    for claim in row.get("claims") or []:
        try:
            read = ClaimEvidence.model_validate(claim)
        except Exception:  # noqa: BLE001 — counted
            unread += 1
            continue
        read.technique_id_valid = True
        read.kept_after_absence_question = False
        read.cites_only_failed_calls = False
        claims.append(read)
    final = run.final_isrs.get(agent)
    findings = list(getattr(final, "findings", None) or [])
    artifacts = list(getattr(final, "artifacts", None) or [])
    if not findings and not artifacts:
        # No answer in force was replayed (its text is the claim summary):
        # the report's tables are the findings' one stored trace.
        findings = list(run.stored_findings.get(agent) or [])
        artifacts = list(run.stored_artifacts.get(agent) or [])
    isr = AgentISR(
        agent_id=agent,
        domain=str(row.get("domain") or agent),
        claims=claims,
        dissent_items=[str(d) for d in row.get("dissent_items") or []],
        revision_round=int(row.get("revision_rounds") or 0),
        findings=findings,
        artifacts=artifacts,
    )
    run.isrs[agent] = isr
    techniques = bool(_snapshot_value(run, f"agents.definitions.{agent}.attck_techniques", True))
    found = _analyst_checks(run, isr, _own(run, agent, None), techniques, whole=False)
    # What the analyst's validation turn does with what survived its retry.
    mark_invalid_technique_ids(isr, found)
    run.in_force_found[agent] = found
    flags = _claim_flags(found, isr, show_text=run.show_text)
    out: dict[str, Any] = {
        "claims": len(claims),
        "findings": len(isr.findings),
        "codes": _tally(flags),
        "flags": flags,
        "not_valid": sorted(
            {str(c.technique_id) for c in claims if c.technique_id and not c.technique_id_valid}
        ),
        "kept_after_absence_question": sorted(
            {str(c.technique_id) for c in claims if c.kept_after_absence_question}
        ),
    }
    if unread:
        out["claims_unread"] = unread
        run.name(
            f"analyst {agent}", f"{unread} claim(s) in force do not read as this tree's claims"
        )
    return out


def _analysts(run: _Run) -> dict[str, Any]:
    rows = {str(r.get("agent_name") or ""): r for r in run.stored.agent_findings}
    texts = run.stored.agent_reports
    out: dict[str, Any] = {}
    run.stored_findings = _stored_findings(run)
    run.stored_artifacts = _stored_artifacts(run)
    if run.stored_findings or run.stored_artifacts:
        run.name(
            "analysts",
            "findings and artifacts are not stored with the claims in force; they are read "
            "back from the stored report's Findings and Appendix A tables (a finding's detail "
            "is not in them)",
        )
    if rows:
        run.name(
            "analysts",
            "the claims in force are stored with the run's own validity and absence notes; "
            "they are reset and decided again from the replayed findings, each counted as one "
            "its analyst was shown (whether it was is not in the record)",
        )
    by_speaker = _messages_by_speaker(run.stored.transcript)
    # In the order the run's state held them: the order the analysts first
    # answered, which is the order their first messages were said in.
    spoken = [
        speaker
        for speaker, messages in by_speaker.items()
        if any(str(m.get("role") or "") == "analyst" for m in messages)
    ]
    for agent in [n for n in dict.fromkeys([*spoken, *texts, *rows]) if n in texts or n in rows]:
        row = rows.get(agent) or {}
        domain = str(row.get("domain") or agent)
        in_force_round = int(row.get("revision_rounds") or 0)
        final_text = texts.get(agent, "")
        answers: list[dict[str, Any]] = []
        try:
            earlier, final_at = _message_answers(
                run, agent, by_speaker.get(agent, []), domain, in_force_round
            )
            answers.extend(earlier)
            if not final_text.strip():
                answers.append(
                    _not_replayable(
                        f"round {in_force_round}", "agent_reports", "no final answer is stored"
                    )
                )
            elif in_force_round == 0 and row.get("claims"):
                answers.append(_not_replayable("round 0", "agent_reports", _SUMMARY_ONLY))
            else:
                answers.append(
                    _answer_record(
                        run,
                        agent,
                        domain,
                        final_text,
                        in_force_round,
                        source="agent_reports",
                        before=final_at,
                        in_force=True,
                    )
                )
        except Exception as exc:  # noqa: BLE001 — named, the other analysts go on
            answers.append({"answer": "answers", **_failed(run, f"analyst {agent} answers", exc)})
        for answer in answers:
            if answer.get("replayed") is False and answer.get("answer") != "answers":
                run.name(f"analyst {agent} {answer.get('answer')}", str(answer.get("why")))
        entry: dict[str, Any] = {"answers": answers}
        if row:
            try:
                entry["in_force"] = _in_force(run, agent, row)
            except Exception as exc:  # noqa: BLE001
                entry["in_force"] = _failed(run, f"analyst {agent} claims in force", exc)
        out[agent] = entry
    if not out:
        run.name("analysts", "the stored run holds no analyst answer and no claims in force")
    return out


# ---------------------------------------------------------------------------
# The judge
# ---------------------------------------------------------------------------


@dataclass
class _Judged:
    bundle: Any = None
    origins: list[Any] = field(default_factory=list)


def _corpus_state(run: _Run) -> Any:
    """How whole the evidence the judge's checks search is, on the run's own record.

    The stored answers are what the run saw unless the byte budget blanked one
    or the run's corpus recorded itself partial; either makes it partial, with
    the counts, as the platform says of a corpus it fell back from.
    """
    from maljan.agents.run_evidence_corpus import CorpusState

    blanked = [e for e in run.ledger if getattr(e, "truncated", False) and not e.output]
    truncation = run.stored.run_summary.get("truncation")
    truncation = truncation if isinstance(truncation, dict) else {}
    recorded = int(truncation.get("evidence_corpus_missing_answers") or 0)
    reason = str(truncation.get("evidence_corpus_partial_reason") or "")
    tools = {str(getattr(e, "tool", "") or "") for e in blanked} | {
        str(t) for t in truncation.get("evidence_corpus_missing_tools") or []
    }
    tools.discard("")
    complete = not blanked and not recorded and not reason
    if not complete:
        run.name(
            "judge evidence",
            f"{len(blanked)} stored answer(s) were blanked by the byte budget and the run's "
            f"corpus recorded {recorded} missing; an absence is advisory here",
        )
    return CorpusState(
        complete=complete,
        missing_answers=len(blanked) + recorded,
        missing_tools=tuple(sorted(tools)),
        why=reason,
    )


def _shown_to_the_judge(run: _Run, found: Sequence[Any]) -> list[Any]:
    """The findings of the round the judge was shown, as far as the stored summary says.

    A finding the answer to the judge's only retry raised first was never shown
    to it, and the run summary records it ``"asked": "false"``. Each replayed
    finding that matches such a row (by the platform's own reading of "the same
    finding", ``not_asked``) was not shown; every other one is counted as shown.
    """
    from maljan.pipeline.validation import Violation, not_asked

    validation = run.stored.run_summary.get("validation")
    rows = validation.get("unresolved") if isinstance(validation, dict) else None
    unshown = [
        Violation(
            code=str(row.get("code") or ""),
            message=str(row.get("message") or ""),
            subject=str(row.get("subject") or ""),
        )
        for row in rows or []
        if isinstance(row, dict)
        and str(row.get("agent") or "judge") == "judge"
        and str(row.get("asked") or "") == "false"
    ]
    run.name(
        "judge",
        "whether the judge was shown each finding is read from the stored summary's rows "
        "(asked: false); a finding it holds no such row for is counted as shown",
    )
    if not unshown:
        return list(found)
    # ``not_asked`` leaves a finding as it is when it matches one of the rows:
    # matched means one of the stored unshown findings.
    return [v for v in found if not not_asked([v], unshown)[0].asked]


def _judge(run: _Run, judged: _Judged) -> dict[str, Any]:
    from maljan.agents.judge_agent import (
        _SETTLED_CODES,
        VERDICT_FALLBACK_CODE,
        VERDICT_FALLBACK_REASON,
        JudgeAgent,
    )
    from maljan.agents.judge_postprocess import ASSESSMENT_RELOCATED_CODE, PROPERTY_NOT_CARRIED_CODE
    from maljan.pipeline import validation as v
    from maljan.schemas.stix_models import Bundle
    from maljan.tools import knowledge

    record = run.stored.judge
    if not record or not isinstance(record.get("bundle"), dict):
        run.name("judge", "no judge answer is stored")
        return {"replayed": False, "why": "no judge answer is stored"}
    shape: list[Any] = []
    where: list[Any] = []
    labels: dict[str, Any] = {}
    written: list[dict[str, Any]] = []
    if record.get("as_written"):
        judge = JudgeAgent.__new__(JudgeAgent)
        judge.logger = _LOG
        judge.truncation_ledger = None
        bundle = judge._bundle_from_response(
            json.dumps(record["bundle"]),
            {},
            run.isrs,
            record=shape,
            origins=where,
            labels=labels,
            as_written=written,
        )
    else:
        run.name(
            "judge",
            "the stored bundle is the parsed one, not the judge's answer as written: what the "
            "parse sets aside is not replayed",
        )
        bundle = Bundle.model_validate(record["bundle"])
    out: dict[str, Any] = {"replayed": True, "objects": len(bundle.objects)}
    fallback = bundle.x_maljan_fallback_verdict is not None
    if fallback:
        out["parsed"] = False
        run.name(
            "judge",
            "the stored answer does not read as a bundle under these rules: the round's "
            "questions about the fallback bundle's indicators are not replayed",
        )

    from maljan.agents.judge_postprocess import build_evidence_corpus
    from maljan.pipeline.evidence_summary import collect as collect_technique_sources
    from maljan.pipeline.nodes import _tools_that_were_shortened, judge_sandbox_facts

    run.name(
        "judge evidence",
        "the sandbox report is not in the stored record: the judge's corpus is the stored tool "
        "answers alone",
    )
    corpus_state = _corpus_state(run)
    searched = [e.output for e in run.ledger if e.output]
    ledger_ids = [str(e.id) for e in run.ledger]
    claims = sum(len(getattr(isr, "claims", None) or []) for isr in run.isrs.values())
    sources = {
        tid: [source for source, _confidence in rows]
        for tid, rows in collect_technique_sources(run.isrs, run.ledger).items()
    }
    # What the round asks: the parse's findings but the settled ones, and the
    # checks of the bundle.
    asked = [
        *(f for f in shape if f.code not in _SETTLED_CODES),
        *v.validate_verdict_bundle(
            bundle,
            build_evidence_corpus(interesting_strings=None, sandbox_report=None) or None,
            attck=knowledge,
            sample=dict(run.identity),
            shortened_tools=sorted(_tools_that_were_shortened(run.ledger)),
            searched=searched,
            corpus_state=corpus_state,
            technique_sources=sources,
            origins=where,
            written=written[0] if written else None,
        ),
        *v.assessment_violations(bundle),
        *v.assessment_conflict_violations(bundle),
        *v.stated_verdict_violations(bundle),
        *v.unsupported_benign_violations(bundle, analyst_claims=claims, ledger_ids=ledger_ids),
        *v.unsupported_malware_violations(bundle, analyst_claims=claims, ledger_ids=ledger_ids),
        *v.unattributed_indicator_violations(
            bundle, judge_sandbox_facts(run.ledger, run.isrs, None)
        ),
    ]
    settled = [f for f in shape if f.code in _SETTLED_CODES]
    # What the round leaves standing: each finding marked whether it was shown,
    # an unattributed indicator the judge kept after being shown the fact
    # recorded as its answer, and the properties the export does not carry.
    left = v.kept_after_the_sandbox_fact(v.not_asked(asked, _shown_to_the_judge(run, asked)))
    if fallback:
        left.append(v.Violation(code=VERDICT_FALLBACK_CODE, message=VERDICT_FALLBACK_REASON))
    else:
        left.extend(f for f in settled if f.code == PROPERTY_NOT_CARRIED_CODE)
    dropped = v.drop_ungrounded_indicators(bundle, left, origins=where)
    relocated = [f for f in settled if f.code == ASSESSMENT_RELOCATED_CODE]
    run.judge_left = left
    run.judge_settled = relocated
    run.judge_codes = {f.code for f in left}
    judged.bundle = bundle
    judged.origins = where
    flags = []
    for finding in left:
        row = _flag(finding, show_text=run.show_text)
        if not finding.asked:
            row["asked"] = False
        if finding.answered:
            row["answered"] = True
        flags.append(row)
    for finding in relocated:
        flags.append({**_flag(finding, show_text=run.show_text), "settled": True})
    out.update({"codes": _tally(flags), "flags": flags, "indicators_dropped": int(dropped)})
    return out


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


@dataclass
class _Built:
    report: Any = None
    items: Any = None
    entries: Any = None


def _reason_after(text: str, opening: str) -> str:
    """The judge's reason in ``<opening> (<reason>)``, as the matrix wrote it, or ``""``."""
    said = text[len(opening) :].strip()
    if not said.startswith("("):
        return ""
    said = said[1:]
    # A dropped technique asked with the check's finding ends ``), asked after …``.
    cut = said.rfind("), asked after ")
    return said[:cut] if cut >= 0 else said[:-1] if said.endswith(")") else said


def _stored_review(run: _Run) -> Any:
    """The judge's technique review, read back from the stored capability matrix, or ``None``.

    The review is the judge's second answer, about the techniques its bundle
    left out; the stored record keeps only what the matrix wrote of it: which
    techniques it dropped, kept or left unconfirmed, and its reasons.
    """
    from maljan.schemas.isr_models import (
        JUDGE_UNCONFIRMED_TECHNIQUE_MARKER,
        judge_dropped_reason,
        judge_kept_note,
    )
    from maljan.schemas.stix_models import TechniqueDecision, TechniqueReview

    dropped, kept = judge_dropped_reason(""), judge_kept_note("")
    asked: list[str] = []
    decisions: list[Any] = []
    for cell in (run.stored.report or {}).get("capability_matrix") or []:
        if not isinstance(cell, dict):
            continue
        tid = str(cell.get("technique_id") or "").strip().upper()
        not_published = str(cell.get("not_published") or "")
        notes = [n.strip() for n in str(cell.get("note") or "").split(";")]
        if not tid:
            continue
        if not_published.startswith(dropped):
            asked.append(tid)
            decisions.append(
                TechniqueDecision(
                    technique_id=tid,
                    decision="drop",
                    reason=_reason_after(not_published, dropped),
                )
            )
            continue
        kept_note = next((n for n in notes if n.startswith(kept)), None)
        if kept_note is not None:
            asked.append(tid)
            decisions.append(
                TechniqueDecision(
                    technique_id=tid, decision="keep", reason=_reason_after(kept_note, kept)
                )
            )
        elif JUDGE_UNCONFIRMED_TECHNIQUE_MARKER in notes:
            asked.append(tid)
    if not asked:
        return None
    run.name(
        "capability matrix",
        "the judge's technique review, a second answer of the judge's, is not stored; its "
        "decisions are read back from the stored capability matrix",
    )
    return TechniqueReview(asked=list(dict.fromkeys(asked)), decisions=decisions)


def _verdict_fallback(bundle: Any, decision: str, codes: set[str]) -> dict[str, Any] | None:
    """The judge node's record of a verdict no judge stated as a bundle, or ``None``.

    The record the judge node hands the report node (``verdict_fallback``),
    written as that node writes it from the bundle and the round's codes; the
    report node's own reading of it is the platform's
    (``the_judge_stated_the_verdict``).
    """
    from maljan.agents.judge_agent import VERDICT_FALLBACK_CODE, VERDICT_TIMEOUT_CODE
    from maljan.pipeline.outcome import normalise_verdict

    stated = getattr(bundle, "x_maljan_fallback_verdict", None) if bundle is not None else None
    recorded = bool(codes & {VERDICT_FALLBACK_CODE, VERDICT_TIMEOUT_CODE})
    if stated is None and not recorded:
        return None
    assessment = getattr(bundle, "x_maljan_assessment", None) if bundle is not None else None
    return {
        "decision": decision,
        "failure": VERDICT_TIMEOUT_CODE if VERDICT_TIMEOUT_CODE in codes else VERDICT_FALLBACK_CODE,
        "recorded": recorded,
        "stated": bool(
            assessment is not None and normalise_verdict(assessment.verdict) == decision
        ),
    }


def _replayed_validation(run: _Run) -> dict[str, Any]:
    """``run_summary.validation`` rebuilt from the replayed findings, by the platform's function.

    What survived on each analyst's claims in force and what the judge's round
    leaves standing are the unresolved rows; the judge's settled relocation is
    counted where its round counts it. Retries and what each producer was told
    and fixed are model turns, which the replay does not make.
    """
    from maljan.pipeline.validation import (
        VALIDITY_CODE,
        validation_metrics,
        validity_check_available,
    )
    from maljan.tools import knowledge

    unresolved = [
        (agent, finding) for agent, found in run.in_force_found.items() for finding in found
    ]
    unresolved.extend(("judge", finding) for finding in run.judge_left)
    fed_back = dict(Counter(finding.code for finding in run.judge_settled))
    run.name(
        "run summary",
        "run_summary.validation is rebuilt from the replayed findings (the claims in force "
        "and the judge's round): retries, what each producer was told and fixed, and the "
        "unparsed and retry answers are model turns the replay does not make",
    )
    return validation_metrics(
        0,
        unresolved,
        fed_back,
        not_run=[] if validity_check_available(knowledge) else [VALIDITY_CODE],
        unparsed_answers=[],
    )


def _build(run: _Run, judged: _Judged, built: _Built) -> dict[str, Any]:
    from maljan.agents.judge_agent import VERDICT_FALLBACK_CODE, VERDICT_FALLBACK_REASON
    from maljan.pipeline.nodes import (
        _overall_confidence,
        evidence_summary,
        the_judge_stated_the_verdict,
        with_verdict_fallback,
    )
    from maljan.pipeline.outcome import (
        corrected_reasons,
        decide_from_bundle,
        unrecognised_verdict_reason,
        verdict_for_run,
    )
    from maljan.pipeline.validation import corroboration
    from maljan.reporting.builder import MalwareReportBuilder
    from maljan.reporting.ledger_report import section_is_grounded

    bundle = judged.bundle
    if bundle is not None and getattr(bundle, "x_maljan_technique_review", None) is None:
        # Set on every bundle the judge node hands on, as the node sets it.
        bundle.x_maljan_technique_review = _stored_review(run)
    stix_output = bundle.model_dump() if bundle is not None else {}
    assessment = getattr(bundle, "x_maljan_assessment", None) if bundle is not None else None
    decision = decide_from_bundle(bundle) if bundle is not None else "Suspicious"
    unreadable = unrecognised_verdict_reason(bundle) if bundle is not None else ""
    decision, inconclusive = verdict_for_run(
        decision, evidence_entries=run.ledger, isr_reports=run.isrs
    )
    fallback = _verdict_fallback(bundle, decision, run.judge_codes)

    # The reasons this verdict carries under these rules, and the rest of the
    # stored ones, which the judge node decided from what the record does not
    # hold; all of them corrected against the ledger as the report node does.
    stored = run.stored.report or {}
    reasons = [str(r) for r in stored.get("degradation_reasons") or []]
    decided = [
        reason
        for reason in (
            VERDICT_FALLBACK_REASON if VERDICT_FALLBACK_CODE in run.judge_codes else "",
            unreadable,
            inconclusive,
        )
        if reason
    ]
    reasons.extend(reason for reason in decided if reason not in reasons)
    run.name(
        "report",
        "degraded_mode and the degradation reasons are the stored report's: the judge node "
        "decides them from inputs the record does not hold (the sandbox report, model "
        "failures, prompt notices); the verdict's own reasons are decided again and joined",
    )

    summary = copy.deepcopy(run.stored.run_summary)
    summary["validation"] = _replayed_validation(run)
    summary["corroboration"] = corroboration(run.isrs, run.ledger)
    builder = MalwareReportBuilder(
        file_hash=run.identity.get("sha256"),
        file_name=run.identity.get("file_name"),
        sample_path=None,
        sandbox_report=None,
        reports={},
        isr_reports=run.isrs,
        stix_output=stix_output,
        run_summary=summary,
        discussion_history=[],
        final_decision=decision,
        overall_confidence=_overall_confidence(
            assessment, judged=the_judge_stated_the_verdict(fallback)
        ),
        judge_assessment=assessment,
        malware_category=getattr(assessment, "malware_category", None),
        degraded_mode=bool(stored.get("degraded_mode")) or bool(decided),
        degradation_reasons=corrected_reasons(reasons, run.ledger),
        sample_platform=run.identity.get("platform"),
        sample_file_type=run.identity.get("file_type"),
        evidence_ledger=run.ledger,
    )
    report = builder.build_deterministic()
    # What the report node adds to the summary once the report is built.
    rebuilt = dict(report.run_summary or {})
    rebuilt["evidence"] = evidence_summary(run.ledger)
    if fallback and not fallback.get("recorded"):
        rebuilt["validation"] = with_verdict_fallback(
            rebuilt.get("validation"), str(fallback.get("failure", "") or "unknown")
        )
    rebuilt["sections_without_evidence"] = sum(
        1 for section in report.sections if not section_is_grounded(section)
    )
    report.run_summary = rebuilt
    built.report = report
    run.name(
        "report",
        "the sandbox report is not in the stored record: what the build reads from it alone "
        "is not rebuilt",
    )
    return {"replayed": True}


def _report_inputs(run: _Run, built: _Built) -> None:
    """The run's sandbox items and each entry's text, as the report rounds read them."""
    from maljan.analysis.sandbox_sections import ItemCitations, item_index_of
    from maljan.pipeline.validation import EntryTexts

    index = item_index_of(run.pack)
    built.items = ItemCitations(index, None) if index is not None else None
    entries = EntryTexts.from_ledger(list(run.ledger), None)
    if built.items is not None:
        from maljan.pipeline.nodes import with_item_texts

        entries = with_item_texts(entries, built.items)
    built.entries = entries


def _run_corpus(run: _Run) -> Any:
    """The run's in-memory corpus, rebuilt from the stored answers, as the export reads it."""
    from maljan.agents.run_evidence_corpus import RunEvidenceCorpus
    from maljan.core.config import get_settings

    ceiling = int(getattr(get_settings().reporting, "evidence_corpus_bytes", 0) or 0)
    corpus = RunEvidenceCorpus(ceiling)
    blanked = 0
    for entry in run.ledger:
        if entry.output:
            corpus.remember(str(entry.id), str(entry.tool or ""), str(entry.output))
        elif entry.truncated:
            blanked += 1
    if blanked:
        run.name(
            "report",
            f"the export's corpus is rebuilt from the stored answers: {blanked} answer(s) the "
            "byte budget blanked after the model read them are not in it",
        )
    return corpus


def _report_values(run: _Run, built: _Built, judged: _Judged) -> dict[str, Any]:
    """The values the export and the IOC table decide, read off the rebuilt report."""
    from maljan.core.config import get_settings
    from maljan.core.truncation_ledger import TruncationLedger
    from maljan.pipeline.evidence_summary import collect as collect_technique_sources
    from maljan.pipeline.evidence_summary import technique_evidence
    from maljan.reporting.builder import build_consolidated_iocs
    from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
    from maljan.schemas.stix_models import Bundle

    report = built.report
    reporting = get_settings().reporting
    if getattr(reporting, "include_extended_stix", True):
        base = (
            Bundle.model_validate(judged.bundle.model_dump()) if judged.bundle is not None else None
        )
        export = ExtendedSTIXRenderer().render(
            report,
            base,
            # A recorder the export's integrity pass writes into, as the run's is.
            ledger=TruncationLedger(),
            corpus=_run_corpus(run),
            technique_sources={
                tid: [source for source, _confidence in rows]
                for tid, rows in collect_technique_sources(run.isrs, run.ledger).items()
            },
            technique_evidence=technique_evidence(run.isrs, run.ledger),
            ledger_ids=[str(entry.id) for entry in run.ledger],
        )
        report.stix_bundle_extended = export.model_dump(mode="json")
        report.consolidated_iocs = build_consolidated_iocs(report)
    else:
        run.name(
            "report",
            "the run's settings leave the extended export out (reporting.include_extended_stix): "
            "the IOC table is the build's own",
        )

    from maljan.schemas.isr_models import judge_dropped_reason

    # A technique the judge dropped carries the judge's own reason; it is the
    # judge's text, printed only with the text.
    dropped = judge_dropped_reason("")
    techniques: dict[str, Any] = {}
    for cell in report.capability_matrix or []:
        tid = str(cell.technique_id or "").strip().upper()
        if not tid:
            continue
        row: dict[str, Any] = {"published": not cell.not_published}
        if cell.not_published:
            why = str(cell.not_published)
            row["why"] = dropped if why.startswith(dropped) and not run.show_text else why
        techniques[tid] = row
    for mapping in report.ttp_mappings or []:
        tid = str(mapping.technique_id or "").strip().upper()
        if tid:
            techniques.setdefault(tid, {"published": True})

    indicators: dict[str, Any] = {}
    for ioc in report.consolidated_iocs or []:
        kind = str(ioc.kind or ioc.type or "")
        key = f"{kind}:{_digest(str(ioc.value))}"
        row = {"kind": kind, "published": ioc.published}
        if run.show_text:
            row["value"] = str(ioc.value)
        indicators[key] = row

    exported: list[str] = []
    types: Counter[str] = Counter()
    for obj in (report.stix_bundle_extended or {}).get("objects") or []:
        types[str(obj.get("type") or "")] += 1
        if obj.get("type") == "attack-pattern":
            for ref in obj.get("external_references") or []:
                if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                    exported.append(str(ref.get("external_id") or ""))
    severity = getattr(report, "severity", None)
    out: dict[str, Any] = {
        "replayed": True,
        "verdict": str(report.verdict),
        "severity": str(getattr(severity, "rating", "") or "") or None,
        "category": report.malware_category,
        "confidence": report.overall_confidence,
        "degraded": bool(report.degraded_mode),
        "sections": [str(section.key) for section in report.sections],
        "persistence": len(report.persistence or []),
        "techniques": dict(sorted(techniques.items())),
        "indicators": dict(sorted(indicators.items())),
        "export": {
            "attack_patterns": sorted(t for t in exported if t),
            "objects": dict(sorted(types.items())),
        },
    }
    if getattr(reporting, "auto_generate_detection_rules", True):
        out.update(_drafts(run, report))
    else:
        run.name(
            "report",
            "the run's settings draft no detection rules (reporting.auto_generate_detection_rules)",
        )
    return out


def _claims_not_discussed(run: _Run, built: _Built) -> dict[str, list[int]]:
    """Per analyst, the numbers of the claims in force the composed body leaves undiscussed."""
    from maljan.reporting.claim_coverage import claims_not_discussed

    rows = claims_not_discussed(built.report, run.isrs)
    built.report.claims_not_discussed = rows
    out: dict[str, list[int]] = {}
    for row in rows:
        out.setdefault(str(row.agent), []).append(int(row.claim_number))
    return dict(sorted(out.items()))


def _drafts(run: _Run, report: Any) -> dict[str, Any]:
    """The detection rules drafted from what the export published, by format."""
    try:
        from maljan.reporting.builder import MalwareReportBuilder

        rules = MalwareReportBuilder.attach_detection_signatures(report).detection_signatures
    except Exception as exc:  # noqa: BLE001 — named as an error, the report values stand
        _failed(run, "detection rules", exc)
        return {}
    kinds = Counter(str(rule.kind) for rule in rules)
    return {
        "detection_rules": dict(sorted(kinds.items())),
        "detection_rules_not_compiled": sum(1 for rule in rules if rule.compile_error),
    }


def _apply_composed(run: _Run, built: _Built) -> None:
    """The composed sections the stored report holds, put on the rebuilt report as the composer
    puts its answers: what the export, the claim coverage and the linter then read."""
    from maljan.reporting.models import C2Channel, TechnicalAnalysis

    stored = run.stored.report or {}
    report = built.report
    intro = stored.get("intro_background")
    if isinstance(intro, str) and intro.strip():
        report.intro_background = intro
    technical = stored.get("technical_analysis")
    if isinstance(technical, dict):
        report.technical_analysis = TechnicalAnalysis.model_validate(technical)
    channels = stored.get("c2_channels")
    if isinstance(channels, list):
        report.c2_channels = [C2Channel.model_validate(c) for c in channels]


def _fp_linter(run: _Run, built: _Built) -> dict[str, Any]:
    """The report linter's warnings over the finished report, by rule and field."""
    from maljan.qa.fp_linter import lint_report

    flags: list[dict[str, Any]] = []
    for warning in lint_report(built.report, run.identity.get("platform") or "unknown"):
        row: dict[str, Any] = {"code": str(warning.rule), "severity": str(warning.severity)}
        if warning.field:
            row["path"] = str(warning.field)
        if run.show_text:
            row["message"] = str(warning.message)
        flags.append(row)
    return {"replayed": True, "codes": _tally(flags), "flags": flags}


def _narrative(run: _Run, built: _Built) -> dict[str, Any]:
    from maljan.pipeline import validation as v
    from maljan.reporting.builder import MalwareReportBuilder
    from maljan.reporting.narrative_agent import (
        NARRATIVE_PROSE,
        NarrativeOutput,
        published_answers,
        published_technique_ids,
    )

    stored = run.stored.report or {}
    payload = {
        "executive_summary": stored.get("executive_summary") or "",
        "key_findings": list(stored.get("key_findings") or []),
        "defensive_recommendations": list(stored.get("defensive_recommendations") or []),
    }
    report = built.report
    if not payload["executive_summary"] and not payload["key_findings"]:
        run.name("narrative", "the stored report carries no narrative")
        return {"replayed": False, "why": "the stored report carries no narrative"}
    run.name(
        "narrative",
        "a recommendation's technique id is read as stored: one the platform read out of the "
        "recommendation's own sentence is not told apart",
    )
    grounding = v.CapabilityGrounding.from_report(report, run.isrs, ledger=built.entries)
    answers = published_answers(report)
    published = published_technique_ids(report)
    known_ids = [row.id for row in report.evidence_index]
    citable = [str(entry.id) for entry in run.ledger]
    items = built.items
    entries = built.entries
    found = [
        *v.schema_violations(
            NarrativeOutput, payload, code="narrative.schema", answer=json.dumps(payload)
        ),
        *v.narrative_capability_violations(payload, grounding),
        *v.key_finding_citation_violations(payload, known_ids, items),
        *v.citation_violations(payload, citable, prose=NARRATIVE_PROSE, items=items),
        *v.wrong_entry_citations(payload, entries, prose=NARRATIVE_PROSE),
        *v.misstated_entry_contents(payload, entries, prose=NARRATIVE_PROSE),
        *v.ledger_absence_contradictions(payload, entries),
        *v.technique_name_violations(payload),
        *(v.recommendation_indicator_violations(payload, answers) if answers else []),
        *v.recommendation_technique_violations(payload, published),
    ]
    # The composer writes over the report the narrative was applied to.
    built.report = MalwareReportBuilder.apply_narrative(report, payload)
    flags = [_flag(f, show_text=run.show_text) for f in found]
    return {"replayed": True, "codes": _tally(flags), "flags": flags}


def _stored_at(report: Mapping[str, Any], place: str) -> Any:
    value: Any = report
    for part in place.split("."):
        value = value.get(part) if isinstance(value, Mapping) else None
    return value


def _composer(run: _Run, built: _Built) -> dict[str, Any]:
    from maljan.pipeline import validation as v
    from maljan.reporting import composer as c
    from maljan.reporting.evidence_bundles import (
        sample_flow_fact,
        sandbox_entry_ids,
        sandbox_item_observation,
        sandbox_saw_no_persistence,
    )
    from maljan.reporting.models import EncryptionScheme, RansomNote

    report = built.report
    stored = run.stored.report or {}
    schemas: dict[str, Any] = {
        "introduction": c._IntroOut,
        "execution_flow": c._FlowOut,
        "configuration": c._ConfigOut,
        "host_identifiers": c._HostIdentifiersOut,
        "commands": c._CommandsOut,
        "encryption_scheme": EncryptionScheme,
        "cli_flags": c._CliFlagsOut,
        "ransom_note": RansomNote,
        "communications": c._C2Out,
        **dict.fromkeys(c._PROSE_SECTIONS, c._ProseOut),
    }
    items = built.items
    entries = built.entries
    grounding = v.CapabilityGrounding.from_report(report, run.isrs, ledger=entries)
    answers = c._published_answers(report)
    citable = [str(entry.id) for entry in run.ledger]
    known_ids = [row.id for row in report.evidence_index]
    sandbox_ids = sandbox_entry_ids(report)
    observed_item = sandbox_item_observation(report, items)
    entry_tools = {row.id: str(row.tool or "") for row in report.evidence_index}
    flow_fact = sample_flow_fact(report)
    saw_no_persistence = sandbox_saw_no_persistence(report)
    extras: dict[str, list[Callable[[Any], list[Any]]]] = {
        "execution_flow": [
            lambda p: v.flow_voice_violations(
                p,
                sandbox_ids,
                tools=entry_tools,
                flow_fact=flow_fact,
                observed_item=observed_item,
            ),
            lambda p: v.persistence_not_observed_violations(
                p, saw_no_persistence, section="execution_flow"
            ),
        ],
        "persistence_detail": [
            lambda p: v.persistence_not_observed_violations(
                p, saw_no_persistence, section="persistence_detail"
            )
        ],
        "configuration": [
            lambda p: v.configuration_citation_violations(p, known_ids, items),
            lambda p: v.stated_value_violations(p, entries),
        ],
        "host_identifiers": [
            lambda p: v.identifier_citation_violations(p, known_ids, items),
            lambda p: v.stated_value_violations(p, entries),
        ],
    }
    sections: dict[str, Any] = {}
    not_written: list[str] = []
    for section in c.COMPOSED_SECTIONS:
        schema = schemas.get(section)
        if schema is None:
            run.name(f"composer {section}", "this replay does not know the section's schema")
            continue
        if section in COMPOSER_PLACES:
            place, key = COMPOSER_PLACES[section]
        else:
            place, key = f"technical_analysis.{section}", None
        value = _stored_at(stored, place)
        if not value:
            not_written.append(section)
            continue
        if section in c._PROSE_SECTIONS:
            payload: Any = {
                "body": str(value.get("body") or ""),
                "evidence_refs": list(value.get("evidence_refs") or []),
            }
        elif key is None:
            payload = dict(value)
        else:
            payload = {key: value}
        prose = c._PROSE_FIELDS.get(schema, ())
        found = [
            *v.schema_violations(
                schema, payload, code="composer.schema", answer=json.dumps(payload)
            ),
            *v.section_capability_violations(payload, grounding),
            *v.citation_violations(payload, citable, prose=prose, items=items),
            *v.wrong_entry_citations(payload, entries, prose=prose),
            *v.misstated_entry_contents(payload, entries, prose=prose),
            *v.ledger_absence_contradictions(payload, entries),
            *v.technique_name_violations(payload),
            *v.repeated_item_violations(payload, c._ITEM_IDENTITY.get(schema, {})),
            *(v.unpublished_value_violations(payload, answers) if answers else []),
        ]
        for extra in extras.get(section, []):
            found.extend(extra(payload))
        flags = [_flag(f, show_text=run.show_text) for f in found]
        sections[section] = {"codes": _tally(flags), "flags": flags}
    codes: Counter[str] = Counter()
    for section in sections.values():
        codes.update(section["codes"])
    return {
        "replayed": True,
        "codes": dict(sorted(codes.items())),
        "sections": sections,
        "not_written": not_written,
    }


# ---------------------------------------------------------------------------
# The tool calls and corroboration
# ---------------------------------------------------------------------------


def _tools(run: _Run) -> dict[str, Any]:
    from maljan.agents.evidence_recorder import SELF_NAMED_ARGUMENT_CODE, self_named_arguments

    flags: list[dict[str, Any]] = []
    for entry in run.ledger:
        arguments = entry.args if isinstance(entry.args, dict) else {}
        found = self_named_arguments(dict(arguments))
        if not found:
            continue
        row: dict[str, Any] = {
            "code": SELF_NAMED_ARGUMENT_CODE,
            "entries": [str(entry.id)],
            "tool": str(entry.tool or ""),
            "arguments": sorted(name for name, _value in found),
        }
        if run.show_text:
            row["values"] = {name: value for name, value in found}
        flags.append(row)
    return {"replayed": True, "calls": len(run.ledger), "codes": _tally(flags), "flags": flags}


def _corroboration(run: _Run, built: _Built) -> dict[str, Any]:
    from maljan.analysis.corroboration import corroborated
    from maljan.pipeline.validation import corroboration

    rows = corroboration(run.isrs, run.ledger)
    published = {
        str(m.technique_id or "").strip().upper()
        for m in (getattr(built.report, "ttp_mappings", None) or [])
    }
    out: dict[str, Any] = {}
    for tid, row in sorted(rows.items()):
        entry: dict[str, Any] = {
            "claimed_by": list(row.get("claimed_by") or []),
            "asserted_by": list(row.get("asserted_by") or []),
            "sources": list(row.get("sources") or []),
            "independent_sources": row.get("independent_sources"),
            "independent_sayers": row.get("independent_sayers"),
            "support": row.get("support") or "",
            "corroborated": bool(corroborated(row)),
        }
        if built.report is not None:
            entry["published"] = str(tid).upper() in published
        out[str(tid)] = entry
    return {"replayed": True, "techniques": out}


# ---------------------------------------------------------------------------
# The replay
# ---------------------------------------------------------------------------


def rules_source() -> dict[str, str]:
    """Where the rules this process runs were imported from."""
    import maljan

    root = Path(maljan.__file__).resolve().parents[2]
    return {"tree": str(root)}


def _environment(env: ReplayEnvironment) -> dict[str, Any]:
    out: dict[str, Any] = {
        "network": "refused",
        "attck": "the vendored tables of the rules' tree",
        "settings_from_run": env.settings_applied,
    }
    if env.settings_refused:
        out["settings_refused"] = dict(sorted(env.settings_refused.items()))
    if env.missing:
        out["doors_this_tree_lacks"] = sorted(env.missing)
    return out


def _settings_notes(run: _Run) -> None:
    """The checks no stored run can replay, and the ones this run's settings put out of reach."""
    for part, missing in (
        ("analysts", ANALYST_NOT_REPLAYED),
        ("judge", JUDGE_NOT_REPLAYED),
        ("composer", COMPOSER_NOT_REPLAYED),
    ):
        for check, why in missing.items():
            run.name(part, f"{check} is not replayed: {why}")
    run.name(
        "analysts",
        "isr.retry_dropped is not replayed: it reads a validation retry's answer against the "
        "answer it fixes, and the record keeps no retry answer",
    )
    run.name(
        "analysts",
        "whether an answer followed the loop's nudge is recorded per analyst, not per answer: "
        "each answer's parse findings are counted as questions put to it (a nudged answer's "
        "are recorded unasked)",
    )
    if _snapshot_value(run, "preprocessing.use_claim_consistency_gate"):
        run.name(
            "analysts",
            "the claim consistency gate was on in this run; its input (each analyst's data) "
            "is not stored, so every claim is checked here, the gate's included",
        )
    if _snapshot_value(run, "validation.weak_alignment"):
        run.name(
            "analysts",
            "validation.weak_alignment was on in this run: its question (attck.weak_alignment) "
            "reads the ATT&CK index, which the replay does not load",
        )


def replay_run(stored: StoredRun, *, show_text: bool = False) -> dict[str, Any]:
    """Every part of the replay over ``stored``, as one record."""
    run = _Run(stored=stored, show_text=show_text)
    out: dict[str, Any] = {"schema": REPLAY_SCHEMA, "run": stored.name}
    for file_name, why in stored.unreadable.items():
        run.name("stored run", f"{file_name} does not read as JSON ({why})")
    with replay_environment(stored.settings) as env:
        out["rules"] = rules_source()
        _read_ledger(run)
        _read_identity(run)
        _settings_notes(run)
        out["analysts"] = _analysts(run)
        judged = _Judged()
        try:
            from maljan.pipeline.validation import mark_claims_citing_only_failed_calls

            mark_claims_citing_only_failed_calls(run.isrs, run.ledger)
        except Exception as exc:  # noqa: BLE001
            _failed(run, "claims citing only failed calls", exc)
        try:
            out["judge"] = _judge(run, judged)
        except Exception as exc:  # noqa: BLE001
            out["judge"] = _failed(run, "judge", exc)
        built = _Built()
        try:
            _build(run, judged, built)
            _report_inputs(run, built)
        except Exception as exc:  # noqa: BLE001
            out["report"] = _failed(run, "report", exc)
        if built.report is not None:
            for part, fn in (("narrative", _narrative), ("composer", _composer)):
                try:
                    out[part] = fn(run, built)
                except Exception as exc:  # noqa: BLE001
                    out[part] = _failed(run, part, exc)
            try:
                _apply_composed(run, built)
            except Exception as exc:  # noqa: BLE001
                _failed(run, "composed sections", exc)
            uncovered: dict[str, list[int]] | None = None
            try:
                uncovered = _claims_not_discussed(run, built)
            except Exception as exc:  # noqa: BLE001
                _failed(run, "claims not discussed", exc)
            try:
                out["report"] = _report_values(run, built, judged)
                if uncovered is not None:
                    out["report"]["claims_not_discussed"] = uncovered
            except Exception as exc:  # noqa: BLE001
                out["report"] = _failed(run, "report values", exc)
            try:
                out["fp_linter"] = _fp_linter(run, built)
            except Exception as exc:  # noqa: BLE001
                out["fp_linter"] = _failed(run, "fp_linter", exc)
        else:
            for part in ("narrative", "composer", "fp_linter"):
                out[part] = {"replayed": False, "why": "the report was not rebuilt"}
                run.name(part, "the report was not rebuilt")
        try:
            out["tool"] = _tools(run)
        except Exception as exc:  # noqa: BLE001
            out["tool"] = _failed(run, "tool", exc)
        try:
            out["corroboration"] = _corroboration(run, built)
        except Exception as exc:  # noqa: BLE001
            out["corroboration"] = _failed(run, "corroboration", exc)
        out["environment"] = _environment(env)
    out["totals"] = totals(out)
    out["not_replayed"] = run.not_replayed
    return out


def totals(record: Mapping[str, Any]) -> dict[str, Any]:
    """Codes counted per producer, over every part of a replay record."""
    analysts: Counter[str] = Counter()
    in_force: Counter[str] = Counter()
    for agent in (record.get("analysts") or {}).values():
        for answer in agent.get("answers") or []:
            analysts.update(answer.get("codes") or {})
        in_force.update((agent.get("in_force") or {}).get("codes") or {})
    out: dict[str, Any] = {
        "answers": dict(sorted(analysts.items())),
        "claims_in_force": dict(sorted(in_force.items())),
    }
    for part in ("judge", "narrative", "composer", "tool", "fp_linter"):
        out[part] = dict(sorted(((record.get(part) or {}).get("codes") or {}).items()))
    return out
