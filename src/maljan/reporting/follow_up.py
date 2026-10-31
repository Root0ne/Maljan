"""A question asked of a finished run, answered from what the run stored.

An analyst may ask a new question after a job has finished. It is answered by
the report's question round (``reporting.question_round``), from the job's
stored run alone: its evidence ledger as stored (``evidence.json``), its
report and the run state rebuilt from both. Nothing is analysed again and no
analysis tool is called: the model may read a stored entry by its id
(``read_evidence`` over the stored ledger, ``agents.ledger_reads``), as the
round may during the run. The answer can only use what the run recorded, and a question
the stored evidence cannot settle is "not determinable from this run" with the
reason. It gets the round's checks: every id it cites must be one the run
issued, "established" needs an entry of a call that answered, "limited
negative" needs the calls that looked, and an analyst's open question is an
unknown, never an absence.

What is read back from the stored run:

- the ledger rows, each as the run's own ``LedgerEntry`` (a row this release
  cannot read is counted and said, and so is a row that keeps part of its
  answer in object storage, which is read as the row holds it);
- the report payload, as ``MalwareReport``;
- the analysts' claims in force (the stored per-agent findings) and the open
  questions they left (the report's "Open questions" section), as the ISRs the
  round reads;
- the run state the round is shown, from the report's sample identity, the
  ledger and the run summary's stages.

The sandbox report is not read back, so a sandbox item stands only as an id
the stored report cites: issued, never an answered entry.

The model is the reporter's model the run's settings snapshot recorded, served
where its provider is served now, else the current one
(:func:`reporter_overrides`); the API builds it and keeps the
answer as a record of its own (``apps/api/app/services/follow_up.py``). The
stored report is never changed. Every step is one pass over what it reads.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import MalwareReport
from maljan.reporting.question_round import QuestionRound, answer_questions

# The token ledger's name for a follow-up question's calls.
FOLLOW_UP_CALL = "follow-up"
# How the reporter's overflow sentence names a follow-up's prompt.
FOLLOW_UP_WHAT = "follow-up question's"

# The reporter's per-agent entry and the settings that pick its model with none.
_REPORTER_ENTRY = "llm.agents.reporter."
_AGENTS = "llm.agents"
_PROVIDER = "llm.provider"
# How the run's settings snapshot writes a value it hid (``settings_masking``).
_MASK = "***"

# Where a follow-up's model came from, as the record says it.
RUN_MODEL = "the reporter's model this run's settings snapshot recorded"
CURRENT_MODEL = "the current report model: this run's settings snapshot records no reporter model"
MASKED_MODEL = (
    "the current report model: this run's settings snapshot holds the reporter's model "
    "with a hidden value, so it cannot be built again"
)
UNKNOWN_PROVIDER = (
    "the current report model: the provider {provider} this run's reporter used is not "
    "registered now"
)
MOVED_MODEL = (
    "the current report model: this run's reporter called {provider} at {recorded}, and "
    "{provider} is served at {current} now, so the run's model is not asked there"
)
UNBUILT_MODEL = (
    "the current report model: the reporter's model this run recorded no longer builds "
    "settings ({error})"
)

# What a recorded model choice carries over: what picks the model, never where
# it is served (an endpoint is the current settings', with their credential).
_CHOICE_FIELDS = ("provider", "model", "effort", "temperature")
# What a current reporter entry keeps whatever model the run recorded: its ceilings.
_CEILINGS = ("max_spend_usd", "max_unpriced_tokens")


def _masked(value: Any) -> bool:
    if isinstance(value, str):
        return _MASK in value
    if isinstance(value, Mapping):
        return any(_masked(v) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_masked(v) for v in value)
    return False


def _place(endpoint: str) -> tuple[str, ...]:
    """Where an endpoint is, as two spellings of it compare: scheme, host, port and path.

    The user name, password and query are left out: the run's snapshot hides
    them, and they do not say which server a call reaches.
    """
    from urllib.parse import urlsplit

    from maljan.core.model_assignments import normalised_endpoint

    raw = normalised_endpoint(endpoint)
    parts = urlsplit(raw)
    try:
        port = parts.port
    except ValueError:
        port = None
    if not parts.scheme or not parts.hostname:
        return (raw,)
    return (parts.scheme.lower(), parts.hostname.lower(), str(port or ""), parts.path.rstrip("/"))


@dataclass
class _Recorded:
    """The model choices the run's reporter made, each with where it was served, or why none."""

    choices: list[dict[str, Any]] = field(default_factory=list)
    entry: bool = False
    source: str = CURRENT_MODEL


def recorded_reporter(snapshot: Any) -> tuple[dict[str, Any], str]:
    """The settings that pick the reporter's model as the run recorded them, and where from.

    ``snapshot`` is the run summary's ``settings_snapshot`` (dotted keys). A
    reporter entry that names a model (``llm.agents.reporter.*``) is the
    model: its provider, model, effort and temperature, and those of each model
    it falls back to. No endpoint is taken from it: where a provider is
    served, and with which credential, is the current settings' business
    (:func:`reporter_overrides`). With no entry, the reporter ran on the judge
    role: ``llm.provider`` and that provider's ``judge_model``. A snapshot that
    records neither, or holds one with a hidden value, gives nothing, and the
    reason says which.
    """
    read = _recorded(snapshot)
    choices = [{k: v for k, v in c.items() if k in _CHOICE_FIELDS} for c in read.choices]
    if not choices:
        return {}, read.source
    if read.entry:
        first, *rest = choices
        return {"reporter": {**first, "fallbacks": rest}}, read.source
    provider, model = choices[0]["provider"], choices[0]["model"]
    return {_PROVIDER: provider, f"llm.{provider}.judge_model": model}, read.source


def _recorded(snapshot: Any) -> _Recorded:
    snap = snapshot if isinstance(snapshot, Mapping) else {}
    entry = {
        key[len(_REPORTER_ENTRY) :]: value
        for key, value in snap.items()
        if isinstance(key, str) and key.startswith(_REPORTER_ENTRY)
    }
    if entry.get("provider") or entry.get("model"):
        chain = [entry, *[f for f in entry.get("fallbacks") or [] if isinstance(f, Mapping)]]
        choices = [
            {k: c.get(k) for k in _CHOICE_FIELDS if c.get(k) not in (None, "")} for c in chain
        ]
        if _masked(choices):
            return _Recorded(source=MASKED_MODEL)
        for choice, held in zip(choices, chain, strict=True):
            choice["_endpoint"] = _recorded_endpoint(snap, choice, held.get("base_url"))
        return _Recorded(choices=choices, entry=True, source=RUN_MODEL)
    provider = snap.get(_PROVIDER)
    model = snap.get(f"llm.{provider}.judge_model") if isinstance(provider, str) else None
    if not provider or not model:
        return _Recorded(source=CURRENT_MODEL)
    if _masked(provider) or _masked(model):
        return _Recorded(source=MASKED_MODEL)
    role: dict[str, Any] = {"provider": provider, "model": model}
    role["_endpoint"] = _recorded_endpoint(snap, role, None)
    return _Recorded(choices=[role], entry=False, source=RUN_MODEL)


def _recorded_endpoint(snap: Mapping[str, Any], choice: Mapping[str, Any], own: Any) -> str:
    """Where the run's reporter sent a choice's calls, as the snapshot says; ``""`` unknown."""
    from maljan.llm.provider_base import facts_of

    provider = str(choice.get("provider") or "")
    try:
        facts = facts_of(provider)
        leaf = facts.base_url_leaf
        configured = snap.get(f"llm.{provider}.{leaf}") if leaf else None
        return str(facts.endpoint(own, configured))
    except Exception:  # noqa: BLE001 — a provider not registered now: said by the caller
        return ""


def _current_endpoint(
    current: Any, provider: str, entry: Mapping[str, Any] | None
) -> tuple[str, str | None]:
    """Where ``provider`` is served under the current settings, and the base URL that says so.

    The current reporter entry's own address for the provider first (its first
    model of that provider that names one), else the provider's configured
    address, else its default (no base URL).
    """
    from maljan.llm.provider_base import facts_of

    facts = facts_of(provider)
    chain: list[Mapping[str, Any]] = []
    if isinstance(entry, Mapping):
        chain = [entry, *[f for f in entry.get("fallbacks") or [] if isinstance(f, Mapping)]]
    configured = facts.configured_base_url(current)
    for held in chain:
        if str(held.get("provider") or "") == provider and held.get("base_url"):
            own = str(held["base_url"])
            return str(facts.endpoint(own, configured)), own
    return str(facts.endpoint(None, configured)), None


def reporter_overrides(
    overrides: Mapping[str, Any], snapshot: Any, current: Any = None
) -> tuple[dict[str, Any], str]:
    """``overrides`` (the stored core settings) with the run's reporter model laid over them.

    Only what picks the model is taken from the run: provider, model, effort
    and temperature, for each model of its list (:func:`recorded_reporter`).
    Where each is served is the current settings' (``current``, else built
    from ``overrides``): the current reporter entry's own address for that
    provider, else the provider's configured one, so the evidence and the
    provider's current credential only go where the operator points them now.
    A recorded model whose provider is no longer registered, or that the run
    called at another place than its provider is served now, is not asked:
    the current report model is, and the source says why.

    The current reporter entry's ceilings are kept under the run's model. A run
    whose reporter ran on the judge role keeps a current entry that holds only
    ceilings and drops one that names a model, so the role's model is built.
    Nothing recorded leaves ``overrides`` as they are.
    """
    from maljan.core.model_assignments import builds_provider, endpoint_label

    read = _recorded(snapshot)
    if not read.choices:
        return dict(overrides), read.source
    if current is None:
        from maljan.core.settings_overrides import build_settings

        current = build_settings(overrides)
    merged = dict(overrides)
    stored = merged.get(_AGENTS)
    agents = dict(stored) if isinstance(stored, Mapping) else {}
    entry = agents.get("reporter")
    held = dict(entry) if isinstance(entry, Mapping) else None
    built: list[dict[str, Any]] = []
    for choice in read.choices:
        provider = str(choice.get("provider") or "")
        recorded = str(choice.get("_endpoint") or "")
        if not provider or not builds_provider(provider) or not recorded:
            return dict(overrides), UNKNOWN_PROVIDER.format(provider=provider or "(none)")
        # On the judge role the model is built from the provider's own
        # address, never a reporter entry's: compared with that address alone.
        now, own = _current_endpoint(current, provider, held if read.entry else None)
        if _place(recorded) != _place(now):
            if _masked(recorded):
                return dict(overrides), MASKED_MODEL
            return dict(overrides), MOVED_MODEL.format(
                provider=provider, recorded=endpoint_label(recorded), current=endpoint_label(now)
            )
        rebuilt = {k: v for k, v in choice.items() if k in _CHOICE_FIELDS}
        if own is not None:
            rebuilt["base_url"] = own
        built.append(rebuilt)
    ceilings = {k: held[k] for k in _CEILINGS if held and held.get(k) is not None}
    if read.entry:
        first, *rest = built
        agents["reporter"] = {**first, "fallbacks": rest, **ceilings}
    else:
        if ceilings:
            agents["reporter"] = ceilings
        else:
            agents.pop("reporter", None)
        merged[_PROVIDER] = built[0]["provider"]
        merged[f"llm.{built[0]['provider']}.judge_model"] = built[0]["model"]
    merged[_AGENTS] = agents
    return merged, read.source


# ---------------------------------------------------------------------------
# The stored run, read back
# ---------------------------------------------------------------------------


@dataclass
class StoredRun:
    """What a follow-up question is answered from: the run as it stored itself.

    ``notes`` says what could not be read back, in the platform's words.
    """

    report: MalwareReport
    ledger: list[Any] = field(default_factory=list)
    citable: list[str] = field(default_factory=list)
    isr_reports: dict[str, Any] = field(default_factory=dict)
    state: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def stored_ledger(rows: Iterable[Mapping[str, Any]]) -> tuple[list[Any], int]:
    """The stored ledger rows as ``LedgerEntry``, in ``seq`` order, and how many did not read.

    A column the row holds as null reads as absent: a database row keeps
    NULL where the entry carried nothing and on every row older than the
    column (``app.models.evidence``), and the entry's default stands for
    that. Every field that admits null defaults to it, so a row that read
    before reads the same.
    """
    from maljan.schemas.evidence import LedgerEntry

    fields = set(LedgerEntry.model_fields)
    ledger: list[Any] = []
    unread = 0
    for row in rows or ():
        if not isinstance(row, Mapping):
            unread += 1
            continue
        kept = {k: v for k, v in row.items() if k in fields and v is not None}
        kept["id"] = row.get("entry_id") or row.get("id")
        try:
            ledger.append(LedgerEntry.model_validate(kept))
        except Exception:  # noqa: BLE001 — counted and said
            unread += 1
    ledger.sort(key=lambda entry: int(getattr(entry, "seq", 0) or 0))
    return ledger, unread


def spilled_rows(rows: Iterable[Any]) -> int:
    """How many stored ledger rows name a part of their answer kept outside the row.

    A ``spilled`` reference (``schemas.evidence_spill``) names a part the row
    does not hold whole; the object store is not read back, so such a row's
    content is read cut.
    """
    count = 0
    for row in rows or ():
        if isinstance(row, Mapping) and any(
            isinstance(ref, Mapping) for ref in row.get("spilled") or []
        ):
            count += 1
    return count


def _column(columns: Sequence[str], name: str) -> int | None:
    lowered = [str(c).strip().lower() for c in columns]
    return lowered.index(name) if name in lowered else None


def _cell(row: Sequence[Any], index: int | None) -> str:
    if index is None or index >= len(row):
        return ""
    return str(row[index] or "").strip()


def stored_open_questions(report: MalwareReport) -> dict[str, list[Any]]:
    """The open questions the analysts left, by agent, read off the report's own section.

    The "Open questions" section (``ledger_report``) prints each question's
    agent, text, why it is open, what would answer it and the entries it
    rests on; each row is read back into the ``OpenQuestion`` it was printed
    from. A reason the section wrote that is not one of the set is ``other``,
    with the cell as its detail.
    """
    from maljan.reporting.models import is_open_question_section
    from maljan.schemas.isr_models import OPEN_QUESTION_REASONS, OpenQuestion

    out: dict[str, list[Any]] = {}
    for section in report.sections:
        if not is_open_question_section(section):
            continue
        columns = list(section.columns)
        agent_at = _column(columns, "agent")
        question_at = _column(columns, "question")
        why_at = _column(columns, "why open")
        answer_at = _column(columns, "what would answer it")
        evidence_at = _column(columns, "evidence")
        for row in section.rows:
            text = _cell(row, question_at)
            if not text:
                continue
            why = _cell(row, why_at)
            reason, _, detail = why.partition(": ")
            if reason not in OPEN_QUESTION_REASONS:
                reason, detail = "other", why
            agent = _cell(row, agent_at)
            evidence = [v.strip() for v in _cell(row, evidence_at).split(",") if v.strip()]
            try:
                question = OpenQuestion.model_validate(
                    {
                        "question": text,
                        "why_open": reason,
                        "detail": detail,
                        "would_answer": _cell(row, answer_at),
                        "evidence_ids": evidence,
                    }
                )
            except Exception:  # noqa: BLE001 — a row that will not read is left out
                continue
            out.setdefault(agent, []).append(question)
    return out


def stored_isrs(
    findings: Iterable[Mapping[str, Any]], report: MalwareReport
) -> tuple[dict[str, Any], int]:
    """The analysts' ISRs as the round reads them, and how many stored claims did not read.

    Each stored per-agent finding row gives its claims in force and dissent;
    the open questions are the report's (:func:`stored_open_questions`). An
    agent that left a question and has no finding row still carries it.
    """
    from maljan.schemas.isr_models import AgentISR, ClaimEvidence

    questions = stored_open_questions(report)
    isrs: dict[str, Any] = {}
    unread = 0
    for row in findings or ():
        if not isinstance(row, Mapping):
            continue
        agent = str(row.get("agent_name") or "").strip()
        if not agent:
            continue
        claims: list[Any] = []
        for claim in row.get("claims") or []:
            try:
                claims.append(ClaimEvidence.model_validate(claim))
            except Exception:  # noqa: BLE001 — counted and said
                unread += 1
        isrs[agent] = AgentISR(
            agent_id=agent,
            domain=str(row.get("domain") or agent),
            claims=claims,
            dissent_items=[str(d) for d in row.get("dissent_items") or []],
            revision_round=int(row.get("revision_rounds") or 0),
            open_questions=questions.pop(agent, []),
        )
    for agent, left in questions.items():
        key = agent or "analysts"
        isrs[key] = AgentISR(agent_id=key, domain=key, revision_round=0, open_questions=left)
    return isrs, unread


def _cited_by_report(report: MalwareReport) -> list[str]:
    """Every id the stored report itself cites: issued by the run, whatever it names."""
    ids: list[str] = []
    for section in report.sections:
        ids.extend(str(v) for v in section.evidence_ids if str(v).strip())
    ids.extend(str(row.id) for row in report.evidence_index if str(row.id).strip())
    return ids


def _stages(run_summary: Any) -> dict[str, Any]:
    rows = run_summary.get("stages") if isinstance(run_summary, Mapping) else None
    return {
        str(row.get("key")): row
        for row in rows or []
        if isinstance(row, Mapping) and str(row.get("key") or "")
    }


def stored_run(
    payload: Any,
    evidence: Iterable[Mapping[str, Any]],
    findings: Iterable[Mapping[str, Any]] = (),
    run_summary: Any = None,
) -> StoredRun:
    """The run a follow-up is answered from, read back from what the job stored.

    ``payload`` is the stored report payload, ``evidence`` the stored ledger
    rows (``evidence.json``'s items), ``findings`` the per-agent finding rows
    and ``run_summary`` the stored run summary. Raises ``ValueError`` when the
    report payload does not read as a report: nothing can be answered from it.
    """
    try:
        report = MalwareReport.model_validate(payload)
    except Exception as exc:
        raise ValueError(
            f"the stored report does not read as a report ({type(exc).__name__})"
        ) from None
    notes: list[str] = []
    rows = list(evidence or ())
    ledger, unread = stored_ledger(rows)
    if unread:
        notes.append(f"{unread} stored ledger row(s) do not read as ledger entries")
    spilled = spilled_rows(rows)
    if spilled:
        notes.append(
            f"{spilled} stored ledger row(s) keep part of their answer in object storage; "
            "the follow-up read them as the row holds them, cut"
        )
    if not ledger:
        notes.append("the stored run holds no evidence ledger")
    isrs, unread_claims = stored_isrs(findings, report)
    if unread_claims:
        notes.append(f"{unread_claims} stored claim(s) do not read as claims")
    citable = list(
        dict.fromkeys(
            [
                *(str(e.id) for e in ledger if str(getattr(e, "id", "") or "")),
                *_cited_by_report(report),
            ]
        )
    )
    identity = report.identity
    state = {
        "file_hash": identity.hashes.sha256,
        "file_name": identity.file_name or "",
        "file_type": identity.file_type,
        "platform": identity.platform,
        "evidence_ledger": ledger,
        "stage_results": _stages(run_summary),
    }
    return StoredRun(
        report=report,
        ledger=ledger,
        citable=citable,
        isr_reports=isrs,
        state=state,
        notes=notes,
    )


async def answer_follow_up(
    reporter: Any, run: StoredRun, question: str, *, facts_block: str = ""
) -> QuestionRound:
    """Ask the reporter's model one question of the stored run; check and settle its answer.

    The question round, as the report stage runs it, over the stored run:
    the same prompt, the same checks, one retry. ``reporter`` is a
    ``NarrativeAgent`` (its ``ask`` holds the call to its output and spend
    bounds and records it on the token ledger under :data:`FOLLOW_UP_CALL`);
    ``None`` leaves the question "not determinable from this run" with the
    reason. ``facts_block`` is the triage pack as the reporter is shown it.
    Never raises.
    """
    from maljan.agents.ledger_reads import LedgerReads
    from maljan.pipeline.run_state import render_run_state
    from maljan.pipeline.validation import EntryTexts

    # The stored ledger, which the reporter's call may read by id, as the
    # question round reads the run's during the run.
    if run.ledger and reporter is not None and getattr(reporter, "ledger_reads", 0) is None:
        reporter.ledger_reads = LedgerReads(run.ledger)
    try:
        texts = EntryTexts.from_ledger(run.ledger, None)
    except Exception as exc:  # noqa: BLE001 — the prose checks then read no entry text
        logger.warning("follow-up: the entries' texts could not be read (%s).", exc)
        texts = None
    return await answer_questions(
        reporter,
        run.report,
        [" ".join(str(question).split())],
        ledger=run.ledger,
        citable_ids=run.citable,
        isr_reports=run.isr_reports,
        facts_block=facts_block,
        run_state=render_run_state(run.state),
        evidence_texts=texts,
        call=FOLLOW_UP_CALL,
        what=FOLLOW_UP_WHAT,
    )
