"""Single-round LLM narrative generation for ``MalwareReport``.

The deterministic ``MalwareReportBuilder`` produces every section of the
report except the prose:

  - ``executive_summary``        — one paragraph SOC-handover style summary
  - ``key_findings``             — bullets, each one finding with the
                                   evidence ids it stands on
  - ``defensive_recommendations``— P0/P1/P2 actions

The capability paragraphs this round used to write are the technical-analysis
subsections the composer writes, one subsection per call, each cited.

``NarrativeAgent.generate()`` runs **once** and falls back gracefully on
any LLM error. The caller (``report_node``) then dispatches between
``MalwareReportBuilder.apply_narrative`` (success) and
``apply_fallback_narrative`` (failure / mock).

The implementation deliberately mirrors the structured-output pattern in
``judge_agent.py:_extract_mediator_verdict`` so the operational behaviour is
familiar to anyone debugging existing agents.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field

from maljan.agents.base_agent import retry_on_connection_error
from maljan.core.config import REPORTER_AGENT_KEY
from maljan.core.logger import logger
from maljan.core.token_ledger import structured_answer
from maljan.llm.registry import structured_output_supported_for_llm
from maljan.pipeline.validation import (
    KEPT_WITH_A_FINDING,
    CapabilityGrounding,
    EntryTexts,
    ValidationTally,
    Violation,
    citation_violations,
    key_finding_citation_violations,
    narrative_capability_violations,
    pack_line_ids,
    record_flagged_statements,
    retry_with_feedback,
    schema_violations,
    technique_name_violations,
    wrong_entry_citations,
)
from maljan.reporting.models import (
    DefensiveRecommendation,
    KeyFinding,
    MalwareReport,
    confidence_text,
)
from maljan.utils.json_cleaner import safe_parse_json

# ---------------------------------------------------------------------------
# Structured output schema
# ---------------------------------------------------------------------------


class NarrativeOutput(BaseModel):
    """LLM output schema. ``DefensiveRecommendation`` is reused as-is."""

    # ``extra="ignore"`` so a chatty LLM that produces extra metadata fields
    # (e.g. "confidence_in_narrative") does not cause validation to crash.
    model_config = ConfigDict(extra="ignore")

    # Lower bounds only: an answer is as long as its evidence needs, and the
    # model decides that. A summary, findings and recommendations each have
    # to be there; no upper bound cuts what the evidence supports.
    executive_summary: str = Field(min_length=120)
    key_findings: list[KeyFinding] = Field(min_length=2)
    defensive_recommendations: list[DefensiveRecommendation] = Field(min_length=3)


# The exact object the answer has to be, with an example of every field. A model
# shown the keys answers with them; a model shown a description of the keys
# answered with its own names on two unrelated models six times out of six.
EXPECTED_OBJECT = """{
  "executive_summary": "One paragraph of at least 120 characters.",
  "key_findings": [
    {"text": "One sentence stating one finding.", "evidence_ids": ["ev_0007"]}
  ],
  "defensive_recommendations": [
    {
      "category": "edr_hunting",
      "action": "The concrete step to take.",
      "rationale": "Why this sample makes it necessary.",
      "priority": "P1",
      "technique_id": "T1490",
      "detection": "The exact observable: API, registry key, event id or rule."
    }
  ]
}"""

EXAMPLE_OBJECT = """{
  "executive_summary": "The sample is a file-encrypting ransomware executable that we assess \
with moderate confidence belongs to a known ransomware family. It encrypts documents on local \
and mapped drives, appends one fixed extension to each file and leaves a note in every folder \
it touches [ev_0012, ev_0019]. Affected hosts should be isolated and restored \
from offline backups.",
  "key_findings": [
    {"text": "It enumerates fixed and mapped network drives before encrypting.",
     "evidence_ids": ["ev_0008"]},
    {"text": "It deletes volume shadow copies with vssadmin before encrypting.",
     "evidence_ids": ["ev_0014"]},
    {"text": "It likely uses a separate key for each file; no key material was recovered.",
     "evidence_ids": []}
  ],
  "defensive_recommendations": [
    {"category": "edr_hunting", "action": "Alert on vssadmin.exe deleting shadow copies.",
     "rationale": "The sample removes shadow copies before encrypting.", "priority": "P0",
     "technique_id": "T1490",
     "detection": "Sysmon event 1 for vssadmin.exe with delete shadows on its command line."},
    {"category": "other", "action": "Keep offline, versioned backups of file shares.",
     "rationale": "Encrypted files cannot be recovered without them.", "priority": "P1",
     "technique_id": "T1486",
     "detection": "Many renames to one new extension within minutes on a file server."},
    {"category": "user_awareness",
     "action": "Warn users not to open unexpected executables from shared folders.",
     "rationale": "The sample needs a user to start it.", "priority": "P2",
     "technique_id": "T1204.002",
     "detection": "Process creation of an unsigned executable from a user share."}
  ]
}"""


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


_SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer producing a CTI analyst report. "
    "Write in calm, technical prose suitable for a SOC handover. "
    "STRICT RULES:\n"
    "1. DO NOT invent capabilities, families, or TTPs. Only describe what the "
    "deterministic evidence below supports. A sandbox answer with nothing in it is "
    "not an execution: describe sandbox behaviour, seen or absent, only where a "
    "sandbox entry above records some.\n"
    "2. Every MITRE ATT&CK technique you cite must appear in parentheses with "
    "its ID, e.g. 'inhibit system recovery (T1490)'.\n"
    "3. executive_summary: one paragraph of at least 120 characters, no headings. This "
    "is a verdict/impact briefing ONLY — state the classification, the severity, "
    "the single most important risk, and the containment call to action. Do NOT "
    "enumerate individual techniques here.\n"
    '4. key_findings: a JSON ARRAY of at least two objects, each {"text": one finding, '
    '"evidence_ids": [the ev_ ids it stands on]}. Emit the key ONCE with a list '
    "value. Cover what the sample is, what it does, how it persists, how it talks "
    "to its C2, how it is detected and what is uncertain. Cite only ev_ ids that "
    "appear in the evidence above; leave evidence_ids empty rather than invent one. "
    "A finding may only summarise what the evidence above holds: never introduce a "
    "fact nothing above states.\n"
    "5. defensive_recommendations: at least three entries, one per action. Each entry "
    "is a JSON object "
    "with EXACTLY these six fields, and the first four are REQUIRED:\n"
    "   - `category`: one of firewall, edr_hunting, registry_hardening, gpo, "
    "patching, user_awareness, other\n"
    "   - `action`: the concrete step to take\n"
    "   - `rationale`: why this sample makes that step necessary\n"
    "   - `priority`: P0, P1 or P2 — P0 only for active C2 / exfiltration / "
    "wiper-grade prevention, P1 for hardening, P2 for hunt / telemetry tasks\n"
    "   - `technique_id`: the ATT&CK technique it defends against, chosen from "
    "the 'Published ATT&CK techniques' list above (null only if none applies)\n"
    "   - `detection`: CONCRETE technical detection guidance — name the "
    "specific API call, registry key, telemetry source (e.g. Sysmon EventID 3 "
    "for network, EventID 13 for registry), or a sigma/yara pointer. Do NOT "
    "write generic advice like 'monitor for suspicious activity'; cite the "
    "exact observable.\n"
    "   Each entry is a distinct, non-overlapping action; do not duplicate an "
    "action already implied by the narrative prose.\n"
    "6. The three fields must NOT restate one another — a reader should be able "
    "to read all three with no repeated sentences.\n"
    "7. State facts plainly and write inferences with estimative words ('likely', "
    "'we assess'); name a confidence level only for attribution. Cite ev_ ids in "
    "square brackets where a sentence rests on an entry, e.g. [ev_0007]. No second "
    "person and no marketing tone.\n"
    "8. Answer with exactly this JSON object, these keys and no others:\n"
    + EXPECTED_OBJECT
    + "\nFor example (the shape only; write what this run's evidence supports):\n"
    + EXAMPLE_OBJECT
)


_LIST_FIELDS = ("key_findings", "defensive_recommendations")

# The calls the manual path may make: the answer and the one retry the
# validation loop gives an answer it finds fault with.
NARRATIVE_ATTEMPTS = 2


def _parse_keeping_duplicate_keys(text: str) -> dict[str, Any] | None:
    """Parse the model's JSON without letting a repeated key overwrite the earlier one.

    Measured on a local model: asked for a list of paragraphs, it emitted the
    list's key **three times as separate keys of one object** rather than once
    with an array. JSON says the last duplicate wins, so ``json.loads`` silently
    reduced three items to one, which then failed list validation — and with
    structured output disabled for local servers there was nothing left to
    catch it.

    Collecting duplicates recovers exactly what the model meant to say. Returns
    ``None`` when the text is not parseable JSON at all, leaving the ordinary
    fence-stripping parser to try.
    """
    import json as _json

    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key not in out:
                out[key] = value
                continue
            existing = out[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                out[key] = [existing, value]
        return out

    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = candidate.split("```", 2)[1] if candidate.count("```") >= 2 else candidate
        candidate = candidate.removeprefix("json").strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        parsed = _json.loads(candidate[start : end + 1], object_pairs_hook=_pairs)
    except Exception:  # noqa: BLE001 — an unparseable body is the other path's problem
        return None
    return parsed if isinstance(parsed, dict) else None


def _narrative_payload(answer: Any) -> dict[str, Any] | None:
    """The model's answer as the dict ``NarrativeOutput`` is validated against.

    Returns ``None`` when there is no JSON in it at all, which
    ``schema_violations`` reports as its own violation rather than treating as
    an empty answer.
    """
    text = _message_text(answer)
    payload = _parse_keeping_duplicate_keys(text) or safe_parse_json(text)
    if not isinstance(payload, dict):
        return None
    return _coerce_narrative_payload(payload)


def _coerce_narrative_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalise shapes the schema accepts but the model reaches for differently.

    Deliberately narrow. It repairs *shape*, never content: a single string
    where a list is declared becomes a one-item list, and nothing invents a
    field the model did not supply — a recommendation missing ``action`` still
    fails validation, because a report that ships an invented remediation step
    is worse than one that ships none.
    """
    out = dict(payload)
    for field in _LIST_FIELDS:
        value = out.get(field)
        if isinstance(value, str):
            out[field] = [value]
        elif isinstance(value, dict):
            out[field] = [value]
    return out


def build_prompt_text(report: MalwareReport) -> str:
    """Return the human-readable prompt body (used by ``_build_prompt`` and tests).

    Every published technique, signature, indicator and persistence entry,
    each whole: the model reads all of what the run established.
    """
    lines: list[str] = [
        "DETERMINISTIC FINDINGS",
        "----------------------",
        f"Verdict: {report.verdict}",
        (
            "Overall confidence: not assessed"
            if report.overall_confidence is None
            else f"Overall confidence: {report.overall_confidence:.2f}"
        ),
        (f"Severity: {report.severity.rating}" if report.severity else "Severity: not assessed"),
        f"Malware category: {report.malware_category or 'unknown'}",
        (
            f"Attribution family: {report.attribution.family or 'unknown'} "
            + (
                "(confidence not assessed)"
                if report.attribution.family_confidence is None
                else f"(confidence {report.attribution.family_confidence:.2f})"
            )
        ),
        "",
    ]

    # Every published fact below is shown whole: no count and no character cut
    # decides what the model may read. The stage's window accounts for the
    # prompt (``NarrativeAgent.prompt_chars`` and ``_call_bound``), and a
    # prompt that does not fit is recorded, not trimmed here.

    # --- TTPs ----------------------------------------------------------
    lines.append("Published ATT&CK techniques:")
    if not report.ttp_mappings:
        lines.append("  (none mapped)")
    else:
        from maljan.analysis.corroboration import rule_match_only
        from maljan.reporting.composer import RULE_ONLY_NOTE

        rule_only = rule_match_only(report)
        for mapping in report.ttp_mappings:
            quote = " | ".join(q for q in mapping.evidence_quotes if q)
            layers = ",".join(mapping.contributing_layers) or "-"
            rule_note = (
                f" — {rule_only[mapping.technique_id]}" if mapping.technique_id in rule_only else ""
            )
            lines.append(
                f"  - {mapping.technique_id} {mapping.technique_name} "
                f"(conf={confidence_text(mapping.confidence)}, layers={layers}){rule_note}: "
                f"{quote}"
            )
        if any(m.technique_id in rule_only for m in report.ttp_mappings):
            lines.append(f"  {RULE_ONLY_NOTE}")
    lines.append("")

    # --- Sandbox signatures ---------------------------------------------
    lines.append("Sandbox signatures:")
    if report.dynamic and report.dynamic.sandbox_signatures:
        for sig in report.dynamic.sandbox_signatures:
            ttps = ",".join(sig.technique_ids) or "-"
            lines.append(f"  - {sig.name} (severity {sig.severity}, ATT&CK={ttps})")
    else:
        lines.append("  (none)")
    lines.append("")

    # --- Import capability profile (the pack's api_capability entry) --------
    lines.append("Import capability profile (as the knowledge table states it):")
    if report.static:
        ordered = sorted(report.static.api_capabilities.items(), key=lambda kv: -kv[1])
        if ordered:
            cited = ", ".join(report.static.api_capabilities_evidence_ids)
            lines.append(
                "  "
                + ", ".join(f"{cat} x{count}" for cat, count in ordered)
                + (f" [{cited}]" if cited else "")
            )
        else:
            lines.append("  (none stated)")
        rule_hits = [
            h for h in report.static.api_technique_hits if h.get("source") == "api_capability"
        ]
        for hit in rule_hits:
            apis = ", ".join(str(a) for a in (hit.get("matched_apis") or []))
            cite = f" [{hit['evidence_id']}]" if hit.get("evidence_id") else ""
            # The rule's own label, because a row is a rule: two rules for one
            # technique carry the catalogue's name twice and rendered as two
            # lines the model could only read as a duplicate.
            rule = f" ({hit['rule']})" if hit.get("rule") else ""
            lines.append(
                f"  - {hit.get('technique_id', '?')} {hit.get('name', '')}{rule}: {apis}{cite}"
            )
    else:
        lines.append("  (no static analysis)")
    lines.append("")

    # --- Network IOCs (the suspicious ones first) ----------------------
    lines.append("Network IOCs:")
    if report.network:
        domains = [d for d in report.network.domains if d.is_suspicious] + [
            d for d in report.network.domains if not d.is_suspicious
        ]
        for dom in domains:
            reason = dom.reason or "observed"
            lines.append(f"  - domain: {dom.fqdn} ({reason})")
        for ip in report.network.ips:
            note = ip.reputation.get("_heuristic_reason") if ip.reputation else None
            tag = note or ("suspicious" if ip.is_suspicious else "observed")
            lines.append(f"  - ip: {ip.address} ({tag})")
    else:
        lines.append("  (no network data)")
    lines.append("")

    # --- Persistence ---------------------------------------------------
    lines.append("Persistence:")
    if report.persistence:
        for mech in report.persistence:
            lines.append(
                f"  - {mech.kind}: {mech.target or ''} ({mech.technique_id or 'no-ATT&CK-id'})"
            )
    else:
        lines.append("  (none detected)")
    lines.append("")

    # --- Static hints --------------------------------------------------
    if report.static:
        if report.static.packer_hint:
            lines.append(f"Packer hint: {report.static.packer_hint}")
        if report.static.obfuscation_indicators:
            ind = ", ".join(report.static.obfuscation_indicators)
            lines.append(f"Obfuscation indicators: {ind}")
        lines.append("")

    lines.extend(
        [
            "TASK",
            "----",
            "Write the three narrative fields described in the system prompt. "
            "Return ONLY the JSON object shown there, with those keys.",
        ]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


# The narrative's prose fields: the only ones a citation is looked for in.
NARRATIVE_PROSE = ("executive_summary", "key_findings")


class NarrativeAgent:
    """One LLM round producing ``NarrativeOutput``. Async, no retry."""

    def __init__(
        self,
        llm: BaseChatModel,
        token_ledger: Any | None = None,
        model_label: str = "",
        *,
        output_cap: int = 0,
        budget_note: str = "",
        generation_rates: Any | None = None,
        window_tokens: int = 0,
    ) -> None:
        self.llm = llm
        # The window the reporter's model serves, 0 when nothing reported one:
        # a call whose budget would not fit beside its prompt is held to what
        # the window leaves (:meth:`_call_bound`).
        self.window_tokens = int(window_tokens or 0)
        # What one answer of this round may run to and how it was reached
        # (``container.report_stage_budget``), and the job's measured rates:
        # together they size the round's wait (:meth:`round_timeout`).
        self.output_cap = int(output_cap or 0)
        self.budget_note = budget_note
        self.generation_rates = generation_rates
        # The narrative round is a real LLM call and counts toward the run's
        # token total on both paths: the structured one asks for the raw turn
        # beside the parsed answer, because the parser hides the usage.
        self.token_ledger = token_ledger
        # The label of the model the round calls first, so a call is recorded
        # under a model even when the answer does not name one.
        self.model_label = model_label
        # The job's event sink, set by the container, so a switch of the
        # reporter's model list is said in the conversation like any agent's.
        self.event_sink: Any | None = None
        # What this round was told was wrong with its answer, by code. The
        # narrative runs after the run summary is built, so the report node
        # reads this and folds it in rather than the builder collecting it.
        self.validation_tally = ValidationTally()
        # What this round's prompt could not hold, in the report's own words;
        # the report node adds each to the report's degradation reasons.
        self.degradations: list[str] = []

    def attempts(self) -> int:
        """The calls this round may make: its answer and one validation retry,
        plus the structured attempt first where the endpoint supports one.

        The structured attempt is counted even for a round whose calls are held
        to the window and so go by the manual path: the wait is then one call
        longer than needed, which errs on the side of waiting.
        """
        return NARRATIVE_ATTEMPTS + (1 if structured_output_supported_for_llm(self.llm) else 0)

    def round_timeout(self, configured: float, prompt_chars: int = 0) -> float:
        """This round's wait: configured, or what its calls need at the model's pace.

        The composer section's rule (``ReportComposer._section_timeout``):
        where the model's rate is measured, each call is given the time its
        output cap takes at that pace (``GenerationRates.call_timeout``, with
        the prompt read at the reading rate where one is measured), and the
        round holds :meth:`attempts` such calls; where it is not, or the round
        has no output cap, the configured wait stands. Recorded in the run
        summary as ``narrative:round``.
        """
        configured = float(configured)
        rates = getattr(self, "generation_rates", None)
        if rates is None:
            return configured
        from maljan.llm.context_window import CHARS_PER_TOKEN
        from maljan.llm.generation_rate import model_name_of

        per_call = float(
            rates.call_timeout(
                "narrative:round",
                model_name_of(self.llm),
                configured,
                int(getattr(self, "output_cap", 0) or 0),
                budget=str(getattr(self, "budget_note", "") or ""),
                prompt_tokens=-(-int(prompt_chars) // CHARS_PER_TOKEN),
            )
        )
        if per_call <= configured:
            return configured
        return per_call * self.attempts()

    def _call_bound(self, turns: Sequence[BaseMessage]) -> int | None:
        """The ``max_tokens`` one call of this round is held to, or ``None``.

        The composer's rule (``context_window.call_output_bound``): where the
        window is known and the budget would not fit beside the prompt, the
        call may write what the window leaves after it.
        """
        from maljan.llm.context_window import (
            accepts_output_bound,
            call_output_bound,
            prompt_overflow_sentence,
        )

        chars = sum(len(str(getattr(message, "content", "") or "")) for message in turns)
        window = int(getattr(self, "window_tokens", 0) or 0)
        overflow = prompt_overflow_sentence("narrative round's", chars, window)
        if overflow is not None and overflow not in self.degradations:
            self.degradations.append(overflow)
        bound = call_output_bound(int(getattr(self, "output_cap", 0) or 0), window, chars)
        if bound is None or not accepts_output_bound(self.llm):
            return None
        return bound

    def _note_room(self, prompt_chars: int) -> None:
        """Record, once, a prompt larger than what the window leaves after the budget.

        Every published fact enters the prompt whole; a prompt that does not
        fit is said, and its calls are held to what the window leaves
        (:meth:`_call_bound`), rather than a fact being left out.
        """
        from maljan.llm.context_window import CHARS_PER_TOKEN

        window = int(getattr(self, "window_tokens", 0) or 0)
        if window <= 0:
            return
        room = max(0, (window - int(getattr(self, "output_cap", 0) or 0)) * CHARS_PER_TOKEN)
        if int(prompt_chars) <= room:
            return
        reason = (
            f"The narrative round's prompt ({int(prompt_chars)} characters) exceeds the "
            f"{room} its model's context window leaves after the reply; its answer was "
            "held to what the window leaves."
        )
        if reason not in self.degradations:
            self.degradations.append(reason)
            logger.warning("NarrativeAgent: %s", reason)

    def prompt_chars(
        self, report: MalwareReport, facts_block: str = "", run_state: str = ""
    ) -> int:
        """The characters of this round's first prompt, as :meth:`generate` builds it."""
        try:
            messages = self._build_prompt(report, facts_block, run_state)
            return sum(len(str(message.content)) for message in messages)
        except Exception:  # noqa: BLE001 — a size is never worth a lost round
            return len(_SYSTEM_PROMPT) + len(facts_block) + len(run_state)

    async def generate(
        self,
        report: MalwareReport,
        isr_reports: Any = None,
        facts_block: str = "",
        run_state: str = "",
        citable_ids: Sequence[str] | None = None,
        evidence: EntryTexts | None = None,
    ) -> NarrativeOutput | None:
        """Return a ``NarrativeOutput`` or ``None`` if both paths fail.

        Path 1 — ``with_structured_output(NarrativeOutput).ainvoke(messages)``
        Path 2 — raw chat → ``safe_parse_json`` → ``model_validate``
        Both surfaces are wrapped in broad ``except`` so the report node can
        always rely on the fallback narrative.
        """
        messages = self._build_prompt(report, facts_block, run_state)
        self._note_room(sum(len(str(message.content)) for message in messages))
        # Where the sentences a check leaves standing are recorded, to be
        # marked where they stand.
        self._report = report

        # What this run actually established, so a summary cannot be the first
        # place "command-and-control" or "data exfiltration" appears. Run 3's
        # did exactly that, over one technique and no network data at all.
        #
        # The analysts' own words are one of the three grounding sources, and
        # this round is graded on the same grounding the composer is: without
        # the ISRs, a capability an analyst stated in a claim would be a
        # violation here and a pass there, on one run.
        grounding = CapabilityGrounding.from_report(report, isr_reports)
        # The entries a key finding may cite: the ledger's, which the pack's
        # own entries are part of.
        known_ids = [row.id for row in report.evidence_index]
        # The ids a bracketed citation in the prose may name: the ones the
        # run's ledger issued, or, handed none, the report's evidence index
        # and the pack's own line ids — never ids read out of prompt text,
        # where a sample's decoded string can carry any.
        citable = (
            list(citable_ids)
            if citable_ids is not None
            else list(dict.fromkeys([*known_ids, *pack_line_ids(facts_block)]))
        )

        # Skip the structured path entirely on endpoints where it does not
        # work. Measured live 2026-08-07: against llama-server this call hung
        # for the full 1800s ``request_timeout`` and was about to retry twice
        # more, producing 90 minutes of a silent report node. The manual-parse
        # path below is what actually serves local servers, and it is reached
        # in seconds instead of an hour and a half.
        # A call that has to be held under its budget goes by the manual path,
        # where the hold can be passed with the call.
        if structured_output_supported_for_llm(self.llm) and self._call_bound(messages) is None:
            try:
                structured = self.llm.with_structured_output(NarrativeOutput, include_raw=True)
                result = structured_answer(
                    await retry_on_connection_error(
                        lambda: structured.ainvoke(messages), what="NarrativeAgent structured"
                    ),
                    self.token_ledger,
                    agent=REPORTER_AGENT_KEY,
                    model=self.model_label,
                )
                if isinstance(result, NarrativeOutput):
                    return self._kept_with_ungrounded_recorded(
                        result, grounding, known_ids, citable, evidence
                    )
                # Some providers return a dict — coerce defensively.
                if isinstance(result, dict):
                    return self._kept_with_ungrounded_recorded(
                        NarrativeOutput.model_validate(result),
                        grounding,
                        known_ids,
                        citable,
                        evidence,
                    )
                logger.warning(
                    "NarrativeAgent: unexpected structured-output type %s; "
                    "falling back to manual parse.",
                    type(result).__name__,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "NarrativeAgent: structured_output path failed (%s); trying manual JSON parse.",
                    exc,
                )

        # Manual-parse fallback, through the validation loop. Useful for local
        # llama.cpp servers that occasionally return text wrapped in ```json
        # fences. ``NarrativeOutput`` carries real constraints — at least two
        # key findings, six fields per recommendation — and
        # those are what a model gets wrong; before the loop the first breach
        # discarded the whole answer and the report shipped the deterministic
        # template with nothing saying which rule was broken. A dropped socket
        # is still retried separately (``retry_on_connection_error``).
        from maljan.llm.context_window import output_bound_kwargs

        async def _run(turns: list[BaseMessage]) -> Any:
            bound = self._call_bound(turns)
            if bound is not None:
                logger.info(
                    "NarrativeAgent: this call may write %d tokens — what its %d-token "
                    "window leaves after the prompt, under its budget of %d.",
                    bound,
                    self.window_tokens,
                    self.output_cap,
                )
            raw = await retry_on_connection_error(
                (lambda: self.llm.ainvoke(turns, **output_bound_kwargs(self.llm, bound)))
                if bound is not None
                else (lambda: self.llm.ainvoke(turns)),
                what="NarrativeAgent raw",
            )
            if self.token_ledger is not None:
                try:
                    from maljan.core.token_ledger import record_response_usage

                    record_response_usage(
                        self.token_ledger, raw, agent=REPORTER_AGENT_KEY, model=self.model_label
                    )
                    from maljan.pipeline.events import announce_model_fallback

                    announce_model_fallback(
                        getattr(self, "event_sink", None), raw, agent="reporter", stage="report"
                    )
                except Exception as exc:  # noqa: BLE001
                    # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure — record_response_usage() swallows its own exceptions, so exc here is only an import/attribute error  # noqa: E501
                    logger.debug("NarrativeAgent: token usage not recorded (%s).", exc)
            return raw

        try:
            payload, violations, retries = await retry_with_feedback(
                _run,
                list(messages),
                [
                    lambda p: schema_violations(NarrativeOutput, p, code="narrative.schema"),
                    lambda p: narrative_capability_violations(p, grounding),
                    lambda p: key_finding_citation_violations(p, known_ids),
                    lambda p: citation_violations(p, citable, prose=NARRATIVE_PROSE),
                    lambda p: wrong_entry_citations(p, evidence, prose=NARRATIVE_PROSE),
                    technique_name_violations,
                ],
                parse=_narrative_payload,
                on_feedback=self.validation_tally.count,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("NarrativeAgent: manual-parse fallback failed (%s); NO NARRATIVE.", exc)
            return None

        self.validation_tally.retries += retries
        self.validation_tally.count(violations)

        # A broken shape and an over-claim are not the same failure. The first
        # leaves nothing usable, so the report falls back to the deterministic
        # template. The second leaves a summary that says more than the run
        # found, and dropping it would replace one wrong summary with none —
        # so it is kept and the terms are recorded, which is what a reader can
        # act on. A citation that is not an evidence id is kept the same way.
        # Nothing rewrites the prose.
        broken = [v for v in violations if v.code not in KEPT_WITH_A_FINDING]
        ungrounded = [v for v in violations if v.code in KEPT_WITH_A_FINDING]
        if broken:
            # ``error``: reaching here means the report ships with no narrative
            # at all, which is a visible hole rather than a degraded detail.
            logger.error(
                "NarrativeAgent: the answer still breaks the schema after %d retr%s (%s); "
                "NO NARRATIVE.",
                retries,
                "y" if retries == 1 else "ies",
                "; ".join(f"{v.path}: {v.message}" for v in broken),
            )
            return None
        self._record_ungrounded(ungrounded)
        try:
            return NarrativeOutput.model_validate(payload)
        except Exception as exc:  # noqa: BLE001
            logger.error("NarrativeAgent: the validated payload would not build (%s).", exc)
            return None

    def _record_ungrounded(self, violations: list[Violation], *, asked: bool = True) -> None:
        """Keep the over-claims and stray citations on the record, without touching the prose."""
        if not violations:
            return
        logger.warning(
            "NarrativeAgent: %d finding(s) on the summary survived the retry and are "
            "recorded unresolved (%s).",
            len(violations),
            ", ".join(v.path for v in violations),
        )
        self.validation_tally.record_unresolved("narrative", violations)
        record_flagged_statements(getattr(self, "_report", None), violations, asked=asked)

    def _kept_with_ungrounded_recorded(
        self,
        output: NarrativeOutput,
        grounding: CapabilityGrounding,
        known_ids: list[str] | None = None,
        citable: Sequence[str] = (),
        evidence: EntryTexts | None = None,
    ) -> NarrativeOutput:
        """The structured path's answer, with its over-claims and stray citations recorded.

        No retry here: ``with_structured_output`` owns the conversation and
        there is no turn to add one to. The answer is still checked, because a
        report that over-claims is no better for having been produced by the
        path that usually works.
        """
        answer = output.model_dump()
        found = [
            *narrative_capability_violations(answer, grounding),
            *key_finding_citation_violations(answer, known_ids or []),
            *citation_violations(answer, citable, prose=NARRATIVE_PROSE),
            *wrong_entry_citations(answer, evidence, prose=NARRATIVE_PROSE),
            *technique_name_violations(answer),
        ]
        self.validation_tally.count(found)
        self._record_ungrounded(found, asked=False)
        return output

    def _build_prompt(
        self, report: MalwareReport, facts_block: str = "", run_state: str = ""
    ) -> list[BaseMessage]:
        """The system turn and the human turn, the two standing blocks leading the human turn.

        ``facts_block`` is the triage pack as the analysts and the judge saw
        it and ``run_state`` the run's state block; the summary is written
        over the same facts, with their ids, and knows which stages ran.
        """
        from maljan.pipeline.run_state import with_run_state

        body = build_prompt_text(report)
        if facts_block:
            body = f"{facts_block}\n\n{body}"
        if run_state:
            body = f"{with_run_state('', run_state)}\n\n{body}"
        return [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=body),
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _message_text(message: Any) -> str:
    """Extract a string from a LangChain message-like object."""
    if message is None:
        return ""
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Handle multi-part content (rare for chat LLMs but possible)
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if text:
                    parts.append(str(text))
        return "".join(parts)
    return str(content)
