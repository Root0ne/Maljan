"""Section-wise Report Composer — authors the professional technical spine.

The deterministic builder fills every factual table;
the existing ``NarrativeAgent`` writes the summary, the key findings and the
defensive recommendations in one round. The Composer authors the rest of the
assessed prose — the background, the execution flow, the technical-analysis
subsections by capability, the configuration and command tables and the C2
channels — **one section per LLM call**, each grounded ONLY in that section's
evidence bundle (``evidence_bundles.bundle_for``).

Why per-section and not one big call: the local Qwen3.6-35B/SWA model stalls and
hallucinates on long single-shot generation (documented in
the authors' findings log, not in this repository). Bounded prompts (≤~1K tokens), a hard
per-section timeout, and a deterministic skip-on-empty keep it stable. The
cardinal rule mirrors the reference spec: **cite the evidence; if a section has
no evidence, leave it empty — never invent** (the renderer states absence).
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from types import UnionType
from typing import Any, Literal, Union, get_args, get_origin

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
    ValidationTally,
    Validator,
    Violation,
    citation_violations,
    configuration_citation_violations,
    flow_voice_violations,
    keep_known_keys,
    pack_line_ids,
    retry_with_feedback,
    schema_violations,
    section_capability_violations,
)
from maljan.reporting.evidence_bundles import bundle_for, is_empty, sandbox_entry_ids
from maljan.reporting.models import (
    C2Channel,
    CliFlag,
    CommandRow,
    ConfigItem,
    EncryptionScheme,
    FlowStep,
    MalwareReport,
    RansomNote,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.utils.json_cleaner import safe_parse_json

# ---------------------------------------------------------------------------
# Per-section output schemas
# ---------------------------------------------------------------------------


class _StructuredOutputUnavailable(Exception):
    """The endpoint cannot do structured output; take the manual-parse path."""


class _ProseOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    body: str = Field("", max_length=2500)
    evidence_refs: list[str] = Field(default_factory=list)


class _IntroOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    text: str = Field("", max_length=1800)


class _CliFlagsOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    flags: list[CliFlag] = Field(default_factory=list)


class _C2Out(BaseModel):
    model_config = ConfigDict(extra="ignore")
    channels: list[C2Channel] = Field(default_factory=list)


class _FlowOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    steps: list[FlowStep] = Field(default_factory=list)


class _ConfigOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    items: list[ConfigItem] = Field(default_factory=list)


class _CommandsOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    commands: list[CommandRow] = Field(default_factory=list)


# Rule 2 is the one that was missing, and its absence was not theoretical: on
# 2026-07-28 a conclusion asserted the sample was a .NET executable calling
# `_CorExeMain` from `mscoree.dll`, repeating a static-analyst claim, on a
# binary whose DETERMINISTIC FACTS said "Microsoft Visual C++ 2015-2022" and
# listed eleven native DLLs with no `mscoree`. Both blocks arrived under one
# "evidence" heading with no stated precedence, so the model had no reason to
# prefer the parser over another model.
_SYSTEM = (
    "You are a senior malware reverse engineer writing ONE section of a technical "
    "analysis report. STRICT RULES:\n"
    "1. Use ONLY the evidence provided below. Do NOT invent capabilities, function "
    "names, flags, crypto details, C2 endpoints, or file names.\n"
    "2. DETERMINISTIC FACTS come from parsers and always outrank ANALYST CLAIMS, "
    "which are another model's output. If a claim contradicts a fact, the fact is "
    "correct. Do NOT reconcile the two into a statement that accommodates both, "
    "and do not hedge. Either drop the claim, or name it and refute it with the "
    "fact — refuting it is better, because a reader who was told the sample is "
    "one thing deserves to know why the report says otherwise.\n"
    "3. A fact marked 'complete list' is exhaustive. Anything absent from it is "
    "absent from the binary, and a claim that relies on it is false.\n"
    "4. If the evidence does not support a field, leave it empty/null. Never guess.\n"
    "5. Be concise and technical; cite concrete artifacts (function name, API, "
    "string, tool output) where possible.\n"
    "6. Cite the ev_ ids of the entries a statement rests on: in the evidence_refs "
    "list where the object has one, and in square brackets in prose, e.g. [ev_0007]. "
    "Only ids that appear in the evidence below.\n"
    "7. State facts plainly and write inferences with estimative words ('likely', "
    "'we assess'). Present tense for what the sample does, past tense for what the "
    "run did. No second person.\n"
    "8. Delivery and attribution this run did not see are context, not "
    "findings: say where they come from, and never write them as observed. A "
    "sandbox answer with nothing in it is not an execution: write 'observed' only "
    "for what a sandbox entry records.\n"
    "9. Output MUST be the JSON object shown in the request, with its keys."
)

# The fields of each section that are prose, and so the only ones a citation
# is looked for in. A section of records — C2 channels, flags, a cipher, a
# ransom note — has none: its fields are notation, not sentences.
_PROSE_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    _ProseOut: ("body",),
    _IntroOut: ("text",),
}

# How many invented keys a degradation reason names. A model that invents
# forty writes forty names into the report header otherwise, and the sentence
# stops being readable long before that.
_MAX_NAMED_KEYS = 6

# What each section is asked for, in one line. Module data, not inline text,
# so the test that holds the prompts to the invented class reads every word a
# model is shown: a checklist of the evaluation key's own items ("campaign id",
# "sleep interval") is a hint as surely as an example is.
_INSTRUCTIONS: dict[str, str] = {
    "introduction": "Write a 2-4 sentence intro.",
    "execution_flow": (
        "List what the sample does from its entry point to its steady state, in order."
    ),
    "prose": "Write the '{title}' subsection.",
    "configuration": (
        "Extract the sample's configuration: its network endpoints, identifiers, keys, "
        "version, timing values and install path."
    ),
    "commands": "Extract the commands the sample accepts from its operator.",
    "encryption_scheme": "Extract the encryption scheme.",
    "cli_flags": "Extract command-line flags.",
    "ransom_note": "Extract the ransom note.",
    "communications": "Describe the C2 channel(s).",
}

# Narrative technical subsections authored as free prose (TechnicalSubsection),
# in the order the report prints them.
_PROSE_SECTIONS: dict[str, str] = {
    "packing_obfuscation": "Packing & Obfuscation",
    "string_resolution": "API and String Resolution",
    "discovery": "Discovery & Enumeration",
    "persistence_detail": "Persistence",
    "evasion_antiforensics": "Defense Evasion & Anti-Forensics",
    "command_and_control": "Command and Control",
    "payloads": "Payloads and Dropped Files",
}

# One example answer per section shape, shown under the object the answer has
# to be. The object alone names the keys; the example shows what goes in them
# — an ordered list with its marks, a value with how it was obtained — which a
# key name cannot. Each is valid against its schema, and a test says so.
# The examples describe an invented file-encrypting sample on purpose: a
# different class of malware from any the evaluation keys describe, with
# placeholder values that match no real sample, so a model that copies the
# shape it is shown cannot copy a finding with it.
_PROSE_EXAMPLE = (
    '{"body": "The note text is stored in a compressed resource [ev_0009]; we assess it is '
    'expanded at run time from the size field that precedes it.", '
    '"evidence_refs": ["ev_0009"]}'
)
_EXAMPLES: dict[str, str] = {
    "prose": _PROSE_EXAMPLE,
    "execution_flow": (
        '{"steps": ['
        '{"order": 1, "action": "Enumerates fixed and mapped drives", "voice": "assessed", '
        '"evidence_refs": ["ev_0008"]}, '
        '{"order": 2, "action": "Deletes volume shadow copies with vssadmin", '
        '"voice": "observed", "evidence_refs": ["ev_0021"]}]}'
    ),
    "configuration": (
        '{"items": ['
        '{"key": "Encrypted file extension", "value": ".example-locked", '
        '"how_obtained": "static-string", "evidence_refs": ["ev_0015"]}, '
        '{"key": "Skipped folders", "value": "Windows, Program Files", '
        '"how_obtained": "inferred", "evidence_refs": []}]}'
    ),
    "commands": (
        '{"commands": ['
        '{"id": "--path", "name": "path", "description": "Limits encryption to one directory", '
        '"evidence_refs": ["ev_0031"]}]}'
    ),
    "communications": (
        '{"channels": [{"name": "Leak upload", "protocol": "SFTP", '
        '"encryption": "SSH transport", "packet_layout": null, '
        '"beacon_format": null, "evidence_ref": null, '
        '"endpoints": ["sftp://upload.example.invalid"], "evidence_refs": ["ev_0019"]}]}'
    ),
}


# What one field of a section schema is answered with, by its declared type.
# A model that is shown the object it has to produce produces it; a model shown
# only the section's name and the word "schema" invents a shape, and six live
# runs on two unrelated models invented one every time.
_PLACEHOLDER_BY_TYPE: dict[Any, str] = {
    str: '"..."',
    bool: "true",
    int: "0",
    float: "0.0",
}


def _field_placeholder(annotation: Any, depth: int = 0) -> str:
    """The value one declared field is answered with, written as JSON.

    A field with a closed vocabulary shows the vocabulary, so a mark such as a
    step's ``voice`` is answered with one of its words rather than invented.
    """
    if depth > 3:
        return "null"
    origin = get_origin(annotation)
    if origin is Literal:
        return '"' + " or ".join(str(arg) for arg in get_args(annotation)) + '"'
    args = [arg for arg in get_args(annotation) if arg is not type(None)]
    if origin in (list, tuple) and args:
        return f"[{_field_placeholder(args[0], depth + 1)}]"
    if origin is UnionType or origin is Union:
        return _field_placeholder(args[0], depth) if args else "null"
    if isinstance(annotation, type) and hasattr(annotation, "model_fields"):
        return _expected_object(annotation, depth + 1)
    return _PLACEHOLDER_BY_TYPE.get(annotation, '"..."')


def _expected_object(schema: type[BaseModel], depth: int = 0) -> str:
    """The exact JSON object a section must answer with, keys and all.

    Built from the schema rather than written out beside it, so the two cannot
    drift: the prompt's rule 6 used to say "conform to the provided JSON
    schema" on a path where no schema was provided at all.
    """
    fields = getattr(schema, "model_fields", {}) or {}
    body = ", ".join(
        f'"{name}": {_field_placeholder(field.annotation, depth)}' for name, field in fields.items()
    )
    return "{" + body + "}"


def _example_for(section: str, schema: type[BaseModel]) -> str:
    """The example answer shown for one section, or ``""`` for the shapes that have none."""
    if schema is _ProseOut:
        return _EXAMPLES["prose"]
    return _EXAMPLES.get(section, "")


def _bundle_text(section: str, bundle: dict[str, Any]) -> str:
    """Render an evidence bundle into a compact prompt body.

    The heading used to be the bare line ``SECTION: <name>``, which is a key
    with a value next to it: both models answered with ``{"SECTION": ...,
    "content": ...}`` often enough that it cannot be a coincidence. It is a
    sentence now.
    """
    lines: list[str] = [f"The evidence for the {section} section follows.", ""]
    # First, and labelled as outranking everything below it. This block is the
    # same on every section and is deliberately NOT part of ``facts``: the
    # skip-on-empty check keys off ``facts``, and folding an always-present
    # block into it would make every bundle look non-empty and turn "state the
    # absence" into "write something anyway" for every section.
    facts = bundle.get("facts") or {}
    binary = bundle.get("binary") or {}
    if binary:
        # Keys the section already carries in ``facts`` are dropped rather than
        # printed twice — the introduction deliberately repeats identity there
        # because identity is its subject.
        rows = [(k, v) for k, v in binary.items() if k not in facts and v not in (None, "", [], {})]
        if rows:
            lines.append("BINARY FACTS (from parsers — these outrank any claim below):")
            lines.extend(f"- {k}: {v}" for k, v in rows)
            lines.append("")
    if facts:
        lines.append("DETERMINISTIC FACTS:")
        for k, v in facts.items():
            if v:
                lines.append(f"- {k}: {v}")
        lines.append("")
    claims = bundle.get("claims") or []
    if claims:
        lines.append("ANALYST CLAIMS (claim — evidence):")
        for c in claims[:10]:
            lines.append(f"- {c.get('claim', '')} — {c.get('evidence_ref', '')}")
        lines.append("")
    tools = bundle.get("tool_outputs") or []
    if tools:
        lines.append("CAPTURED TOOL OUTPUT:")
        for t in tools[:6]:
            sym = f" [{t.get('symbol')}]" if t.get("symbol") else ""
            lines.append(f"- {t.get('tool', '')}{sym}: {t.get('output', '')[:1200]}")
        lines.append("")
    return "\n".join(lines)


# The calls one section may take: its answer and the one retry the validation
# loop gives an answer that breaks its schema.
SECTION_ATTEMPTS = 2


def _reached_the_cap(answer: Any, cap: int) -> bool:
    """Whether the server stopped this answer at its output cap."""
    from maljan.core.truncation_ledger import completion_tokens_of, hit_length_cap

    if hit_length_cap(answer):
        return True
    produced = completion_tokens_of(answer)
    return bool(cap > 0 and produced is not None and produced >= cap)


class ReportComposer:
    """Authors the professional spine section-by-section. Async; per-section
    timeout + deterministic skip. Never raises to the caller."""

    def __init__(
        self,
        llm: BaseChatModel,
        section_max_tokens: int = 900,
        per_section_timeout: int = 120,
        token_ledger: Any | None = None,
        model_label: str = "",
        generation_rates: Any | None = None,
        output_cap: int | None = None,
        caps_by_model: dict[str, int] | None = None,
        turn_share: float | None = None,
    ) -> None:
        self.llm = llm
        self.section_max_tokens = section_max_tokens
        # What the model is allowed to generate for one section: the section's
        # own budget, plus room for its reasoning when the model has not been
        # asked to keep reasoning out (the container decides). The wait and the
        # cut are both judged against this, because it is what the server caps.
        self.output_cap = int(output_cap or section_max_tokens)
        # Each model of the reporter's list, by the label its answers carry,
        # and the cap its own provider was given: what "cut" means for the
        # model that answered.
        self.caps_by_model = dict(caps_by_model or {})
        # The job's share of a section's clock a model of the list may take
        # before the next one is asked.
        self.turn_share = turn_share
        self.per_section_timeout = per_section_timeout
        self.token_ledger = token_ledger
        # The label of the model the sections call first, so a call is
        # recorded under a model even when the answer does not name one.
        self.model_label = model_label
        # The job's event sink, set by the container, so a switch of the
        # reporter's model list is said in the conversation like any agent's.
        self.event_sink: Any | None = None
        # The job's measured generation rates (``llm.generation_rate``). A
        # section's wait is sized from them so a slow model is given the time
        # its ``section_max_tokens`` take; ``None`` keeps the configured wait.
        self.generation_rates = generation_rates
        # What each section was told was wrong with its answer, by code, across
        # every section. The composer runs after the run summary is built, so
        # the report node reads this and folds it in.
        self.validation_tally = ValidationTally()
        # Set per ``compose`` call; empty until then, which grounds nothing and
        # therefore judges nothing (see ``ungrounded_capabilities``).
        self._grounding = CapabilityGrounding()
        # The triage pack and the run state for this report, set per
        # ``compose`` call.
        self._facts_block = ""
        self._run_state = ""
        # What this report lost or had trimmed, in the words the report's own
        # degradation reasons are written in. A section dropped after its
        # retries used to leave the report with no conclusion and nothing
        # saying so; the keys an answer invented used to take the whole
        # section with them.
        self.degradations: list[str] = []

    async def compose(
        self,
        report: MalwareReport,
        isr_reports: dict[str, Any] | None = None,
        facts_block: str = "",
        run_state: str = "",
        citable_ids: Sequence[str] | None = None,
    ) -> None:
        """Fill report.intro_background / technical_analysis / c2_channels.

        Mutates ``report`` in place; each section is best-effort.

        ``facts_block`` is the triage pack and ``run_state`` the run's state
        block; every section's prompt leads with the two, so no section is
        written without the facts the run established or without knowing
        which stages ran.
        """
        ta = report.technical_analysis or TechnicalAnalysis()
        authored = 0
        self._facts_block = facts_block
        self._run_state = run_state
        # The ids a section may cite: the ones the run's ledger issued, or,
        # handed none, the pack's own line ids — never ids read out of prompt
        # text, where a sample's decoded string can carry any.
        self._citable = list(citable_ids) if citable_ids is not None else pack_line_ids(facts_block)
        # What this run established, read once and asked of every section, so
        # a conclusion cannot be the first place "command-and-control" appears.
        self._grounding = CapabilityGrounding.from_report(report, isr_reports)

        # 1. Introduction / background.
        intro = await self._author(
            "introduction", report, isr_reports, _IntroOut, _INSTRUCTIONS["introduction"]
        )
        if intro and isinstance(intro, _IntroOut) and intro.text.strip():
            report.intro_background = intro.text.strip()
            authored += 1

        # The entries this run recorded, and which of them a sandbox wrote: an
        # execution step marked observed has to cite one of the second, and a
        # configuration value said to be decrypted one of the first.
        known_ids = [row.id for row in report.evidence_index]
        sandbox_ids = sandbox_entry_ids(report)

        # 2. The execution flow, entry to steady state.
        flow = await self._author(
            "execution_flow",
            report,
            isr_reports,
            _FlowOut,
            _INSTRUCTIONS["execution_flow"],
            validators=[lambda p: flow_voice_violations(p, sandbox_ids)],
        )
        if flow and isinstance(flow, _FlowOut) and flow.steps:
            ta.execution_flow = self._kept("execution_flow", flow.steps, 20)
            authored += 1

        # 3. Free-prose technical subsections (only when evidence exists).
        for section, title in _PROSE_SECTIONS.items():
            out = await self._author(
                section,
                report,
                isr_reports,
                _ProseOut,
                _INSTRUCTIONS["prose"].format(title=title),
            )
            if out and isinstance(out, _ProseOut) and out.body.strip():
                sub = TechnicalSubsection(
                    title=title, body=out.body.strip(), evidence_refs=out.evidence_refs[:8]
                )
                setattr(ta, section, sub)
                authored += 1

        # 4. Structured extractions (configuration, commands, crypto, CLI
        # flags, ransom note).
        config = await self._author(
            "configuration",
            report,
            isr_reports,
            _ConfigOut,
            _INSTRUCTIONS["configuration"],
            validators=[lambda p: configuration_citation_violations(p, known_ids)],
        )
        if config and isinstance(config, _ConfigOut) and config.items:
            ta.configuration = self._kept("configuration", config.items, 30)
            authored += 1

        commands = await self._author(
            "commands",
            report,
            isr_reports,
            _CommandsOut,
            _INSTRUCTIONS["commands"],
        )
        if commands and isinstance(commands, _CommandsOut) and commands.commands:
            ta.commands = self._kept("commands", commands.commands, 40)
            authored += 1

        enc = await self._author(
            "encryption_scheme",
            report,
            isr_reports,
            EncryptionScheme,
            _INSTRUCTIONS["encryption_scheme"],
        )
        if enc and isinstance(enc, EncryptionScheme) and _has_content(enc):
            ta.encryption_scheme = enc
            authored += 1

        cli = await self._author(
            "cli_flags", report, isr_reports, _CliFlagsOut, _INSTRUCTIONS["cli_flags"]
        )
        if cli and isinstance(cli, _CliFlagsOut) and cli.flags:
            ta.cli_flags = self._kept("cli_flags", cli.flags, 30)
            authored += 1

        note = await self._author(
            "ransom_note", report, isr_reports, RansomNote, _INSTRUCTIONS["ransom_note"]
        )
        if note and isinstance(note, RansomNote) and _has_content(note):
            ta.ransom_note = note
            authored += 1

        # 5. Communications / C2 channels.
        c2 = await self._author(
            "communications", report, isr_reports, _C2Out, _INSTRUCTIONS["communications"]
        )
        if c2 and isinstance(c2, _C2Out) and c2.channels:
            report.c2_channels = self._kept("communications", c2.channels, 6)
            authored += 1

        if _has_content(ta):
            report.technical_analysis = ta
        logger.info("ReportComposer: authored %d professional section(s).", authored)

    async def _author(
        self,
        section: str,
        report: MalwareReport,
        isr_reports: dict[str, Any] | None,
        schema: type[BaseModel],
        instruction: str,
        validators: list[Validator] | None = None,
    ) -> BaseModel | None:
        """Author one section from its isolated bundle. Skips empty bundles;
        structured-output → manual-parse → None; hard per-section timeout.

        ``validators`` are the section's own checks beyond its schema and the
        capability grounding every section gets; what they find is shown to the
        model once and, if it survives, recorded beside the section.
        """
        bundle = bundle_for(section, report, report.technical_evidence, isr_reports)
        if is_empty(bundle):
            return None
        from maljan.pipeline.run_state import with_run_state

        head: list[str] = []
        run_state = str(getattr(self, "_run_state", "") or "")
        if run_state:
            head.append(with_run_state("", run_state))
        facts = str(getattr(self, "_facts_block", "") or "")
        if facts:
            head.append(facts)
        # The two standing blocks lead, then the instruction, then the exact
        # object the answer has to be, then the section's own bundle. The
        # object is in the prompt because the manual parse is the primary path
        # on a local server — ``with_structured_output`` is skipped there — and
        # on that path nothing had ever shown the model a key name.
        contract = (
            "Answer with exactly this JSON object, these keys and no others:\n"
            f"{_expected_object(schema)}\n"
            "A field the evidence does not support is left empty or null; the keys stay."
        )
        example = _example_for(section, schema)
        if example:
            contract += (
                "\nFor example (the shape only; write what this run's evidence supports):\n"
                + example
            )
        human = "\n\n".join([*head, instruction, contract, _bundle_text(section, bundle)])
        messages = [
            SystemMessage(content=_SYSTEM),
            HumanMessage(content=human),
        ]
        timeout = self._section_timeout()
        self._start_the_section_clock(timeout)
        try:
            return await asyncio.wait_for(
                self._invoke(messages, schema, section=section, validators=validators or []),
                timeout=timeout,
            )
        except TimeoutError:
            logger.warning("ReportComposer: section '%s' timed out; skipping.", section)
            self._note_degradation(
                f"report section '{section}' is missing: it did not answer within {int(timeout)}s"
            )
            return None
        except Exception as exc:  # noqa: BLE001
            # ``error``, not ``warning``: a dropped section is missing content
            # in a delivered report, and at warning level in a noisy worker log
            # nobody ever noticed one had gone.
            logger.error("ReportComposer: section '%s' failed (%s); SKIPPED.", section, exc)
            self._note_degradation(
                f"report section '{section}' is missing: the round failed ({type(exc).__name__})"
            )
            return None

    def _start_the_section_clock(self, seconds: float) -> None:
        """Measure the model list's turn deadline against this section's clock.

        Not a restart: the report node starts the list once, at the start of
        the report stage, and a model that failed as a provider in one section
        has failed for the next as well. Restarting per section waited out a
        stalled first model's deadline in every section.
        """
        enter = getattr(getattr(self, "llm", None), "enter_loop", None)
        if not callable(enter) or seconds <= 0:
            return
        share = getattr(self, "turn_share", None)
        if not isinstance(share, int | float):
            from maljan.llm.fallback import _configured_share

            share = _configured_share()
        if share > 0:
            enter(float(seconds), float(share))

    def _cap_of(self, answer: Any) -> int:
        """The output cap of the model that gave ``answer``."""
        from maljan.llm.fallback import turn_model

        model, _switched = turn_model(answer)
        caps = getattr(self, "caps_by_model", None) or {}
        return int(caps.get(model) or getattr(self, "output_cap", 0) or 0)

    def _section_timeout(self) -> float:
        """One section's wait: configured, or what its calls need at the model's pace.

        A section is its answer and, when the answer breaks its schema, the one
        retry the validation loop allows: ``SECTION_ATTEMPTS`` calls. Where a
        rate is measured the wait holds that many calls of the output cap at
        the model's pace; where none is, the configured wait stands for the
        whole section, as it always did.
        """
        configured = float(self.per_section_timeout)
        rates = getattr(self, "generation_rates", None)
        if rates is None:
            return configured
        from maljan.llm.generation_rate import model_name_of

        per_call = float(
            rates.call_timeout(
                "composer:section",
                model_name_of(self.llm),
                configured,
                int(getattr(self, "output_cap", 0) or self.section_max_tokens or 0),
            )
        )
        if per_call <= configured:
            return configured
        return per_call * SECTION_ATTEMPTS

    async def _invoke(
        self,
        messages: list[BaseMessage],
        schema: type[BaseModel],
        *,
        section: str = "",
        validators: list[Validator] | None = None,
    ) -> BaseModel | None:
        # Skipped outright on endpoints where structured output does not work
        # — see ``structured_output_supported``. The per-section timeout below
        # bounds the damage here, unlike the narrative round, but paying it on
        # every one of eight sections is still eight timeouts nobody needs.
        citable = list(getattr(self, "_citable", None) or [])
        prose = _PROSE_FIELDS.get(schema, ())
        try:
            if not structured_output_supported_for_llm(self.llm):
                raise _StructuredOutputUnavailable
            structured = self.llm.with_structured_output(schema, include_raw=True)
            result = structured_answer(
                await retry_on_connection_error(
                    lambda: structured.ainvoke(messages), what="ReportComposer structured"
                ),
                self.token_ledger,
                agent=REPORTER_AGENT_KEY,
                model=self.model_label,
            )
            if isinstance(result, dict):
                result = schema.model_validate(result)
            if isinstance(result, schema):
                # No retry on this path — ``with_structured_output`` owns the
                # conversation and there is no turn to add one to — but the
                # answer is still checked: a section that over-claims is no
                # better for having come from the path that usually works.
                answer = result.model_dump()
                found = [
                    *section_capability_violations(answer, self._grounding),
                    *citation_violations(answer, citable, prose=prose),
                ]
                for extra in validators or []:
                    found.extend(extra(answer))
                self.validation_tally.count(found)
                self._record_ungrounded(section or schema.__name__, found)
                return result
        except Exception as exc:  # noqa: BLE001
            logger.debug("ReportComposer: structured path failed (%s); manual parse.", exc)
        # Manual JSON fallback for local servers returning fenced JSON, through
        # the validation loop: a section whose shape is wrong is a section
        # missing from a delivered report, and the model can usually fix it
        # when told which field broke which rule.
        declined = False
        cut = False
        cut_at = 0

        async def _run(turns: list[BaseMessage]) -> Any:
            nonlocal cut, cut_at
            raw = await retry_on_connection_error(
                lambda: self.llm.ainvoke(turns), what="ReportComposer raw"
            )
            if _reached_the_cap(raw, self._cap_of(raw)):
                cut, cut_at = True, self._cap_of(raw)
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
                    logger.debug("ReportComposer: token usage not recorded (%s).", exc)
            return raw

        def _parse(answer: Any) -> Any:
            nonlocal declined
            payload = safe_parse_json(_message_text(answer))
            declined = bool(payload) and _section_declined(payload, schema)
            if not payload or declined:
                return None
            opened = _unwrap_section_envelope(payload, schema)
            opened = _section_text_envelope(opened, schema, section)
            kept, dropped = keep_known_keys(schema, opened)
            if dropped:
                # Kept, not refused: the fields the schema declares were
                # answered and the section is publishable. What was dropped is
                # named where a reader of the report will find it.
                logger.warning(
                    "ReportComposer: section '%s' carried %d key(s) the schema does not "
                    "declare (%s); the known fields are kept.",
                    section or schema.__name__,
                    len(dropped),
                    ", ".join(dropped),
                )
                named = ", ".join(dropped[:_MAX_NAMED_KEYS])
                if len(dropped) > _MAX_NAMED_KEYS:
                    named += f" and {len(dropped) - _MAX_NAMED_KEYS} more"
                self._note_degradation(
                    f"report section '{section or schema.__name__}' dropped the keys "
                    f"{named}, which its schema does not declare"
                )
            return kept

        def _validate(payload: Any) -> list[Violation]:
            # A declined section is an empty one, not a broken one: the model
            # looked at the bundle and said there is nothing here. Asking it
            # again would be arguing with a correct answer.
            if declined:
                return []
            found = [
                *schema_violations(schema, payload, code="composer.schema"),
                *section_capability_violations(payload, self._grounding),
                *citation_violations(payload, citable, prose=prose),
            ]
            for extra in validators or []:
                found.extend(extra(payload))
            return found

        payload, violations, retries = await retry_with_feedback(
            _run,
            list(messages),
            [_validate],
            parse=_parse,
            on_feedback=self.validation_tally.count,
        )
        self.validation_tally.retries += retries
        self.validation_tally.count(violations)
        if declined:
            # Logged at info so the skip is still traceable, and never as an
            # error a reader would go chasing.
            logger.info(
                "ReportComposer: section '%s' declined by the model (no content); skipping.",
                section or schema.__name__,
            )
            return None
        # A section whose shape is wrong cannot be published; a section that
        # over-claims, or cites something that is not an evidence id, can, and
        # dropping it would leave the report with neither the sentence nor the
        # record of it. What is wrong is kept on the record and the prose is
        # left exactly as the model wrote it.
        broken = [v for v in violations if v.code not in KEPT_WITH_A_FINDING]
        ungrounded = [v for v in violations if v.code in KEPT_WITH_A_FINDING]
        if broken:
            logger.error(
                "ReportComposer: section '%s' still breaks its schema after %d retr%s (%s); "
                "SKIPPED.",
                section or schema.__name__,
                retries,
                "y" if retries == 1 else "ies",
                "; ".join(f"{v.path}: {v.message}" for v in broken),
            )
            if cut:
                # The cap ended the answer, not the model: the schema only
                # failed because the JSON was cut off. Said as what it was.
                self._note_degradation(
                    f"report section '{section or schema.__name__}' is missing: its answer "
                    f"reached the output cap of {cut_at} tokens and was cut off "
                    "(composer_section_max_tokens; a model's reasoning counts against it)"
                )
                return None
            self._note_degradation(
                f"report section '{section or schema.__name__}' is missing: its answer did "
                f"not fit the schema after {retries} retr{'y' if retries == 1 else 'ies'} "
                f"({', '.join(sorted({v.code for v in broken}))})"
            )
            return None
        self._record_ungrounded(section or schema.__name__, ungrounded)
        return schema.model_validate(payload)

    def _kept[T](self, section: str, rows: list[T], limit: int) -> list[T]:
        """The first ``limit`` of a model's list, and a record when that cut any.

        A list the report prints is capped so one runaway answer cannot fill
        it; a reader is told the cap applied rather than shown a page of the
        answer as if it were the whole.
        """
        if len(rows) > limit:
            self._note_degradation(
                f"report section '{section}' was trimmed: the report keeps the first "
                f"{limit} of the {len(rows)} items the report model wrote"
            )
        return list(rows[:limit])

    def _note_degradation(self, reason: str) -> None:
        """One sentence about what this report lost, once."""
        if reason not in self.degradations:
            self.degradations.append(reason)

    def _record_ungrounded(self, section: str, violations: list[Violation]) -> None:
        """Keep a section's over-claims and stray citations on the record, prose untouched.

        Records only. The manual path has already counted these as leftovers of
        its retry loop, and counting them twice would say the model was told
        twice.
        """
        if not violations:
            return
        logger.warning(
            "ReportComposer: section '%s' kept with finding(s) at %s; recorded unresolved.",
            section,
            ", ".join(v.path for v in violations),
        )
        self.validation_tally.record_unresolved(f"composer:{section}", violations)


def _section_declined(payload: Any, schema: type[BaseModel]) -> bool:
    """True for ``{"<section>": null}``: the model's way of saying "nothing here".

    The same envelope ``_unwrap_section_envelope`` opens, with ``null`` where
    the object would be. Measured live on 2026-09-08 (qwen3:8b, full profile):
    ``encryption_scheme``, ``ransom_note`` and ``conclusion`` all came back this
    way for a sample that encrypts nothing and drops no note, and each was
    logged as a failed section. A declined section is an empty one, not a
    broken one, so the caller skips it without an error. The scalar envelope
    (``{"encryption_scheme": "RC4, XOR"}``) is still left to fail: there is a
    value there that nobody should guess a field for.
    """
    if not isinstance(payload, dict) or len(payload) != 1:
        return False
    ((key, value),) = payload.items()
    return key not in schema.model_fields and value is None


def _unwrap_section_envelope(payload: Any, schema: type[BaseModel]) -> Any:
    """Strip a ``{"<section>": {...}}`` wrapper the model added around its answer.

    Skipping structured output on local servers promoted the manual parse from
    a rare fallback to the primary path, and that exposed this: the prompt says
    "SECTION: ransom_note", so the model answers ``{"ransom_note": {...}}``.
    Validating that envelope against the inner schema fails on every structured
    section — ``extra="forbid"`` is deliberate and stays.

    Only an unambiguous envelope is opened: exactly one key, that key is not a
    real field, and the value is an object. A single key holding a scalar
    (``{"encryption_scheme": "RC4, XOR"}`` — the other live payload) carries no
    object to recover, so it is left to fail rather than guessed at.
    """
    if not isinstance(payload, dict) or len(payload) != 1:
        return payload
    ((key, value),) = payload.items()
    if key in schema.model_fields or not isinstance(value, dict):
        return payload
    return value


def _the_prose_field(schema: type[BaseModel]) -> str | None:
    """Which field of ``schema`` holds the section's own prose, or ``None``.

    ``text`` when the schema declares one, and otherwise the schema's single
    string-typed field. A schema with several — a ransom note has a filename
    and its verbatim content, an encryption scheme has nine — has no such
    field, and guessing one would be interpretation rather than a move.
    """
    fields = getattr(schema, "model_fields", {}) or {}
    if "text" in fields:
        return "text"
    strings = [name for name, field in fields.items() if _is_a_string_field(field.annotation)]
    return strings[0] if len(strings) == 1 else None


def _is_a_string_field(annotation: Any) -> bool:
    """Whether this field holds one string, rather than a list of them."""
    if annotation is str:
        return True
    if get_origin(annotation) in (UnionType, Union):
        return [arg for arg in get_args(annotation) if arg is not type(None)] == [str]
    return False


def _section_text_envelope(payload: Any, schema: type[BaseModel], section: str) -> Any:
    """``{"<section>": "the prose"}`` put where the schema wants it.

    A move, not a guess. Both models answered every section with the section's
    own name as the key, six runs out of six, and where the value was a string
    the section's whole text was thrown away for want of a field name. It is
    opened only when the one key *is* this section's name, its value is a
    string, and the schema has one field that holds prose; anything else — a
    renamed key, two keys, a value that is a list — needs interpretation and is
    dropped as before, named in the report's own degradation reasons.
    """
    if not isinstance(payload, dict) or len(payload) != 1:
        return payload
    ((key, value),) = payload.items()
    if not isinstance(value, str) or not value.strip():
        return payload
    if key in getattr(schema, "model_fields", {}) or key.strip().lower() != section.strip().lower():
        return payload
    field = _the_prose_field(schema)
    return payload if field is None else {field: value}


def _message_text(msg: Any) -> str:
    content = getattr(msg, "content", msg)
    return content if isinstance(content, str) else str(content)


def _has_content(model: BaseModel) -> bool:
    """True when any field on a structured model carries real content.

    A string a model writes to fill a field it has nothing for ("none",
    "unknown", "n/a") is not content: a block made only of them would print a
    family-specific section for a sample that has none of it.
    """
    for key, value in model.model_dump().items():
        if isinstance(value, bool) or key in {"evidence_ref", "evidence_refs"}:
            continue
        if isinstance(value, str) and value.strip().lower() in _PLACEHOLDER_VALUES:
            continue
        if value:
            return True
    return False


_PLACEHOLDER_VALUES = frozenset(
    {"", "none", "unknown", "n/a", "na", "null", "-", "not applicable", "not found", "no data"}
)
