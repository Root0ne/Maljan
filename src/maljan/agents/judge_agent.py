"""Chief Judge and Mediator agent.

JudgeAgent is NOT an expert analyst — it does not inherit from BaseAnalyst.
It has two distinct responsibilities:
  1. mediate(): Find contradictions between expert reports during the
     negotiation loop, using structured output for reliable confidence scoring.
  2. give_verdict(): Produce the final STIX 2.1 Bundle after negotiation ends,
     together with the severity, malware category and family attribution the
     report prints.

What the judge is shown:
  - The analysts' reports and, compactly, their ISR summaries.
  - An evidence summary (``pipeline.evidence_summary``): per technique id, the
    sources that named it and each source's own confidence. No combined number,
    because a combined number is one the judge defers to instead of reading the
    evidence.
  - Why the run is degraded, when it is. The judge weighs it and sets its own
    confidence; nothing caps the number afterwards.
  - Similar prior cases from long-term memory, as few-shot context.

What comes back is checked by ``pipeline.validation`` and, when something is
wrong, put back to the judge once as feedback. What is still wrong after that
is returned alongside the bundle for the run summary to record.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections.abc import Iterable, Sequence
from typing import TYPE_CHECKING, Any, NamedTuple

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate

from maljan.agents.base_agent import (
    BudgetMeter,
    LoopBudget,
    _turn_key,
    retry_on_connection_error,
    run_on_agent_loop,
)
from maljan.core.config import get_settings
from maljan.core.logger import logger
from maljan.core.token_ledger import TokenLedger, record_response_usage
from maljan.core.truncation_ledger import TruncationLedger, record_judge_response
from maljan.pipeline.events import emit_judge_question, scrub
from maljan.pipeline.mediation_models import MediatorVerdict
from maljan.pipeline.state import AgentArgument
from maljan.pipeline.validation import (
    ValidationTally,
    Violation,
    assessment_conflict_violations,
    assessment_violations,
    drop_ungrounded_indicators,
    retry_with_feedback,
    unsupported_benign_violations,
    unsupported_malware_violations,
    validate_verdict_bundle,
)
from maljan.schemas.evidence import EvidenceCounter, LedgerEntry
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore

# How many times the judge is asked again about a verdict answer that was
# wrong. One: a second correction has never produced a better bundle than the
# first, and every turn is a full judge timeout.
_VERDICT_RETRIES = 1

# The correction the judge is given for an answer that was not a bundle.
_NOT_JSON_FEEDBACK = (
    "Your previous answer was not a JSON STIX bundle. Return the JSON bundle only, "
    "no tool calls, no prose."
)

# What is recorded when even the retry was not a bundle. The code lands in
# ``run_summary.validation.unresolved``; the reason joins the report's
# degradation reasons, where a reader looking at a verdict with no severity
# will find out why it has none.
VERDICT_FALLBACK_CODE = "verdict.fallback"
VERDICT_FALLBACK_REASON = "judge verdict fell back to text extraction"

# What is recorded when the judge never answered at all. A retry would cost a
# second full judge timeout and could only produce the same fallback bundle, so
# nothing is asked again — but a verdict extracted from the analysts' text
# because the judge timed out is not a verdict the judge gave, and the run
# summary says so rather than showing a clean validation block.
VERDICT_TIMEOUT_CODE = "verdict.timeout"
VERDICT_TIMEOUT_REASON = "the judge did not answer within its budget"


def _answer_text(answer: Any) -> str:
    """The text of a model answer, whatever shape it arrived in."""
    content = getattr(answer, "content", answer)
    return str(content if content is not None else "")


def _is_not_json(answer: Any) -> bool:
    """Whether an answer is something other than a JSON object.

    An empty ``content`` carrying ``tool_calls`` counts: the judge binds no
    tools on the verdict path, so a tool call there is the local model
    emitting its own control tokens rather than an answer.
    """
    from maljan.utils.json_cleaner import safe_parse_json

    text = _answer_text(answer).strip()
    if not text:
        return True
    return not isinstance(safe_parse_json(text), dict)


# Consensus threshold: mediator confidence must reach this to stop negotiation early
CONSENSUS_THRESHOLD = 0.85

# What we assume when the mediator's agreement score cannot be read at all.
# Deliberately below CONSENSUS_THRESHOLD: an unreadable mediator must not be
# able to end the negotiation, and must not be mistakable for a real score.
_UNREADABLE_AGREEMENT = 0.0

# ``agreement_confidence: 0.95`` / ``**confidence**= 95%`` / ``"confidence": 0.9``
# / ``The confidence score is: 0.78``.
#
# A short run of anything-but-a-separator is allowed between the key and the
# ``:``/``=`` so ordinary phrasing parses, but the number must follow the
# separator **immediately**. That is the whole point: "Confidence: 0.95 (based
# on 3 agents)" must yield 0.95, never the 3 — see
# ``_extract_confidence_from_text`` for the false consensus that produced.
_AGREEMENT_RE = re.compile(
    r"confidence[^\n:=]{0,24}?[:=]\s*(\d*\.?\d+)\s*(%?)",
    re.IGNORECASE,
)


# How much of the evidence summary reaches the prompt. The block is one line
# per technique and the tail of it is the techniques one source mentioned once;
# a bound keeps a chatty run from crowding out the analysts' own text.
_EVIDENCE_SUMMARY_CHARS = 2000


class JudgeVerdict(NamedTuple):
    """What ``give_verdict`` produced, and what was still wrong with it.

    The violations travel with the bundle rather than being logged and dropped:
    they are what ``run_summary.validation.unresolved`` is made of, and a run
    whose judge could not ground an indicator should say so where a reader
    looks, not only in a worker log nobody keeps.
    """

    bundle: Bundle
    violations: list[Violation]
    retries: int
    # Every violation the judge was shown, by code — including the ones the
    # retry fixed, which nothing else in the run records.
    fed_back: dict[str, int] = {}


# The judge's system prompt. A module constant so that
# ``composition.builtin_prompt("judge")`` and ``give_verdict`` cannot disagree
# about what the judge is told; the text is unchanged from the inline literal
# it replaces.
JUDGE_VERDICT_SYSTEM = (
    "You are the Chief Malware Judge. Based on the expert reports below, "
    "provide a final verdict: Malware, Benign, or Suspicious.\n\n"
    "RULES:\n"
    "- Map findings to MITRE ATT&CK using AttackPattern objects (valid IDs: T#### or T####.###).\n"
    "- Omit technique ID if unsure.\n"
    "- On every Relationship, set x_maljan_confidence (0.0-1.0), "
    "x_maljan_evidence_basis (static|dynamic|network|all|unknown), "
    "and x_maljan_contributing_agents list.\n"
    "- ALL STIX object IDs MUST be ``<type>--<random uuid4>`` "
    "(spec-compliant 8-4-4-4-12 hex). NEVER reuse example UUIDs from "
    "the schema description. NEVER use ``<type>--T####`` (non-UUID).\n"
    "- DO NOT emit Indicator objects whose pattern values are inferred, "
    "hypothetical, or example. Every Indicator's pattern value MUST "
    "appear verbatim in the deterministic evidence (static strings, "
    "sandbox observations, or network IOCs). When in doubt, emit zero "
    "Indicators — the deterministic renderer will fill them in.\n"
    "- You decide severity, malware category and family; nothing downstream "
    "computes them for you and nothing overrides what you say. Add a top-level "
    "``x_maljan_assessment`` object to the bundle:\n"
    '    "x_maljan_assessment": {\n'
    '      "severity": {"rating": "Critical|High|Medium|Low|Informational",\n'
    '                   "rationale": "why the evidence supports that rating"},\n'
    '      "malware_category": "free text, e.g. ransomware / loader / infostealer",\n'
    '      "family": {"name": "...", "confidence": 0.0-1.0,\n'
    '                 "evidence_ids": ["ev_0012"]},\n'
    '      "confidence": 0.0-1.0\n'
    "    }\n"
    "  Omit any of the four you cannot support. A family name MUST cite the "
    "evidence ids it was read from; a family with no evidence ids is a guess, "
    "and the report will say so.\n"
    "- Benign is a finding, not a default. It says the evidence was examined "
    "and nothing malicious was in it. If this run produced no evidence and no "
    "analyst claim, say so and return Suspicious: an empty report is not a "
    "clean sample.\n"
    "- Return ONLY a valid JSON STIX 2.1 Bundle. No markdown wrappers."
)


# What the judge is told about the sample itself, before any analysis of it.
# The hash the job was queued under, the name it arrived with and the format
# detection are the router's; the md5 and size are read from the sandbox's own
# file block. They are in the prompt always, not only when a lookup is due.
#
# The file name is whatever the submitter typed, so it is labelled as
# submitted, and every value is written on its own line with its line breaks
# removed: a name that carried a newline could otherwise close the block and
# open one of its own.
#
# A live run made the case: the mediator told the judge to look the sample's
# hash up, and no message in the conversation carried a hash. The static
# analyst had produced no claims, so there was nothing in the prose either, and
# the judge opened a seventeen-tool loop with nothing to ask about.
SAMPLE_IDENTITY_HEADER = (
    "SAMPLE IDENTITY (established by the router and the sandbox's own file block, not by analysis)"
)

_IDENTITY_FIELDS: tuple[tuple[str, str], ...] = (
    ("sha256", "sha256"),
    ("sha1", "sha1"),
    ("md5", "md5"),
    ("file_name", "file name (as submitted)"),
    ("size_bytes", "size (bytes)"),
    ("file_type", "file type"),
    ("platform", "platform"),
)


def sample_identity_block(sample: Any) -> str:
    """The sample's own facts as one block, or ``""`` when there are none."""
    data = sample if isinstance(sample, dict) else {}
    rows = [
        f"{label}: {' '.join(str(data[key]).split())}"
        for key, label in _IDENTITY_FIELDS
        if str(data.get(key) or "").strip()
    ]
    if not rows:
        return ""
    return f"=== {SAMPLE_IDENTITY_HEADER} ===\n" + "\n".join(rows)


def _identity_prefix(sample: Any) -> str:
    """The identity block as a prompt prefix, with its blank line."""
    block = sample_identity_block(sample)
    return f"{block}\n\n" if block else ""


def _standing_blocks(run_state: str, facts_block: str) -> str:
    """The run-state block and the pack as a prompt prefix, each with its blank line.

    The run state first, between its markers, because it is the shorter and
    the one a reader orients by; the pack after it, under its own heading.
    """
    from maljan.pipeline.run_state import with_run_state

    parts: list[str] = []
    if run_state:
        parts.append(with_run_state("", run_state))
    if facts_block:
        parts.append(facts_block)
    return "".join(f"{part}\n\n" for part in parts if part)


def _sha256_of(sample: Any) -> str:
    """The sha256 the identity block carries, for a sentence that names it."""
    data = sample if isinstance(sample, dict) else {}
    return str(data.get("sha256") or "").strip()


def _who_is_asked(message: Any) -> str | None:
    """The agent a judge turn is asking, when the same turn delegates to one.

    The judge's own ``ask_<key>`` tools are the only place a question in this
    loop names a recipient. A turn that calls none is asking the room.
    """
    from maljan.agents.delegation import tool_name

    prefix = tool_name("")
    for call in list(getattr(message, "tool_calls", None) or []):
        name = str((call or {}).get("name") or "")
        if name.startswith(prefix):
            return name[len(prefix) :] or None
    return None


class JudgeAgent(BudgetMeter):
    """Chief controller responsible for mediation, consensus detection, and final verdict.

    Usage:
        judge = JudgeAgent(llm=some_llm)
        argument, is_consensus = judge.mediate(reports, history)
        bundle = judge.give_verdict(reports, history, attck_validator=validator)
    """

    def __init__(
        self,
        llm: BaseChatModel,
        config: Any | None = None,
    ) -> None:
        self.llm = llm
        self.logger = logger.getChild("judge")
        # Read by ``_supports_structured_output``. Optional so standalone use
        # (tests, scripts) still works; the container passes the real one.
        self._config = config
        # Per-run token ledger (findings-log §4 Item 1); attached by the
        # container in get_judge_agent(). None when run standalone.
        self.token_ledger: TokenLedger | None = None
        # Which stage of the active team this judge is running as. Set by the
        # node before it works — the debate stage when it mediates, the verdict
        # stage when it rules — and read by the evidence recorder.
        self.pipeline_stage: str = "analysis"
        # The job this agent serves, set by the container that built it. Every
        # attach asks for it, so two agents in one job share their handles.
        self._job_id: str = ""
        # Per-run truncation ledger (pitfall P6); same lifecycle. The judge is
        # where ``judge_max_tokens`` binds and where the STIX integrity pass
        # runs, so this is the most load-bearing attachment point of the three.
        self.truncation_ledger: TruncationLedger | None = None
        # Hand the judge a way back to its container, the same way
        # ``BaseAnalyst`` does — read by ``_server_registry`` below. None for
        # standalone use (tests, scripts).
        self._container: Any = None
        # Reasons the run summary should carry, filled in by
        # ``_initialize_mcp_client``. Empty when it attached everything, or
        # never ran.
        self.tools: list[Any] = []
        self.degradation_reasons: list[Any] = []
        # The judge calls tools too — threat intel on a disputed indicator, an
        # ATT&CK or family lookup — and a verdict that cites one has to be
        # checkable the same way an analyst's claim is. Same counter as the
        # analysts, so the ids are one sequence across the whole job.
        self.evidence_counter: EvidenceCounter | None = None
        # The name the meter and the console draw this agent under. Fixed:
        # there is one judge, and the ledger already stamps its entries with
        # this word.
        self.name: str = "judge"
        # The budget meter's rows for this agent's loops, drained by the node
        # that reads its ledger. The meter itself comes from ``BudgetMeter``,
        # so the judge's rows are the shape the analysts' rows are.
        self._budget_records: list[dict[str, Any]] = []
        # Accumulated across mediation rounds and drained by the judge node,
        # for the reason the analysts' buffer is: ``mediate`` runs the loop
        # once per round, and a buffer replaced on each of them would persist
        # only the last round's calls while the earlier ones consumed ids.
        self._evidence_entries: list[LedgerEntry] = []

    def _publish_questions(self, conversation: list[Any], already: set[str]) -> None:
        """Publish each question the judge has asked and not published yet.

        A question, not every intermediate turn. The judge's loop narrates as
        much as it asks, and a console that drew the narration as a question
        card would put a card in front of the reader on nearly every turn; a
        turn whose text ends in a question mark is the one a reader can
        actually answer or wait on. A turn that also calls ``ask_<key>`` names
        that agent as the addressee, because that is who the judge is asking.

        Identified by where the turn sits and what it said, so a hook that
        sees the same conversation twice — which it does, once per model turn
        — publishes each question once, while a judge that asks the identical
        question a second time is published twice. Never raises: this is
        telemetry inside a prompt hook, and a hook that throws ends the loop.
        """
        try:
            for index, message in enumerate(conversation):
                if getattr(message, "type", "") != "ai":
                    continue
                marker = _turn_key(message, index)
                if marker in already:
                    continue
                already.add(marker)
                text = str(getattr(message, "content", "") or "").strip()
                if not text or not text.rstrip().endswith("?"):
                    continue
                emit_judge_question(
                    self._event_sink(),
                    stage=str(getattr(self, "pipeline_stage", "") or "verdict"),
                    text=scrub(text),
                    addressed_to=_who_is_asked(message),
                )
        except Exception as exc:  # noqa: BLE001 — a prompt hook never fails a loop
            self.logger.debug("judge question not published (%s).", exc)

    def _server_registry(self) -> Any | None:
        """The job's tool-server registry, or None when this judge runs bare."""
        container = getattr(self, "_container", None)
        if container is None:
            return None
        return container.get_server_registry()

    def _job_key(self) -> str:
        """A per-job identity for the handles' same-job short circuit."""
        return self._job_id or "job"

    def _definition_tool_refs(self) -> list[Any]:
        """The judge definition's ``ToolRef``s, under the active profile.

        ``JudgeAgent`` is not a ``BaseAnalyst`` and has no ``ResolvedAgent``,
        so it reads its definition itself. The key is always ``judge``: the
        settings validator refuses a second definition with that role.
        """
        container = getattr(self, "_container", None)
        if container is None:
            return []
        from maljan.agents.composition import mcp_refs_for

        return list(mcp_refs_for(container.config, "judge"))

    def _profile_excluded_servers(self) -> str:
        """The servers the active profile withholds, as ``atools_for``'s argument."""
        container = getattr(self, "_container", None)
        if container is None:
            return ""
        from maljan.agents.composition import _excluded_servers

        return _excluded_servers(container.config, "judge")

    async def _initialize_mcp_client(self) -> None:
        """Attach every tool server bound to the ``judge`` role, on this loop.

        Awaited rather than handed to the shared agent loop, for the reason
        ``aclose`` below spells out: whichever loop enters the toolkit's exit
        stack has to be the one that unwinds it.
        """
        if getattr(self, "tools", None):
            return
        registry = self._server_registry()
        if registry is None:
            return
        seen: dict[str, str] = {}
        tools, reasons = await registry.atools_for(
            "judge", self._job_key(), exclude=self._profile_excluded_servers(), seen=seen
        )
        # The judge's definition names its servers the same way an analyst's
        # does, and ``knowledge`` reaches it by that reference alone — it is
        # bound to no role. Awaited here rather than taken from a
        # ``ResolvedAgent`` for the reason ``aclose`` spells out: whichever
        # loop enters a toolkit's exit stack has to be the one that unwinds it.
        for ref in self._definition_tool_refs():
            picked, ref_reasons = await registry.atools_for_ref(ref, self._job_key(), seen=seen)
            tools.extend(picked)
            reasons.extend(ref_reasons)
        self.tools = tools
        self.degradation_reasons = reasons
        self.logger.info("Judge tool servers: %s", [t.name for t in self.tools])

    async def aclose(self) -> None:
        """Release every judge-bound tool server and its stdio subprocess.

        Deliberately *not* routed through the shared agent loop, unlike the
        analysts'. The judge enters its toolkits with a plain ``await`` on
        whichever loop the graph node is running — see
        ``_initialize_mcp_client`` above — so that is the loop that owns the
        exit stacks, and handing the close to a different one is exactly how
        anyio's "cancel scope in a different task" error is produced.

        Without this, every mediation round that failed to initialise left
        another ``threatintel-mcp`` subprocess running: the guard on the
        caller is ``if self.tools: return``, and a failed init never sets
        ``tools``. ``ServerHandle.aclose`` carries the bound this used to
        apply itself.
        """
        self.tools = []
        registry = self._server_registry()
        if registry is None:
            return
        # ``handles_for`` rather than ``for_agent``: a server the registry
        # attached on a second loop has a handle of its own, and this judge
        # cannot tell which of them is the one it was handed. Each closes on
        # the loop that opened it, so it does not need to.
        for handle in registry.handles_for("judge"):
            await handle.aclose()

    async def execute_tool_loop(self, prompt_messages: list) -> str:
        """Execute a tool-calling ReAct loop for the agent."""
        import asyncio

        from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
        from langgraph.prebuilt import create_react_agent

        messages_pre: list[BaseMessage] = []
        for role, content in prompt_messages:
            if role == "system":
                messages_pre.append(SystemMessage(content=content))
            elif role == "human":
                messages_pre.append(HumanMessage(content=content))

        if not getattr(self, "tools", None):
            self.logger.warning("No tools initialized. Falling back to standard LLM invoke.")
            # Wrap the no-tools ainvoke in the
            # same hard timeout used by the tools path so a stalled / queued
            # llama-server cannot freeze the judge node.
            no_tools_timeout = get_settings().react_agent_timeout_overrides.get(
                "judge", get_settings().react_agent_timeout
            )
            response = await asyncio.wait_for(
                retry_on_connection_error(
                    lambda: self.llm.ainvoke(messages_pre),
                    what="Judge no-tools path",
                    log=self.logger,
                ),
                timeout=float(no_tools_timeout),
            )
            record_response_usage(self.token_ledger, response, prompt_text=str(messages_pre))
            record_judge_response(
                getattr(self, "truncation_ledger", None),
                response,
                # The cap this call was actually built with. Passed because the
                # local server truncates silently — same token count, same
                # ``finish_reason: "stop"`` — so the count is the only evidence.
                cap=getattr(get_settings().llm, "judge_max_tokens", None),
            )
            return str(response.content)

        self.logger.info("JudgeAgent starting ReAct agent loop with %d tools...", len(self.tools))

        from maljan.agents.evidence_recorder import EvidenceRecorder, record_tools

        # As in ``BaseAnalyst.execute_tool_loop``: without a container there is
        # no counter, and one per mediation round would reissue ``ev_0001``.
        if self.evidence_counter is None:
            self.evidence_counter = EvidenceCounter()
        recorder = EvidenceRecorder(
            "judge",
            counter=self.evidence_counter,
            # The stage the node set before it called: mediation happens in a
            # debate stage and the verdict in the verdict stage, and a ledger
            # entry that says "analysis" for either sends a reader looking for
            # an analyst that never made the call.
            stage=str(getattr(self, "pipeline_stage", "") or "analysis"),
            sink=self._event_sink(),
        )
        messages = messages_pre

        settings = get_settings()
        timeout = settings.react_agent_timeout
        max_steps = int(settings.react_agent_max_steps)
        # The judge is an agent by every other measure here — its ledger
        # entries carry its name, it binds servers by role, the console draws
        # it as a step — so its loop is metered like one. Without this the one
        # loop with a hard wall-clock timeout was the only one that never said
        # a cap had ended it.
        budget = LoopBudget(max_steps, float(timeout))
        cap: str | None = None
        turns: list[Any] = []

        asked: set[str] = set()

        def _count_the_turns(state: Any) -> list[Any]:
            """Count the conversation before every model turn, and change nothing.

            The analysts' loop counts on the same hook because it is already
            there to refresh their run-state block. The judge has no block to
            refresh, and without something counting, a loop cut off at its
            wall clock hands the meter an empty conversation and records the
            zero steps this meter exists to stop recording.

            The same hook is where a question the judge asks mid-loop is
            published. It is the one seam the loop offers between two model
            turns, so a question reaches a reader while the judge is still
            waiting on the answer rather than after the verdict, which is the
            whole point of showing it.
            """
            conversation = state.get("messages") if isinstance(state, dict) else None
            if conversation is None:
                conversation = getattr(state, "messages", None) or []
            conversation = list(conversation)
            # The turn about to be taken counts. The hook runs before the
            # model, so a loop cut off *during* its first turn would otherwise
            # record nothing at all — and the judge's characteristic failure is
            # exactly that, one verdict call that ran past its wall clock.
            budget.note_turns(conversation)
            budget.own_steps += 1
            self._publish_questions(conversation, asked)
            return conversation

        agent_executor = create_react_agent(
            self.llm, record_tools(self.tools, recorder), prompt=_count_the_turns
        )
        self.logger.info(
            "JudgeAgent invoking ReAct (timeout=%ds, tools=%d)...",
            timeout,
            len(self.tools),
        )
        try:
            result = await asyncio.wait_for(
                agent_executor.ainvoke(
                    {"messages": messages},
                    {"recursion_limit": max_steps},
                ),
                timeout=timeout,
            )
            _msgs = result.get("messages", []) or []
            turns = list(_msgs)
            msg_count = len(_msgs)
            self.logger.info("JudgeAgent ReAct loop completed: %d messages.", msg_count)
            # Record every AI turn the ReAct executor produced
            # so the mediator's tool-loop LLM calls land in the per-run
            # TokenLedger (the tools path previously recorded nothing — only
            # the no-tools fallback above did).
            for _m in _msgs:
                if getattr(_m, "type", "") == "ai":
                    record_response_usage(self.token_ledger, _m)
            return str(_msgs[-1].content)
        except TimeoutError:
            self.logger.error("JudgeAgent ReAct timed out after %ds.", timeout)
            cap = "time"
            raise
        finally:
            # In a ``finally`` for the reason the analysts' loop uses one: a
            # mediation that timed out still made the calls it made.
            self._evidence_entries.extend(recorder.entries)
            self._record_budget(
                budget,
                turns,
                cap,
                detail=(f"the loop did not answer within {timeout}s" if cap else ""),
            )
            self._budget_tick(budget, turns, final=True, ledger_entries=len(recorder.entries))

    def drain_evidence_entries(self) -> list[LedgerEntry]:
        """Every entry the judge's tool loops gathered, handing over ownership."""
        entries = self._evidence_entries
        self._evidence_entries = []
        return entries

    @staticmethod
    def _has_explicit_dissent(isr_reports: dict[str, AgentISR] | None) -> bool:
        """Check if any agent has registered explicit dissent against peer findings.

        When all dissent_items are empty, agents fundamentally agree on the
        evidence — the mediator only needs to confirm consensus, not run
        ThreatIntel tools to resolve disputes.
        """
        if not isr_reports:
            return True  # conservative: no ISR data means we can't tell
        return any(
            bool(isr.dissent_items) for isr in isr_reports.values() if isinstance(isr, AgentISR)
        )

    def _holds_a_lookup_tool(self) -> bool:
        """Whether a reputation server is among this judge's own tools.

        Asked of the servers rather than of the tool names: the loop can only
        answer an identity question if something in it can look a hash up, and
        a judge holding only the knowledge sidecar would spend a full timeout
        to learn nothing.
        """
        from maljan.agents.tool_pinning import server_of
        from maljan.core.config import REPUTATION_SERVER_KEYS

        attached = {server_of(tool) for tool in (getattr(self, "tools", None) or [])}
        referenced = {str(ref.server) for ref in self._definition_tool_refs()}
        return bool((attached | referenced) & set(REPUTATION_SERVER_KEYS))

    def _can_ask_an_identity_question(self, ledger_servers: Iterable[str] | None) -> bool:
        """Whether the judge should open its tool loop to ask who this sample is.

        The loop used to run on dissent alone, so a run where every analyst
        agreed — and none of them had a reputation tool to agree *about* —
        ended with a judge holding a bound VirusTotal server it never called
        and a family of None.

        What settles it is the run's own record: the servers the evidence
        ledger names. An earlier version read the analysts' prose for words
        like "malware family", which turned the trigger *off* for the sentence
        an analyst writes when it consulted nothing at all ("no malware family
        could be determined") — the very case the trigger exists for. A tool
        call is a fact, and a sentence is not one.
        """
        if not self._holds_a_lookup_tool():
            return False
        from maljan.core.config import REPUTATION_SERVER_KEYS

        asked = {str(name) for name in (ledger_servers or ())}
        return not (asked & set(REPUTATION_SERVER_KEYS))

    async def mediate(
        self,
        reports: dict[str, str],
        history: list[AgentArgument],
        isr_reports: dict[str, AgentISR] | None = None,
        consensus_threshold: float | None = None,
        ledger_servers: Iterable[str] | None = None,
        sample: Any = None,
        facts_block: str = "",
        run_state: str = "",
    ) -> tuple[AgentArgument, bool]:
        """Find contradictions between expert reports and determine consensus.

        Accepts a generic dict of agent reports so any number of agents can
        participate without requiring changes to this method's signature.

        Fast path: when no explicit dissent is present in the ISRs, the mediator
        skips the expensive ReAct tool loop and uses a single LLM call to
        produce the structured verdict. ThreatIntel tools are only invoked when
        agents actually disagree on specific indicators.

        Args:
            reports: Mapping of agent name to their latest report text.
            history: Accumulated negotiation arguments from prior rounds.
            isr_reports: Optional structured ISR objects. When provided, their
                summaries are appended to give the judge per-claim confidence
                scores and explicit dissent signals.

        Returns:
            Tuple of (AgentArgument with mediator findings, bool indicating consensus).
        """
        self.logger.info("Mediating %d expert reports for contradictions...", len(reports))
        needs_tools = self._has_explicit_dissent(isr_reports)
        identity_unanswered = not needs_tools and self._can_ask_an_identity_question(ledger_servers)
        needs_tools = needs_tools or identity_unanswered

        # Build a human-readable summary of all reports
        reports_text = "\n\n".join(
            f"--- {name.upper()} ANALYST ---\n{report}" for name, report in reports.items()
        )

        # Append ISR summaries when available — gives judge access to per-claim
        # confidence scores and explicit dissent signals from each agent.
        if isr_reports:
            isr_block = "\n\n".join(
                f"[ISR] {isr.to_text_summary()}"
                for isr in isr_reports.values()
                if isr.claims  # skip empty ISRs
            )
            if isr_block:
                reports_text = f"{reports_text}\n\n=== STRUCTURED CLAIMS (ISR) ===\n{isr_block}"

        # The mediator is NOT allowed to state a
        # verdict or describe the sample as "clean". Its only job is to
        # surface explicit contradictions between agents and quantify how
        # aligned they are. The downstream judge LLM owns the verdict
        # decision — earlier prompt wording let "CLEAN / NO THREAT DETECTED"
        # prose leak into the judge prompt and bias the verdict toward
        # benign even when YARA had a hit.
        prompt_messages = [
            (
                "system",
                "You are the Lead Cyber Security Mediator. Your ONLY task is to "
                "compare expert analyst reports and emit:\n"
                "  1. A list of EXPLICIT contradictions between agents "
                "(one bullet per contradiction).\n"
                "  2. A single agreement_confidence in [0.0, 1.0] for how "
                "aligned the agents are — NOT the maliciousness of the sample.\n\n"
                "HARD RULES:\n"
                "- DO NOT emit a verdict. Never write 'Malware', 'Benign', "
                "'Suspicious', 'CLEAN', 'NO THREAT', or any synonym.\n"
                "- DO NOT recommend re-running pipelines or filling data gaps.\n"
                "- When an analyst has failed/empty output, write 'no input "
                "from <agent>' and EXCLUDE that analyst from the contradiction "
                "count. DO NOT treat absence of input as confirmation of "
                "cleanliness.\n"
                "- agreement_confidence reflects ONLY agent alignment, NOT how "
                "suspicious the sample looks. Two analysts unanimously saying "
                "nothing is still high alignment (1.0).\n"
                "- Your LAST line MUST be exactly 'agreement_confidence: <number>' "
                "with a decimal between 0.0 and 1.0 — no percent sign, no words, "
                "no range. Nothing may follow it. When this line is missing or "
                "unreadable the run is treated as no-consensus and every analyst "
                "is made to revise again, so it is not optional.\n"
                "- The downstream Judge alone decides Malware/Benign/Suspicious. "
                + (
                    "You have reputation tools and no analyst has consulted one. "
                    f"Look the sample's hash up once — its sha256 is {_sha256_of(sample)} "
                    "and it is in the sample identity block below — cite what comes back "
                    "as evidence, and treat a reputation label as one source rather than "
                    "as the verdict.\n"
                    if identity_unanswered and _sha256_of(sample)
                    else "You have reputation tools and no analyst has consulted one. "
                    "Look the sample up once to settle its identity, cite what comes "
                    "back as evidence, and treat a reputation label as one source "
                    "rather than as the verdict.\n"
                    if identity_unanswered
                    else "You have Threat Intelligence tools to verify disputed "
                    "IPs/domains/hashes — use them only to resolve contradictions.\n"
                    if needs_tools
                    else "No Threat Intelligence tools are needed for this run.\n"
                ),
            ),
            (
                "human",
                f"{_standing_blocks(run_state, facts_block)}"
                f"{_identity_prefix(sample)}"
                f"Expert Reports:\n{reports_text}\n\nPrevious Discussion:\n{history}\n\n"
                "List the contradictions and give a single agreement_confidence "
                "score. Do not state a verdict.",
            ),
        ]

        if needs_tools:
            self.logger.info(
                "Mediator: %s — running ReAct tool loop.",
                "no analyst consulted a reputation source"
                if identity_unanswered
                else "explicit dissent detected",
            )
            await self._initialize_mcp_client()
            reasoning_text = await self.execute_tool_loop(prompt_messages)
        else:
            self.logger.info("Mediator: no dissent — fast path (single LLM call).")
            # Pass already-formatted content as BaseMessage list to avoid
            # ChatPromptTemplate interpreting literal { } inside report text
            # (e.g. JSON snippets) as template variables.
            from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage

            direct_messages: list[BaseMessage] = []
            for role, content in prompt_messages:
                if role == "system":
                    direct_messages.append(SystemMessage(content=content))
                elif role == "human":
                    direct_messages.append(HumanMessage(content=content))
            try:
                response = await asyncio.wait_for(
                    retry_on_connection_error(
                        lambda: self.llm.ainvoke(direct_messages),
                        what="Mediator fast path",
                        log=self.logger,
                    ),
                    timeout=float(get_settings().react_agent_timeout),
                )
            except TimeoutError:
                self.logger.error("Mediator fast-path timed out. Falling back to tool loop.")
                await self._initialize_mcp_client()
                reasoning_text = await self.execute_tool_loop(prompt_messages)
            else:
                reasoning_text = str(response.content)

        # Now extract the final structured output from the detailed reasoning.
        # IMPORTANT: reasoning_text may contain curly braces from LLM output
        # (e.g. JSON, {type}), so we use a template variable instead of f-string.
        extract_prompt = ChatPromptTemplate.from_messages(
            [
                (
                    "system",
                    "Extract the final structured verdict from the mediator's reasoning log.\n"
                    "You MUST produce a structured response with:\n"
                    "- contradictions: list of specific contradictions found\n"
                    "- resolution_summary: what was resolved and what remains\n"
                    "- confidence: float 0.0-1.0 (0.9+ means experts agree, no contradictions)",
                ),
                (
                    "human",
                    "{reasoning_log}",
                ),
            ]
        )

        # Structured output extraction with bounded retry; if every attempt
        # still fails, fall back to the regex-based extractor so the
        # negotiation loop can keep running.
        verdict = await self._extract_mediator_verdict(extract_prompt, reasoning_text)

        is_consensus = verdict.confidence >= self._consensus_threshold(consensus_threshold)
        log_msg = "Consensus reached" if is_consensus else "No consensus yet"
        self.logger.info("%s (confidence=%.2f)", log_msg, verdict.confidence)

        finding = (
            f"{verdict.resolution_summary}\n\n"
            f"Contradictions: {'; '.join(verdict.contradictions) or 'None'}\n"
            f"Confidence: {verdict.confidence:.2f}"
        )
        argument = AgentArgument(
            agent_name="Mediator",
            finding=finding,
            confidence_score=verdict.confidence,
        )
        return argument, is_consensus

    async def give_verdict(
        self,
        reports: dict[str, str],
        history: list[AgentArgument],
        isr_reports: dict[str, AgentISR] | None = None,
        evidence_summary: str = "",
        degradation_note: str = "",
        memory_store: MemoryStore | None = None,
        evidence_corpus: set[str] | None = None,
        current_sample_id: str | None = None,
        sample: Any = None,
        ledger_ids: Sequence[str] | None = None,
        facts_block: str = "",
        run_state: str = "",
    ) -> JudgeVerdict:
        """The final decision: a STIX bundle plus the judge's own assessment.

        ``evidence_summary`` is the block from ``pipeline.evidence_summary`` —
        who named which technique and how sure each one was. ``degradation_note``
        says why this run is thin, when it is; both go into the prompt because
        the judge is the component that should be weighing them. ``facts_block``
        is the triage pack as every analyst saw it and ``run_state`` the run's
        state block; both lead the human turn so the verdict is drawn over the
        same facts the analysts were given.

        The answer is validated (``pipeline.validation.validate_verdict_bundle``)
        and, when something is wrong, handed back once with the problems named.
        Whatever is still wrong comes back in :class:`JudgeVerdict.violations`
        rather than being fixed in place — except an ungrounded indicator, which
        is dropped, because a STIX consumer has no way to read a caveat.
        """
        self.logger.info("Formulating final malware verdict with MITRE ATT&CK mapping...")

        # Build compact reports to avoid context bloat.
        # Full reports can exceed 15K tokens; we truncate each to ~500 chars
        # and only keep ISR claims + the evidence summary.
        report_parts: list[str] = []
        for name, report in reports.items():
            truncated = report[:500] + "..." if len(report) > 500 else report
            report_parts.append(f"--- {name.upper()} ANALYST ---\n{truncated}")
        reports_text = "\n\n".join(report_parts)

        # Include ISR summaries (compact)
        if isr_reports:
            isr_block = "\n".join(
                f"[{name}] domain={isr.domain} | "
                f"claims={len(isr.claims)} | "
                f"mean_conf={isr.mean_confidence:.2f}"
                for name, isr in isr_reports.items()
                if isr.claims
            )
            if isr_block:
                reports_text += f"\n\n=== ISR SUMMARIES ===\n{isr_block}"

        if evidence_summary:
            reports_text = f"{reports_text}\n\n{evidence_summary[:_EVIDENCE_SUMMARY_CHARS]}"

        if degradation_note:
            reports_text = f"{reports_text}\n\n{degradation_note}"

        # Long-term memory — inject top-K similar past cases as
        # weighted priors. The block is bounded (~1.2 KB worst case for
        # top_k=3) and degrades gracefully to an empty string when the store
        # is empty or retrieval fails.
        memory_block = self._build_memory_context(
            isr_reports, memory_store, current_sample_id=current_sample_id
        )
        if memory_block:
            reports_text = f"{reports_text}\n\n{memory_block}"

        # Built as messages rather than through ``ChatPromptTemplate``: the
        # system turn now contains a JSON skeleton, and a template would read
        # its braces as placeholders and refuse the prompt outright.
        messages: list[Any] = [
            SystemMessage(content=JUDGE_VERDICT_SYSTEM),
            HumanMessage(
                content=(
                    f"{_standing_blocks(run_state, facts_block)}"
                    f"{_identity_prefix(sample)}"
                    f"Expert Reports:\n{reports_text}\n\n"
                    f"Negotiation History:\n{str(history)[:800]}\n\n"
                    "Return a JSON STIX 2.1 Bundle."
                )
            ),
        ]

        # Resolve the judge-specific timeout via the same override mechanism
        # the analyst agents use. ``react_agent_timeout_overrides`` ships
        # with ``{"static": 600, "judge": 300}`` so local Qwen3.6-35B has
        # enough headroom for the verdict round (the 2026-05-23 E2E run hit
        # the previous hardcoded 180s ceiling). Falls back to the global
        # ``react_agent_timeout`` when no override is configured.
        _settings = get_settings()
        _overrides = getattr(_settings, "react_agent_timeout_overrides", {}) or {}
        timeout = float(_overrides.get("judge", _settings.react_agent_timeout))
        self.logger.info("JudgeAgent invoking verdict LLM (timeout=%ds)...", timeout)

        # Reset per call, not once: a first call that timed out and left the
        # flag set made every later parse return the fallback, and a fallback
        # that happened to validate dirty would then spend a second full judge
        # timeout and throw the answer away.
        timed_out = False

        async def _ask(turns: list[Any]) -> Any:
            return await retry_on_connection_error(
                lambda: self.llm.ainvoke(turns),
                what="Judge verdict",
                log=self.logger,
            )

        async def _run(turns: list[Any]) -> Any:
            nonlocal timed_out
            timed_out = False
            try:
                # On the shared agent loop, not on the graph's. The judge's
                # model is one cached client and the mediator has already used
                # it — from ``run_on_agent_loop`` — by the time the verdict is
                # asked for, so its httpx pool holds connections bound to that
                # loop. Awaiting the same client here on the worker's loop made
                # the *first* verdict request of every run die instantly with
                # ``APIConnectionError("Connection error.")`` before a byte
                # reached llama-server; the SDK then dropped the dead
                # connection and the retry, opening a fresh one, always
                # succeeded. See ``run_on_agent_loop`` for the same fault in
                # the mediator, and for why one loop owns every LLM call.
                return await run_on_agent_loop(_ask(turns), timeout, label="judge:verdict")
            except TimeoutError:
                self.logger.error("JudgeAgent verdict timed out after %ds.", timeout)
                timed_out = True
                return "[TIMEOUT]"

        # Whether the answer being validated was a JSON bundle at all, and how
        # many turns have been spent. A model that answered with prose or with
        # a tool call has said nothing about the sample, and the fallback
        # extraction over that text is worth building only once the model has
        # had its one chance to answer properly.
        not_json = False
        attempts = 0

        def _parse(answer: Any) -> Bundle:
            nonlocal not_json, attempts
            attempts += 1
            if timed_out:
                not_json = False
                return self._fallback_bundle_from_text(
                    "[TIMEOUT]", reports, isr_reports, extracted=False
                )
            not_json = _is_not_json(answer)
            if not_json:
                self.logger.warning(
                    "Judge verdict: the model answered with %d character(s) that are not a JSON "
                    "bundle; asking once more before falling back to text extraction.",
                    len(_answer_text(answer)),
                )
                if attempts <= _VERDICT_RETRIES:
                    # A retry is coming and this bundle would be thrown away.
                    return Bundle(objects=[])
            return self._bundle_from_response(answer, reports, isr_reports)

        # The same catalogue the analyst loop consults. Absent (an air-gapped
        # box with no vendored id list) the technique question is skipped
        # rather than answered wrongly.
        try:
            from maljan.tools import knowledge as _knowledge
        except Exception as exc:  # noqa: BLE001 — a knowledge lookup degrades, never raises
            self.logger.debug("Judge verdict: the knowledge tools are unavailable (%s).", exc)
            _knowledge = None  # type: ignore[assignment]

        _analyst_claims = sum(
            len(getattr(isr, "claims", None) or []) for isr in (isr_reports or {}).values()
        )

        def _verdict_checks(bundle: Bundle) -> list[Violation]:
            """What a Benign or a Malware verdict over a silent run cites.

            Its own function because it runs on the timeout path too, where it
            is recorded rather than fed back: those two checks are the ones
            that ask whether the verdict in front of them has anything behind
            it, and the path that most needed asking was the one path that
            skipped them.
            """
            return [
                *unsupported_benign_violations(
                    bundle,
                    analyst_claims=_analyst_claims,
                    ledger_ids=ledger_ids,
                ),
                *unsupported_malware_violations(
                    bundle,
                    analyst_claims=_analyst_claims,
                    ledger_ids=ledger_ids,
                ),
            ]

        def _validate(bundle: Bundle) -> list[Violation]:
            # A timeout produced no answer, so there is nothing to give
            # feedback about. Reporting no violations ends the loop: a retry
            # would cost a second full judge timeout and could only produce the
            # same fallback bundle. What the checks below have to say about the
            # fallback bundle is recorded after the loop instead.
            if timed_out:
                return []
            if not_json:
                return [Violation(code="verdict.not_json", message=_NOT_JSON_FEEDBACK)]
            return [
                *validate_verdict_bundle(bundle, evidence_corpus, attck=_knowledge, sample=sample),
                *assessment_violations(bundle),
                *assessment_conflict_violations(bundle),
                *_verdict_checks(bundle),
            ]

        tally = ValidationTally()
        bundle, violations, retries = await retry_with_feedback(
            _run,
            messages,
            [_validate],
            max_retries=_VERDICT_RETRIES,
            parse=_parse,
            on_feedback=tally.count,
            sink=self._event_sink(),
            agent="judge",
            stage=str(getattr(self, "pipeline_stage", "") or "verdict"),
        )
        if timed_out:
            # No answer at all, so there is nothing to feed back and nothing
            # was: the bundle is this pipeline's own conservative verdict.
            # Cheap to record and invisible without it. The two verdict checks
            # run here rather than in the loop: they annotate what the fallback
            # carries, they do not change it, and a retry is not what they ask
            # for on a path where nobody is listening.
            violations = [
                *violations,
                Violation(code=VERDICT_TIMEOUT_CODE, message=VERDICT_TIMEOUT_REASON),
                *_verdict_checks(bundle),
            ]
        if not_json:
            # The retry answered with prose or a tool call as well, so the
            # bundle is whatever the text extraction could make of it. That is
            # a fact about this run, not a schema problem the model can fix:
            # the feedback violation is replaced by one that says the verdict
            # is a fallback, and it stays unresolved so the run summary and the
            # report's degradation reasons both carry it.
            violations = [v for v in violations if v.code != "verdict.not_json"]
            violations.append(
                Violation(code=VERDICT_FALLBACK_CODE, message=VERDICT_FALLBACK_REASON)
            )
        dropped = drop_ungrounded_indicators(bundle, violations)
        if dropped:
            self.logger.warning(
                "Judge verdict: %d indicator(s) stayed ungrounded after the retry and were "
                "dropped; they are recorded in the run summary.",
                dropped,
            )
        return JudgeVerdict(
            bundle=bundle, violations=violations, retries=retries, fed_back=dict(tally.by_code)
        )

    def _bundle_from_response(
        self,
        answer: Any,
        reports: dict[str, str],
        isr_reports: dict[str, AgentISR] | None,
    ) -> Bundle:
        """The model's raw answer as a Bundle, or the text fallback."""
        raw = str(getattr(answer, "content", answer))

        from maljan.utils.json_cleaner import safe_parse_json

        data = safe_parse_json(raw)
        if not isinstance(data, dict):
            self.logger.warning(
                "LLM did not return a JSON object (got %s). Attempting text-based fallback.",
                type(data).__name__,
            )
            return self._fallback_bundle_from_text(raw, reports, isr_reports)

        try:
            # No technique-id filter here. Dropping the object silently is what
            # made ``stix.unknown_technique`` unreachable: the judge never
            # learned it had invented an id, and the report showed one fewer
            # attack-pattern with nothing saying why. ``pipeline.validation`` is
            # the single place that decides an id is wrong, and it says so.
            from maljan.agents.judge_postprocess import postprocess_judge_bundle

            data = postprocess_judge_bundle(data, ledger=getattr(self, "truncation_ledger", None))
            return Bundle.model_validate(data)
        except Exception as exc:  # noqa: BLE001 — a malformed bundle degrades to the fallback
            self.logger.warning(
                "LLM did not return a valid Bundle: %s. Attempting text-based fallback.", exc
            )
            return self._fallback_bundle_from_text(raw, reports, isr_reports)

    async def _extract_mediator_verdict(
        self,
        extract_prompt: ChatPromptTemplate,
        reasoning_text: str,
        max_attempts: int = 3,
        base_delay: float = 0.5,
    ) -> MediatorVerdict:
        """Run ``with_structured_output`` with bounded exponential-backoff retry.

        ``with_structured_output`` itself may raise for providers that don't
        support the structured-output path — we build the wrapper inside the
        loop so a provider-level failure also routes through the fallback.

        Check the provider
        capability table before attempting ``with_structured_output``.
        Ollama (and any future provider that lacks tool-calling) is routed
        directly to the text fallback so we don't pay 3 retry rounds for a
        feature that will never work. The capability table lives in
        ``maljan.llm.registry``.
        """
        if not self._supports_structured_output():
            self.logger.info(
                "Provider lacks structured-output support; using text fallback "
                "for mediator verdict extraction."
            )
            return self._fallback_mediate(reasoning_text)

        last_exc: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                llm_structured = self.llm.with_structured_output(MediatorVerdict)
                result = await (extract_prompt | llm_structured).ainvoke(
                    {"reasoning_log": reasoning_text}
                )
                if isinstance(result, MediatorVerdict):
                    return result
                raise ValueError(
                    f"Structured output produced unexpected type: {type(result).__name__}"
                )
            except Exception as exc:
                last_exc = exc
                self.logger.warning(
                    "Structured mediator output failed (attempt %d/%d): %s",
                    attempt,
                    max_attempts,
                    exc,
                )
                if attempt < max_attempts:
                    await asyncio.sleep(base_delay * (2 ** (attempt - 1)))

        self.logger.error(
            "Structured mediator output exhausted retries (%d). Falling back to text extraction. "
            "Last error: %s",
            max_attempts,
            last_exc,
        )
        return self._fallback_mediate(reasoning_text)

    # ------------------------------------------------------------------
    # Verdict keyword detection (used by the text fallback path)
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_from_text(text: str) -> str:
        """Token-level verdict extraction.

        The previous implementation searched for ``"malware"`` and
        ``"benign"`` as substrings, which let phrases like *"not malware"*
        or *"likely not benign"* flip the result. We now tokenise into
        word-shape segments and ignore negation neighbours.
        """
        import re

        tokens = re.findall(r"[a-z]+", text.lower())
        if not tokens:
            return "Suspicious"

        negators = {"not", "no", "non", "neither", "without", "isn't"}
        for i, tok in enumerate(tokens):
            if tok == "malware":
                prev = tokens[i - 1] if i > 0 else ""
                if prev not in negators and prev != "non":
                    return "Malware"
        for i, tok in enumerate(tokens):
            if tok in {"benign", "clean"} or tok.startswith("non-malicious"):
                prev = tokens[i - 1] if i > 0 else ""
                if prev not in negators:
                    return "Benign"
        return "Suspicious"

    def _fallback_bundle_from_text(
        self,
        text: str,
        reports: dict[str, str],
        isr_reports: dict[str, AgentISR] | None = None,
        *,
        extracted: bool = True,
    ) -> Bundle:
        """Build a minimal STIX Bundle when the LLM fails to produce valid JSON.

        The verdict is read out of the judge's own text and the bundle's object
        set follows it: a ``malware`` object only when the verdict is Malware.
        It used to be emitted unconditionally, and since the pipeline read the
        verdict off the objects, the bundle's shape overrode the verdict the
        judge had actually expressed — a judge that timed out reported Malware
        over a signed sample with no claim behind it.

        ``extracted`` is false when there was no answer to read at all, which is
        what a timeout leaves. Then the verdict is this pipeline's own
        conservative one rather than anything a model said, and the bundle says
        so in ``x_maljan_fallback_verdict``.
        """
        from maljan.pipeline.outcome import INCONCLUSIVE_VERDICT
        from maljan.schemas.stix_models import Bundle

        decision = self._verdict_from_text(text) if extracted else INCONCLUSIVE_VERDICT

        if extracted:
            self.logger.info(
                "Fallback Bundle: extracted verdict='%s' from text response (%d chars).",
                decision,
                len(text),
            )
        else:
            self.logger.info(
                "Fallback Bundle: no answer to read; the verdict is the pipeline's own '%s'.",
                decision,
            )

        # Fail closed. This used to union two sets and emit them as one: the
        # technique identifiers the analysts had claimed against cited evidence,
        # and any identifier matching the pattern anywhere in the model's raw
        # response. Both became attack-patterns in the same bundle, with nothing
        # to tell them apart -- so on the path where the judge had failed, the
        # model had more influence over what reached an analyst than on the path
        # where it worked. Identifiers scraped from the raw text are real ATT&CK
        # identifiers no evidence source claimed, which is exactly what a schema
        # check cannot catch. They are recorded for audit and are not emitted.
        import re

        _VALID_TID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")
        tids: set[str] = set()
        if isr_reports:
            for isr in isr_reports.values():
                for claim in isr.claims:
                    if claim.technique_id and _VALID_TID_RE.match(claim.technique_id):
                        tids.add(claim.technique_id)
        model_only = sorted(set(_VALID_TID_RE.findall(text)) - tids)
        if model_only:
            self.logger.warning(
                "Fallback Bundle: %d technique identifier(s) appeared in the model's raw "
                "response and in no evidence claim; recorded, not emitted: %s",
                len(model_only),
                ", ".join(model_only),
            )

        # Don't bake the raw fallback text (which may contain ``[TIMEOUT]``
        # or other internal markers) into the malware SDO description —
        # downstream cross-layer aggregation can upgrade the verdict in
        # ``report_node`` and the user-visible description should reflect
        # the final verdict, not the intermediate fallback. The judge
        # rationale is preserved in ``x_maljan_fallback_reasoning`` for
        # debug consumers.
        text_snippet = (text[:2000] if text else "No structured output available.").replace(
            "\n", " "
        )
        objects: list[dict[str, Any]] = []
        malware_id = ""
        if decision == "Malware":
            malware_id = f"malware--{uuid.uuid4()}"
            malware: dict[str, Any] = {
                "type": "malware",
                "id": malware_id,
                "name": "analyzed-sample",
                "malware_types": ["unknown"],
                "is_family": False,
                "description": (
                    f"Verdict: {decision} (judge fallback; subject to cross-layer review)"
                ),
                "x_maljan_fallback_reasoning": text_snippet,
                "x_maljan_degraded_path": True,
            }
            # Only when non-empty: the STIX validator refuses a property
            # serialised as null or as an empty array, which is one of the two
            # conformance defects an external validator found in this emitter.
            if model_only:
                malware["x_maljan_model_only_technique_ids"] = model_only
            objects.append(malware)
        else:
            # A verdict that is not Malware gets no malware object, so the
            # rationale and the record of what was dropped need somewhere else
            # to live: a Note, which is where STIX puts an analyst's own words
            # about a set of objects.
            note: dict[str, Any] = {
                "type": "note",
                "id": f"note--{uuid.uuid4()}",
                "abstract": f"Verdict: {decision} (judge fallback)",
                "content": text_snippet,
                "x_maljan_degraded_path": True,
            }
            if model_only:
                note["x_maljan_model_only_technique_ids"] = model_only
            objects.append(note)

        for tid in sorted(tids):
            attack_id = f"attack-pattern--{uuid.uuid4()}"
            objects.append(
                {
                    "type": "attack-pattern",
                    "id": attack_id,
                    "name": tid,
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": tid,
                            "url": f"https://attack.mitre.org/techniques/{tid}",
                        }
                    ],
                }
            )
            if not malware_id:
                # Nothing to relate the technique to, and a relationship with a
                # dangling source is a defect the integrity pass would prune.
                continue
            objects.append(
                {
                    "type": "relationship",
                    "id": f"relationship--{uuid.uuid4()}",
                    "relationship_type": "uses",
                    "source_ref": malware_id,
                    "target_ref": attack_id,
                    "x_maljan_confidence": 0.5,
                    "x_maljan_evidence_basis": "unknown",
                    "x_maljan_contributing_agents": [],
                    "x_maljan_technique_id": tid,
                }
            )

        return Bundle.model_validate(
            {
                "objects": objects,
                "x_maljan_fallback_verdict": {
                    "decision": decision,
                    "source": "extracted" if extracted else "pipeline",
                },
            }
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _consensus_threshold(self, override: float | None = None) -> float:
        """The confidence at which mediation counts as consensus.

        ``NEGOTIATION__CONSENSUS_THRESHOLD`` was documented, validated and
        never read: the check used the module constant, so setting the
        variable changed nothing. The debate stage's own threshold wins when
        the caller passes one, then the configured global, and the constant
        remains the default for standalone use.
        """
        if override is not None:
            return float(override)
        negotiation = getattr(self._config, "negotiation", None)
        value = getattr(negotiation, "consensus_threshold", None)
        return float(value) if value is not None else CONSENSUS_THRESHOLD

    def _supports_structured_output(self) -> bool:
        """Delegates to the registry — see ``structured_output_supported``.

        ``self._config`` was read here but never assigned (``JudgeAgent`` took
        no config), so the provider name came from ``ChatOpenAI._llm_type`` =
        ``"openai-chat"``, absent from ``PROVIDER_CAPABILITIES``, and every
        provider got the unknown-provider default. The container passes the
        config now, and the decision itself is shared with the two other
        callers that were making it independently.
        """
        from maljan.llm.registry import structured_output_supported

        return structured_output_supported(getattr(self, "_config", None), self.llm)

    def _fallback_mediate(
        self,
        reasoning_text: str,
    ) -> MediatorVerdict:
        """Plain-text fallback when structured output is unavailable.

        Not really a fallback: the capability check in
        ``_extract_mediator_verdict`` routes every provider here, so this is
        the only path that decides consensus in production.
        """
        confidence = self._extract_confidence_from_text(reasoning_text)
        if confidence is None:
            # Previously this returned a hardcoded 0.5, indistinguishable from
            # a mediator that genuinely scored 0.5 and logged nowhere. Since
            # 0.5 < CONSENSUS_THRESHOLD it also meant the negotiation loop
            # could never converge: the 2026-07-29 run showed exactly
            # ``confidence=0.50`` every round and burned all five revisions.
            # An unreadable log is now loud, and still cannot end the loop.
            self.logger.warning(
                "Mediator agreement score not found in the reasoning log; "
                "treating as no-consensus. First 200 chars: %r",
                reasoning_text.strip()[:200],
            )
            confidence = _UNREADABLE_AGREEMENT
        return MediatorVerdict(
            contradictions=[],
            resolution_summary=reasoning_text[:500],
            confidence=confidence,
        )

    @staticmethod
    def _extract_confidence_from_text(text: str) -> float | None:
        """Read the mediator's agreement score, or ``None`` if it is not there.

        The number must sit **adjacent to the key** — the previous version
        accepted any token on any line mentioning "confidence" and clamped it
        into range, so ``"Confidence: 0.95 (based on 3 agents)"`` scanned in
        reverse, hit ``3``, clamped to 1.0 and declared instant consensus off
        a number that was never a score. Out-of-range values are therefore
        rejected rather than clamped: clamping is what made the wrong token
        look legitimate.

        The reasoning prompt asks for ``agreement_confidence``; the bare word
        is accepted too because the model does not always echo the key.
        """
        matches = _AGREEMENT_RE.findall(text or "")
        for raw, pct in reversed(matches):  # the model's last word wins
            try:
                value = float(raw)
            except ValueError:
                continue
            if pct:
                value /= 100.0
            if 0.0 <= value <= 1.0:
                return value
        return None

    @staticmethod
    def _build_memory_context(
        isr_reports: dict | None,
        memory_store: MemoryStore | None,
        current_sample_id: str | None = None,
    ) -> str:
        """Retrieve similar past cases and format them as a few-shot prompt block.

        Queries the MemoryStore with a summary of the
        current ISR claims. The retrieved cases are formatted as a structured
        context block to help the judge leverage historical analysis patterns.

        The judge is explicitly instructed to treat retrieved cases as weighted
        priors — not to copy technique IDs blindly, but to corroborate them with
        current evidence. This prevents retrieval hallucination (assuming a past
        case's TTPs must apply to the current sample).

        Args:
            isr_reports: Current ISR reports (used to build the search query).
            memory_store: MemoryStore-protocol object, or None to skip.

        Returns:
            Formatted prompt block string, or "" when store is None/empty or
            no similar cases are found.
        """
        if memory_store is None or not isr_reports:
            return ""

        # Build search query from all current ISR claims
        query_parts: list[str] = []
        for isr in isr_reports.values():
            for claim in isr.claims:
                query_parts.append(claim.claim)
                if claim.evidence_ref:
                    query_parts.append(claim.evidence_ref)
                if claim.technique_id:
                    query_parts.append(claim.technique_id)
        query = " ".join(query_parts)

        if not query.strip():
            return ""

        try:
            # Never retrieve the current
            # sample's own past run as a "weighted prior". Newer
            # QdrantStore.retrieve accepts ``exclude_sample_id``; older
            # MemoryStore implementations (InMemoryStore in tests) may
            # not — fall back to the unfiltered call in that case.
            try:
                cases = memory_store.retrieve(
                    query,
                    top_k=3,
                    exclude_sample_id=current_sample_id,
                )
            except TypeError:
                cases = memory_store.retrieve(query, top_k=3)
                if current_sample_id:
                    cases = [c for c in cases if c.sample_id != current_sample_id]
        except Exception:  # noqa: BLE001
            # Never let retrieval failure block verdict generation
            return ""

        if not cases:
            return ""

        total = len(cases)
        lines: list[str] = [
            "=== LONG-TERM MEMORY: Similar Past Case(s) ===",
            "Use these historical analyses as WEIGHTED PRIORS for TTP selection.",
            "Do NOT copy technique IDs blindly — corroborate with current evidence.",
            "",
        ]

        for idx, case in enumerate(cases, 1):
            ttps = ", ".join(case.technique_ids) if case.technique_ids else "none"
            summary = (
                (case.summary_text[:200] + "...")
                if len(case.summary_text) > 200
                else case.summary_text
            )
            lines.append(
                f"[{idx}/{total}] sample_id: {case.sample_id} (category: {case.malware_category})"
            )
            lines.append(f"  Past techniques: {ttps}")
            lines.append(f"  Behavioral summary: {summary}")

        lines.append("=== END LONG-TERM MEMORY ===")
        return "\n".join(lines)
