"""What the stub model answers: one script per role, read from the request itself.

The role is read from the request — the words its system prompt opens with,
the negotiation framing a revision appends, the tools it carries — never from
an agent's configured name, so a renamed or added agent of the same kind is
answered the same way:

* an **analyst** (any request offering tools, or asking for ``CLAIM:`` blocks)
  calls the tools it was given, against the run's own sample, and then answers
  with ``CLAIM`` blocks that cite ledger ids the request carries;
* a **revision** (the analyst's prompt with the negotiation framing) disputes
  nothing and restates its claims;
* the **mediator** names no contradiction and states its agreement;
* the **judge** answers a STIX bundle with its assessment, one attack-pattern
  per technique the analysts claimed and an indicator only for a value the run
  holds verbatim; the **technique question** keeps every technique it is asked;
* the **narrative** and each **composer section** answer the JSON object their
  request shows, citing ids the request carries.

A scenario turns the same script into a failure the live runs met: an answer
cut at its cap with only thinking, an empty answer, a schema break, a long tool
loop, a slow model, one server error before success. ``Brain.answer`` returns
the role it read, the reply, and the fault it applied, for the stub's log.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from scripts.rehearsal import wire

# The scenarios a run can select, each with the sentence the runner prints. A
# fault that hits "first calls" hits the first call of every instance of a role:
# each analyst (told apart by its own system prompt), each composer section,
# and each single-call role once.
SCENARIOS: dict[str, str] = {
    "normal": "every role answers well-formed, citing the run's own ledger ids",
    "cut_at_cap": "every first call is cut at its output cap with only thinking and no text",
    "empty_answer": (
        "every first call answers with no text at all; a composer section's with whitespace alone"
    ),
    "schema_break": "every first call answers in a form its reader cannot parse",
    "long_loop": "every analyst calls tools for many steps before answering",
    "slow_model": "every call takes a fixed time before it answers",
    "server_error_once": "every first call is a 500, and the call after it is answered",
    "rate_limited": "every first call is a 429 with retry-after, and the call after it is answered",
    "overloaded": "every first call is a 529 (503 on the OpenAI wire)",
    "stream_error": "every first streamed answer breaks off with an overloaded error mid-stream",
    "redacted_thinking": "every answer that thinks also carries a redacted_thinking block",
    "unusual_stop": (
        "every first call stops as refusal, pause_turn or model_context_window_exceeded"
    ),
    "prose_instead_of_tool": (
        "every first structured call answers in prose instead of calling its schema tool"
    ),
    "deadline_hit": "every call is slow enough that the run's configured deadline fires",
    "cross_loop": (
        "the report stage's calls follow the analysts' calls on one client; answers are normal"
    ),
}

# The faults that hit the first call of each role instance.
_FIRST_CALL_FAULTS = {
    "cut_at_cap",
    "empty_answer",
    "schema_break",
    "server_error_once",
    "rate_limited",
    "overloaded",
    "stream_error",
    "unusual_stop",
    "prose_instead_of_tool",
}
# The scenarios that only one wire can carry; on the other they run as normal.
SCENARIO_WIRES: dict[str, set[str]] = {
    "redacted_thinking": {"anthropic"},
    "prose_instead_of_tool": {"anthropic"},
}
# How each role stops in ``unusual_stop``.
_UNUSUAL_STOPS = {
    "analyst": "context_window",
    "revision": "pause_turn",
    "mediator": "refusal",
    "mediator_extract": "refusal",
    "judge": "refusal",
    "technique_question": "refusal",
    "narrative": "pause_turn",
    "composer": "pause_turn",
}
_STRUCTURED_ROLES = {"mediator_extract", "judge", "technique_question", "narrative", "composer"}


@dataclass(frozen=True)
class Markers:
    """The product's own words a request's role is read from, taken from its prompt constants."""

    technique_question: str
    mediator_extract: str
    mediator: str
    judge: str
    narrative: str
    composer: str
    revision: str
    feedback: str
    no_tool_nudge: str
    keep_question: str
    sample_path: str
    section: re.Pattern[str]
    contract: str


def _head(text: str, width: int = 60) -> str:
    return text.strip().splitlines()[0][:width]


@lru_cache(maxsize=1)
def markers() -> Markers:
    """Every marker, read from the product's prompt constants and builders.

    A product that rewords a prompt moves the marker with it; a prompt the
    product no longer builds the way a marker expects shows up as a request
    answered as ``other``, which the checklist fails.
    """
    from maljan.agents import configurable_analyst
    from maljan.agents.base_agent import _REVISION_ISR_FRAMING
    from maljan.agents.judge_agent import (
        JUDGE_VERDICT_SYSTEM,
        MEDIATION_EXTRACTION_SYSTEM,
        MEDIATOR_SYSTEM_HEAD,
        TECHNIQUE_QUESTION_SYSTEM,
    )
    from maljan.agents.prompt_fragments import no_tool_call_question
    from maljan.agents.static_analyst import _extract_load_hint
    from maljan.pipeline.validation import FEEDBACK_PREAMBLE, RetryDrops, retry_drop_question
    from maljan.reporting import composer, narrative_agent

    keep = re.search(r"KEEP <label>: <reason>", retry_drop_question(RetryDrops()))
    if keep is None:
        raise RuntimeError("the retry-drops question no longer asks for KEEP <label>: <reason>")
    probe = "/rehearsal-marker-path"
    hint = _extract_load_hint(json.dumps({"analysis_file_path": probe}), frozenset({"tool"}))
    sentinel = "rehearsalsection"
    header = composer._bundle_text(sentinel, {}, None).splitlines()[0]
    before, _, after = header.partition(sentinel)
    contract = composer.section_contract(
        "introduction", composer.SECTION_SCHEMAS["introduction"]
    ).splitlines()[0]
    return Markers(
        technique_question=_head(TECHNIQUE_QUESTION_SYSTEM),
        mediator_extract=_head(MEDIATION_EXTRACTION_SYSTEM),
        mediator=_head(MEDIATOR_SYSTEM_HEAD),
        judge=_head(JUDGE_VERDICT_SYSTEM),
        narrative=_head(narrative_agent._SYSTEM_PROMPT),
        composer=_head(composer._SYSTEM),
        revision=_head(_REVISION_ISR_FRAMING),
        feedback=FEEDBACK_PREAMBLE,
        no_tool_nudge=no_tool_call_question(["tool"]).split(".")[0],
        keep_question=keep.group(0),
        sample_path=os.path.commonprefix(
            [hint.split(probe)[0], configurable_analyst._PATH_HEADER.split("{path}")[0]]
        ),
        section=re.compile(re.escape(before) + r"([a-z_]+)" + re.escape(after)),
        contract=contract,
    )


_EVIDENCE_ID = re.compile(r"\bev_\d{4,}\b")
_PACK_LINE = re.compile(r"^\[(ev_\d{4,})\]\s+([^:\n]+):\s*(.+)$", re.MULTILINE)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b")
_CLAIM_LABEL = re.compile(r"\[([a-z][a-z0-9_]* claim \d+)\]")

# What a step of a tool loop prefers to call, in order. Each is a tool the
# platform's own sidecars or sandbox closures serve offline.
_TOOL_PREFERENCE: tuple[str, ...] = (
    "pe_info",
    "strings",
    "iocs_from_file",
    "sandbox_items",
    "sandbox_processes",
    "sandbox_signatures",
    "sandbox_network",
    "read_pcap_summary",
    "pcap_summary",
    "attck_lookup",
    "api_capability",
    "identify_file",
    "hashes",
    "function_index",
)
# Tools a rehearsal never calls: they reach a third party, write files, or
# hand work to another agent.
_NEVER_CALL = re.compile(
    r"^(put_sample|begin_put|chunk|finish|unpack_upx|carve_payloads|transform_bytes|"
    r"check_|get_file_report|get_url|get_domain|get_ip|ask_|submit|reanalyze)"
)

# A technique and the catalogue's own words for it, so a claim naming one
# describes it; a value that marks it in the evidence chooses it.
_TECHNIQUE_WORDS: tuple[tuple[str, str, str], ...] = (
    (
        "CurrentVersion\\Run",
        "T1547.001",
        "It adds a Registry Run key so that it starts at user logon (boot or logon "
        "autostart execution)",
    ),
    (
        "CreateRemoteThread",
        "T1055",
        "It injects code into another process with WriteProcessMemory and "
        "CreateRemoteThread (process injection)",
    ),
    (
        "http",
        "T1071.001",
        "It communicates with a web address over HTTP, an application layer protocol "
        "for command and control",
    ),
)


@dataclass
class _Facts:
    """What a request lets a script cite."""

    ids: list[str]
    lines: list[tuple[str, str, str]]
    urls: list[str]
    sample_path: str
    sha256: str


def _facts(request: wire.Request) -> _Facts:
    text = request.all_text
    ids = list(dict.fromkeys(_EVIDENCE_ID.findall(text)))
    lines = list(dict.fromkeys(_PACK_LINE.findall(text)))
    urls = list(dict.fromkeys(url.rstrip(".,);'\"") for url in _URL.findall(text)))
    path = re.search(re.escape(markers().sample_path) + r"[^)]*\):\s*(\S+)", text)
    sha = _SHA256.search(text)
    return _Facts(
        ids=ids,
        lines=lines,
        urls=urls,
        sample_path=path.group(1) if path else "",
        sha256=sha.group(0) if sha else "",
    )


def role_of(request: wire.Request) -> str:
    """The role a request is answered as, read from the request alone."""
    system = request.system
    found = markers()
    for role in ("technique_question", "mediator_extract", "mediator", "judge", "narrative"):
        if getattr(found, role) in system:
            return role
    if found.composer in system:
        return "composer"
    if found.revision in system:
        return "revision"
    if request.tools or "CLAIM:" in request.all_text:
        return "analyst"
    return "other"


def composer_section(request: wire.Request) -> str:
    """The composer section a request asks for, as the prompt names it."""
    found = markers().section.search(request.all_text)
    return found.group(1) if found else ""


def instance_of(role: str, request: wire.Request) -> str:
    """Which instance of ``role`` asked: an analyst by its own system prompt, a section by name."""
    if role in ("analyst", "revision"):
        head = request.system.split("\n", 1)[0][:120]
        return f"{role}:{hashlib.sha256(head.encode()).hexdigest()[:10]}"
    if role == "composer":
        return f"composer:{composer_section(request)}"
    return role


# The roles each pipeline stage's model calls answer as. ``deadline_hit``
# aimed at a stage holds only these calls, so the deadline lands in it.
STAGE_ROLES: dict[str, frozenset[str]] = {
    "analysis": frozenset({"analyst"}),
    "debate": frozenset({"mediator", "mediator_extract", "revision"}),
    "verdict": frozenset({"judge", "technique_question"}),
    "report": frozenset({"narrative", "composer"}),
}
# How long a call of the aimed-at stage is held: longer than any deadline a
# rehearsal sets, so the run is still in that stage when its deadline fires.
STAGE_HOLD_S = 3600.0


class Brain:
    """Answers every request of one run; state is per run (``reset``)."""

    def __init__(
        self,
        scenario: str = "normal",
        loop_steps: int | None = None,
        slow_seconds: float | None = None,
        deadline_in: str | None = None,
    ) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; one of {sorted(SCENARIOS)}")
        if deadline_in and (scenario != "deadline_hit" or deadline_in not in STAGE_ROLES):
            raise ValueError(
                f"deadline_in {deadline_in!r} aims deadline_hit at one of {sorted(STAGE_ROLES)}"
            )
        self.scenario = scenario
        self.deadline_in = deadline_in or ""
        self.slow_roles = STAGE_ROLES[deadline_in] if deadline_in else frozenset()
        self.loop_steps = (
            loop_steps if loop_steps is not None else (12 if scenario == "long_loop" else 2)
        )
        default_slow = {"slow_model": 1.0, "deadline_hit": 2.0}.get(scenario, 0.0)
        if deadline_in:
            default_slow = STAGE_HOLD_S
        self.slow_seconds = slow_seconds if slow_seconds is not None else default_slow
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self._faulted: set[str] = set()
            self._mediations = 0

    # ------------------------------------------------------------------ entry

    def answer(self, request: wire.Request) -> tuple[str, wire.Reply, str]:
        role = role_of(request)
        fault = self._fault_for(role, request)
        reply = (
            self._faulted_reply(role, fault, request) if fault else self._scripted(role, request)
        )
        if self.scenario == "redacted_thinking" and request.api == "anthropic" and reply.thinking:
            reply.redacted = True
            reply.note = {**reply.note, "redacted": True}
        reply.delay = self.slow_seconds if not self.slow_roles or role in self.slow_roles else 0.0
        return role, reply, fault

    def _fault_for(self, role: str, request: wire.Request) -> str:
        if self.scenario not in _FIRST_CALL_FAULTS:
            return ""
        if request.api not in SCENARIO_WIRES.get(self.scenario, {request.api}):
            return ""
        if self.scenario == "prose_instead_of_tool" and not (
            role in _STRUCTURED_ROLES and len(request.tools) == 1
        ):
            return ""
        if self.scenario == "stream_error" and not request.stream:
            return ""
        key = instance_of(role, request)
        with self._lock:
            if key in self._faulted:
                return ""
            self._faulted.add(key)
        return self.scenario

    def _faulted_reply(self, role: str, fault: str, request: wire.Request) -> wire.Reply:
        thinking = "Weighing the evidence before writing the answer. " * 40
        if fault == "cut_at_cap":
            return wire.Reply(thinking=thinking, stop="max_tokens")
        if fault == "empty_answer":
            # A composer section's empty answer is whitespace alone, as a model
            # that thinks first can end one: an answer with no text that a
            # retry must neither send back (the Messages API refuses a turn of
            # whitespace with a 400) nor ask about as broken JSON.
            return wire.Reply(text="\n\n" if role == "composer" else "", stop="end")
        if fault == "server_error_once":
            return wire.Reply(status=500, error="Internal server error")
        if fault == "rate_limited":
            return wire.Reply(
                status=429,
                error="This request would exceed your rate limit; retry after the time given.",
                headers={"retry-after": "1"},
            )
        if fault == "overloaded":
            status = 529 if request.api == "anthropic" else 503
            return wire.Reply(status=status, error="Overloaded")
        if fault == "unusual_stop":
            stop = _UNUSUAL_STOPS.get(role, "refusal")
            return wire.Reply(thinking="Considering the request.", stop=stop)
        if fault in ("stream_error", "prose_instead_of_tool"):
            reply = self._scripted(role, request)
            if fault == "stream_error":
                reply.stream_error = True
                return reply
            # The answer written as text, the schema tool left uncalled.
            text = reply.text or "".join(json.dumps(call.args) for call in reply.tool_calls)
            return wire.Reply(
                thinking="I will state the answer directly.",
                text=f"Here is the answer.\n{text}",
                note=reply.note,
            )
        # schema_break: a reply its reader cannot take, in the role's own medium.
        if role in ("analyst", "revision"):
            return wire.Reply(text="The sample looks interesting but I will not list findings.")
        if role == "mediator":
            return wire.Reply(text="The analysts mostly agree.")
        return wire.Reply(
            thinking=_SECTION_THINKING if _thinks_first(role, request) else "",
            text='{"executive_summary": "cut off mid',
        )

    # ---------------------------------------------------------------- scripts

    def _scripted(self, role: str, request: wire.Request) -> wire.Reply:
        facts = _facts(request)
        if role == "analyst":
            return self._analyst(request, facts)
        if role == "revision":
            return self._revision(request, facts)
        if role == "mediator":
            return self._mediator(request)
        if role == "mediator_extract":
            return _as_schema_call(request, json.dumps(_mediator_verdict(request.last_user_text)))
        if role == "judge":
            return _as_schema_call(
                request,
                self._bundle(request, facts),
                thinking="Weighing the claims.",
            )
        if role == "technique_question":
            return _as_schema_call(request, self._technique_answer(request))
        if role == "narrative":
            labels = list(dict.fromkeys(_CLAIM_LABEL.findall(request.all_text)))
            return _as_schema_call(request, self._narrative(facts, labels))
        if role == "composer":
            text, content = self._composer(request, facts)
            reply = _as_schema_call(
                request, text, thinking=_SECTION_THINKING if _thinks_first(role, request) else ""
            )
            section = composer_section(request)
            reply.note = {
                "section": section,
                "content": content,
                "deliberately_empty": self.deliberately_empty(section, request),
            }
            return reply
        return wire.Reply(text=self._previous_or(request, "No further answer."))

    def _mediator(self, request: wire.Request) -> wire.Reply:
        """One blocking contradiction in the first round, so a revision round runs; none after."""
        with self._lock:
            self._mediations += 1
            first = self._mediations == 1
        thinking = "Comparing the analysts' claims against each other and the ledger."
        if first and "--- " in request.last_user_text:
            return wire.Reply(
                thinking=thinking,
                text=(
                    "The analysts read the same entries but weigh them differently.\n"
                    "CONTRADICTIONS:\n"
                    "- static: its confidence in the network claim; the dynamic analyst "
                    "rates the same entry lower [blocking: the two must agree on one "
                    "reading]\n"
                    "agreement_confidence: 0.6"
                ),
            )
        return wire.Reply(
            thinking=thinking,
            text="No analyst contradicts another.\nCONTRADICTIONS: NONE\nagreement_confidence: 0.9",
        )

    def _previous_or(self, request: wire.Request, default: str) -> str:
        for turn in reversed(request.turns):
            if turn.role == "assistant" and turn.text:
                return turn.text
        return default

    # ---------------------------------------------------------------- analyst

    def _analyst(self, request: wire.Request, facts: _Facts) -> wire.Reply:
        last = request.turns[-1] if request.turns else wire.Turn(role="user")
        if markers().keep_question in last.text:
            return wire.Reply(text=_keep_every_item(last.text))
        if markers().feedback in last.text:
            return wire.Reply(text=_corrected(self._previous_or(request, ""), last.text))
        calls_made = len(request.tool_calls_made)
        choice = request.raw.get("tool_choice")
        tools_withheld = choice == "none" or (
            isinstance(choice, dict) and choice.get("type") == "none"
        )
        wants_tools = bool(request.tools) and calls_made < self.loop_steps and not tools_withheld
        nudged = markers().no_tool_nudge in last.text and not tools_withheld
        if wants_tools or (request.tools and nudged):
            call = _next_call(request, facts, calls_made)
            if call is not None:
                return wire.Reply(
                    thinking=f"Step {calls_made + 1}: reading {call.name}.",
                    text="",
                    tool_calls=[call],
                )
        text = self._isr(request, facts)
        return wire.Reply(
            thinking="Writing the findings from the cited entries.",
            text=text,
            note={"claims": claims_in(text), "answer": "final"},
        )

    def _isr(self, request: wire.Request, facts: _Facts) -> str:
        """Claims from this analyst's own tool answers first, then from the pack's lines.

        Each technique claim uses the catalogue's words for its technique and
        cites the entry holding the value that marks it; every other claim
        restates what its cited entry records. Analysts with different tools
        therefore answer differently, as real ones do.
        """
        names = {
            call.id: call.name for turn in request.turns for call in turn.tool_calls if call.id
        }
        own: dict[str, str] = {}
        for result in request.tool_results:
            ids = _EVIDENCE_ID.findall(result.text)
            body = _body_of(result.text, limit=None)
            if ids and body:
                own.setdefault(ids[0], f"{names.get(result.id, 'tool')}: {body}")
        pack = {ident: f"{tool}: {body}" for ident, tool, body in facts.lines}
        blocks: list[str] = []
        used: set[str] = set()
        techniques: set[str] = set()
        for source in (own, pack):
            for marker, technique, sentence in _TECHNIQUE_WORDS:
                if technique in techniques:
                    continue
                for ident, text in source.items():
                    if marker.lower() in text.lower() and ident not in used:
                        blocks.append(_claim(sentence, ident, text, 0.8, technique))
                        used.add(ident)
                        techniques.add(technique)
                        break
        plain = [i for i in own if i not in used][:2] + [i for i in pack if i not in used][:1]
        for ident in plain:
            text = own.get(ident) or pack[ident]
            blocks.append(
                _claim(
                    f"The {text.split(':', 1)[0]} answer records what it read from the sample",
                    ident,
                    text,
                    0.6,
                    "NONE",
                )
            )
        if not blocks:
            return "No claim can be made: no ledger entry was shown to this analyst."
        return "\n".join(blocks)

    def _revision(self, request: wire.Request, facts: _Facts) -> wire.Reply:
        """Its own claims, as the request shows them, restated whole; no dispute."""
        last = request.turns[-1] if request.turns else wire.Turn(role="user")
        if markers().keep_question in last.text:
            return wire.Reply(text=_keep_every_item(last.text))
        if markers().feedback in last.text:
            return wire.Reply(text=_corrected(self._previous_or(request, ""), last.text))
        mine = _original_claims(request.last_user_text)
        body = "\n".join(mine) if mine else self._isr(request, facts)
        return wire.Reply(
            text=f"{body}\nDISPUTES: NONE",
            note={"claims": claims_in(body), "answer": "revision"},
        )

    # ------------------------------------------------------------------ judge

    def _bundle(self, request: wire.Request, facts: _Facts) -> str:
        claimed = sorted(set(_TECHNIQUE.findall(_reports_part(request))))
        # The last technique claimed is left off the bundle when there are two
        # or more, so the technique question that follows the verdict is asked.
        techniques = claimed[:-1] if len(claimed) > 1 else claimed
        cite = facts.ids[:2]
        objects: list[dict[str, Any]] = [
            {
                "type": "malware",
                "id": "malware--1",
                "name": "rehearsal sample",
                "is_family": False,
                "malware_types": ["remote-access-trojan"],
            }
        ]
        for n, technique in enumerate(techniques, 1):
            objects.append(
                {
                    "type": "attack-pattern",
                    "id": f"attack-pattern--{n}",
                    "name": technique,
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": technique}
                    ],
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "id": f"relationship--{n}",
                    "relationship_type": "uses",
                    "source_ref": "malware--1",
                    "target_ref": f"attack-pattern--{n}",
                    "x_maljan_confidence": 0.8,
                    "x_maljan_evidence_basis": "static",
                    "x_maljan_contributing_agents": [],
                }
            )
        assessment = {
            "verdict": "Malware",
            "confidence": 0.8,
            "severity": {
                "rating": "High",
                "rationale": "The analysts' claims, each citing this run's ledger, "
                "describe malicious behaviour.",
            },
            "malware_category": "trojan",
        }
        if cite:
            assessment["severity"]["rationale"] += f" [{cite[0]}]"
        bundle = {
            "type": "bundle",
            "id": "bundle--1",
            "x_maljan_assessment": assessment,
            "objects": objects,
        }
        return json.dumps(bundle, separators=(",", ":"))

    @staticmethod
    def _technique_answer(request: wire.Request) -> str:
        asked = list(dict.fromkeys(_TECHNIQUE.findall(request.last_user_text)))
        rows = [
            {"id": tid, "decision": "keep", "reason": "the cited entry shows the sample doing it"}
            for tid in asked
        ]
        return json.dumps(rows)

    # ---------------------------------------------------------------- reports

    @staticmethod
    def _narrative(facts: _Facts, labels: list[str]) -> str:
        cite = facts.ids[:3] or []
        first = f" [{cite[0]}]" if cite else ""
        summary = (
            "The sample is a Windows executable that we assess as malicious with high "
            "confidence; it carries network indicators and behaviour the analysts tied to "
            f"command and control{first}. Affected hosts should be isolated and reviewed."
        )
        findings = [
            {
                "text": "The run recorded the sample's identity and imports.",
                "evidence_ids": cite[:1],
            },
            {
                "text": "The analysts cited the run's own ledger for each claim"
                + (" (" + ", ".join(labels) + ")" if labels else "")
                + ".",
                "evidence_ids": cite[1:2],
            },
        ]
        recommendations = [
            {
                "category": "firewall",
                "action": "Block the network indicators this run recorded.",
                "rationale": "The sample holds them as its endpoints.",
                "priority": "P0",
                "technique_id": None,
                "detection": "Sysmon EventID 3 network connections to the recorded hosts.",
            },
            {
                "category": "edr_hunting",
                "action": "Hunt for the sample's hash across endpoints.",
                "rationale": "The same file may be present on other hosts.",
                "priority": "P1",
                "technique_id": None,
                "detection": "File creation events matching the recorded sha256.",
            },
            {
                "category": "user_awareness",
                "action": "Warn users not to start unexpected executables.",
                "rationale": "The sample needs a user to start it.",
                "priority": "P2",
                "technique_id": None,
                "detection": "Process creation of unsigned executables from user folders.",
            },
        ]
        return json.dumps(
            {
                "executive_summary": summary,
                "key_findings": findings,
                "defensive_recommendations": recommendations,
            }
        )

    def _composer(self, request: wire.Request, facts: _Facts) -> tuple[str, bool]:
        """The section's JSON object, and whether it holds anything the report prints."""
        section = composer_section(request)
        template = None
        for turn in request.turns:
            if turn.role == "user":
                template = _answer_template(turn.text) or template
        evidence = _section_evidence(request)
        ids = list(dict.fromkeys(_EVIDENCE_ID.findall(evidence))) or facts.ids
        cite = ids[:1]
        urls = list(dict.fromkeys(url.rstrip(".,);'\"]") for url in _URL.findall(evidence)))
        labels = ", ".join(dict.fromkeys(_CLAIM_LABEL.findall(evidence)))
        readings = f" The analysts' readings stand as written ({labels})." if labels else ""
        grounded = _Grounding(
            sentence=(
                f"The run recorded what its tools read from the sample [{cite[0]}].{readings}"
                if cite
                else f"The run recorded what its tools read from the sample.{readings}"
            ),
            cite=cite,
            url=urls[0] if urls else "",
            url_entry=_entry_holding(urls[0], evidence) if urls else "",
        )
        if template is None:
            return json.dumps({"text": grounded.sentence}), True
        listed = _sample_values(section, facts)
        if listed is not None:
            return json.dumps(listed), True
        answer = _fill(template, grounded, section)
        return json.dumps(answer), _has_content(answer)

    @staticmethod
    def deliberately_empty(section: str, request: wire.Request) -> bool:
        """Whether the script leaves ``section`` empty on purpose: the sample has nothing for it."""
        if section in _SAMPLE_LISTS:
            return _strings_entry(_facts(request)) == ""
        if section in _EMPTY_LISTS or section in _EMPTY_OBJECTS:
            return True
        if section in _VALUE_LISTS:
            evidence = _section_evidence(request)
            urls = [
                u for u in _URL.findall(evidence) if _entry_holding(u.rstrip(".,);'\"]"), evidence)
            ]
            return not urls
        return False


def _body_of(text: str, limit: int | None = 200) -> str:
    """A tool answer's own text: no id stamp, no fence lines, no run-state block, one line."""
    text = text.split("=== RUN STATE", 1)[0]
    kept = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("<<") or _EVIDENCE_ID.fullmatch(line.strip("[]")):
            continue
        kept.append(line)
    joined = " ".join(kept)
    return joined if limit is None else joined[:limit]


_ORIGINAL_CLAIM = re.compile(
    r"^\s*Claim \d+: (?P<claim>.+?)(?: \((?P<tids>T\d{4}(?:\.\d{3})?(?:, T\d{4}(?:\.\d{3})?)*)\))?"
    r" \| Evidence: (?P<evidence>.*?) \| Confidence: (?P<confidence>[0-9.]+)\s*$",
    re.MULTILINE,
)


# A claim block as an answer writes it, which is how a later round's revision
# request shows the answer in force: the revision the analyst wrote before.
_WRITTEN_CLAIM = re.compile(
    r"^CLAIM(?: \d+)?:[ \t]*(?P<claim>.+?)[ \t]*$"
    r"(?:\nEVIDENCE:[ \t]*(?P<evidence>.*?)[ \t]*$)?"
    r"(?:\nCONFIDENCE:[ \t]*(?P<confidence>[0-9.]+)[ \t]*$)?"
    r"(?:\nTECHNIQUE:[ \t]*(?P<tids>.*?)[ \t]*$)?",
    re.MULTILINE,
)


def _original_claims(text: str) -> list[str]:
    """The ``CLAIM`` blocks of the analyst's own report, read from a revision request.

    The first round shows the report as numbered lines (``Claim 1: … |
    Evidence: … | Confidence: …``); a later round shows the answer in force as
    the analyst wrote it, in ``CLAIM:`` blocks. Both are read, so a revision
    restates every claim of the answer in force in every round.
    """
    head, marker, tail = text.partition("YOUR ORIGINAL REPORT:")
    if not marker:
        return []
    own = tail.split("PEER REPORTS:", 1)[0]
    rows = [
        (m.group("claim"), m.group("evidence"), m.group("confidence"), m.group("tids"))
        for m in _ORIGINAL_CLAIM.finditer(own)
    ] or [
        (m.group("claim"), m.group("evidence"), m.group("confidence"), m.group("tids"))
        for m in _WRITTEN_CLAIM.finditer(own)
    ]
    blocks = []
    for claim, evidence, confidence, tids in rows:
        # A line the report did not show is not made up: only what it showed is restated.
        lines = [f"CLAIM: {claim.rstrip('.')}."]
        lines += [f"EVIDENCE: {evidence}"] if evidence is not None else []
        lines += [f"CONFIDENCE: {confidence}"] if confidence is not None else []
        lines += [f"TECHNIQUE: {tids or 'NONE'}", "---"]
        blocks.append("\n".join(lines))
    return blocks


def _claim(sentence: str, ident: str, text: str, confidence: float, technique: str) -> str:
    return (
        f"CLAIM: {sentence}.\n"
        f"EVIDENCE: [{ident}] {text[:160]}\n"
        f"CONFIDENCE: {confidence}\n"
        f"TECHNIQUE: {technique}\n---"
    )


_CLAIM_LINE = re.compile(r"^CLAIM(?: \d+)?:\s*(.+?)\s*$", re.MULTILINE)


def claims_in(text: str) -> list[str]:
    """The claim sentences an answer writes, each without its closing full stop."""
    return [found.rstrip(".") for found in _CLAIM_LINE.findall(text or "")]


def _without_techniques(answer: str) -> str:
    return re.sub(r"(?m)^TECHNIQUE:.*$", "TECHNIQUE: NONE", answer) if answer else ""


_FLAGGED_CLAIM = re.compile(r"\bclaims\[(\d+)\]")
_ITEM_LABEL = re.compile(r"^([A-Z]\d+)\. ", re.MULTILINE)


# What a composer section's answer on the Anthropic wire thinks first. Claude
# Haiku 5.5 thinks by default, so a section's answer is a block list, thinking
# then text, which a streamed join starts with the empty string of its opening
# chunk: sent back by a validation retry, that string is the empty text block
# a paid run's section was refused for.
_SECTION_THINKING = "Weighing the section's evidence."


def _thinks_first(role: str, request: wire.Request) -> bool:
    return role == "composer" and request.api == "anthropic"


def _as_schema_call(request: wire.Request, text: str, thinking: str = "") -> wire.Reply:
    """``text`` as the reply, or as a call of the one schema tool the request offers.

    A provider that asks for structured output offers the answer's schema as
    its only tool and reads the call's input as the answer; any other request
    reads the text.
    """
    if len(request.tools) == 1:
        try:
            args = json.loads(text)
        except ValueError:
            args = None
        if isinstance(args, dict):
            name = str(request.tools[0].get("name") or "")
            return wire.Reply(thinking=thinking, tool_calls=[wire.ToolCall(name=name, args=args)])
        if isinstance(args, list):
            name = str(request.tools[0].get("name") or "")
            schema = request.tools[0].get("schema") or {}
            key = next(iter(schema.get("properties") or {"items": None}))
            return wire.Reply(
                thinking=thinking, tool_calls=[wire.ToolCall(name=name, args={key: args})]
            )
    return wire.Reply(thinking=thinking, text=text)


def _mediator_verdict(log: str) -> dict[str, Any]:
    """The structured verdict a mediator's log states: its contradictions and agreement."""
    block = log.rsplit("CONTRADICTIONS:", 1)[-1]
    lines = [line.strip()[2:] for line in block.splitlines() if line.strip().startswith("- ")]
    found = re.search(r"agreement_confidence:\s*([0-9.]+)", log)
    confidence = float(found.group(1)) if found else 0.0
    return {
        "contradictions": lines,
        "resolution_summary": "The analysts' claims were compared against each other.",
        "confidence": confidence,
    }


def _corrected(previous: str, feedback: str) -> str:
    """The claims a check named, written again under their numbers with no technique.

    A claim the feedback does not name is not written again, so it stays as
    the first answer wrote it. Feedback naming no claim is answered with the
    whole answer, its technique lines withdrawn.
    """
    blocks = [b.strip() for b in re.split(r"(?m)^---\s*$", previous) if "CLAIM" in b]
    flagged = sorted({int(n) for n in _FLAGGED_CLAIM.findall(feedback)})
    if not flagged or not blocks:
        return _without_techniques(previous) or previous
    out = []
    for index in flagged:
        if index < len(blocks):
            block = re.sub(r"^CLAIM(?: \d+)?:", f"CLAIM {index + 1}:", blocks[index], count=1)
            out.append(_without_techniques(block))
    return "\n---\n".join(out) + "\n---" if out else _without_techniques(previous)


def _keep_every_item(question: str) -> str:
    """``KEEP`` for every item a retry-drops question lists, with a reason."""
    labels = list(dict.fromkeys(_ITEM_LABEL.findall(question)))
    return "\n".join(f"KEEP {label}: the cited entry still shows it" for label in labels)


def _reports_part(request: wire.Request) -> str:
    """The analysts' reports the verdict request carries, from whichever turn holds them."""
    for turn in request.turns:
        if turn.role == "user" and "Expert Reports:" in turn.text:
            return turn.text.partition("Expert Reports:")[2]
    return request.last_user_text


def _fillable(tool: dict[str, Any], facts: _Facts) -> dict[str, Any] | None:
    """Arguments for ``tool`` this run can give it, or ``None`` when one cannot be given."""
    schema = tool.get("schema") or {}
    properties = schema.get("properties") or {}
    required = list(schema.get("required") or [])
    args: dict[str, Any] = {}
    for name in required:
        lowered = name.lower()
        kind = (properties.get(name) or {}).get("type")
        value: Any
        if "pcap" in lowered:
            return None
        if "path" in lowered or lowered in ("file", "filename", "sample"):
            if not facts.sample_path:
                return None
            value = facts.sample_path
        elif lowered == "section":
            value = "events"
        elif "technique" in lowered or lowered in ("query", "tid", "id", "ids"):
            value = "T1071.001"
        elif "api" in lowered or lowered == "name":
            value = "InternetOpenW"
        elif "hash" in lowered or "sha" in lowered:
            if not facts.sha256:
                return None
            value = facts.sha256
        elif kind == "integer":
            value = 0
        else:
            return None
        args[name] = [value] if kind == "array" else value
    return args


def _varied(args: dict[str, Any], tool: dict[str, Any], step: int) -> dict[str, Any]:
    """``args`` made different from the same tool's earlier calls, where its schema allows."""
    properties = (tool.get("schema") or {}).get("properties") or {}
    for name in ("offset", "k", "packet_limit", "limit"):
        if name in properties and name not in args and step:
            kind = (properties.get(name) or {}).get("type")
            if kind in ("integer", None, "number"):
                return {**args, name: step if name == "offset" else step + 1}
    return args


def _next_call(request: wire.Request, facts: _Facts, step: int) -> wire.ToolCall | None:
    tools = {str(tool.get("name") or ""): tool for tool in request.tools}
    order = [name for name in _TOOL_PREFERENCE if name in tools]
    order += sorted(name for name in tools if name not in order)
    candidates: list[wire.ToolCall] = []
    for name in order:
        if _NEVER_CALL.match(name):
            continue
        args = _fillable(tools[name], facts)
        if args is not None:
            candidates.append(wire.ToolCall(name=name, args=args))
    if not candidates:
        return None
    chosen = candidates[step % len(candidates)]
    rounds = step // len(candidates)
    return wire.ToolCall(chosen.name, _varied(chosen.args, tools[chosen.name], rounds))


def _answer_template(text: str) -> Any:
    marker = markers().contract + "\n"
    if marker not in text:
        return None
    line = text.split(marker, 1)[1].split("\n", 1)[0]
    try:
        return json.loads(line)
    except ValueError:
        return None


@dataclass
class _Grounding:
    """What a composer section may write: a sentence, the ids it cites, a value it holds."""

    sentence: str
    cite: list[str]
    url: str
    url_entry: str


def _section_evidence(request: wire.Request) -> str:
    text = request.all_text
    found = markers().section.search(text)
    return text[found.end() :] if found else text


def _entry_holding(value: str, evidence: str) -> str:
    """The id of the entry line whose text holds ``value``, from a section's evidence."""
    for line in evidence.splitlines():
        if value in line:
            ids = _EVIDENCE_ID.findall(line)
            if ids:
                return ids[0]
    return ""


# The sections whose list items name a value read from an entry: one is written
# only for a value the section's evidence shows in the entry it cites.
_VALUE_LISTS = {"configuration", "communications"}
# The sections whose items no rehearsal value fills: written empty.
_EMPTY_LISTS = {"host_identifiers", "commands", "cli_flags"}
# The list sections the rehearsal sample holds a value for: its mutex name, its
# operator command and its command-line flag, each cited to the strings entry
# that read them out of the file.
_SAMPLE_LISTS = {"host_identifiers", "commands", "cli_flags"}


def _strings_entry(facts: _Facts) -> str:
    """The id of the pack's strings entry, which holds the sample's strings whole."""
    for ident, tool, _body in facts.lines:
        if tool.strip() == "strings":
            return ident
    return ""


def _sample_values(section: str, facts: _Facts) -> dict[str, Any] | None:
    """A list section written from the values the rehearsal sample carries, or ``None``."""
    from scripts.rehearsal.sample import SAMPLE_COMMAND, SAMPLE_FLAG, SAMPLE_MUTEX

    entry = _strings_entry(facts)
    if section not in _SAMPLE_LISTS or not entry:
        return None
    if section == "host_identifiers":
        row = {"kind": "String", "value": SAMPLE_MUTEX, "purpose": "", "evidence_refs": [entry]}
        return {"identifiers": [row]}
    if section == "commands":
        name = SAMPLE_COMMAND.rsplit(" ", 1)[-1]
        row = {
            "id": SAMPLE_COMMAND,
            "name": name,
            "description": f"The file holds the command line {SAMPLE_COMMAND} [{entry}].",
            "evidence_refs": [entry],
        }
        return {"commands": [row]}
    row = {
        "flag": SAMPLE_FLAG,
        "description": f"The file holds the flag {SAMPLE_FLAG} [{entry}].",
        "evidence_ref": entry,
    }
    return {"flags": [row]}


# The sections answered with every field empty: nothing in a rehearsal supports them.
_EMPTY_OBJECTS = {"encryption_scheme", "ransom_note"}
# Fields with a fixed word in a value list.
_VALUE_WORDS = {
    "how_obtained": "static-string",
    "protocol": "HTTP",
    "key": "Command-and-control URL",
    "name": "HTTP channel",
}


def _fill(template: Any, grounded: _Grounding, section: str, key: str = "") -> Any:
    """``template`` with every placeholder written from what ``grounded`` holds."""
    if isinstance(template, dict):
        return {k: _fill(v, grounded, section, k) for k, v in template.items()}
    if section in _EMPTY_OBJECTS:
        return [] if isinstance(template, list) else None
    if isinstance(template, list):
        if key in ("evidence_refs", "evidence_ids"):
            cited = [grounded.url_entry] if section in _VALUE_LISTS else grounded.cite
            return [ident for ident in cited if ident]
        if key == "endpoints":
            return [grounded.url] if grounded.url else []
        if not template or not isinstance(template[0], dict) or section in _EMPTY_LISTS:
            return []
        if section in _VALUE_LISTS and not (grounded.url and grounded.url_entry):
            return []
        return [_fill(template[0], grounded, section)]
    if isinstance(template, bool):
        return None
    if isinstance(template, int):
        return 1
    if section in _VALUE_LISTS:
        if key == "value":
            return grounded.url
        if key == "evidence_ref":
            return grounded.url_entry
        return _VALUE_WORDS.get(key)
    if key == "voice":
        return "assessed"
    if key == "evidence_ref":
        return grounded.cite[0] if grounded.cite else None
    return grounded.sentence


def _has_content(answer: Any) -> bool:
    """Whether an answer holds any value beyond its citations."""
    if isinstance(answer, dict):
        return any(
            _has_content(value)
            for key, value in answer.items()
            if key not in ("evidence_refs", "evidence_ids", "evidence_ref")
        )
    if isinstance(answer, list):
        return any(_has_content(item) for item in answer)
    return answer not in (None, "")
