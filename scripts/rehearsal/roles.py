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

import json
import re
import threading
from dataclasses import dataclass
from typing import Any

from scripts.rehearsal import wire

# The scenarios a run can select, each with the sentence the runner prints.
SCENARIOS: dict[str, str] = {
    "normal": "every role answers well-formed, citing the run's own ledger ids",
    "cut_at_cap": (
        "each role's first call is cut at its output cap with only thinking and no text"
    ),
    "empty_answer": "each role's first call answers with no text at all",
    "schema_break": "each role's first call answers in a form its reader cannot parse",
    "long_loop": "every analyst calls tools for many steps before answering",
    "slow_model": "every call takes a fixed time before it answers",
    "server_error_once": "each role's first call is a 500, and the call after it is answered",
    "cross_loop": (
        "the report stage's calls follow the analysts' calls on one client; answers are normal"
    ),
}

# The faults that hit a role's first call only.
_FIRST_CALL_FAULTS = {"cut_at_cap", "empty_answer", "schema_break", "server_error_once"}

# Role markers, read from the system prompt, most specific first.
_SYSTEM_MARKERS: tuple[tuple[str, str], ...] = (
    ("technique_question", "Your verdict is given."),
    ("mediator_extract", "Extract the final structured verdict from the mediator's"),
    ("mediator", "Lead Cyber Security Mediator"),
    ("judge", "Chief Malware Judge"),
    ("narrative", "producing a CTI analyst report"),
    ("composer", "writing ONE section of a technical analysis report"),
)
_REVISION_MARKER = "You are in a negotiation round."
_FEEDBACK_MARKER = "Your previous answer had these problems:"
_NO_TOOL_NUDGE = "written without calling any tool"
_KEEP_QUESTION = "KEEP <label>: <reason>"

_EVIDENCE_ID = re.compile(r"\bev_\d{4,}\b")
_PACK_LINE = re.compile(r"^\[(ev_\d{4,})\]\s+([^:\n]+):\s*(.+)$", re.MULTILINE)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_URL = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
_SAMPLE_PATH = re.compile(r"Sample path \(use exactly this string[^)]*\):\s*(\S+)")
_SHA256 = re.compile(r"\b[0-9a-f]{64}\b")
_COMPOSER_SECTION = re.compile(r"The evidence for the ([a-z_]+) section follows\.")

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
    path = _SAMPLE_PATH.search(text)
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
    for role, marker in _SYSTEM_MARKERS:
        if marker in system:
            return role
    if _REVISION_MARKER in system:
        return "revision"
    if request.tools or "CLAIM:" in request.all_text:
        return "analyst"
    return "other"


def composer_section(request: wire.Request) -> str:
    """The composer section a request asks for, as the prompt names it."""
    found = _COMPOSER_SECTION.search(request.all_text)
    return found.group(1) if found else ""


class Brain:
    """Answers every request of one run; state is per run (``reset``)."""

    def __init__(
        self,
        scenario: str = "normal",
        model_name: str = "rehearsal-model",
        loop_steps: int | None = None,
        slow_seconds: float | None = None,
    ) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; one of {sorted(SCENARIOS)}")
        self.scenario = scenario
        self.model_name = model_name
        self.loop_steps = (
            loop_steps if loop_steps is not None else (12 if scenario == "long_loop" else 2)
        )
        self.slow_seconds = (
            slow_seconds if slow_seconds is not None else (1.0 if scenario == "slow_model" else 0.0)
        )
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self._faulted: set[str] = set()
            self._mediations = 0

    # ------------------------------------------------------------------ entry

    def answer(self, request: wire.Request) -> tuple[str, wire.Reply, str]:
        role = role_of(request)
        fault = self._fault_for(role)
        reply = self._faulted_reply(role, fault) if fault else self._scripted(role, request)
        reply.delay = self.slow_seconds
        return role, reply, fault

    def _fault_for(self, role: str) -> str:
        if self.scenario not in _FIRST_CALL_FAULTS:
            return ""
        with self._lock:
            if role in self._faulted:
                return ""
            self._faulted.add(role)
        return self.scenario

    @staticmethod
    def _faulted_reply(role: str, fault: str) -> wire.Reply:
        if fault == "cut_at_cap":
            return wire.Reply(
                thinking="Weighing the evidence before writing the answer. " * 40,
                stop="max_tokens",
            )
        if fault == "empty_answer":
            return wire.Reply(text="", stop="end")
        if fault == "server_error_once":
            return wire.Reply(status=500, error="the rehearsal server failed this call once")
        # schema_break: a reply its reader cannot take, in the role's own medium.
        if role in ("analyst", "revision"):
            return wire.Reply(text="The sample looks interesting but I will not list findings.")
        if role == "mediator":
            return wire.Reply(text="The analysts mostly agree.")
        return wire.Reply(text='{"executive_summary": "cut off mid')

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
            return _as_schema_call(request, self._narrative(facts))
        if role == "composer":
            text, content = self._composer(request, facts)
            reply = _as_schema_call(request, text)
            reply.note = {"section": composer_section(request), "content": content}
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
        if _KEEP_QUESTION in last.text:
            return wire.Reply(text=_keep_every_item(last.text))
        if _FEEDBACK_MARKER in last.text:
            return wire.Reply(text=_corrected(self._previous_or(request, ""), last.text))
        calls_made = len(request.tool_calls_made)
        wants_tools = bool(request.tools) and calls_made < self.loop_steps
        if wants_tools or (request.tools and _NO_TOOL_NUDGE in last.text):
            call = _next_call(request, facts, calls_made)
            if call is not None:
                return wire.Reply(
                    thinking=f"Step {calls_made + 1}: reading {call.name}.",
                    text="",
                    tool_calls=[call],
                )
        text = self._isr(request, facts)
        return wire.Reply(thinking="Writing the findings from the cited entries.", text=text)

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
        if _KEEP_QUESTION in last.text:
            return wire.Reply(text=_keep_every_item(last.text))
        if _FEEDBACK_MARKER in last.text:
            return wire.Reply(text=_corrected(self._previous_or(request, ""), last.text))
        mine = _original_claims(request.last_user_text)
        body = "\n".join(mine) if mine else self._isr(request, facts)
        return wire.Reply(text=f"{body}\nDISPUTES: NONE")

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
    def _narrative(facts: _Facts) -> str:
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
                "text": "The analysts cited the run's own ledger for each claim.",
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
        grounded = _Grounding(
            sentence=(
                f"The run recorded what its tools read from the sample [{cite[0]}]."
                if cite
                else "The run recorded what its tools read from the sample."
            ),
            cite=cite,
            url=urls[0] if urls else "",
            url_entry=_entry_holding(urls[0], evidence) if urls else "",
        )
        if template is None:
            return json.dumps({"text": grounded.sentence}), True
        answer = _fill(template, grounded, section)
        return json.dumps(answer), _has_content(answer)


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


def _original_claims(text: str) -> list[str]:
    """The ``CLAIM`` blocks of the analyst's own report, read from a revision request."""
    head, marker, tail = text.partition("YOUR ORIGINAL REPORT:")
    if not marker:
        return []
    own = tail.split("PEER REPORTS:", 1)[0]
    blocks = []
    for found in _ORIGINAL_CLAIM.finditer(own):
        claim = found.group("claim").rstrip(".")
        evidence = found.group("evidence")
        blocks.append(
            f"CLAIM: {claim}.\nEVIDENCE: {evidence}\n"
            f"CONFIDENCE: {found.group('confidence')}\n"
            f"TECHNIQUE: {found.group('tids') or 'NONE'}\n---"
        )
    return blocks


def _claim(sentence: str, ident: str, text: str, confidence: float, technique: str) -> str:
    return (
        f"CLAIM: {sentence}.\n"
        f"EVIDENCE: [{ident}] {text[:160]}\n"
        f"CONFIDENCE: {confidence}\n"
        f"TECHNIQUE: {technique}\n---"
    )


def _without_techniques(answer: str) -> str:
    return re.sub(r"(?m)^TECHNIQUE:.*$", "TECHNIQUE: NONE", answer) if answer else ""


_FLAGGED_CLAIM = re.compile(r"\bclaims\[(\d+)\]")
_ITEM_LABEL = re.compile(r"^([A-Z]\d+)\. ", re.MULTILINE)


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
    return candidates[step % len(candidates)]


def _answer_template(text: str) -> Any:
    marker = "Answer with exactly this JSON object, these keys and no others:\n"
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
    found = _COMPOSER_SECTION.search(text)
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
