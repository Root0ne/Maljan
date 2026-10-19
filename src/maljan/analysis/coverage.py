"""What looked, over which input and how much of it; and what the run could not establish.

``run_summary.coverage`` is built once, by :func:`coverage_record`, in the
report node after the run's last tool call, and as of the stop for a run
stopped part-way. Everything in it is read by code from what the run already
recorded: the evidence ledger (each call's tool, server, arguments, answer
state and the facts its tool declared), the analysts' final answers, the
sandbox report in hand, the tool servers the job could not attach and the
inputs the run shortened. No model writes any of it and no model reads it.
The report prints it at the end of the run summary appendix
(:func:`coverage_lines`); a summary stored without it prints nothing.

**The rule: coverage never overstates.** Where the record cannot tell, the
value is ``partial`` or ``unknown``, with the reason.

**Inputs.** A call's input is read from its arguments by the roles its tool
declared (``ToolFacts.arguments``), never by its name or its tool's name. A
value under a file role (``isolation.SAMPLE_ARGUMENT_ROLES``) is named by what
it is: the sample (its path, or a path ending in its file name), the job's
packet capture, a layer an earlier answer declared it produced, or a file by
its path. A value under any other role is kept as its role and a short digest,
never the value: the ledger entry holds it. A declared sample or capture
argument the call left out is the one the platform fills in, where the tool's
source declares it reads the staged sample (``agents.tool_pinning``). A call
under the platform's sandbox report source (``tool_declarations.SANDBOX``)
reads the sandbox report. A tool that declares nothing is read by value: an
argument holding the sample, the capture or a produced layer is that input.

**Layers.** A layer exists only where an answer says it produced one: a path
the answer holds under the argument name file tools declare for reading a
produced file (the ``carved`` role, :data:`LAYER_ROLE`: ``carved_path`` as
shipped), other than the call's own input. A tool that answers its output
under any other key produces no layer the record can see, by design: what
counts is declared, never guessed from a name. No layer is inferred from a
later call's arguments. A layer no call examined is a gap of every negative
over the input it came from.

**How much was read.** "Whole" is granted, never assumed. A call read its
whole input only when every one of these holds: (a) its tool is declared to
read its whole input, by the one declaration that says so today (the
``evidence_roots._WHOLE_FILE_TOOLS`` consumer kinds: identity, signing); a
tool of any other kind never reads whole; (b) every argument it was passed is
a declared input role, since no declaration marks any other argument as not
narrowing, so any other argument makes the read part, named; (c) the answer
was not cut and is not known to hold part of its rows or an unknown share of
them, by the one reading the line under every tool answer is built from
(``schemas.answer_completeness``): a true paging flag, a given next field, a
count bound to its list and above the rows shown however the page is placed,
a page before the last, a page of unknown count, the shortening bookkeeping. A
complete ``total`` caps nothing, so the record and the line agree on every
answer. An answer of no readable shape, or one holding a number longer than
its own text, reads ``unknown``; (d) the input's own record is
complete: a negative over a sandbox report that was not observed is
``failed``, and one over an observed report naming no capture is ``partial``;
(e) the input read is the sample: a read of a layer, another file or an
argument alone does not stand for it.
Most calls read ``partial`` or ``input_unknown`` today, which is the honest
value.

**Negative findings.** No structured marker says a claim is negative (the
validation layer's absence reading is asked only of a claim carrying a
technique id), so a claim is read as negative from its wording, clause by
clause (:func:`negative_clauses`); a claim its analyst kept after the absence
question counts too. Each negative clause is recorded with the entries cited
in it (a claim whose every clause is negative also counts its evidence
field), and its coverage:

* ``full``: every cited call read its whole input, (a) to (e) above;
* ``input_unknown``: a cited call is of a tool that declares nothing;
* ``partial``: a cited call did not answer, was cut, capped, passed an
  argument outside its input roles or is not declared to read its whole
  input; a call of the same declared kind over the same input did not answer;
  a layer of that input was never examined, or examined by no cited call; the
  sandbox report names no capture; or the calls read something other than the
  sample;
* ``failed``: no cited call answered, or the sandbox report they read was not
  observed;
* ``unknown``: the negative clause cites no entry the ledger holds, or an
  answer has no shape the record can read its markers from.

**What the run could not establish.** The calls that failed, were not run or
were refused, by tool and reason; the answers cut or not shown; the layers no
call examined; the sandbox report and the packet capture where there was
none; the tool servers the job could not attach; how many server rests the
appendix lists; the ledger rows that could not be read; and the inputs the
run shortened. The analysts that failed, were skipped or claimed nothing are
read by the renderer from the report's own analyst records, so the two never
disagree.

Every reading is one pass over the ledger, the claims and the answers'
structure.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextvars import ContextVar
from typing import Any

COVERAGE_VERSION = 1

FULL = "full"
INPUT_UNKNOWN = "input_unknown"
PARTIAL = "partial"
FAILED = "failed"
UNKNOWN = "unknown"

# How a call's answer stands.
ANSWERED = "answered"
CUT = "cut"
NOT_SHOWN = "not_shown"
CALL_FAILED = "failed"
NOT_RUN = "not_run"
GUARD = "guard"
_NO_ANSWER = frozenset({CALL_FAILED, NOT_RUN, GUARD, NOT_SHOWN})
_READ = frozenset({ANSWERED, CUT})

# Whether a call read its whole input.
WHOLE = "whole"
PART = "part"
NOT_KNOWN = "not_known"
SHAPE_UNKNOWN = "shape_unknown"

# The inputs a call can be over.
SAMPLE = "sample"
CAPTURE = "capture"
SANDBOX_REPORT = "sandbox_report"
LAYER = "layer"
FILE = "file"
ROLE = "role"
UNDECLARED = "undeclared"
UNNAMED = "unnamed"
NO_INPUT = "none"
# The inputs read whole when nothing narrower is asked.
_WHOLE_INPUTS = frozenset({SAMPLE, CAPTURE, SANDBOX_REPORT, LAYER, FILE})
# The inputs whose name the report prints (a path, the sample, a layer).
_NAMED_INPUTS = frozenset({SAMPLE, CAPTURE, SANDBOX_REPORT, LAYER, FILE})

# The declared argument role a file tool reads a produced file under
# (``core.builtin_declarations``: ``{"path": "path", "carved": "carved_path"}``).
# A role is declaration vocabulary, as a kind is.
LAYER_ROLE = "carved"

NOT_ESTABLISHED_INTRO = "**What this run could not establish:**"
LOOKED_INTRO = "**What each tool looked at, and over which input:**"
NEGATIVES_INTRO = (
    "**Negative findings and what looked** (a claim is read as negative from its wording, "
    "clause by clause, or because its analyst kept it after the absence question; coverage "
    "counts only the entries cited in the negative clause, and each call is named by its "
    "ledger entry, which holds its arguments):"
)
# How a claim was read as negative.
WORDING = "wording"
ABSENCE_QUESTION = "absence_question"
NOTHING_MISSING = (
    "Nothing recorded: every tool call answered whole, and no input, layer, tool server or "
    "analyst was recorded missing."
)
# Said after a capability subsection's "nothing recorded" line, only where the
# record exists.
ABSENCE_POINTER = (
    "What each tool looked at, and over which input, is under the coverage lines of Appendix B."
)
GUARD_NOTE = "counted apart from the calls, as the evidence counts are"

# ---------------------------------------------------------------------------
# Reading a claim as a negative
# ---------------------------------------------------------------------------

# A negation that negates the word after it on its own: "not packed", "no
# mutex", "never beaconed", "did not beacon" ("n't" endings too).
_STRONG_NEGATIONS = frozenset({"no", "not", "never", "none", "nothing", "cannot"})
# A negation that says something was not found only beside a word of finding:
# "without any trace of", "zero matches".
_WEAK_NEGATIONS = frozenset({"without", "zero"})
# A word right after a negation that makes it assert or need something:
# "no doubt", "not only", "no longer", "does not require".
_ASSERTING_NEXT = frozenset(
    {"doubt", "only", "longer", "merely", "just", "require", "requires", "need", "needs"}
)
# A word of finding, read beside a weak negation.
_FOUND_WORDS = frozenset(
    {
        "found",
        "observed",
        "detected",
        "present",
        "seen",
        "identified",
        "recorded",
        "matched",
        "match",
        "matches",
        "returned",
        "contacted",
        "reported",
        "evidence",
        "indication",
        "indications",
        "sign",
        "signs",
        "trace",
        "traces",
        "hits",
        "results",
    }
)
# A word that says it on its own.
_ABSENCE_WORDS = frozenset({"absent", "absence", "lacks", "lacking", "lack", "missing"})
# Evasion, not absence: "cannot be detected by", "it is not detected". A
# negation over one of these words, followed by "by" or with the sample as the
# clause's subject, claims the sample hides; it says nothing was not found.
_DETECTION_WORDS = frozenset({"detected", "detectable", "flagged", "caught"})
_BE_WORDS = frozenset({"be", "been", "being", "is", "are", "was", "were"})
_SELF_WORDS = frozenset({"it", "sample", "malware", "binary", "payload", "implant"})
# Where a clause ends: a mark followed by a space or the end ("explorer.exe"
# and "0x40.1" stay whole), or a word that opens a new clause. "yet" right
# after a negation ("not yet observed") is part of it.
_CLAUSE_WORDS = ("but", "however", "although", "though", "while", "whereas", "yet")
_CLAUSE_SPLIT_RE = re.compile(
    r"[.;:!?](?=\s|$)|(?<!not )(?<!n't )\b(?:" + "|".join(_CLAUSE_WORDS) + r")\b",
    re.IGNORECASE,
)
_QUOTES = "'\"‘’“”`"


def _tokens(text: str) -> list[str]:
    """The words of ``text``, lower-cased, with quote marks at their edges taken off."""
    out: list[str] = []
    word: list[str] = []
    for char in text:
        if char.isalnum() or char in "'’-_":
            word.append(char)
            continue
        if word:
            out.append("".join(word).lower().replace("’", "'").strip(_QUOTES))
            word = []
    if word:
        out.append("".join(word).lower().replace("’", "'").strip(_QUOTES))
    return [token for token in out if token]


def _negates(token: str) -> bool:
    return token in _STRONG_NEGATIONS or token.endswith("n't")


def _evasion(tokens: Sequence[str]) -> bool:
    """Whether the clause claims the sample evades detection ("cannot be detected by")."""
    for at, token in enumerate(tokens):
        if not _negates(token):
            continue
        after = at + 1
        while after < len(tokens) and tokens[after] in _BE_WORDS:
            after += 1
        if after < len(tokens) and tokens[after] in _DETECTION_WORDS:
            by = after + 1 < len(tokens) and tokens[after + 1] == "by"
            if by or any(word in _SELF_WORDS for word in tokens[:at]):
                return True
    return False


def _clause_is_negative(clause: str) -> bool:
    tokens = _tokens(clause)
    if not tokens or _evasion(tokens):
        return False
    weak = found = False
    for at, token in enumerate(tokens):
        if token in _ABSENCE_WORDS:
            return True
        following = tokens[at + 1] if at + 1 < len(tokens) else ""
        if _negates(token):
            if following not in _ASSERTING_NEXT:
                return True
            continue
        if token in _WEAK_NEGATIONS and following not in _ASSERTING_NEXT:
            weak = True
        if token in _FOUND_WORDS:
            found = True
        if weak and found:
            return True
    return False


def _clauses(text: str) -> list[tuple[str, bool]]:
    """``text`` split at clause boundaries, each clause with whether it reads as negative.

    A piece holding nothing but citations belongs to the clause before it.
    """
    from maljan.schemas.evidence import ENTRY_ID_RE

    out: list[tuple[str, bool]] = []
    for piece in _CLAUSE_SPLIT_RE.split(str(text or "")):
        said = piece.strip(" ,\t\n")
        if not said:
            continue
        if out and not any(ch.isalnum() for ch in ENTRY_ID_RE.sub("", said)):
            clause, negative = out[-1]
            out[-1] = (f"{clause} {said}", negative)
            continue
        out.append((said, _clause_is_negative(said)))
    return out


def negative_clauses(text: str) -> list[str]:
    """The clauses of ``text`` that read as negative from their wording, in order.

    ``text`` is split at clause boundaries (a sentence mark, or "but",
    "however", "although", "though", "while", "whereas", "yet"; "not yet" stays
    whole). A clause reads as negative when it holds a negation that stands
    over the word after it ("no", "not", "never", "none", "nothing",
    "cannot", a word ending in "n't": "not packed", "no network activity",
    "did not beacon"), a weak negation ("without", "zero") beside a word of
    finding, or a word of absence ("absent", "lacks", "missing"). A negation
    followed by a word that makes it assert ("no doubt", "not only", "no
    longer", "does not require") negates nothing, and a clause that claims
    evasion ("cannot be detected by", "it is not detected") is not a negative.
    A mixed claim counts for its negative clauses alone. One pass.
    """
    return [clause for clause, negative in _clauses(text) if negative]


def states_a_negative(text: str) -> bool:
    """Whether any clause of ``text`` reads as negative (:func:`negative_clauses`)."""
    return bool(negative_clauses(text))


# ---------------------------------------------------------------------------
# Reading a call
# ---------------------------------------------------------------------------


def _field(row: Any, name: str) -> Any:
    if isinstance(row, Mapping):
        return row.get(name)
    return getattr(row, name, None)


def _entry_id(entry: Any) -> str:
    return str(_field(entry, "id") or "").strip().lower()


def _state(entry: Any) -> str:
    """How the entry's answer stands (:data:`ANSWERED`, :data:`CUT` …)."""
    from maljan.pipeline.triage_pack import NOT_RUN_PREFIX
    from maljan.schemas.answer_completeness import platform_cut
    from maljan.schemas.evidence import answer_not_shown, is_guard_answer

    if is_guard_answer(entry):
        return GUARD
    if _field(entry, "ok") is False:
        said = str(_field(entry, "error") or _field(entry, "output") or "")
        return NOT_RUN if said.startswith(NOT_RUN_PREFIX) else CALL_FAILED
    if answer_not_shown(entry):
        return NOT_SHOWN
    if platform_cut(entry) > 0:
        return CUT
    return ANSWERED


def _reason(entry: Any) -> str:
    return " ".join(str(_field(entry, "error") or _field(entry, "output") or "").split())


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _digest(value: Any) -> str:
    """A short digest of a value the record does not copy (``tool_fence.digest_of``)."""
    import json

    from maljan.agents.tool_fence import digest_of

    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)
    return digest_of(text)


def _fills_staged_sample(entry: Any) -> bool:
    """Whether the entry's source declares its tools read the sample the platform staged."""
    try:
        from maljan.core.declared_reading import declarations
        from maljan.core.tool_declarations import ToolDeclarations

        ref = ToolDeclarations.source_of(entry)
        held = declarations().source(ref) if ref is not None else None
        return bool(held is not None and held.reads_staged_sample)
    except Exception:  # noqa: BLE001 — an unreadable declaration declares nothing
        return False


def _reads_the_sandbox_report(entry: Any) -> bool:
    """Whether the entry's tool is declared under the platform's sandbox report source."""
    from maljan.core.tool_declarations import SANDBOX, ToolDeclarations

    return ToolDeclarations.source_of(entry) == SANDBOX


def _structure(entry: Any) -> Any:
    from maljan.schemas.evidence import parse_structured

    held = _field(entry, "structured")
    if held is not None:
        return held
    return parse_structured(str(_field(entry, "output") or ""))


def _reading(entry: Any, structure: Any) -> Any:
    """The answer's completeness reading, the one the line under every tool answer is built from.

    ``schemas.answer_completeness.read_answer``, with the call's arguments (its
    ``offset`` places a page) and the answer's text length (no number in it can
    be longer). ``capped`` is true exactly where the line speaks of the
    answer's structure: a true paging flag, a given next field, a count bound
    to its list and above the rows shown on every placing of the page, a page
    before the last, a page of unknown count, or the shortening bookkeeping. A
    complete ``total`` caps nothing.
    """
    from maljan.schemas.answer_completeness import read_answer

    args = _field(entry, "args")
    # The text the structure was read from bounds its numbers; a structure the
    # server returned beside its text has no such text.
    held = _field(entry, "structured") is not None
    return read_answer(
        structure,
        args=args if isinstance(args, Mapping) else None,
        text_chars=None if held else len(str(_field(entry, "output") or "")),
    )


# The consumer table naming the kinds declared to state a fact about the file
# as a whole (``builtin_declarations.CONSUMER_KINDS``: identity, signing). The
# one declaration today that a tool reads its whole input; a tool of any other
# kind is never read as having read all of it.
_WHOLE_INPUT_TABLE = "evidence_roots._WHOLE_FILE_TOOLS"


def _declared_whole(entry: Any) -> bool:
    from maljan.core.declared_reading import reads_as

    try:
        return bool(reads_as(entry, _WHOLE_INPUT_TABLE))
    except Exception:  # noqa: BLE001 — an unreadable declaration declares nothing
        return False


class _Inputs:
    """The run's inputs by value: the sample, its capture and the layers answers produced."""

    def __init__(
        self,
        sample_path: str,
        capture_path: str,
        layers: Mapping[str, tuple[str, str, int]],
    ) -> None:
        self.sample = str(sample_path or "")
        self.sample_name = os.path.basename(self.sample)
        self.capture = str(capture_path or "")
        self.capture_name = os.path.basename(self.capture)
        self.layers = layers

    def known(self, value: Any, name: str = "", at: int | None = None) -> dict[str, Any] | None:
        """The input a path value names, or ``None`` when it names none the run knows.

        A bare file name is read as the sample's or the capture's only under an
        argument named for a path (``tool_pinning.is_path_argument``), as the
        path guard reads it. A layer is one an answer before the call at
        ``at`` produced.
        """
        if not isinstance(value, str) or not value:
            return None
        from maljan.agents.tool_pinning import is_path_argument

        by_name = os.path.basename(value)
        named_path = by_name != value or is_path_argument(name)
        if self.sample and (value == self.sample or (named_path and by_name == self.sample_name)):
            return {"input": SAMPLE}
        if self.capture and (
            value == self.capture or (named_path and by_name == self.capture_name)
        ):
            return {"input": CAPTURE}
        held = self.layers.get(value)
        if held is not None and (at is None or held[2] < at):
            return {"input": LAYER, "path": value, "from": held[0], "from_tool": held[1]}
        return None


def _input_key(label: Mapping[str, Any]) -> str:
    kind = str(label.get("input") or "")
    if kind in (FILE, LAYER):
        return f"{FILE}:{label.get('path')}"
    if kind == ROLE:
        return f"{ROLE}:{label.get('role')}:{label.get('digest')}"
    return kind


def _call(
    entry: Any, inputs: _Inputs, fills: Callable[[Any], bool], at: int | None = None
) -> dict[str, Any]:
    """One call: its tool, server, declared kind, answer state, inputs and how much it read."""
    from maljan.agents.tool_pinning import CAPTURE_ARG_NAMES, names_the_sample
    from maljan.analysis.isolation import SAMPLE_ARGUMENT_ROLES
    from maljan.core.declared_reading import kind_free_facts, kind_of

    facts = kind_free_facts(entry)
    roles = dict(getattr(facts, "arguments", None) or {})
    kind = kind_of(entry)
    declared = bool(kind or roles)
    args = _field(entry, "args")
    args = dict(args) if isinstance(args, Mapping) else {}
    over: list[dict[str, Any]] = []
    used: set[str] = set()
    if _reads_the_sandbox_report(entry):
        over.append({"input": SANDBOX_REPORT})
    filled = bool(roles) and fills(entry)
    for role, name in roles.items():
        value = args.get(name)
        used.add(name)
        if _empty(value):
            if filled and names_the_sample(name):
                over.append({"input": SAMPLE, "filled": True})
            elif filled and name in CAPTURE_ARG_NAMES and inputs.capture:
                over.append({"input": CAPTURE, "filled": True})
            continue
        if role in SAMPLE_ARGUMENT_ROLES and isinstance(value, str):
            over.append(inputs.known(value, name, at) or {"input": FILE, "path": value})
        else:
            over.append({"input": ROLE, "role": str(role), "digest": _digest(value)})
    for name, value in args.items():
        if name in used:
            continue
        label = inputs.known(value, name, at)
        if label is not None:
            used.add(name)
            over.append(label)
    if not over:
        if not declared and args:
            label = {"input": UNDECLARED}
            if fills(entry):
                label["server_reads_staged_sample"] = True
            over.append(label)
        elif not args and not roles:
            over.append({"input": NO_INPUT})
        else:
            over.append({"input": UNNAMED})
    seen: set[str] = set()
    distinct = []
    for label in over:
        key = _input_key(label)
        if key not in seen:
            seen.add(key)
            distinct.append(label)
    state = _state(entry)
    # Every argument outside the declared input roles: no declaration marks
    # any as not narrowing, so each one may narrow the read.
    narrowed = [name for name in args if name not in used and not _empty(args.get(name))]
    structure = _structure(entry) if state in _READ else None
    reading = _reading(entry, structure)
    capped = reading.capped
    whole = declared and _declared_whole(entry)
    limits: list[str] = []
    if state == CUT:
        limits.append("cut")
    if capped:
        limits.append("capped")
    if narrowed:
        limits.append("arguments")
    if declared and not whole:
        limits.append("not_declared_whole")
    if not declared or any(label["input"] in (UNDECLARED, UNNAMED) for label in distinct):
        read = NOT_KNOWN
    elif limits:
        read = PART
    elif state in _READ and (not isinstance(structure, Mapping | list) or reading.malformed):
        # The answer has no shape the record can read its markers from, or a
        # number in it longer than the text it came from.
        read = SHAPE_UNKNOWN
    else:
        read = WHOLE
    call: dict[str, Any] = {
        "entry": _entry_id(entry),
        "tool": str(_field(entry, "tool") or ""),
        "server": str(_field(entry, "server") or ""),
        "kind": kind,
        "state": state,
        "over": distinct,
        "read": read,
    }
    if limits:
        call["limits"] = limits
    if narrowed:
        call["narrowed_by"] = narrowed
    if capped:
        call["capped"] = True
    if state in (CALL_FAILED, NOT_RUN):
        call["reason"] = _reason(entry)
    if state == CUT:
        from maljan.schemas.answer_completeness import platform_cut

        call["dropped"] = platform_cut(entry)
    return call


def _layer_names(ledger: Sequence[Any]) -> set[str]:
    """The argument names declared under :data:`LAYER_ROLE`, shipped or on the run's entries."""
    from maljan.core.declared_reading import kind_free_facts, shipped_by_name

    names: set[str] = set()
    for facts in shipped_by_name().values():
        name = (getattr(facts, "arguments", None) or {}).get(LAYER_ROLE)
        if name:
            names.add(str(name))
    for entry in ledger:
        name = (getattr(kind_free_facts(entry), "arguments", None) or {}).get(LAYER_ROLE)
        if name:
            names.add(str(name))
    return names


def _produced_layers(
    ledger: Sequence[Any], names: set[str], sample: str, capture: str
) -> dict[str, tuple[str, str, int]]:
    """Each layer an answer says it produced, with the first entry, its tool and its place.

    A path the answer holds under a declared layer argument name, other than
    the call's own arguments, the sample and the capture. Read one leaf at a
    time.
    """
    from maljan.schemas.evidence import is_guard_answer

    produced: dict[str, tuple[str, str, int]] = {}
    if not names:
        return produced
    for index, entry in enumerate(ledger):
        if _field(entry, "ok") is False or str(_field(entry, "repeated_of") or "").strip():
            continue
        if is_guard_answer(entry):
            continue
        args = _field(entry, "args")
        own = (
            {v for v in (args or {}).values() if isinstance(v, str)}
            if isinstance(args, Mapping)
            else set()
        )
        stack = [_structure(entry)]
        while stack:
            node = stack.pop()
            if isinstance(node, Mapping):
                for key, value in node.items():
                    if (
                        key in names
                        and isinstance(value, str)
                        and value
                        and value not in own
                        and value not in (sample, capture)
                        and value not in produced
                    ):
                        produced[value] = (
                            _entry_id(entry),
                            str(_field(entry, "tool") or ""),
                            index,
                        )
                    elif isinstance(value, Mapping | list | tuple):
                        stack.append(value)
            elif isinstance(node, list | tuple):
                stack.extend(node)
    return produced


def _ledger(entries: Iterable[Any]) -> tuple[list[Any], int]:
    """The entries as models, and how many rows could not be read."""
    from maljan.schemas.evidence import LedgerEntry

    out: list[Any] = []
    unreadable = 0
    for entry in entries or ():
        if isinstance(entry, Mapping):
            try:
                entry = LedgerEntry.model_validate(dict(entry))
            except Exception:  # noqa: BLE001 — counted and said, never lost silently
                unreadable += 1
                continue
        out.append(entry)
    return out, unreadable


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


def _claims(isr_reports: Mapping[str, Any] | None) -> Iterable[tuple[str, Any]]:
    for agent, report in (isr_reports or {}).items():
        claims = _field(report, "claims")
        for claim in claims if isinstance(claims, list | tuple) else ():
            yield str(agent), claim


def _kind_key(call: Mapping[str, Any]) -> str:
    """What a call looks for: its declared kind, else its own tool."""
    return f"kind:{call['kind']}" if call.get("kind") else f"tool:{call['server']}:{call['tool']}"


class _Run:
    """The run's calls and layers, indexed once for every negative."""

    def __init__(
        self,
        calls: dict[str, dict[str, Any]],
        order: dict[str, int],
        holders: Mapping[str, str],
        layers: Mapping[str, tuple[str, str, int]],
        sandbox_incomplete: str = "",
        no_capture: bool = False,
    ) -> None:
        # The sandbox report's statement where it was not observed, and
        # whether an observed one names no capture.
        self.sandbox_incomplete = sandbox_incomplete
        self.no_capture = no_capture
        self.calls = calls
        self.order = order
        self.holders = holders
        # A call that did not answer, by input and by what it looks for.
        self.no_answer: dict[tuple[str, str], list[str]] = {}
        # The layers examined (read by a call that answered), and each layer
        # by the input it came from.
        self.examined: set[str] = set()
        self.children: dict[str, list[tuple[str, str]]] = {}
        for call in calls.values():
            whole = all(label["input"] in _WHOLE_INPUTS for label in call["over"])
            for label in call["over"]:
                if call["state"] in _NO_ANSWER and whole:
                    self.no_answer.setdefault((_input_key(label), _kind_key(call)), []).append(
                        call["entry"]
                    )
                if label["input"] == LAYER and call["state"] in _READ:
                    self.examined.add(str(label["path"]))
        for path, (producer, _tool, _index) in layers.items():
            made = calls.get(producer)
            for parent in made["over"] if made else ():
                self.children.setdefault(_input_key(parent), []).append((path, producer))
        self.unexamined = [
            {"path": path, "from": held[0], "from_tool": held[1]}
            for path, held in layers.items()
            if path not in self.examined
        ]


def _negative(
    run: _Run, agent: str, text: str, clause: str, cited: set[str], read_by: str
) -> dict[str, Any]:
    held: list[str] = []
    unheld: list[str] = []
    for found in sorted(cited):
        holder = run.holders.get(found, found)
        if holder in run.calls:
            if holder not in held:
                held.append(holder)
        else:
            unheld.append(found)
    held.sort(key=lambda key: run.order.get(key, 0))
    looked = [run.calls[key] for key in held]
    row: dict[str, Any] = {"agent": agent, "claim": text, "read_by": read_by, "looked": looked}
    if clause:
        row["negative"] = clause
    if unheld:
        row["not_in_ledger"] = unheld
    if not looked:
        row["coverage"] = UNKNOWN
        return row
    answered = [c for c in looked if c["state"] in _READ]
    if not answered:
        row["coverage"] = FAILED
        return row
    # An input whose own record is incomplete: a sandbox report not observed.
    if run.sandbox_incomplete and any(
        label["input"] == SANDBOX_REPORT for call in answered for label in call["over"]
    ):
        row["coverage"] = FAILED
        row["why"] = {"input": SANDBOX_REPORT, "statement": run.sandbox_incomplete}
        return row
    gaps: list[dict[str, Any]] = []
    for call in looked:
        if call["state"] in _NO_ANSWER or call["state"] == CUT:
            gaps.append({"gap": "cited", "entry": call["entry"], "state": call["state"]})
            continue
        if call.get("narrowed_by"):
            gaps.append({"gap": "narrowed", "entry": call["entry"], "by": call["narrowed_by"]})
        if call.get("capped"):
            gaps.append({"gap": "capped", "entry": call["entry"]})
        if "not_declared_whole" in (call.get("limits") or []):
            gaps.append({"gap": "not_declared_whole", "entry": call["entry"]})
    if run.no_capture and any(
        label["input"] == SANDBOX_REPORT for call in answered for label in call["over"]
    ):
        gaps.append({"gap": "no_capture"})
    # The input read is the input the clause is about: a read of the sample
    # stands for it; one over a layer, another file or an argument alone does
    # not.
    over_sample = any(
        label["input"] in (SAMPLE, CAPTURE, SANDBOX_REPORT)
        for call in answered
        for label in call["over"]
    )
    if not over_sample:
        read = [label for call in answered for label in call["over"]]
        gaps.append({"gap": "input_mismatch", "over": read})
    keys = {_input_key(label) for call in answered for label in call["over"]}
    looks_for = {_kind_key(call) for call in answered}
    reported: set[str] = set(held)
    same_kind: list[str] = []
    for key in sorted(keys):
        for what in sorted(looks_for):
            for entry_id in run.no_answer.get((key, what), ()):
                if entry_id not in reported:
                    reported.add(entry_id)
                    same_kind.append(entry_id)
        for path, producer in run.children.get(key, ()):
            if path in reported or f"{FILE}:{path}" in keys:
                continue
            reported.add(path)
            gap = "layer_never_examined" if path not in run.examined else "layer_not_read"
            gaps.append({"gap": gap, "path": path, "from": producer})
    if same_kind:
        # Listed once, under what the run could not establish; named here by
        # their ids alone.
        same_kind.sort(key=lambda key: run.order.get(key, 0))
        gaps.append({"gap": "same_kind_no_answer", "entries": same_kind})
    if gaps:
        row["coverage"] = PARTIAL
        row["gaps"] = gaps
    elif any(call["read"] == NOT_KNOWN for call in answered):
        row["coverage"] = INPUT_UNKNOWN
    elif any(call["read"] != WHOLE for call in answered):
        row["coverage"] = UNKNOWN
        row["why"] = {"answer_shape": [c["entry"] for c in answered if c["read"] != WHOLE]}
    else:
        row["coverage"] = FULL
    return row


def _negatives(run: _Run, isr_reports: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    from maljan.schemas.evidence import entry_ids_in

    rows: list[dict[str, Any]] = []
    for agent, claim in _claims(isr_reports):
        text = str(_field(claim, "claim") or "")
        ref = str(_field(claim, "evidence_ref") or "")
        clauses = _clauses(text)
        negative = [clause for clause, is_negative in clauses if is_negative]
        if negative:
            # The evidence field is the whole claim's citation: it counts for a
            # negative clause only where no clause of the claim asserts.
            every = len(negative) == len(clauses)
            for clause in negative:
                cited = entry_ids_in(clause) or (entry_ids_in(ref) if every else set())
                rows.append(_negative(run, agent, text, clause, cited, WORDING))
        elif _field(claim, "kept_after_absence_question") is True:
            rows.append(
                _negative(run, agent, text, "", entry_ids_in(f"{text} {ref}"), ABSENCE_QUESTION)
            )
    return rows


def _not_established(
    run: _Run,
    calls: Sequence[dict[str, Any]],
    *,
    sandbox_report: Any,
    capture_path: str,
    server_reasons: Sequence[str],
    server_rests: int,
    unreadable: int,
    shortened: Sequence[str],
) -> list[dict[str, Any]]:
    from maljan.pipeline.sandbox_status import OBSERVED, sandbox_status

    rows: list[dict[str, Any]] = []
    grouped: dict[tuple[str, ...], tuple[dict[str, Any], set[str]]] = {}
    for call in calls:
        state = call["state"]
        if state == ANSWERED:
            continue
        key = (call["tool"], call["server"], state, call.get("reason", ""))
        held = grouped.get(key)
        if held is None:
            row: dict[str, Any] = {
                "what": "call",
                "tool": call["tool"],
                "server": call["server"],
                "kind": call["kind"],
                "state": state,
                "entries": [],
                "over": [],
            }
            if call.get("reason"):
                row["reason"] = call["reason"]
            held = grouped[key] = (row, set())
            rows.append(row)
        row, known = held
        row["entries"].append(call["entry"])
        if state == CUT:
            row["dropped"] = int(row.get("dropped") or 0) + int(call.get("dropped") or 0)
        for label in call["over"]:
            label_key = _input_key(label)
            if label_key not in known:
                known.add(label_key)
                row["over"].append(label)
    rows.extend({"what": "layer", **layer} for layer in run.unexamined)
    found = sandbox_status(sandbox_report)
    if found.status != OBSERVED:
        rows.append({"what": "input", "input": SANDBOX_REPORT, "reason": found.statement})
    if not capture_path:
        rows.append(
            {
                "what": "input",
                "input": CAPTURE,
                "reason": (
                    "the sandbox report names no packet capture"
                    if isinstance(sandbox_report, Mapping) and sandbox_report
                    else "no sandbox report, so no packet capture"
                ),
            }
        )
    rows.extend({"what": "server", "reason": str(r)} for r in server_reasons if str(r).strip())
    if server_rests:
        rows.append({"what": "server_rests", "count": int(server_rests)})
    if unreadable:
        rows.append({"what": "unreadable_rows", "count": int(unreadable)})
    rows.extend({"what": "shortened", "reason": str(r)} for r in shortened if str(r).strip())
    return rows


def _tools(calls: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each tool on each server: its kind, its calls by state and the inputs it read, in order.

    A guard's answer is counted apart from the calls, as ``run_summary.evidence``
    counts it. A path input is named; any other is counted by its role.
    """
    rows: dict[tuple[str, str], tuple[dict[str, Any], set[str]]] = {}
    out: list[dict[str, Any]] = []
    for call in calls:
        key = (call["tool"], call["server"])
        held = rows.get(key)
        if held is None:
            row: dict[str, Any] = {
                "tool": call["tool"],
                "server": call["server"],
                "kind": call["kind"],
                "calls": 0,
                "guard_answers": 0,
                "states": {},
                "over": [],
                "roles": {},
            }
            held = rows[key] = (row, set())
            out.append(row)
        row, known = held
        if call["state"] == GUARD:
            row["guard_answers"] += 1
            continue
        row["calls"] += 1
        row["states"][call["state"]] = int(row["states"].get(call["state"], 0)) + 1
        for label in call["over"]:
            label_key = _input_key(label)
            if label_key in known:
                continue
            known.add(label_key)
            if label["input"] == ROLE:
                role = str(label.get("role"))
                row["roles"][role] = int(row["roles"].get(role, 0)) + 1
            else:
                row["over"].append(label)
    return out


def coverage_record(
    *,
    entries: Iterable[Any] = (),
    isr_reports: Mapping[str, Any] | None = None,
    sample_path: str | None = None,
    sandbox_report: Any = None,
    server_reasons: Sequence[str] = (),
    server_rests: int = 0,
    unreadable: int = 0,
    shortened: Sequence[str] = (),
    partial_reason: str = "",
    fills_staged_sample: Callable[[Any], bool] | None = None,
) -> dict[str, Any] | None:
    """``run_summary.coverage`` as of now, or ``None`` where it cannot be read. Never raises.

    ``entries`` is the run's evidence ledger, in order; ``isr_reports`` the
    analysts' final answers; ``sample_path`` the sample as the worker holds
    it; ``sandbox_report`` the run's sandbox report document, or ``None``;
    ``server_reasons`` the tool servers the job could not attach;
    ``server_rests`` how many rests the run summary lists; ``unreadable`` the
    ledger rows the caller could not read; ``shortened`` the inputs the run
    shortened. ``partial_reason`` says why the record may miss what the step
    the run stopped in did. ``fills_staged_sample`` says whether an entry's
    source declares it reads the staged sample (the live declaration by
    default).
    """
    try:
        from maljan.schemas.evidence import is_guard_answer, repeat_holders
        from maljan.schemas.sandbox_document import place

        ledger, own_unreadable = _ledger(entries)
        capture = place(sandbox_report, "network.pcap_local_path") if sandbox_report else None
        capture_path = str(capture) if isinstance(capture, str) else ""
        sample = str(sample_path or "")
        fills = fills_staged_sample or _fills_staged_sample
        layers = _produced_layers(ledger, _layer_names(ledger), sample, capture_path)
        inputs = _Inputs(sample, capture_path, layers)
        holders = repeat_holders(ledger)
        calls: dict[str, dict[str, Any]] = {}
        order: dict[str, int] = {}
        ran: list[dict[str, Any]] = []
        for index, entry in enumerate(ledger):
            entry_id = _entry_id(entry)
            if not entry_id or entry_id in calls:
                continue
            # A repeat holds no answer of its own; the entry it names does. A
            # guard's answer names itself and is a call no tool ran.
            if str(_field(entry, "repeated_of") or "").strip() and not is_guard_answer(entry):
                continue
            call = _call(entry, inputs, fills, index)
            calls[entry_id] = call
            order[entry_id] = index
            ran.append(call)
        from maljan.pipeline.sandbox_status import OBSERVED, sandbox_status

        found = sandbox_status(sandbox_report)
        run = _Run(
            calls,
            order,
            holders,
            layers,
            sandbox_incomplete="" if found.status == OBSERVED else found.statement,
            no_capture=found.status == OBSERVED and not capture_path,
        )
        record: dict[str, Any] = {
            "v": COVERAGE_VERSION,
            "tools": _tools(ran),
            "negatives": _negatives(run, isr_reports),
            "not_established": _not_established(
                run,
                ran,
                sandbox_report=sandbox_report,
                capture_path=capture_path,
                server_reasons=list(server_reasons or ()),
                server_rests=int(server_rests or 0),
                unreadable=int(unreadable or 0) + own_unreadable,
                shortened=list(shortened or ()),
            ),
        }
        if partial_reason:
            record["partial_reason"] = str(partial_reason)
        return record
    except Exception:  # noqa: BLE001 — a record is never worth a report
        from maljan.core.logger import logger

        logger.warning("coverage: the record could not be built; the report carries none.")
        return None


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

_CODE_SPAN: ContextVar[Callable[[str], str] | None] = ContextVar("coverage_code", default=None)


def _c(value: Any) -> str:
    code = _CODE_SPAN.get()
    if code is not None:
        return code(str(value))
    from maljan.reporting.renderers.markdown import _code_span, _one_line

    return _code_span(_one_line(str(value)))


def _entry(entry_id: Any) -> str:
    """One ledger entry, named as the report names any run value."""
    return f"entry {_c(entry_id)}"


def _entries(ids: Sequence[Any]) -> str:
    many = len(ids) > 1
    return f"entr{'ies' if many else 'y'} " + ", ".join(_c(e) for e in ids)


def input_phrase(label: Mapping[str, Any]) -> str:
    """One input as the report names it: a path, the sample or a layer by name; a role by role."""
    kind = str(label.get("input") or "")
    filled = " (filled in by the platform)" if label.get("filled") else ""
    if kind == SAMPLE:
        return f"the sample{filled}"
    if kind == CAPTURE:
        return f"the packet capture{filled}"
    if kind == SANDBOX_REPORT:
        return "the sandbox report"
    if kind == LAYER:
        return (
            f"the layer {_c(label.get('path'))} produced by {_entry(label.get('from'))} "
            f"({_c(label.get('from_tool'))})"
        )
    if kind == FILE:
        return f"the file {_c(label.get('path'))}"
    if kind == ROLE:
        return f"its {_c(label.get('role'))} argument"
    if kind == UNDECLARED:
        said = "an input the tool does not declare"
        if label.get("server_reads_staged_sample"):
            said += " (its server is handed the staged sample)"
        return said
    if kind == UNNAMED:
        return "an input the call does not name"
    if kind == NO_INPUT:
        return "no input it names (the call took no arguments)"
    return "an input not recorded"


def _inputs_phrase(labels: Sequence[Mapping[str, Any]]) -> str:
    return ", ".join(input_phrase(label) for label in labels) or "no input it names"


def _tool_phrase(row: Mapping[str, Any]) -> str:
    said = _c(row.get("tool"))
    if row.get("kind"):
        said += f" (kind {_c(row['kind'])})"
    if row.get("server"):
        said += f" on {_c(row['server'])}"
    return said


_STATE_WORDS = {
    ANSWERED: "answered",
    CUT: "answered and was cut",
    NOT_SHOWN: "answered and was not shown to the model",
    CALL_FAILED: "failed",
    NOT_RUN: "was not run",
    GUARD: "was refused by a guard, with no tool run",
}


def _call_phrase(call: Mapping[str, Any]) -> str:
    said = f"{_tool_phrase(call)} ({_entry(call.get('entry'))}) looked over "
    said += _inputs_phrase(call.get("over") or [])
    state = str(call.get("state") or "")
    if state != ANSWERED:
        said += f", and {_STATE_WORDS.get(state, state)}"
        if call.get("reason"):
            said += f" ({_c(call['reason'])})"
    elif call.get("read") == NOT_KNOWN:
        said += ", how much of it the record cannot tell (the tool declares nothing)"
    return said


def _not_established_line(row: Mapping[str, Any]) -> str:
    what = row.get("what")
    if what == "call":
        state = str(row.get("state") or "")
        said = f"{_tool_phrase(row)} {_STATE_WORDS.get(state, state)}"
        said += (
            f" over {_inputs_phrase(row.get('over') or [])} ({_entries(row.get('entries') or [])})"
        )
        if state == CUT and row.get("dropped"):
            said += f": {int(row['dropped']):,} characters cut"
        if row.get("reason"):
            said += f": {_c(row['reason'])}"
        return said + "."
    if what == "layer":
        return (
            f"The layer {_c(row.get('path'))} produced by {_entry(row.get('from'))} "
            f"({_c(row.get('from_tool'))}) was never examined."
        )
    if what == "input":
        name = "No sandbox report" if row.get("input") == SANDBOX_REPORT else "No packet capture"
        return f"{name}: {str(row.get('reason') or 'not recorded').rstrip('.')}."
    if what == "server":
        return f"Tool server not attached: {_c(row.get('reason'))}."
    if what == "server_rests":
        count = int(row.get("count") or 0)
        return (
            f"{count} tool server rest{'' if count == 1 else 's'}, listed with the run summary "
            "lines above."
        )
    if what == "unreadable_rows":
        count = int(row.get("count") or 0)
        return (
            f"{count} ledger row{'' if count == 1 else 's'} could not be read; a claim citing "
            f"{'it' if count == 1 else 'one'} reads as citing no entry."
        )
    if what == "shortened":
        return f"Input shortened: {_c(row.get('reason'))}."
    return ""


def _analyst_lines(
    failed: Sequence[str], skipped: Mapping[str, str], silent: Sequence[str]
) -> list[str]:
    """The analysts the report's own analyst record names as failed, skipped or silent."""
    lines = [f"Analyst {_c(a)} failed; what it would have read was not read." for a in failed]
    for agent, why in skipped.items():
        lines.append(f"Analyst {_c(agent)} was skipped" + (f" ({_c(why)})." if why else "."))
    lines.extend(f"Analyst {_c(a)} ran and made no claims." for a in silent)
    return lines


_COVERAGE_WORDS = {
    FULL: "coverage full",
    INPUT_UNKNOWN: "coverage of the input unknown",
    PARTIAL: "coverage partial",
    FAILED: "coverage failed",
    UNKNOWN: "coverage unknown",
}


def _gap_phrase(gap: Mapping[str, Any]) -> str:
    kind = gap.get("gap")
    if kind == "cited":
        state = str(gap.get("state") or "")
        return f"{_entry(gap.get('entry'))} {_STATE_WORDS.get(state, state)}"
    if kind == "narrowed":
        by = ", ".join(_c(name) for name in gap.get("by") or [])
        return (
            f"{_entry(gap.get('entry'))} was passed arguments no declaration marks as not "
            f"narrowing ({by})"
        )
    if kind == "capped":
        return f"{_entry(gap.get('entry'))} says its answer holds part of the rows"
    if kind == "not_declared_whole":
        return f"{_entry(gap.get('entry'))} is of a tool no declaration says reads its whole input"
    if kind == "no_capture":
        return "the sandbox report names no packet capture"
    if kind == "input_mismatch":
        return f"the calls read {_inputs_phrase(gap.get('over') or [])}, not the sample"
    if kind == "same_kind_no_answer":
        count = len(gap.get("entries") or [])
        return (
            f"{count} call{'' if count == 1 else 's'} of the same kind over the same input did not "
            "answer (listed under what this run could not establish)"
        )
    if kind == "layer_never_examined":
        return (
            f"the layer {_c(gap.get('path'))} produced by {_entry(gap.get('from'))} was never "
            "examined"
        )
    if kind == "layer_not_read":
        return (
            f"the layer {_c(gap.get('path'))} produced by {_entry(gap.get('from'))} was read by no "
            "call the clause cites"
        )
    return _c(kind)


def _negative_line(row: Mapping[str, Any], quote: Callable[[str], str]) -> str:
    coverage = str(row.get("coverage") or UNKNOWN)
    if row.get("negative"):
        quoted = f"“{quote(str(row['negative']))}”"
    else:
        quoted = f"“{quote(str(row.get('claim') or ''))}” (kept after the absence question)"
    said = f"{_c(row.get('agent'))}: {quoted}: {_COVERAGE_WORDS.get(coverage, coverage)}"
    looked = row.get("looked") or []
    if coverage == UNKNOWN and not looked:
        said += ": the negative clause cites no entry the ledger holds"
        if row.get("not_in_ledger"):
            said += f" (it names {_entries(row['not_in_ledger'])})"
        return said + "."
    said += ". " + "; ".join(_call_phrase(call) for call in looked)
    why = row.get("why") or {}
    if why.get("input") == SANDBOX_REPORT:
        said += (
            f". The sandbox report's own record is incomplete: "
            f"{str(why.get('statement') or 'not observed').rstrip('.')}"
        )
    elif why.get("answer_shape"):
        said += (
            f". The answer of {_entries(why['answer_shape'])} has no shape the record can read "
            "its truncation markers from"
        )
    gaps = row.get("gaps") or []
    if gaps:
        said += ". Not covered: " + "; ".join(_gap_phrase(gap) for gap in gaps)
    if row.get("not_in_ledger"):
        said += f". It also names {_entries(row['not_in_ledger'])}, which the ledger does not hold"
    return said + "."


def _looked_line(row: Mapping[str, Any]) -> str:
    calls = int(row.get("calls") or 0)
    states = row.get("states") or {}
    said = f"{_tool_phrase(row)}: {calls} call{'' if calls == 1 else 's'}"
    inputs = [input_phrase(label) for label in row.get("over") or []]
    inputs += [
        f"{int(count)} {_c(role)} value{'' if int(count) == 1 else 's'}"
        for role, count in (row.get("roles") or {}).items()
    ]
    if inputs:
        said += " over " + ", ".join(inputs)
    rest = [
        f"{int(count)} {_STATE_WORDS.get(state, state)}"
        for state, count in states.items()
        if state != ANSWERED and count
    ]
    if rest:
        said += "; " + ", ".join(rest)
    guards = int(row.get("guard_answers") or 0)
    if guards:
        said += f"; {guards} more answered by a guard with no tool run ({GUARD_NOTE})"
    return said + "."


def coverage_lines(
    record: Any,
    code: Callable[[str], str] | None = None,
    quote: Callable[[str], str] | None = None,
    analysts: tuple[Sequence[str], Mapping[str, str], Sequence[str]] | None = None,
) -> tuple[list[str], list[str], list[str]]:
    """The three blocks' lines: what could not be established, what looked, the negatives.

    ``([], [], [])`` for no record. ``code`` prints a value the run supplied;
    ``quote`` a model's claim, as the report prints a model's words inline;
    ``analysts`` the failed, skipped (with why) and silent analysts of the
    report's own analyst record, printed with what could not be established,
    so the two never disagree.
    """
    if not isinstance(record, Mapping) or "v" not in record:
        return [], [], []
    token = _CODE_SPAN.set(code)
    try:
        say = quote or (lambda text: text)
        missing = [
            line
            for line in (_not_established_line(row) for row in record.get("not_established") or [])
            if line
        ]
        if analysts is not None:
            missing.extend(_analyst_lines(*analysts))
        if record.get("partial_reason"):
            missing.insert(
                0,
                f"This record may be incomplete: {record['partial_reason']}, and what the step "
                "it stopped in did may not be in it.",
            )
        if not missing:
            missing = [NOTHING_MISSING]
        looked = [
            _looked_line(row) for row in record.get("tools") or [] if isinstance(row, Mapping)
        ]
        negatives = [
            _negative_line(row, say)
            for row in record.get("negatives") or []
            if isinstance(row, Mapping)
        ]
        return missing, looked, negatives
    finally:
        _CODE_SPAN.reset(token)
