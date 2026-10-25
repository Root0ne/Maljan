"""Which of a run's reasons cost it evidence, and which are the operator's choice.

A run's degradation reasons say what it could not examine that it would
otherwise have examined: capa not installed, a sandbox fetch that failed, a
tool that errored, a cap or a timeout that cut the work short. Some of the
sentences the registry records are of another kind. A threat-intel key the
operator never set, a server the operator switched off, a tool a shared server
withholds because its configuration does not let it be held to the job: none
of these took evidence from this run that its configuration would have given
it. Listed with the losses, they drew the DEGRADED RUN banner over a run that
lost nothing, and buried the reasons that did cost it something.

So they are told apart here and listed on their own (``operator_choices``):
still on every surface that lists the reasons, never in the banner and never
in what makes the run degraded. A setting counts as unset only where the
server's manifest says so by its code (``not_configured``), never by the words
of its reason. A sentence this module does not recognise stays a degradation.

Of the reasons that stay, one decision (:func:`is_loss`) says which cost this
sample anything: the degraded flag and the tools the banner names both read
it, so a run is never degraded with nothing named.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from maljan.providers.sample_open import withheld_by_policy, withheld_tool
from maljan.providers.servers import AGENT_TOOL_UNAVAILABLE_REASON, SERVER_DISABLED

# ``server.<key>.<tool>_unavailable(`` opens a manifest's sentence (``Unavailable``).
_UNAVAILABLE_TOOL = re.compile(r"^server\.(?P<server>[^.]+)\.(?P<tool>[^.(]+)_unavailable\(")
# ``triage.<tool>_failed``: a pack tool that did not answer at all.
_PACK_FAILED = re.compile(r"^triage\.(?P<tool>.+)_failed$")
# ``triage.<tool>_degraded``: a pack tool that answered a smaller set than it wanted.
_PACK_PARTIAL = re.compile(r"^triage\.(?P<tool>.+)_degraded$")
# ``agent tool '<server>.<name>' unavailable``, and after it what made it so.
_AGENT_TOOL = re.compile(
    "^"
    + re.escape(AGENT_TOOL_UNAVAILABLE_REASON)
    .replace(re.escape("{server}"), r"(?P<server>[^'.]*)")
    .replace(re.escape("{name}"), r"(?P<name>[^']*)")
    + r"(?:: (?P<why>.+))?$",
    re.DOTALL,
)
# What an agent reference names for every tool of its server.
_EVERY_TOOL = "*"


def _manifest_reason(reason: str) -> str | None:
    """The ``<why>`` of ``server.<key>.<tool>_unavailable(<why>)``; ``None`` for another sentence.

    Read to its own closing parenthesis, since a module's reason quotes the
    import's words in parentheses of their own.
    """
    opening = _UNAVAILABLE_TOOL.match(reason)
    if opening is None:
        return None
    depth = 1
    for at in range(opening.end(), len(reason)):
        if reason[at] == "(":
            depth += 1
        elif reason[at] == ")":
            depth -= 1
            if depth == 0:
                return reason[opening.end() : at]
    return None


def is_operator_choice(reason: str, not_configured: Iterable[str] = ()) -> bool:
    """Whether ``reason`` is the operator's configuration rather than a loss of evidence.

    Three sentences are: a tool the job's servers name in ``not_configured``
    (their manifests' ``not_configured`` code, with no value for the setting
    in the platform's own settings: ``ServerHandle.not_configured_reasons``),
    a tool a shared server withholds by its configured policy
    (``sample_open.withheld_by_policy``), and a referenced tool of a server
    the operator switched off. A manifest's sentence no manifest code backs is
    a loss whatever its words, as is a tool withheld because its schema could
    not be read or the job kept no note of its programs, a library not
    installed and a server that could not attach.
    """
    text = str(reason or "")
    if _UNAVAILABLE_TOOL.match(text):
        return text in set(not_configured)
    if withheld_by_policy(text):
        return True
    agent_tool = _AGENT_TOOL.match(text)
    if agent_tool is not None and agent_tool.group("why"):
        why = agent_tool.group("why")
        return why == SERVER_DISABLED or is_operator_choice(why, not_configured)
    return False


def split_operator_choices(
    reasons: Iterable[str], not_configured: Iterable[str] = ()
) -> tuple[list[str], list[str]]:
    """``reasons`` as the run's degradations and the operator's choices, each in order."""
    unset = frozenset(str(r) for r in not_configured)
    kept: list[str] = []
    chosen: list[str] = []
    for reason in reasons or ():
        text = str(reason)
        (chosen if is_operator_choice(text, unset) else kept).append(text)
    return kept, chosen


@dataclass(frozen=True)
class SampleFacts:
    """What a run holds about its sample that decides whether a missing tool cost it anything.

    ``file_type`` is the sample's routed format, ``""`` when the run holds
    none. ``failures`` are the run's failed calls, ledger entries or the run
    summary's tool-failure rows: a tool that answered one with a
    missing-dependency error (``errors.answered_short_of_a_library``) had its
    missing part reached by this run, whatever the format says. ``without_reads`` holds,
    by ``(server, tool)``, the routed formats a tool's missing part reads as
    the job's own server manifests declare them; a tool not there is read
    from the shipped declaration (``sidecar_needs.without_reads``).
    """

    file_type: str = ""
    failures: tuple[Any, ...] = ()
    without_reads: Mapping[tuple[str, str], frozenset[str]] = field(default_factory=dict)

    @property
    def routed(self) -> str:
        routed = str(self.file_type or "").strip().lower()
        return "" if routed == "unknown" else routed


@dataclass(frozen=True)
class _Named:
    """The tool a reason names: its server's key where the reason gives one, and how it said it."""

    tool: str
    server: str | None = None
    # "pack" (a triage token), "server" (a manifest's sentence), "agent" (an
    # agent's reference) or "withheld" (a shared server's withhold, whose
    # label is no server key).
    kind: str = "server"


def _tool_of(reason: str) -> _Named | None:
    """The tool a reason names, or ``None`` for a loss that is no tool's."""
    pack = _PACK_FAILED.match(reason) or _PACK_PARTIAL.match(reason)
    if pack is not None:
        return _Named(pack.group("tool"), kind="pack")
    server = _UNAVAILABLE_TOOL.match(reason)
    if server is not None:
        return _Named(server.group("tool"), server.group("server"))
    agent = _AGENT_TOOL.match(reason)
    if agent is not None:
        name = agent.group("name")
        # A reference to every tool of a server names the server.
        if name == _EVERY_TOOL:
            return _Named(agent.group("server"), kind="agent")
        return _Named(name, agent.group("server"), kind="agent")
    withheld = withheld_tool(reason)
    if withheld:
        return _Named(withheld, kind="withheld")
    return None


def _cannot_apply(named: _Named, routed: str) -> bool:
    """Whether ``tool`` serves only formats other than the sample's known ``routed`` one.

    A server's tool by the routed formats it declares
    (``declared_reading.routed_formats_of``: ``macho_info`` serves Mach-O);
    a pack step by the formats its shipped step runs for. Nothing is said of
    a tool that declares none, nor of a sample of no known format.
    """
    if not routed or named.kind == "withheld":
        return False
    if named.server is not None:
        from maljan.core.declared_reading import routed_formats_of

        formats = routed_formats_of(f"mcp:{named.server}", named.tool)
    elif named.kind == "pack":
        from maljan.core.pack_steps import shipped_step

        step = shipped_step(named.tool)
        formats = frozenset(step.formats) if step is not None else frozenset()
    else:
        return False
    return bool(formats) and routed not in formats


def _answers_all_it_needs(reason: str, named: _Named, facts: SampleFacts) -> bool:
    """Whether a tool that answered part lost this sample nothing.

    ``triage.<tool>_degraded`` and ``; still answers <what>`` are tools that
    answer part of what they would (``archive_list`` without py7zr still
    lists a zip). The part they cannot answer is not this sample's only when
    the tool declares the routed formats it reads (``without_reads``), the
    run holds the sample's format outside them, and the tool did not answer
    this run with its missing-dependency error: a 7z carved out of a PE is
    the 7z reader's loss whatever the top-level format says.
    """
    from maljan.tools.sidecar_needs import without_reads

    if named.kind not in ("pack", "server"):
        return False
    server, tool = named.server, named.tool
    if _PACK_PARTIAL.match(reason) is None:
        manifest = _manifest_reason(reason)
        tail = reason.split(f"({manifest})", 1)[1] if manifest is not None else ""
        if "; still answers " not in tail:
            return False
    from maljan.tools.errors import answered_short_of_a_library

    if not facts.routed or answered_short_of_a_library(tool, facts.failures):
        return False
    reads = facts.without_reads.get((server or "", tool))
    if reads is None:
        reads = without_reads(tool, server)
    return reads is not None and bool(reads) and facts.routed not in reads


def costs_this_sample_nothing(reason: str, facts: SampleFacts) -> bool:
    """Whether the tool ``reason`` names could not have answered anything of this sample.

    A tool serving only other formats (``macho_info`` on a PE sample), or one
    that answered all the sample needs of it (:func:`_answers_all_it_needs`).
    """
    named = _tool_of(str(reason or ""))
    if named is None:
        return False
    return _cannot_apply(named, facts.routed) or _answers_all_it_needs(str(reason), named, facts)


def is_loss(
    reason: str, facts: SampleFacts | None = None, not_configured: Iterable[str] = ()
) -> bool:
    """Whether ``reason`` cost this run evidence it would otherwise have had.

    Every reason does but the operator's choices and a tool that could not
    have answered anything of this sample (:func:`costs_this_sample_nothing`).
    """
    text = str(reason or "")
    if is_operator_choice(text, not_configured):
        return False
    return not costs_this_sample_nothing(text, facts or SampleFacts())


def lost_tools(
    reasons: Iterable[str], facts: SampleFacts | None = None, not_configured: Iterable[str] = ()
) -> list[str]:
    """The tools of the losses among ``reasons`` (:func:`is_loss`), each once, in order.

    Bare names, for the one sentence a reader of the header gets: the codes
    and remedies are §13's. A loss that names no tool (an analyst failure, a
    capture not fetched) is said by the header's other clauses.
    """
    found: list[str] = []
    for reason in reasons or ():
        text = str(reason)
        named = _tool_of(text)
        if named is not None and named.tool not in found and is_loss(text, facts, not_configured):
            found.append(named.tool)
    return found


def facts_record(facts: SampleFacts) -> dict[str, Any] | None:
    """What the run summary keeps of ``facts`` (``loss_facts``), ``None`` when there is nothing.

    The tools that answered short of a library and what each tool's missing
    part reads, as the judge node decided on them: the report's header reads
    them back (:func:`facts_from_record`) so the tools it names are the ones
    the degraded flag was set on.
    """
    from maljan.tools.errors import short_of_a_library_rows

    failures = short_of_a_library_rows(facts.failures)
    reads = [
        {"server": server, "tool": tool, "formats": sorted(formats)}
        for (server, tool), formats in sorted(facts.without_reads.items())
    ]
    record: dict[str, Any] = {}
    if failures:
        record["failures"] = failures
    if reads:
        record["without_reads"] = reads
    return record or None


def facts_from_record(
    record: Any, file_type: str = "", fallback_failures: Iterable[Any] = ()
) -> SampleFacts:
    """The facts a run summary kept (:func:`facts_record`), with the sample's format.

    A summary written before it kept them reads its tool-failure rows
    (``fallback_failures``) and the shipped declarations instead.
    """
    held = record if isinstance(record, Mapping) else {}
    failures = held.get("failures")
    reads: dict[tuple[str, str], frozenset[str]] = {}
    for row in held.get("without_reads") or ():
        if isinstance(row, Mapping) and row.get("tool"):
            key = (str(row.get("server") or ""), str(row["tool"]))
            reads[key] = frozenset(str(f) for f in row.get("formats") or ())
    return SampleFacts(
        file_type=str(file_type or ""),
        failures=tuple(failures if isinstance(failures, list) else fallback_failures),
        without_reads=reads,
    )
