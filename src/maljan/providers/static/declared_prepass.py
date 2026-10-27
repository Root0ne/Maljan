"""The passes the platform makes itself on a server that declares their tools, read by data.

A static provider that can read a program's call graph, hash its functions or
scan it for anti-analysis code offers each through the provider interface
(``StaticProvider.call_graph``, ``function_hashes``, ``anti_analysis_scan``).
The generic MCP provider has no code of its own for any of them: its server's
block names the tool for each (``MCPServerConfig.prepass_tools``), and the
answer is read here by that tool's own declaration (``tool_facts``):

* ``arguments`` says where the call names the sample: role ``path`` takes the
  path the server sees, role ``program`` the name the job's open of it was
  given (``providers.sample_open``); a tool that declares neither is called
  with none, for a server that keeps the opened sample as its session.
* ``rows`` is where the answer's rows sit (the answer itself when it is a list
  and nothing is declared), and ``values`` / ``places`` the path inside a row
  of each part a pass reads; a part declared nowhere is read from the row's
  key of the same name.

A call graph answered as text is read as ``CALLER -> CALLEE`` lines, one call
each. A function named with one of the block's ``auto_name_prefixes`` before
a hexadecimal address gives that address.

Nothing here names a tool: with no ``prepass_tools`` the provider answers as
it does undeclared (``None``, no hashes, no scan). Each read is linear in the
answer.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.anti_analysis import PassFailed
from maljan.analysis.sink_reachability import CallGraph
from maljan.core.tool_declarations import ToolFacts, select

# The parts each pass reads of a row, by the name a declaration's ``values``
# or ``places`` gives them.
CALLER, CALLEE, ADDRESS = "caller", "callee", "address"
FUNCTION, HASH, NAME = "function", "hash", "name"
CATEGORY, TECHNIQUE, INSTRUCTION, OFFSET = "category", "technique", "instruction", "offset"

# The argument roles a pass fills.
PATH_ROLE, PROGRAM_ROLE = "path", "program"


class DeclaredPassFailed(PassFailed):
    """A declared pass that was made and did not complete, with what happened."""


def declared_tool(block: Any, which: str) -> str:
    """The tool ``block`` names for the pass ``which`` (``call_graph`` …), ``""`` for none."""
    declared = getattr(block, "prepass_tools", None)
    return str(getattr(declared, which, "") or "") if declared is not None else ""


def block_declaration(block: Any, tool: str, source: str = "") -> ToolFacts | None:
    """The declaration in force for ``tool`` under ``block``, or ``None``.

    With ``source`` (``mcp:<key>``), what the block's server declares of
    itself is laid under the block's own (``declared_reading.tools_in_force``);
    without, the block's own alone.
    """
    if not tool:
        return None
    if source:
        from maljan.core.declared_reading import tools_in_force

        held: Any = tools_in_force(source, block)
    else:
        held = getattr(block, "tool_facts", None) or {}
    facts = held.get(tool)
    return facts if isinstance(facts, ToolFacts) else None


def call_arguments(
    facts: ToolFacts | None, *, path: str | None, program: str | None
) -> dict[str, Any] | None:
    """The arguments a pass's call gives, by the roles the tool declares; ``None`` when one
    it declares has no value to give (the call is not made)."""
    roles = dict(facts.arguments) if facts is not None else {}
    out: dict[str, Any] = {}
    for role, value in ((PATH_ROLE, path), (PROGRAM_ROLE, program)):
        argument = roles.get(role)
        if not argument:
            continue
        if not value:
            return None
        out[argument] = value
    return out


def answer_value(answer: Any) -> Any:
    """A tool's answer as data: its text parsed as JSON where it is JSON, else the text.

    An answer handed back as content blocks is read as their text, joined.
    """
    if isinstance(answer, list) and answer and all(isinstance(b, dict) for b in answer):
        texts = [b.get("text") for b in answer if isinstance(b.get("text"), str)]
        if texts:
            answer = "\n".join(texts)
    if isinstance(answer, str):
        text = answer.strip()
        if text[:1] in ("{", "["):
            try:
                return json.loads(text)
            except ValueError:
                return answer
        return answer
    return answer


def _part(row: Any, facts: ToolFacts | None, name: str) -> Any:
    declared = (facts.values.get(name) or facts.places.get(name)) if facts is not None else None
    if declared:
        found = select(row, declared)
        return found[0] if found else None
    return row.get(name) if isinstance(row, dict) else None


def rows_of(answer: Any, facts: ToolFacts | None) -> list[Any]:
    """The rows of ``answer``: where ``rows`` says, else the answer itself when it is a list."""
    if facts is not None and facts.rows:
        return select(answer, facts.rows)
    return list(answer) if isinstance(answer, list) else []


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _address_reader(prefixes: Iterable[str]) -> Callable[[str], str | None]:
    """The address a function's name gives after one of ``prefixes``, ``0x``-prefixed."""
    words = [re.escape(str(p)) for p in prefixes if str(p)]
    if not words:
        return lambda _name: None
    pattern = re.compile(rf"\A(?:{'|'.join(words)})(?:0x)?([0-9a-fA-F]+)\Z")

    def read(name: str) -> str | None:
        match = pattern.match(name)
        return f"0x{match.group(1)}" if match else None

    return read


def call_graph_of(answer: Any, facts: ToolFacts | None, prefixes: Iterable[str] = ()) -> CallGraph:
    """A call-graph answer as a :class:`CallGraph`.

    Text is read as ``CALLER -> CALLEE`` lines; data by its rows, each a
    ``caller`` and a ``callee`` (or a two-item list of them), with the
    caller's ``address`` where the row places it.
    """
    edges: list[tuple[str, str]] = []
    addresses: dict[str, str] = {}
    if isinstance(answer, str):
        for line in answer.splitlines():
            if " -> " in line:
                caller, _, callee = line.partition(" -> ")
                edges.append((caller.strip(), callee.strip()))
    else:
        for row in rows_of(answer, facts):
            if isinstance(row, list | tuple) and len(row) == 2:
                edges.append((_text(row[0]), _text(row[1])))
                continue
            caller, callee = _text(_part(row, facts, CALLER)), _text(_part(row, facts, CALLEE))
            edges.append((caller, callee))
            where = _text(_part(row, facts, ADDRESS))
            if caller and where:
                addresses.setdefault(caller, where)
    graph = CallGraph.of_edges(edges)
    named = _address_reader(prefixes)
    for name in {*graph.callees, *(c for called in graph.callees.values() for c in called)}:
        if name not in addresses:
            said = named(name)
            if said is not None:
                addresses[name] = said
    return CallGraph(callees=graph.callees, addresses=addresses)


def function_hashes_of(answer: Any, facts: ToolFacts | None) -> list[tuple[str, str]]:
    """A function-hash answer as ``(function, hash)`` pairs, each function once.

    A row names its function by ``name``, else ``function``, else ``address``;
    a row with no hash, or naming no function, is left out.
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for row in rows_of(answer, facts):
        digest = _text(_part(row, facts, HASH))
        name = next(
            (
                said
                for part in (NAME, FUNCTION, ADDRESS)
                if (said := _text(_part(row, facts, part)))
            ),
            "",
        )
        if not digest or not name or (name, digest) in seen:
            continue
        seen.add((name, digest))
        out.append((name, digest))
    return out


def scan_findings(answer: Any, facts: ToolFacts | None) -> list[dict[str, Any]]:
    """A scan answer's rows in the scan's row vocabulary (``analysis.anti_analysis``).

    Each row's ``category``, ``technique``, ``instruction``, ``offset`` and
    ``function`` where it holds them; a row with none of them is left out.
    """
    out: list[dict[str, Any]] = []
    for row in rows_of(answer, facts):
        finding = {
            part: said
            for part in (CATEGORY, TECHNIQUE, INSTRUCTION, OFFSET, FUNCTION)
            if (said := _text(_part(row, facts, part)))
        }
        if finding:
            out.append(finding)
    return out


@dataclass
class DeclaredScan:
    """One job's anti-analysis scan by a server's declared scan tool (``AntiAnalysisScan``).

    ``call`` makes the scan and answers the tool's raw answer; it is ``None``
    when ``unavailable`` says why nothing can be scanned. ``tool`` is the
    declared tool, recorded in the answer.
    """

    provider: str
    formats: frozenset[str]
    sample_path: str = ""
    unavailable: str = ""
    tool: str = ""
    facts: ToolFacts | None = None
    call: Callable[[], Any] | None = field(default=None, repr=False)

    def anti_analysis(
        self, host_path: str = "", function_starts: Sequence[Any] = ()
    ) -> dict[str, Any]:
        """The server's scan, whole, with its exact part stated (``read_findings``), by the
        one rule every scan's stated part is chosen by (``STATED_RULE``)."""
        from maljan.analysis.anti_analysis import image_of, starts_of
        from maljan.providers.static.ghidra.passes import STATED_RULE, read_findings
        from maljan.tools.errors import error_parts

        if self.call is None:
            raise DeclaredPassFailed(self.unavailable or "no scan tool is declared")
        raw = self.call()
        parts = error_parts(raw)
        if parts is not None:
            raise DeclaredPassFailed(f"{self.tool} refused the scan: {parts[1][:300]}")
        answer = answer_value(raw)
        if not isinstance(answer, dict | list):
            raise DeclaredPassFailed(f"{self.tool} answered {str(answer)[:200]!r}")
        findings = scan_findings(answer, self.facts)
        return {
            "tool": self.tool,
            "server": self.provider,
            "program": self.sample_path,
            "how": STATED_RULE,
            "total_findings": len(findings),
            "returned": len(findings),
            "notes": [],
            **read_findings(findings, image_of(host_path), starts_of(function_starts)),
            "findings": findings,
        }

    def close(self) -> None:
        return None
