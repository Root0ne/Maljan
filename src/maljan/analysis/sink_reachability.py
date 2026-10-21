"""Sink-reachability triage for the static analysts (Maltracker-inspired).

ISSTA'24 "Maltracker" observes that malicious behaviour concentrates in the
functions that can *reach* security-sensitive sink APIs through the call
graph. We apply the same idea to binary analysis: given a program's call graph
(:class:`CallGraph`, the neutral shape any static provider turns its own call
graph into through ``StaticProvider.call_graph``), we find the functions that
transitively reach a curated set of sensitive sinks, rank them by the breadth
of malicious capability they touch, and render a compact "priority functions"
hint.

An analyst injects that hint into its prompt so it spends its limited
decompilation budget on the malicious core instead of walking the whole
function graph by hand — fewer ReAct rounds, smaller prompts.

The module is pure and deterministic: it takes a call graph and returns a
ranking and a hint string. Any binary without named sink callees (e.g. a
stripped, statically linked ELF) yields an empty hint, so the analyst
transparently falls back to its normal behaviour.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from maljan.utils.written_forms import hint_escaped

# ---------------------------------------------------------------------------
# Sensitive sink catalogue: normalized-API-name -> capability category.
# Names are stored lowercase and WITHOUT the trailing A/W charset suffix; the
# normaliser strips module prefixes, thunk_/imp_ wrappers, stdcall @N suffixes,
# Zw->Nt aliasing, and a trailing A/W so callers match these keys.
# ---------------------------------------------------------------------------
SENSITIVE_SINKS: dict[str, str] = {
    # --- code injection / process manipulation ---
    "virtualallocex": "injection",
    "virtualprotectex": "injection",
    "ntprotectvirtualmemory": "injection",
    "writeprocessmemory": "injection",
    "ntwritevirtualmemory": "injection",
    "createremotethread": "injection",
    "createremotethreadex": "injection",
    "ntcreatethreadex": "injection",
    "rtlcreateuserthread": "injection",
    "queueuserapc": "injection",
    "ntqueueapcthread": "injection",
    "setthreadcontext": "injection",
    "ntsetcontextthread": "injection",
    "ntmapviewofsection": "injection",
    "ntunmapviewofsection": "injection",
    "mapviewoffile": "injection",
    # --- process / command execution ---
    "createprocess": "exec",
    "createprocessinternal": "exec",
    "createprocessasuser": "exec",
    "shellexecute": "exec",
    "shellexecuteex": "exec",
    "winexec": "exec",
    "system": "exec",
    "popen": "exec",
    "execve": "exec",
    "execl": "exec",
    "execlp": "exec",
    "execvp": "exec",
    "posix_spawn": "exec",
    # --- network / C2 ---
    "socket": "network",
    "connect": "network",
    "send": "network",
    "recv": "network",
    "sendto": "network",
    "recvfrom": "network",
    "bind": "network",
    "listen": "network",
    "accept": "network",
    "wsastartup": "network",
    "wsasocket": "network",
    "getaddrinfo": "network",
    "gethostbyname": "network",
    "inet_addr": "network",
    "internetopen": "network",
    "internetconnect": "network",
    "internetopenurl": "network",
    "httpopenrequest": "network",
    "httpsendrequest": "network",
    "winhttpopen": "network",
    "winhttpconnect": "network",
    "winhttpsendrequest": "network",
    "urldownloadtofile": "network",
    "curl_easy_perform": "network",
    # --- cryptography (ransomware / packing) ---
    "cryptencrypt": "crypto",
    "cryptdecrypt": "crypto",
    "cryptacquirecontext": "crypto",
    "cryptgenkey": "crypto",
    "cryptderivekey": "crypto",
    "bcryptencrypt": "crypto",
    "bcryptdecrypt": "crypto",
    "evp_encryptinit": "crypto",
    "evp_decryptinit": "crypto",
    # --- persistence ---
    "regsetvalue": "persistence",
    "regsetvalueex": "persistence",
    "regcreatekey": "persistence",
    "regcreatekeyex": "persistence",
    "ntsetvaluekey": "persistence",  # Zw* is folded onto Nt* by _normalize_api
    "ntcreatekey": "persistence",
    "createservice": "persistence",
    "openscmanager": "persistence",
    "startservice": "persistence",
    "setwindowshookex": "persistence",
    # --- dynamic API resolution / loaders ---
    "loadlibrary": "loader",
    "loadlibraryex": "loader",
    "getprocaddress": "loader",
    "ldrloaddll": "loader",
    "ldrgetprocedureaddress": "loader",
    # --- anti-analysis / evasion ---
    "isdebuggerpresent": "anti-analysis",
    "checkremotedebuggerpresent": "anti-analysis",
    "ntqueryinformationprocess": "anti-analysis",
    "outputdebugstring": "anti-analysis",
    "ntsetinformationthread": "anti-analysis",
    "blockinput": "anti-analysis",
    "ptrace": "anti-analysis",
    # --- discovery ---
    "createtoolhelp32snapshot": "discovery",
    "process32first": "discovery",
    "process32next": "discovery",
    "enumprocesses": "discovery",
    "getcomputername": "discovery",
    # --- credential access ---
    "openprocesstoken": "credential",
    "adjusttokenprivileges": "credential",
    "lookupprivilegevalue": "credential",
    "lsaretrieveprivatedata": "credential",
    "credenumerate": "credential",
}

_STDCALL_SUFFIX_RE = re.compile(r"@\d+$")


def _normalize_api(name: str) -> str:
    """Reduce a call-graph node name to a comparable sink key.

    Strips module and PE import decoration so ``KERNEL32.dll::CreateFileW``,
    ``thunk_CreateFileA``, ``__imp__WinExec@4`` and ``ZwWriteVirtualMemory``
    all collapse onto a catalogue key.
    """
    n = name.strip()
    if "::" in n:  # drop module/namespace prefix
        n = n.rsplit("::", 1)[-1]
    n = n.lstrip("_")
    for prefix in ("imp_", "thunk_"):
        if n.lower().startswith(prefix):
            n = n[len(prefix) :].lstrip("_")
    n = _STDCALL_SUFFIX_RE.sub("", n)
    n = n.lower()
    if n.startswith("zw"):  # Zw* and Nt* are the same native call
        n = "nt" + n[2:]
    return n


def _sink_category(name: str) -> str | None:
    """Return the sink category for a node name, or None if it is not a sink."""
    norm = _normalize_api(name)
    cat = SENSITIVE_SINKS.get(norm)
    if cat is not None:
        return cat
    # Tolerate the ANSI/Unicode charset suffix (CreateFileA -> createfile).
    if norm and norm[-1] in ("a", "w"):
        return SENSITIVE_SINKS.get(norm[:-1])
    return None


@dataclass(frozen=True)
class CallGraph:
    """A program's call graph, as any static provider reads it.

    ``callees`` maps each calling function to the functions and APIs it calls,
    by the names the provider gives them. ``addresses`` maps a function's name
    to its address (``0x``-prefixed) where the provider knows it; a function
    with none is named by its name alone.
    """

    callees: Mapping[str, frozenset[str]]
    addresses: Mapping[str, str] = field(default_factory=dict)

    @classmethod
    def of_edges(
        cls, edges: Iterable[tuple[str, str]], addresses: Mapping[str, str] | None = None
    ) -> CallGraph:
        """The graph of ``(caller, callee)`` pairs; an empty name on either side is left out."""
        callees: dict[str, set[str]] = {}
        for caller, callee in edges:
            caller, callee = str(caller).strip(), str(callee).strip()
            if caller and callee:
                callees.setdefault(caller, set()).add(callee)
        return cls(
            callees={k: frozenset(v) for k, v in callees.items()},
            addresses=dict(addresses or {}),
        )

    def adjacency(self) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
        """``(forward, reverse)``: each caller's callees, and each callee's callers."""
        forward: dict[str, set[str]] = {k: set(v) for k, v in self.callees.items()}
        reverse: dict[str, set[str]] = {}
        for caller, callees in forward.items():
            for callee in callees:
                reverse.setdefault(callee, set()).add(caller)
        return forward, reverse


@dataclass
class SuspiciousFunction:
    """A function ranked by its reachability to sensitive sink APIs."""

    name: str
    categories: set[str] = field(default_factory=set)
    sinks: set[str] = field(default_factory=set)
    distance: int = 1 << 30
    # Where the function stands, as the call graph gives it; ``None`` unknown.
    address: str | None = None

    def sort_key(self) -> tuple[int, int, int, str]:
        # More categories first, then more sinks, then closer to the sink,
        # then a stable name tiebreak.
        return (-len(self.categories), -len(self.sinks), self.distance, self.name)


def rank_suspicious_functions(graph: CallGraph, max_funcs: int = 12) -> list[SuspiciousFunction]:
    """Rank functions that can transitively reach a sensitive sink API.

    Performs a backward breadth-first walk from every sink node and ranks the
    ancestor functions by the breadth of sink categories they touch.
    """
    forward, reverse = graph.adjacency()
    nodes = set(forward) | set(reverse)
    sink_cats: dict[str, str] = {}
    for node in nodes:
        cat = _sink_category(node)
        if cat is not None:
            sink_cats[node] = cat

    info: dict[str, SuspiciousFunction] = {}
    for sink, cat in sink_cats.items():
        seen = {sink}
        queue: deque[tuple[str, int]] = deque([(sink, 0)])
        while queue:
            node, dist = queue.popleft()
            for caller in reverse.get(node, ()):
                if caller in seen:
                    continue
                seen.add(caller)
                rec = info.setdefault(
                    caller, SuspiciousFunction(name=caller, address=graph.addresses.get(caller))
                )
                rec.categories.add(cat)
                rec.sinks.add(_normalize_api(sink))
                rec.distance = min(rec.distance, dist + 1)
                queue.append((caller, dist + 1))

    # Keep real functions (callers) that are not themselves sinks.
    ranked = [f for name, f in info.items() if name in forward and name not in sink_cats]
    ranked.sort(key=SuspiciousFunction.sort_key)
    return ranked[:max_funcs]


# The clause of a priority follow-up that points the reading at a technique.
# Its own constant so an agent whose definition turns the technique line off
# (``AgentDefinition.attck_techniques``) is sent the follow-up without it.
ATTCK_PURPOSE = " to pick the right ATT&CK technique"

# What to do with the priority functions, in no provider's tools' words: the
# sentence a provider that names none of its own (``priority_follow_up``) gets.
FOLLOW_UP = (
    "Read these functions first with the tools in your tool list. NOTE: reachable is NOT "
    "the same as data-connected — before asserting a 'capability reached' claim, confirm "
    "the data path (forward from the source, or backward from the sink argument) and "
    "classify the terminal (caller-supplied / decoded-config / fixed constant)"
    + ATTCK_PURPOSE
    + ".\n"
)


def _in_data_form(name: str) -> str:
    """A sample-controlled name in the pack's data form: control characters escaped."""
    return hint_escaped(str(name))


def priority_hint(ranked: list[SuspiciousFunction], follow_up: str = FOLLOW_UP) -> str:
    """Render a prompt hint listing the ranked functions, then ``follow_up``.

    Returns an empty string for no function, so callers can treat ``""`` as
    "no guidance".
    """
    if not ranked:
        return ""
    lines = [
        "PRIORITY FUNCTIONS — these reach security-sensitive APIs via the call "
        "graph; decompile and analyse them FIRST (they form the malicious core):",
    ]
    for f in ranked:
        # Names come from the sample's symbol table; each is quoted in the
        # pack's data form so none can end its line or pose as an instruction.
        where = _in_data_form(f.address or f.name)
        cats = ", ".join(sorted(f.categories))
        sinks = ", ".join(_in_data_form(s) for s in sorted(f.sinks)[:4])
        lines.append(
            f"- {_in_data_form(f.name)} (@ {where}) [{cats}] -> reaches: {sinks} "
            f"({f.distance} hop{'s' if f.distance != 1 else ''})"
        )
    lines.append(follow_up)
    return "\n".join(lines)


def build_priority_hint(graph: CallGraph, max_funcs: int = 12, follow_up: str = FOLLOW_UP) -> str:
    """The hint for ``graph``'s functions nearest the malicious core; ``""`` with none.

    Empty when the call graph carries no named sink APIs (e.g. a stripped
    binary).
    """
    return priority_hint(rank_suspicious_functions(graph, max_funcs=max_funcs), follow_up)
