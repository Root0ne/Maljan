"""Sink-reachability triage for the static analyst (Maltracker-inspired).

ISSTA'24 "Maltracker" observes that malicious behaviour concentrates in the
functions that can *reach* security-sensitive sink APIs through the call
graph. We apply the same idea to binary analysis: given a program call
graph (from Ghidra MCP ``get_full_call_graph``), we find the functions that
transitively reach a curated set of sensitive sinks, rank them by the breadth
of malicious capability they touch, and render a compact "priority functions"
hint.

The static analyst injects that hint into its prompt so it spends its limited
decompilation budget on the malicious core instead of walking the whole
function graph by hand — fewer ReAct rounds, smaller prompts.

The module is pure and deterministic: it takes the raw call-graph text and
returns a hint string. Any binary without named sink callees (e.g. a stripped,
statically linked ELF) yields an empty hint, so the analyst transparently
falls back to its normal behaviour.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

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
_FUN_ADDR_RE = re.compile(r"^FUN_0*([0-9a-fA-F]+)$")


def _normalize_api(name: str) -> str:
    """Reduce a call-graph node name to a comparable sink key.

    Strips Ghidra/PE decoration so ``KERNEL32.dll::CreateFileW``,
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


def parse_call_graph(text: str) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Parse ``CALLER -> CALLEE`` edge lines into forward and reverse adjacency.

    Returns ``(forward, reverse)`` where ``forward[caller]`` is the set of
    callees and ``reverse[callee]`` is the set of callers.
    """
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for line in text.splitlines():
        if " -> " not in line:
            continue
        caller, _, callee = line.partition(" -> ")
        caller = caller.strip()
        callee = callee.strip()
        if not caller or not callee:
            continue
        forward.setdefault(caller, set()).add(callee)
        reverse.setdefault(callee, set()).add(caller)
    return forward, reverse


@dataclass
class SuspiciousFunction:
    """A function ranked by its reachability to sensitive sink APIs."""

    name: str
    categories: set[str] = field(default_factory=set)
    sinks: set[str] = field(default_factory=set)
    distance: int = 1 << 30

    @property
    def address(self) -> str | None:
        """Return the ``0x``-prefixed address embedded in a ``FUN_xxxx`` name."""
        m = _FUN_ADDR_RE.match(self.name)
        return f"0x{m.group(1)}" if m else None

    def sort_key(self) -> tuple[int, int, int, str]:
        # More categories first, then more sinks, then closer to the sink,
        # then a stable name tiebreak.
        return (-len(self.categories), -len(self.sinks), self.distance, self.name)


def rank_suspicious_functions(
    forward: dict[str, set[str]],
    reverse: dict[str, set[str]],
    max_funcs: int = 12,
) -> list[SuspiciousFunction]:
    """Rank functions that can transitively reach a sensitive sink API.

    Performs a backward breadth-first walk from every sink node and ranks the
    ancestor functions by the breadth of sink categories they touch.
    """
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
                rec = info.setdefault(caller, SuspiciousFunction(name=caller))
                rec.categories.add(cat)
                rec.sinks.add(_normalize_api(sink))
                rec.distance = min(rec.distance, dist + 1)
                queue.append((caller, dist + 1))

    # Keep real functions (callers) that are not themselves sinks.
    ranked = [f for name, f in info.items() if name in forward and name not in sink_cats]
    ranked.sort(key=SuspiciousFunction.sort_key)
    return ranked[:max_funcs]


def build_priority_hint(call_graph_text: str, max_funcs: int = 12) -> str:
    """Render a prompt hint listing the functions nearest the malicious core.

    Returns an empty string when the call graph carries no named sink APIs
    (e.g. a stripped binary), so callers can treat ``""`` as "no guidance".
    """
    forward, reverse = parse_call_graph(call_graph_text)
    if not forward:
        return ""
    ranked = rank_suspicious_functions(forward, reverse, max_funcs=max_funcs)
    if not ranked:
        return ""

    lines = [
        "PRIORITY FUNCTIONS — these reach security-sensitive APIs via the call "
        "graph; decompile and analyse them FIRST (they form the malicious core):",
    ]
    for f in ranked:
        where = f.address or f.name
        cats = ", ".join(sorted(f.categories))
        sinks = ", ".join(sorted(f.sinks)[:4])
        lines.append(
            f"- {f.name} (@ {where}) [{cats}] -> reaches: {sinks} "
            f"({f.distance} hop{'s' if f.distance != 1 else ''})"
        )
    lines.append(
        "Use decompile_function / get_function_callees on these first. NOTE: "
        "reachable is NOT the same as data-connected — before asserting a "
        "'capability reached' claim, confirm the data path with analyze_dataflow "
        "(forward from the source, or backward from the sink argument) and "
        "classify the terminal (caller-supplied / decoded-config / fixed "
        "constant) to pick the right ATT&CK technique.\n"
    )
    return "\n".join(lines)
