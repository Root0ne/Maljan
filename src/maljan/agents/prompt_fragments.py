"""The paragraph that tells an analyst what this sample's format looks like.

Every built-in analyst prompt used to name Windows artefacts in its constant
text — registry keys, ``HKLM\\...\\Run``, ``cmd.exe`` — which is the right
instruction for a PE and a misleading one for everything else. An analyst told
to cite a registry key for an APK either invents one or reports nothing.

So the platform-specific half moves here, and the constants keep only what is
true of every sample. One short paragraph is inserted between an analyst's own
head and its provider fragment, naming the artefacts that actually exist on the
sample in front of it. A format nobody has written a paragraph for gets the
neutral default, which asks for concrete artefacts without naming any OS.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

# Keyed by platform, since the artefacts follow the operating system rather
# than the container the code arrived in: a DEX and an APK look for the same
# things. ``file_type`` refines this below where the format matters more than
# the platform (a document, a script).
_BY_PLATFORM: dict[str, str] = {
    "windows": (
        "This sample targets Windows. Look for registry keys and Run/RunOnce "
        "autostart entries, services and drivers, scheduled tasks, DLLs loaded "
        "or side-loaded, WinAPI calls (process and memory APIs, CreateProcess, "
        "the crypto and network APIs), mutexes, and command lines spawned "
        "through cmd.exe, PowerShell or WMI."
    ),
    "linux": (
        "This sample targets Linux. Look for ELF sections and imported "
        "symbols, systemd units, cron and rc scripts, dotfile and profile "
        "modification, syscalls (execve, ptrace, mount, socket), shared "
        "objects loaded or preloaded through LD_PRELOAD, file permissions and "
        "setuid bits, and shell command lines."
    ),
    "macos": (
        "This sample targets macOS. Look for Mach-O load commands and linked "
        "dylibs, launchd agents and daemons and their plists, entitlements and "
        "code-signing status, dyld insertion, TCC and keychain access, "
        "AppleScript or osascript execution, and login items."
    ),
    "android": (
        "This sample targets Android. Look for the manifest's declared "
        "permissions, exported activities, services and broadcast receivers, "
        "the DEX classes and methods that carry the logic, reflection and "
        "dynamic class loading, bundled native libraries, accessibility and "
        "device-admin requests, and the URLs and endpoints the app contacts."
    ),
    "ios": (
        "This sample targets iOS. Look for the bundle's Info.plist and its "
        "declared URL schemes and background modes, entitlements and "
        "provisioning profile, linked frameworks and dylibs, Objective-C or "
        "Swift class and selector names, and keychain access."
    ),
    "multi": (
        "This sample is not bound to one operating system. Name the platform "
        "each artefact belongs to as you cite it, and do not assume Windows "
        "behaviour for an artefact that could come from any host."
    ),
}

# Where the format says more than the platform does.
_BY_FILE_TYPE: dict[str, str] = {
    "ole2": (
        "This sample is an OLE2 document. Look for VBA macro streams and their "
        "auto-execution entry points, embedded and linked objects, external "
        "relationships and remote templates, and the process the macro "
        "ultimately launches."
    ),
    "ooxml": (
        "This sample is an Office Open XML document. Look for the macro "
        "streams and their auto-execution entry points, the relationship "
        "targets that fetch remote content, embedded objects and DDE fields, "
        "and the process the document ultimately launches."
    ),
    "pdf": (
        "This sample is a PDF. Look for JavaScript and OpenAction entries, "
        "embedded files and launch actions, URIs, and object streams whose "
        "filters hide the payload."
    ),
    "jar": (
        "This sample is a Java archive. Look for the manifest's main class, "
        "the classes that carry the logic, reflection and dynamic class "
        "loading, and the endpoints it contacts. It runs on any host with a "
        "JVM, so name the platform an artefact belongs to as you cite it."
    ),
}

_SCRIPT_FRAGMENT = (
    "This sample is a script, so the payload is the text itself. Work through "
    "each layer of obfuscation and decoding in order — string concatenation "
    "and character arithmetic, base64 and hex blobs, compression, "
    "Invoke-Expression or eval — and cite what each stage decodes to, not only "
    "that a stage exists. Name the commands and the endpoints the final stage "
    "reaches."
)

_ARCHIVE_FRAGMENT = (
    "This sample is an archive: the evidence is what it carries. Name the "
    "entries, their types and their sizes, flag anything double-extensioned, "
    "password-protected or oversized once expanded, and say plainly when the "
    "contents could not be read."
)

_NEUTRAL = (
    "The sample's format was not identified, so assume nothing about the "
    "operating system it targets. Cite concrete artefacts from the data in "
    "front of you — strings, byte offsets, endpoints, command lines — and say "
    "which of them are absent rather than reporting on artefacts a different "
    "platform would have."
)


def format_fragment(file_type: str, platform: str) -> str:
    """The artefact paragraph for one sample's format, never empty.

    The file type wins where it says more than the platform does — a macro
    document, a script and an archive each need their own instruction whatever
    host they land on — and the platform answers for everything else.
    """
    from maljan.extractors.sample_identity import file_type_category

    ft = (file_type or "").strip().lower()
    plat = (platform or "").strip().lower()

    specific = _BY_FILE_TYPE.get(ft)
    if specific:
        return specific
    category = file_type_category(ft)
    if category == "script":
        by_platform = _BY_PLATFORM.get(plat)
        return f"{_SCRIPT_FRAGMENT} {by_platform}" if by_platform else _SCRIPT_FRAGMENT
    if category == "archive":
        return _ARCHIVE_FRAGMENT
    return _BY_PLATFORM.get(plat, _NEUTRAL)


# The optional machine channel. Every tool result an analyst reads arrives
# prefixed with its ledger id, and this is what turns those ids into something
# the report can print: the analyst repeats the key artefacts it established
# and names the calls it read them from.
#
# Optional in both directions. An analyst that emits nothing here loses no
# claim and fails no check — the ISR contract above is unchanged and remains
# the only thing the negotiation runs on. What it loses is the table: the
# report can only print an import list, a permission set or an endpoint list
# if some analyst says it saw one.
# How an analyst keeps a network value as an indicator. The platform publishes
# a sandbox address the sample's tree did not make only when a model keeps it,
# and reads the artifact tolerantly; this is the shape it asks for.
ENDPOINTS_ROW_SHAPE = (
    "A network endpoint you hold to be the sample's infrastructure is an artifact of "
    'kind "endpoints" whose rows are ["ip", address], ["domain", name] or ["url", url]; '
    "an address or a name you only mention in a claim is not kept as an indicator."
)

FINDINGS_BLOCK_FRAGMENT = (
    "\n\nAfter your findings, you may append one fenced block labelled "
    "maljan-findings containing JSON with two optional keys.\n"
    '"artifacts" is a list of the concrete things you established — hashes, '
    "imports, permissions, IOCs, processes, persistence entries, network "
    "endpoints. Each has a kind, a label, either a value or columns plus rows, "
    "and evidence_ids naming the tool results you read them from. " + ENDPOINTS_ROW_SHAPE + "\n"
    '"findings" is a list of your conclusions: a title, a detail, optional '
    "technique_ids, a confidence between 0 and 1, and evidence_ids.\n"
    "Every tool result you were shown starts with its id in brackets, for "
    "example [ev_0007]; cite those ids and no others. Emit the block only for "
    "what you actually observed, and omit it entirely when you have nothing "
    "structured to add.\n"
    "```maljan-findings\n"
    '{"artifacts": [{"kind": "imports", "label": "Suspicious imports", '
    '"columns": ["Library", "Function"], "rows": [["KERNEL32.dll", '
    '"VirtualAllocEx"]], "evidence_ids": ["ev_0002"]}], '
    '"findings": [{"title": "Allocates memory in a remote process", '
    '"technique_ids": ["T1055"], "confidence": 0.8, '
    '"evidence_ids": ["ev_0002"]}]}\n'
    "```"
)


# The shape every analyst's claims are parsed from, and the one place it is
# written. It asks for the ledger id in the evidence line because that is what
# the run can check: a claim whose technique cites a tool result is a claim
# somebody can follow, and a technique with nothing behind it is what put
# sixteen speculative ids in front of a judge on a signed binary.
#
# Each tool result the analyst is shown opens with its id in brackets, so the
# id is in front of the model when it writes the line.
CLAIM_FORMAT_FRAGMENT = (
    "Format each finding as:\n"
    "CLAIM: <claim text>\n"
    "EVIDENCE: <artifact reference, naming the tool result you read it from, "
    "for example [ev_0002]>\n"
    "CONFIDENCE: <float>\n"
    "TECHNIQUE: <T-ID or NONE>\n"
    "---\n"
)


# The one sentence an analyst holding a reputation tool needs. A live run bound
# VirusTotal to the judge, the judge only opened its tool loop on dissent, and
# the whole analysis ran without anyone asking who the sample was: 19 ledger
# entries, none of them a reputation lookup, and a family of None.
#
# The second half is the load-bearing half. A detection ratio is one source
# among the run's own, and an analyst that reads it as the answer has stopped
# analysing -- which is the failure mode a reputation tool invites.
REPUTATION_LOOKUP_FRAGMENT = (
    "\n\nWhen a reputation tool is among your tools, look the sample's hash up once, "
    "cite what comes back with its evidence id like any other tool result, and weigh "
    "it as one source: a reputation label is not the verdict, and an unknown hash is "
    "not a clean sample."
)


# What an agent is told about its tools, built from the list its request
# carries rather than written into any role's or provider's text. A live run
# sent the static analyst 36 tools under a provider fragment that said it had
# none; the model believed the fragment, answered in one turn and called
# nothing. Every statement about tools a prompt makes comes from here, so it
# can only say what the list says.
#
# The families are where the tools came from: a registry server by its key,
# the team's ``ask_<agent>`` tools, the sandbox report's tools, and the tools
# of the provider the role attaches itself (Ghidra, radare2, a sandbox's own
# server), which carry no server key of their own.
TEAM_FAMILY = "team"
SANDBOX_FAMILY = "sandbox"
PROVIDER_FAMILY = "provider"

NO_TOOLS_STATEMENT = (
    "No tools are attached to this request, so answer from the evidence in front of "
    "you. Do not describe tool calls you did not make, and do not claim the analysis "
    "was impossible: the evidence you are given is real."
)


# Where an in-process tool says it came from: ``provider`` for the tools a
# role's own provider attached, ``sandbox`` for the sandbox report's. A
# registry server's tools carry their server key instead, and the team's
# ``ask_`` tools carry ``team`` there.
SOURCE_METADATA_KEY = "maljan_source"


def stamp_source(tools: Sequence[Any], source: str) -> list[Any]:
    """``tools``, each marked as coming from ``source``, so its family is read, not guessed.

    A tool that cannot be copied is kept as it is; its family is then inferred.
    """
    out: list[Any] = []
    for tool in tools:
        copy = getattr(tool, "model_copy", None)
        if not callable(copy):
            out.append(tool)
            continue
        metadata = {**(getattr(tool, "metadata", None) or {}), SOURCE_METADATA_KEY: source}
        try:
            out.append(copy(update={"metadata": metadata}))
        except Exception:  # noqa: BLE001 — a mark is never worth a tool
            out.append(tool)
    return out


def tool_family(tool: object) -> str:
    """The family one tool belongs to: its server key, or its in-process source.

    A tool that carries neither is inferred from its name, the way the sandbox
    report's tools are named, and is otherwise a provider's.
    """
    from maljan.agents.tool_pinning import server_of

    server = server_of(tool)
    if server:
        return server
    source = str((getattr(tool, "metadata", None) or {}).get(SOURCE_METADATA_KEY, "") or "")
    if source in (SANDBOX_FAMILY, PROVIDER_FAMILY):
        return source
    if str(getattr(tool, "name", "")).startswith("sandbox_"):
        return SANDBOX_FAMILY
    return PROVIDER_FAMILY


def offered(tools: Sequence[Any]) -> list[Any]:
    """The tools a loop binds: the list without the delivery tools.

    The ``put_sample*`` tools are how the platform hands a remote server the
    sample, and ``tool_pinning.pin_paths`` keeps them from the model; a
    sentence built from a list that still held them would name a server none
    of whose tools the request carries.
    """
    from maljan.agents.tool_pinning import DELIVERY_TOOLS

    return [tool for tool in tools if str(getattr(tool, "name", "")) not in DELIVERY_TOOLS]


def tool_families(tools: Sequence[object]) -> list[str]:
    """Every family in ``tools``, in the order the list first names it."""
    return list(dict.fromkeys(tool_family(tool) for tool in offered(tools)))


def _family_label(family: str, provider_label: str) -> str:
    if family == TEAM_FAMILY:
        return "your team's other agents (one `ask_<agent>` tool each)"
    if family == SANDBOX_FAMILY:
        return "the job's sandbox report"
    if family == PROVIDER_FAMILY:
        return provider_label or "the provider attached to this role"
    return f"the `{family}` server"


def tools_statement(
    tools: Sequence[object], *, provider_label: str = "", provider_expected: bool = False
) -> str:
    """The one sentence about tools a prompt carries, true of ``tools``.

    ``provider_expected`` is for a prompt resolved before the role attaches its
    own provider — the settings probe and the resolved prompt of a built-in
    role. It names the provider's family without counting tools nobody has
    listed yet; the prompt the role sends is built again from the list it
    sends, where the provider's tools are present or the sentence says nothing
    of them.
    """
    families = tool_families(tools)
    if provider_expected and PROVIDER_FAMILY not in families:
        families.insert(0, PROVIDER_FAMILY)
    if not families:
        return NO_TOOLS_STATEMENT
    named = [_family_label(family, provider_label) for family in families]
    joined = named[0] if len(named) == 1 else ", ".join(named[:-1]) + " and " + named[-1]
    return (
        f"The tools attached to this request come from {joined}; their names and "
        "arguments are listed with the request. Call them where the evidence in front "
        "of you leaves a question open or a claim needs checking, and cite each result "
        "by the evidence id it carries."
    )


def has_decompiler(tools: Sequence[object]) -> bool:
    """Whether any tool in ``tools`` decompiles, by the name it is offered under."""
    return any("decompile" in name.lower() for name in tool_names(tools))


def has_xrefs(tools: Sequence[object]) -> bool:
    """Whether any tool in ``tools`` reads cross-references, by the name it is offered under."""
    return any("xref" in name.lower() for name in tool_names(tools))


def tool_names(tools: Sequence[object]) -> frozenset[str]:
    """The names ``tools`` are offered under."""
    return frozenset(str(getattr(tool, "name", "")) for tool in offered(tools))


# What a turn that can call no tool says in place of the loop's sentence. The
# final-answer nudge and the forced synthesis resend the loop's conversation,
# system turn included, with no tool callable; the sentence that described the
# loop's tools is replaced so the system turn agrees with the turn's own words.
TOOL_FREE_TURN_STATEMENT = (
    "No tool can be called in this turn, so answer from the evidence and the tool "
    "results already in front of you."
)

_TOOLS_STATEMENT_RE = re.compile(
    re.escape("The tools attached to this request come from")
    + r".*?"
    + re.escape("cite each result by the evidence id it carries."),
    re.DOTALL,
)


def for_a_tool_free_turn(system_text: str) -> str:
    """``system_text`` with its sentence about tools replaced by ``TOOL_FREE_TURN_STATEMENT``.

    A text with no such sentence — a stand-in, an operator's prompt from
    before the sentence existed — is returned as it is.
    """
    text = _TOOLS_STATEMENT_RE.sub(TOOL_FREE_TURN_STATEMENT, system_text, count=1)
    return text.replace(NO_TOOLS_STATEMENT, TOOL_FREE_TURN_STATEMENT)
