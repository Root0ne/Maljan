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
FINDINGS_BLOCK_FRAGMENT = (
    "\n\nAfter your findings, you may append one fenced block labelled "
    "maljan-findings containing JSON with two optional keys.\n"
    '"artifacts" is a list of the concrete things you established — hashes, '
    "imports, permissions, IOCs, processes, persistence entries, network "
    "endpoints. Each has a kind, a label, either a value or columns plus rows, "
    "and evidence_ids naming the tool results you read them from.\n"
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
