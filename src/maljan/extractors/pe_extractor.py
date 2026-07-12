"""Extract the StaticAnalysis section of the report from binary bytes.

Despite the name, this module handles **PE, ELF and unknown binaries** —
the entry point is ``build_static_analysis()`` which dispatches to the right
parser based on the file's magic bytes. PE samples get the richest output
(sections, imports, exports, embedded resources); other formats currently
fall back to a strings + magic header extraction so the report still
surfaces some signal.

Suspicious flagging is rule-based (no LLM) — see ``_SUSPICIOUS_IMPORTS`` and
``_HIGH_ENTROPY_THRESHOLD``. The flags are advisory; the narrative agent
later expands on them, and the heatmap aggregates them into capability
cells.

Reuses ``maljan.loaders.pe_loader.PELoader`` for low-level parsing —
extending rather than rewriting.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import (
    ImportRow,
    PESection,
    StaticAnalysis,
    StringIOC,
)

# ---------------------------------------------------------------------------
# Heuristics — suspicious-import classifier
# ---------------------------------------------------------------------------

_HIGH_ENTROPY_THRESHOLD = 7.0
_MIN_STRING_LENGTH = 6
_MAX_STRINGS_KEPT = 200
_MAX_IOC_STRINGS = 80

# DLL→function classifier — extend rather than replace.
_SUSPICIOUS_IMPORTS: dict[str, str] = {
    # Process injection
    "VirtualAlloc": "process_injection",
    "VirtualAllocEx": "process_injection",
    "WriteProcessMemory": "process_injection",
    "CreateRemoteThread": "process_injection",
    "NtCreateThreadEx": "process_injection",
    "RtlCreateUserThread": "process_injection",
    "QueueUserAPC": "process_injection",
    "SetWindowsHookEx": "process_injection",
    # Anti-analysis / anti-debug
    "IsDebuggerPresent": "anti_debug",
    "CheckRemoteDebuggerPresent": "anti_debug",
    "NtQueryInformationProcess": "anti_debug",
    "GetTickCount": "anti_debug",
    "QueryPerformanceCounter": "anti_debug",
    "OutputDebugStringA": "anti_debug",
    # Network / C2
    "WSAStartup": "network",
    "WSASocketA": "network",
    "connect": "network",
    "InternetOpenA": "network",
    "InternetOpenUrlA": "network",
    "HttpSendRequestA": "network",
    "URLDownloadToFileA": "network",
    "WinHttpConnect": "network",
    "WinHttpOpen": "network",
    "WinHttpSendRequest": "network",
    "send": "network",
    "recv": "network",
    # Crypto
    "CryptAcquireContextA": "crypto",
    "CryptEncrypt": "crypto",
    "CryptDecrypt": "crypto",
    "BCryptEncrypt": "crypto",
    "BCryptDecrypt": "crypto",
    "CryptGenKey": "crypto",
    # File & persistence
    "CreateFileA": "filesystem",
    "WriteFile": "filesystem",
    "DeleteFileA": "filesystem",
    "MoveFileExA": "filesystem",
    "CopyFileA": "filesystem",
    "SetFileAttributesA": "filesystem",
    "RegCreateKeyExA": "registry",
    "RegSetValueExA": "registry",
    "RegOpenKeyExA": "registry",
    # Privilege / token
    "AdjustTokenPrivileges": "privilege",
    "OpenProcessToken": "privilege",
    "LookupPrivilegeValueA": "privilege",
    "ImpersonateLoggedOnUser": "privilege",
    "CreateProcessAsUserA": "privilege",
    # Execution
    "WinExec": "execution",
    "ShellExecuteA": "execution",
    "CreateProcessA": "execution",
    "LoadLibraryA": "execution",
    "GetProcAddress": "execution",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_static_analysis(
    *,
    sample_path: str | None,
) -> StaticAnalysis | None:
    """Return ``StaticAnalysis`` for ``sample_path`` or ``None`` if unreadable."""
    if not sample_path:
        return None
    path = Path(sample_path)
    if not (path.exists() and path.is_file()):
        logger.warning("pe_extractor: %s does not exist", sample_path)
        return None
    try:
        blob = path.read_bytes()
    except OSError as exc:
        logger.warning("pe_extractor: read failed (%s)", exc)
        return None

    sections: list[PESection] = []
    imports: list[ImportRow] = []
    exports: list[str] = []
    embedded: list[dict[str, Any]] = []
    packer_hint: str | None = None
    obfuscation: list[str] = []

    if blob[:2] == b"MZ":
        sections, imports, exports, embedded, packer_hint, obfuscation = _parse_pe(blob)
    elif blob[:4] == b"\x7fELF":
        sections = _parse_elf_sections(blob)
        imports = _parse_elf_imports(blob)
        exports = _parse_elf_exports(blob)

    strings = _extract_string_iocs(blob)

    if not packer_hint and any(s.entropy >= _HIGH_ENTROPY_THRESHOLD for s in sections):
        packer_hint = "high-entropy sections (possibly packed/encrypted)"

    return StaticAnalysis(
        sections=sections,
        imports=imports,
        exports=exports,
        interesting_strings=strings,
        embedded_resources=embedded,
        packer_hint=packer_hint,
        obfuscation_indicators=obfuscation,
    )


# ---------------------------------------------------------------------------
# PE parsing
# ---------------------------------------------------------------------------


def _parse_pe(
    blob: bytes,
) -> tuple[
    list[PESection],
    list[ImportRow],
    list[str],
    list[dict[str, Any]],
    str | None,
    list[str],
]:
    """Return sections, imports, exports, resources, packer_hint, obfuscation."""
    try:
        import pefile  # type: ignore[import-not-found]
    except ImportError:
        logger.warning("pe_extractor: pefile unavailable, skipping PE parse")
        return [], [], [], [], None, []

    try:
        pe = pefile.PE(data=blob, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            ]
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: PE parse failed (%s)", exc)
        return [], [], [], [], None, []

    sections = _pe_sections(pe)
    imports = _pe_imports(pe)
    exports = _pe_exports(pe)
    embedded = _pe_resources(pe)
    packer_hint = _pe_packer_hint(pe, sections)
    obfuscation = _pe_obfuscation_indicators(sections, imports)
    return sections, imports, exports, embedded, packer_hint, obfuscation


def _pe_sections(pe: Any) -> list[PESection]:
    out: list[PESection] = []
    for sect in getattr(pe, "sections", []):
        raw_name = sect.Name or b""
        try:
            name = raw_name.decode("utf-8", errors="replace").strip("\x00 ")
        except Exception:  # noqa: BLE001
            name = repr(raw_name)
        entropy = float(sect.get_entropy() or 0.0)
        char = int(getattr(sect, "Characteristics", 0))
        is_writable = bool(char & 0x80000000)
        is_executable = bool(char & 0x20000000)
        rwx = is_writable and is_executable
        out.append(
            PESection(
                name=name or "(unnamed)",
                virtual_address=f"0x{int(sect.VirtualAddress):08x}",
                virtual_size=int(sect.Misc_VirtualSize or 0),
                raw_size=int(sect.SizeOfRawData or 0),
                entropy=round(entropy, 3),
                characteristics=_format_characteristics(char),
                is_suspicious=(entropy >= _HIGH_ENTROPY_THRESHOLD or rwx),
            )
        )
    return out


def _format_characteristics(char: int) -> str:
    flags: list[str] = []
    if char & 0x20000000:
        flags.append("EXECUTE")
    if char & 0x40000000:
        flags.append("READ")
    if char & 0x80000000:
        flags.append("WRITE")
    if char & 0x00000020:
        flags.append("CODE")
    if char & 0x00000040:
        flags.append("INITIALIZED_DATA")
    if char & 0x00000080:
        flags.append("UNINITIALIZED_DATA")
    return "|".join(flags) or f"0x{char:08x}"


def _pe_imports(pe: Any) -> list[ImportRow]:
    rows: list[ImportRow] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        try:
            dll = (entry.dll or b"").decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            dll = "(unknown)"
        for imp in entry.imports or []:
            fn = (imp.name or b"").decode("utf-8", errors="replace") if imp.name else None
            if not fn:
                fn = f"Ordinal_{getattr(imp, 'ordinal', '?')}"
            category = _SUSPICIOUS_IMPORTS.get(fn)
            rows.append(
                ImportRow(
                    dll=dll,
                    function=fn,
                    is_suspicious=bool(category),
                    category=category,
                )
            )
    return rows


def _pe_exports(pe: Any) -> list[str]:
    out: list[str] = []
    export_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export_dir is None:
        return out
    for sym in getattr(export_dir, "symbols", []) or []:
        if sym.name:
            try:
                out.append(sym.name.decode("utf-8", errors="replace"))
            except Exception:  # noqa: BLE001
                continue
    return out


# Standard Win32 resource-type IDs (RT_*). 2026-07 audit (Bulgu #16): the
# report showed raw "TYPE_3 / TYPE_5" which carry no meaning; map the well-known
# ids to their symbolic names so the STATIC tab reads "RT_ICON (…)" etc.
_RT_NAMES: dict[int, str] = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    12: "RT_GROUP_CURSOR",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    17: "RT_DLGINCLUDE",
    19: "RT_PLUGPLAY",
    20: "RT_VXD",
    21: "RT_ANICURSOR",
    22: "RT_ANIICON",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _resource_type_name(resource_type: Any) -> str:
    """Human-readable resource type: custom string name, RT_* symbol, or id."""
    name_obj = getattr(resource_type, "name", None)
    if name_obj and getattr(name_obj, "string", None):
        return str(name_obj.string.decode("utf-8", errors="replace"))
    rid = getattr(resource_type, "id", None)
    if isinstance(rid, int) and rid in _RT_NAMES:
        return _RT_NAMES[rid]
    return f"TYPE_{rid if rid is not None else '?'}"


def _pe_resources(pe: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rsrc_dir = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if rsrc_dir is None:
        return out
    for resource_type in getattr(rsrc_dir, "entries", []) or []:
        type_name = _resource_type_name(resource_type)
        directory = getattr(resource_type, "directory", None)
        for resource_id in getattr(directory, "entries", []) or []:
            entry_id = (
                resource_id.name.string.decode("utf-8", errors="replace")
                if getattr(resource_id, "name", None) and resource_id.name
                else getattr(resource_id, "id", None)
            )
            sub_dir = getattr(resource_id, "directory", None)
            for lang in getattr(sub_dir, "entries", []) or []:
                data = getattr(lang, "data", None)
                if data is not None:
                    out.append(
                        {
                            "type": type_name,
                            "id": entry_id,
                            "size": int(getattr(data.struct, "Size", 0) or 0),
                        }
                    )
    return out


def _pe_packer_hint(pe: Any, sections: list[PESection]) -> str | None:
    for sect in sections:
        if sect.name.lower().startswith("upx"):
            return "UPX"
    section_names = {s.name.lower() for s in sections}
    if section_names & {".aspack", ".adata"}:
        return "ASPack"
    if section_names & {".themida", ".winlice"}:
        return "Themida"
    if section_names & {".vmp0", ".vmp1", ".vmp2"}:
        return "VMProtect"
    return None


def _pe_obfuscation_indicators(sections: list[PESection], imports: list[ImportRow]) -> list[str]:
    out: list[str] = []
    rwx = [
        s.name for s in sections if "WRITE" in s.characteristics and "EXECUTE" in s.characteristics
    ]
    if rwx:
        out.append(f"RWX sections present: {', '.join(rwx)}")
    high_entropy = [s.name for s in sections if s.entropy >= _HIGH_ENTROPY_THRESHOLD]
    if high_entropy:
        out.append(
            f"High-entropy sections (>= {_HIGH_ENTROPY_THRESHOLD}): {', '.join(high_entropy)}"
        )
    # GetProcAddress + LoadLibrary => dynamic API resolution (common evasion)
    api_resolution = {row.function for row in imports} & {
        "GetProcAddress",
        "LoadLibraryA",
        "LoadLibraryW",
    }
    if len(api_resolution) >= 2:
        out.append("Dynamic API resolution (LoadLibrary + GetProcAddress)")
    return out


# ---------------------------------------------------------------------------
# Minimal ELF section parser
# ---------------------------------------------------------------------------


def _parse_elf_sections(blob: bytes) -> list[PESection]:
    """Compute entropy per ELF section. Falls back to whole-binary stats."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
    except ImportError:
        # pyelftools is not a hard dep; report a single synthetic section so
        # the UI still shows something instead of an empty table.
        return [
            PESection(
                name="(binary)",
                virtual_address="0x0",
                virtual_size=len(blob),
                raw_size=len(blob),
                entropy=round(_shannon_entropy(blob), 3),
                characteristics="ELF",
                is_suspicious=False,
            )
        ]

    out: list[PESection] = []
    try:
        from io import BytesIO

        elf = ELFFile(BytesIO(blob))
        for section in elf.iter_sections():
            data = section.data() if section.data_size else b""
            entropy = _shannon_entropy(data) if data else 0.0
            flags = []
            sh_flags = int(getattr(section.header, "sh_flags", 0))
            if sh_flags & 0x4:
                flags.append("EXECUTE")
            if sh_flags & 0x1:
                flags.append("WRITE")
            if sh_flags & 0x2:
                flags.append("ALLOC")
            out.append(
                PESection(
                    name=section.name or "(unnamed)",
                    virtual_address=f"0x{int(section.header.sh_addr):08x}",
                    virtual_size=int(section.header.sh_size or 0),
                    raw_size=int(section.header.sh_size or 0),
                    entropy=round(entropy, 3),
                    characteristics="|".join(flags) or f"0x{sh_flags:08x}",
                    is_suspicious=(entropy >= _HIGH_ENTROPY_THRESHOLD),
                )
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: ELF parse failed (%s)", exc)
    return out


# ELF API surface that's most useful to call out for malware triage:
# native execution, anti-debug, code injection, persistence, network.
_ELF_SUSPICIOUS_FUNCTIONS: frozenset[str] = frozenset(
    {
        "execve",
        "execv",
        "execvp",
        "execvpe",
        "execl",
        "execle",
        "execlp",
        "fork",
        "vfork",
        "clone",
        "system",
        "popen",
        "ptrace",
        "syscall",
        "mmap",
        "mmap64",
        "mprotect",
        "memfd_create",
        "dlopen",
        "dlsym",
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "recv",
        "send",
        "recvfrom",
        "sendto",
        "inet_pton",
        "inet_ntop",
        "getaddrinfo",
        "gethostbyname",
        "setuid",
        "setgid",
        "seteuid",
        "setegid",
        "chroot",
        "unshare",
    }
)


def _parse_elf_imports(blob: bytes) -> list[ImportRow]:
    """Return DT_NEEDED libraries paired with undefined .dynsym symbols.

    Each ``(library, function)`` pair becomes one :class:`ImportRow`. The
    library column lists every DT_NEEDED entry once for the first import
    and then ``""`` to keep tables compact. Set ``is_suspicious=True``
    when the function name matches :data:`_ELF_SUSPICIOUS_FUNCTIONS`.
    """
    try:
        from elftools.elf.dynamic import DynamicSection  # type: ignore[import-not-found]
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
        from elftools.elf.sections import SymbolTableSection  # type: ignore[import-not-found]
    except ImportError:
        return []

    out: list[ImportRow] = []
    try:
        from io import BytesIO

        elf = ELFFile(BytesIO(blob))
        # DT_NEEDED libraries
        libraries: list[str] = []
        for section in elf.iter_sections():
            if isinstance(section, DynamicSection):
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        libraries.append(tag.needed)

        # Imported (undefined) symbols
        dynsym = elf.get_section_by_name(".dynsym")
        if not isinstance(dynsym, SymbolTableSection):
            return []
        functions: list[str] = []
        for symbol in dynsym.iter_symbols():
            if not symbol.name:
                continue
            info = symbol.entry.st_info
            if info.type != "STT_FUNC" and info.type != "STT_NOTYPE":
                continue
            # Undefined section index → imported by the dynamic linker.
            if symbol.entry.st_shndx == "SHN_UNDEF":
                functions.append(symbol.name)

        # Combine: emit each function once with its library hint, or "" if
        # we cannot map it to a specific DT_NEEDED entry.
        lib_label = libraries[0] if libraries else ""
        for fn in functions:
            out.append(
                ImportRow(
                    dll=lib_label,
                    function=fn,
                    is_suspicious=fn in _ELF_SUSPICIOUS_FUNCTIONS,
                )
            )
            lib_label = ""  # compact: only the first row shows the lib
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: ELF imports parse failed (%s)", exc)
    return out


def _parse_elf_exports(blob: bytes) -> list[str]:
    """Return defined (exported) function symbol names from .dynsym."""
    try:
        from elftools.elf.elffile import ELFFile  # type: ignore[import-not-found]
        from elftools.elf.sections import SymbolTableSection  # type: ignore[import-not-found]
    except ImportError:
        return []

    out: list[str] = []
    try:
        from io import BytesIO

        elf = ELFFile(BytesIO(blob))
        dynsym = elf.get_section_by_name(".dynsym")
        if not isinstance(dynsym, SymbolTableSection):
            return []
        for symbol in dynsym.iter_symbols():
            if not symbol.name:
                continue
            info = symbol.entry.st_info
            if info.type != "STT_FUNC":
                continue
            if symbol.entry.st_shndx != "SHN_UNDEF":
                out.append(symbol.name)
    except Exception as exc:  # noqa: BLE001
        logger.warning("pe_extractor: ELF exports parse failed (%s)", exc)
    return out


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# String / IOC extraction
# ---------------------------------------------------------------------------

_URL_RE = re.compile(rb"https?://[A-Za-z0-9._\-/?=&%:#~+]+")
_IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_REG_RE = re.compile(rb"HK(?:LM|CU|CR|U|CC)[\\\\][A-Za-z0-9_\-\\\\ ./]+")
_PATH_RE = re.compile(rb"(?:[A-Za-z]:\\\\|/)[A-Za-z0-9_\-./\\\\ ]+")
_EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(
    rb"(?<![A-Za-z0-9.])(?:[A-Za-z0-9-]{1,63}\.){1,3}[A-Za-z]{2,24}(?![A-Za-z0-9.])"
)
_MUTEX_RE = re.compile(rb"\\BaseNamedObjects\\[A-Za-z0-9_\-]+")
_PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING_LENGTH)


def _extract_string_iocs(blob: bytes) -> list[StringIOC]:
    """Scan binary strings for typed indicators of compromise."""
    iocs: list[StringIOC] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: bytes) -> None:
        try:
            decoded = value.decode("utf-8", errors="replace").strip("\x00")
        except Exception:  # noqa: BLE001
            return
        if len(decoded) < _MIN_STRING_LENGTH:
            return
        key = (kind, decoded.lower())
        if key in seen:
            return
        seen.add(key)
        if len(iocs) < _MAX_IOC_STRINGS:
            iocs.append(StringIOC(value=decoded, kind=kind))  # type: ignore[arg-type]

    for match in _URL_RE.findall(blob):
        _add("url", match)
    for match in _IP_RE.findall(blob):
        # 127.0.0.1 / 0.0.0.0 / RFC1918 filtered as noise
        ip = match.decode("ascii", errors="ignore")
        if not _is_meaningful_ip(ip):
            continue
        _add("ip", match)
    for match in _REG_RE.findall(blob):
        _add("registry", match)
    for match in _PATH_RE.findall(blob):
        _add("path", match)
    for match in _EMAIL_RE.findall(blob):
        _add("email", match)
    for match in _MUTEX_RE.findall(blob):
        _add("mutex", match)
    for match in _DOMAIN_RE.findall(blob):
        text = match.decode("ascii", errors="ignore")
        if _looks_like_domain(text):
            _add("domain", match)

    return iocs


def _is_meaningful_ip(ip: str) -> bool:
    """Heuristic filter: only keep IPs that *look like* real public hosts.

    Audit 2026-05-17 (IOC-01) tightened this from the original RFC1918 +
    loopback filter — the IPv4 regex matched a flood of false positives
    on Go binaries (X.509 ASN.1 OIDs ``2.5.4.62``, the well-known
    ``1.1.1.1`` test constant, etc.). The full picture:

    * Reject any octet > 255 (already enforced).
    * Reject the canonical reserved blocks (loopback, broadcast,
      RFC1918, link-local, multicast, documentation, IETF reserved).
    * Reject ``1.x.x.x`` — Cloudflare's 1.1.1.1 / 1.0.0.1 are real, but
      every Go runtime + IETF doc string also pulls ``1.1.1.1`` /
      ``1.2.3.4`` out, so we drop the whole /8 rather than chase
      false-positives one at a time. Operators who *really* need to
      keep public 1.x.x.x can disable this filter at the caller.
    * Reject any IP whose first octet is in 0..5 — overlaps with X.509
      OID prefixes (``2.5.4.X``, ``5.4.X.X``) and reserved IETF blocks.
    """
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False

    a, b, c, d = nums

    # X.509 OID overlap + IETF reserved ranges
    if a <= 5:
        return False
    # RFC1122 loopback
    if a == 127:
        return False
    # RFC1918 private
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    # RFC3927 link-local
    if a == 169 and b == 254:
        return False
    # RFC5737 documentation blocks
    if (
        (a == 192 and b == 0 and c == 2)
        or (a == 198 and b == 51 and c == 100)
        or (a == 203 and b == 0 and c == 113)
    ):
        return False
    # Multicast + reserved
    if a >= 224:
        return False
    # Limited broadcast
    if a == 255 and b == 255 and c == 255 and d == 255:
        return False
    return True


_NON_DOMAIN_SUFFIXES: tuple[str, ...] = (
    # Native binaries
    ".exe",
    ".dll",
    ".sys",
    ".so",
    ".dylib",
    # Source / scripts
    ".py",
    ".js",
    ".c",
    ".h",
    ".cpp",
    ".cxx",
    ".cc",
    ".hpp",
    ".java",
    # Bundled bytecode / archive build artefacts that otherwise surface as
    # bogus DOMAIN matches (resources.arsc, classes.dex, etc.) — deny them.
    ".apk",
    ".aab",
    ".arsc",
    ".dex",
    ".smali",
    ".kotlin_module",
    # Bundled assets shipped inside archives
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".xml",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".html",
    ".htm",
    ".css",
    ".txt",
    ".md",
    ".csv",
    # Java / .NET / Office formats
    ".jar",
    ".class",
    ".war",
    ".ear",
    ".docx",
    ".xlsx",
    ".pptx",
    ".doc",
    ".xls",
    ".ppt",
    ".pdf",
)


def _looks_like_domain(text: str) -> bool:
    """Filter out obvious non-domain matches (filenames, version strings)."""
    if text.startswith(".") or text.endswith("."):
        return False
    lower = text.lower()
    if any(lower.endswith(suffix) for suffix in _NON_DOMAIN_SUFFIXES):
        return False
    if text.count(".") > 4:
        return False
    if len(text) < 5:
        return False
    return True
