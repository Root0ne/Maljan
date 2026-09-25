"""The evidence ledger, projected back into the report's typed blocks.

``MalwareReport.static``, ``.dynamic``, ``.network`` and ``.persistence`` are
shapes several layers still read — the import-capability layer wants
``static.imports``, the DGA scorer wants ``network.domains``, the Sigma
generator wants persistence entries. Those layers used to be fed by extractors
that re-parsed the sample and the sandbox report inside the report builder,
which is exactly the arrangement that made a report say things no agent had
observed.

So the blocks stay and their source changes: they are filled from what the
tools returned and what the agents established, and from nothing else. A tool
that was never called leaves its block empty, and every layer downstream of an
empty block degrades to silence rather than inventing a substitute.

Nothing here parses a file or a report. It reads ``LedgerEntry.structured`` and
``AgentISR.artifacts``, and the one thing it computes itself is the sample's
own hashes — the routing minimum a report needs even when no agent thought to
ask for them.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from maljan.analysis.technique_ids import api_capability_hits, sigma_technique_ids
from maljan.core.logger import logger
from maljan.reporting.models import (
    DynamicBehavior,
    ExportRow,
    FileHashes,
    ImportRow,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    PersistenceMechanism,
    PESection,
    ProcessNode,
    RegistryMod,
    SampleIdentity,
    SandboxSignature,
    SignatureInfo,
    StaticAnalysis,
    StringIOC,
)
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.schemas.sandbox_report import SAMPLE_TREE_KEY

if TYPE_CHECKING:
    from maljan.schemas.evidence import LedgerEntry
    from maljan.schemas.isr_models import AgentISR

# The identity tools, in the order their answers should win: a hash the sample
# was actually hashed for beats one a format tool reported in passing.
_IDENTITY_TOOLS = ("identify_file", "hashes", "signing_info")

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_STRING_KINDS = {
    "url",
    "ip",
    "registry",
    "path",
    "mutex",
    "domain",
    "email",
    "command",
    "secret",
    "crypto_wallet",
    "other",
}

# What an artifact's ``kind`` has to say to be read as persistence, and the
# typed kind it becomes. Anything else an analyst calls persistence lands as
# ``other``, which is a real answer rather than a dropped row.
_PERSISTENCE_KINDS = {
    "registry_run",
    "scheduled_task",
    "service",
    "wmi_subscription",
    "com_hijacking",
    "startup_folder",
    "dll_search_hijacking",
    "driver",
    "image_hijack",
    "appinit_dll",
    "lsa_provider",
    "winlogon_helper",
    "systemd_service",
    "systemd_timer",
    "cron_job",
    "init_d",
    "rc_local",
    "ld_preload",
    "xdg_autostart",
    "other",
}


def _payloads(ledger: list[LedgerEntry], *tools: str) -> list[tuple[LedgerEntry, dict[str, Any]]]:
    """Every successful call of ``tools`` whose answer was a JSON object."""
    out: list[tuple[LedgerEntry, dict[str, Any]]] = []
    for entry in ledger or []:
        if entry.tool not in tools or not entry.ok:
            continue
        data = entry.structured
        if isinstance(data, dict) and not data.get("error"):
            out.append((entry, data))
    return out


def _artifacts(isrs: dict[str, AgentISR] | None, *kinds: str) -> list[Any]:
    """Every agent artifact whose ``kind`` is one of ``kinds``."""
    wanted = {k.lower() for k in kinds}
    out: list[Any] = []
    for isr in (isrs or {}).values():
        for artifact in getattr(isr, "artifacts", None) or []:
            if str(getattr(artifact, "kind", "")).lower() in wanted:
                out.append(artifact)
    return out


def _rows_of(artifact: Any) -> list[list[str]]:
    rows = getattr(artifact, "rows", None) or []
    return [[str(cell) for cell in row] for row in rows if isinstance(row, list | tuple)]


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def identity_from_ledger(
    ledger: list[LedgerEntry],
    *,
    sample_path: str | None,
    file_name: str | None,
    file_hash: str | None,
    file_type: str,
    platform: str,
) -> SampleIdentity:
    """The sample's identity, from the identity tools where they ran.

    Where they did not, the routing minimum stands in: the format and platform
    the pipeline routed on, the hashes computed here, and the file's own name
    and size. A report with no identity block is not an option — every consumer
    keys on the sha256 — so this is the one place the builder still reads the
    file itself.
    """
    facts: dict[str, Any] = {}
    for _entry, data in _payloads(ledger, *_IDENTITY_TOOLS):
        for key, value in data.items():
            if value not in (None, "", [], {}):
                facts.setdefault(key, value)

    computed = _hashes_of(sample_path)
    hashes = FileHashes(
        sha256=str(facts.get("sha256") or computed.get("sha256") or file_hash or ""),
        md5=str(facts.get("md5") or computed.get("md5") or ""),
        sha1=str(facts.get("sha1") or computed.get("sha1") or ""),
        imphash=_opt(facts.get("imphash")),
        ssdeep=_opt(facts.get("ssdeep")),
        tlsh=_opt(facts.get("tlsh")),
    )

    size = int(facts.get("size") or computed.get("size") or 0)
    header = _header_facts(ledger)
    return SampleIdentity(
        hashes=hashes,
        file_name=file_name or (Path(sample_path).name if sample_path else None),
        file_size_bytes=size,
        file_type=str(facts.get("file_type") or file_type or "unknown"),
        platform=str(facts.get("platform") or platform or "unknown"),  # type: ignore[arg-type]
        mime_type=_opt(facts.get("mime")),
        magic_bytes=str(facts.get("magic_hex") or computed.get("magic_hex") or ""),
        signing=_signing_from_ledger(ledger),
        **header,
    )


# The PE ``Machine`` values a reader recognises, by the name they go by.
PE_MACHINES: dict[int, str] = {
    0x14C: "x86",
    0x8664: "x86-64",
    0x1C0: "ARM",
    0x1C4: "ARM Thumb-2",
    0xAA64: "ARM64",
    0x200: "IA-64",
}


def pe_architecture(machine: int) -> str:
    """The architecture a PE ``Machine`` value names, or the value itself."""
    return PE_MACHINES.get(machine, f"machine 0x{machine:x}")


def _header_facts(ledger: list[LedgerEntry]) -> dict[str, Any]:
    """What the format tool read out of the header, as ``SampleIdentity`` fields.

    Only what the tool stated: an architecture the machine field names (and
    the raw value when this table does not know it), whether the image is a
    library, the export directory's own name, the version resource's internal
    name, and the header's timestamp. Nothing is inferred from the file name.
    """
    out: dict[str, Any] = {}
    for _entry, data in _payloads(ledger, "pe_info"):
        machine = data.get("machine")
        if isinstance(machine, int) and machine and not isinstance(machine, bool):
            out.setdefault("architecture", pe_architecture(machine))
        if isinstance(data.get("is_dll"), bool):
            out.setdefault("is_dll", data["is_dll"])
        if data.get("export_name"):
            out.setdefault("export_name", str(data["export_name"]))
        version = data.get("version_info")
        if isinstance(version, dict):
            name = _opt(version.get("InternalName")) or _opt(version.get("OriginalFilename"))
            if name:
                out.setdefault("internal_name", name)
        stamp = data.get("timestamp")
        if isinstance(stamp, int) and stamp > 0 and not isinstance(stamp, bool):
            out.setdefault("compile_timestamp", datetime.fromtimestamp(stamp, tz=UTC))
    for _entry, data in _payloads(ledger, "elf_info"):
        bits, endian = data.get("bitness"), data.get("endianness")
        if bits and endian:
            out.setdefault("architecture", f"{bits}-bit, {endian}-endian")
    return out


def _signing_from_ledger(ledger: list[LedgerEntry]) -> SignatureInfo:
    """The signature facts as the pack's ``signing_info`` entry states them.

    Signed means any of the three signature kinds the tool looks for is
    present; the subject and issuer are Authenticode's, or an APK's signer
    when that is the one present. ``signature_valid`` is set only when the
    tool reports a chain verdict (``authenticode.valid``); the extractor
    does not verify chains today, so it stays ``None`` rather than reading
    "present" as "valid". The entry id travels with the facts.
    """
    for entry, data in _payloads(ledger, "signing_info"):
        auth = _dict_of(data.get("authenticode"))
        apk = _dict_of(data.get("apk"))
        macho = _dict_of(data.get("macho"))
        valid = auth.get("valid")
        return SignatureInfo(
            is_signed=bool(auth.get("present") or apk.get("present") or macho.get("present")),
            signer_subject=_opt(auth.get("subject")) or _opt(apk.get("subject")),
            signer_issuer=_opt(auth.get("issuer")) or _opt(apk.get("issuer")),
            signer_thumbprint=_opt(auth.get("thumbprint")) or _opt(apk.get("thumbprint")),
            signature_valid=valid if isinstance(valid, bool) else None,
            evidence_id=entry.id,
        )
    return SignatureInfo()


def _dict_of(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _hashes_of(sample_path: str | None) -> dict[str, Any]:
    """The three cryptographic hashes, the size and the magic bytes of a file.

    Never raises: a sample the report cannot open is a report with fewer facts,
    not a failed build.
    """
    if not sample_path:
        return {}
    try:
        blob = Path(sample_path).read_bytes()
    except OSError as exc:
        logger.warning("ledger projection: could not read %s (%s).", sample_path, exc)
        return {}
    return {
        # Sample fingerprints — VirusTotal, MalwareBazaar and MISP all index by
        # them — never signatures.
        "md5": hashlib.md5(  # nosemgrep: insecure-hash-algorithm-md5
            blob, usedforsecurity=False
        ).hexdigest(),
        # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
        "sha1": hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "size": len(blob),
        "magic_hex": blob[:16].hex(),
    }


def _opt(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


# ---------------------------------------------------------------------------
# Static
# ---------------------------------------------------------------------------


def static_from_ledger(
    ledger: list[LedgerEntry], isrs: dict[str, AgentISR] | None = None
) -> StaticAnalysis | None:
    """``StaticAnalysis`` from the format tools and the analysts' artifacts.

    ``None`` when nothing static was gathered, which is the honest answer for a
    run whose analyst never opened the binary — and the signal the layers
    reading this block use to stay quiet.
    """
    static = StaticAnalysis()
    seen = False

    for _entry, data in _payloads(ledger, "pe_info", "elf_info", "macho_info", "apk_info"):
        seen = True
        for row in data.get("sections") or []:
            if not isinstance(row, dict):
                continue
            static.sections.append(
                PESection(
                    name=str(row.get("name") or ""),
                    virtual_address=_hex(row.get("virtual_address")),
                    virtual_size=_int(row.get("virtual_size")),
                    raw_size=_int(row.get("raw_size")),
                    raw_offset=_int(row.get("raw_offset")),
                    entropy=float(row.get("entropy") or 0.0),
                    characteristics=str(row.get("characteristics") or ""),
                )
            )
        for row in data.get("imports") or []:
            if not isinstance(row, dict):
                continue
            static.imports.append(
                ImportRow(dll=str(row.get("dll") or ""), function=str(row.get("function") or ""))
            )
        static.exports.extend(str(name) for name in data.get("exports") or [])
        for row in data.get("export_rows") or []:
            if isinstance(row, dict):
                ordinal = row.get("ordinal")
                static.export_rows.append(
                    ExportRow(
                        name=str(row.get("name") or ""),
                        ordinal=ordinal if isinstance(ordinal, int) else None,
                        rva=_opt(row.get("rva")),
                    )
                )
        # An APK's declared permissions are its import table: the same
        # question — what did the author ask the platform for — answered in
        # the vocabulary Android uses.
        static.exports.extend(str(name) for name in data.get("permissions") or [])
        if data.get("pdb_path"):
            static.pdb_path = str(data["pdb_path"])
        rows = [row for row in data.get("packer_signatures") or [] if row]
        packers = [
            str(row.get("name") or row) if isinstance(row, dict) else str(row) for row in rows
        ]
        if packers and not static.packer_hint:
            static.packer_hint = packers[0]
            # What ``pe_info`` states: the packer's name and the sections that
            # carry it. No confidence — the tool states none, and the flat 0.50
            # this used to write printed under "Measured" as if it had.
            static.packer_matches = [
                {
                    "name": name,
                    "kind": "packer",
                    "method": "section_name",
                    "evidence": [str(s) for s in (row.get("sections") or [])]
                    if isinstance(row, dict)
                    else [],
                }
                for name, row in zip(packers, rows, strict=True)
            ]

    for _entry, data in _payloads(ledger, "iocs_from_file", "iocs_from_text"):
        seen = True
        for row in data.get("iocs") or []:
            if not isinstance(row, dict):
                continue
            static.interesting_strings.append(
                StringIOC(
                    value=str(row.get("value") or ""),
                    kind=_string_kind(row.get("kind")),  # type: ignore[arg-type]
                    notes=_opt(row.get("notes")),
                )
            )

    # capa reaches the report as a tool call like everything else
    # (``providers.static.capa_yara.ledger_entries``); this is what keeps its
    # technique hits in front of the layers that read ``static``, rather than
    # folding the bundle into the builder by hand.
    for _entry, data in _payloads(ledger, "capa"):
        for row in data.get("capabilities") or []:
            if not isinstance(row, dict):
                continue
            seen = True
            namespace = str(row.get("namespace") or "")
            for technique in row.get("attck") or []:
                tid = _technique_id(technique)
                if not tid:
                    continue
                static.api_technique_hits.append(
                    {
                        "technique_id": tid,
                        "name": str(row.get("rule") or ""),
                        # No confidence: capa says a rule matched, which is
                        # a presence and not a probability.
                        "matched_apis": [namespace] if namespace else [],
                        "source": "capa",
                    }
                )

    # The capability profile is what the knowledge table said about the import
    # set when the pack asked (``tools.knowledge.api_capability``): a category
    # per API and the technique rules that list it. Counted here and cited by
    # the entry's id. Which rules fired is ``api_capability_hits``' answer, the
    # same one corroboration reads.
    for entry, data in _payloads(ledger, "api_capability"):
        rows = [row for row in data.get("capabilities") or [] if isinstance(row, dict)]
        for row in rows:
            category = str(row.get("category") or "").strip()
            if category:
                static.api_capabilities[category] = static.api_capabilities.get(category, 0) + 1
        for category, rate in (data.get("behaviour_rates") or {}).items():
            share = (rate or {}).get("seen_on_benign_percent") if isinstance(rate, dict) else None
            if isinstance(share, int | float) and not isinstance(share, bool):
                static.api_capability_rates[str(category)] = float(share)
        corpus = (data.get("corpora") or {}).get("benign")
        if isinstance(corpus, str) and corpus and not static.api_capability_corpus:
            static.api_capability_corpus = corpus
        for hit in api_capability_hits(data):
            static.api_technique_hits.append(
                {**hit, "source": "api_capability", "evidence_id": entry.id}
            )
        if rows:
            seen = True
            static.api_capabilities_evidence_ids.append(entry.id)

    for artifact in _artifacts(isrs, "imports"):
        for row in _rows_of(artifact):
            if len(row) >= 2:
                seen = True
                static.imports.append(ImportRow(dll=row[0], function=row[1]))
    for artifact in _artifacts(isrs, "iocs", "indicators"):
        for row in _rows_of(artifact):
            if len(row) >= 2:
                seen = True
                static.interesting_strings.append(
                    StringIOC(value=row[1], kind=_string_kind(row[0]))  # type: ignore[arg-type]
                )

    if not seen:
        return None
    # One binary read twice — the triage pack's pe_info and the analyst's own —
    # is one section table, one import table and one export list. Merging each
    # call's rows printed every section and export twice.
    static.sections = _once(static.sections, lambda s: (s.name, s.virtual_address, s.raw_offset))
    static.imports = _once(static.imports, lambda row: (row.dll, row.function))
    static.exports = list(dict.fromkeys(static.exports))
    static.export_rows = _once(static.export_rows, lambda row: (row.name, row.ordinal, row.rva))
    # capa run twice over one file fires the same rules twice.
    static.api_technique_hits = _once(
        static.api_technique_hits,
        lambda hit: (
            hit.get("technique_id"),
            hit.get("name"),
            hit.get("rule"),
            hit.get("source"),
            tuple(hit.get("matched_apis") or ()),
        ),
    )
    return static


def _once[T](rows: list[T], key: Any) -> list[T]:
    """``rows`` with each key kept at its first occurrence, in order."""
    seen: set[Any] = set()
    out: list[T] = []
    for row in rows:
        marker = key(row)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(row)
    return out


def _string_kind(value: Any) -> str:
    kind = str(value or "").strip().lower()
    return kind if kind in _STRING_KINDS else "other"


def _hex(value: Any) -> str:
    try:
        return hex(int(value))
    except (TypeError, ValueError):
        return str(value or "")


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _technique_id(value: Any) -> str:
    """The ``T1027`` out of a capa ATT&CK label, or the label if it is already one."""
    text = str(value or "")
    match = _TECHNIQUE_RE.search(text)
    return match.group(0) if match else ""


# ---------------------------------------------------------------------------
# Dynamic
# ---------------------------------------------------------------------------


def dynamic_from_ledger(
    ledger: list[LedgerEntry], isrs: dict[str, AgentISR] | None = None
) -> DynamicBehavior | None:
    """``DynamicBehavior`` from the sandbox tools the dynamic analyst called."""
    dynamic = DynamicBehavior()
    seen = False

    for _entry, data in _payloads(ledger, "sandbox_processes"):
        nodes = [
            ProcessNode(
                pid=_int(row.get("pid")),
                ppid=_int(row.get("ppid")),
                name=str(row.get("name") or ""),
                command_line=str(row.get("command_line") or ""),
            )
            for row in data.get("processes") or []
            if isinstance(row, dict)
        ]
        if nodes:
            seen = True
            dynamic.process_tree.extend(_as_tree(nodes))

    for _entry, data in _payloads(ledger, "sandbox_signatures"):
        for row in data.get("signatures") or []:
            if not isinstance(row, dict):
                continue
            seen = True
            dynamic.sandbox_signatures.append(
                SandboxSignature(
                    name=str(row.get("name") or ""),
                    description=str(row.get("description") or ""),
                    severity=_int(row.get("severity")),
                )
            )

    for _entry, data in _payloads(ledger, "sandbox_registry_ops"):
        for row in data.get("registry") or []:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or "")
            if not key:
                continue
            seen = True
            dynamic.registry_mods.append(
                RegistryMod(
                    hive=_hive_of(key),  # type: ignore[arg-type]
                    key=key,
                    operation=_registry_operation(row.get("operation")),  # type: ignore[arg-type]
                    new_value=_opt(row.get("value")),
                )
            )

    for _entry, data in _payloads(ledger, "sandbox_api_calls"):
        for row in data.get("apis") or []:
            if not isinstance(row, dict):
                continue
            seen = True
            dynamic.notable_apis.append(
                {
                    "api": str(row.get("api") or ""),
                    "count": _int(row.get("count")),
                    "process": ", ".join(str(p) for p in row.get("processes") or []),
                    "arguments": str(row.get("first_args") or ""),
                }
            )

    for _entry, data in _payloads(ledger, "sandbox_mutexes"):
        names = [str(name) for name in data.get("mutexes") or [] if name]
        if names:
            seen = True
            dynamic.file_operations.extend({"operation": "mutex", "name": name} for name in names)

    for _entry, data in _payloads(ledger, "sandbox_dropped_files"):
        for row in data.get("dropped") or []:
            if isinstance(row, dict):
                seen = True
                dynamic.file_operations.append({"operation": "write", **row})

    # A sandbox that cannot fill a section says so in the report's own
    # ``unavailable`` list, and that disclaimer is the difference between "the
    # sample did nothing" and "this sandbox does not watch for it".
    for _entry, data in _payloads(ledger, "sandbox_report_section"):
        if str(data.get("section") or "") != "unavailable":
            continue
        rows = data.get("rows")
        if isinstance(rows, list) and rows:
            seen = True
            dynamic.unavailable = [str(row) for row in rows]

    for artifact in _artifacts(isrs, "processes"):
        for row in _rows_of(artifact):
            if row:
                seen = True
                dynamic.process_tree.append(
                    ProcessNode(pid=_int(row[0]), name=row[1] if len(row) > 1 else "")
                )

    return dynamic if seen else None


# The registry hives a key path can name, and the label the typed model uses.
_HIVES: tuple[tuple[str, str], ...] = (
    ("hklm", "HKLM"),
    ("hkey_local_machine", "HKLM"),
    ("hkcu", "HKCU"),
    ("hkey_current_user", "HKCU"),
    ("hkcr", "HKCR"),
    ("hkey_classes_root", "HKCR"),
    ("hku", "HKU"),
    ("hkey_users", "HKU"),
    ("hkcc", "HKCC"),
    ("hkey_current_config", "HKCC"),
    ("\\registry\\machine", "HKLM"),
    ("\\registry\\user", "HKU"),
)

_REGISTRY_OPERATIONS = {"create", "modify", "delete", "query"}


def _hive_of(key: str) -> str:
    """The hive a registry path names, or ``UNKNOWN`` when it names none."""
    lowered = key.strip().lower()
    for prefix, hive in _HIVES:
        if lowered.startswith(prefix):
            return hive
    return "UNKNOWN"


def _registry_operation(value: Any) -> str:
    """One of the four operations the typed model knows; anything else is a query."""
    operation = str(value or "").strip().lower()
    return operation if operation in _REGISTRY_OPERATIONS else "query"


def _as_tree(nodes: list[ProcessNode]) -> list[ProcessNode]:
    """The flat process list nested by parent, roots first.

    The tool answers a list because a list is what the sandbox recorded; the
    report shows a tree because "what spawned what" is the question a reader
    asks of it. A process whose parent is not in the list is a root — the
    sandbox did not watch the parent, and hiding the child under nothing would
    lose it.
    """
    by_pid = {node.pid: node for node in nodes}
    roots: list[ProcessNode] = []
    for node in nodes:
        parent = by_pid.get(node.ppid)
        if parent is not None and parent is not node:
            parent.children.append(node)
        else:
            roots.append(node)
    return roots


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


_DomainSource = Literal["sandbox", "analyst", "strings"]
# What one source is worth against another. A name the sample resolved outranks
# a name an analyst wrote down, which outranks a run of bytes in the file.
_DOMAIN_SOURCE_RANK: dict[str, int] = {"strings": 0, "analyst": 1, "sandbox": 2}


def network_from_ledger(
    ledger: list[LedgerEntry],
    isrs: dict[str, AgentISR] | None = None,
    sandbox_report: dict[str, Any] | None = None,
) -> NetworkIOCs | None:
    """``NetworkIOCs`` from the sandbox network tool and the IOC tools.

    ``sandbox_report`` is the job's whole report. When it holds an observation
    the sandbox rows are read from it, every row, rather than from the views a
    model paged through: which process made a flow is a fact about the whole
    report, and an address a paged view never showed is still an address the
    sample's guest reached. Without it the ledger's views are read, and a page
    of a view states no attribution but the sample's own.

    Domains are scored by the same assessor the DGA layer reads
    (``extractors.network_extractor``), so ``is_suspicious``, ``dga_score`` and
    the homograph verdict mean here exactly what they meant when a sandbox
    extractor filled this block.
    """
    from maljan.extractors.network_extractor import (
        _assess_domain,
        _is_emittable_domain,
        address_is_publishable,
    )

    network = NetworkIOCs()
    domains: dict[str, NetworkDomain] = {}
    ips: dict[str, NetworkIP] = {}
    urls: dict[str, NetworkURL] = {}

    def _add(kind: str, value: str, source: _DomainSource = "strings") -> None:
        value = (value or "").strip()
        if not value:
            return
        if kind == "domain":
            # What somebody watched is never dropped here. The reserved and
            # private-use names a sandbox resolved are exactly the lateral
            # movement an analyst reads a case for, and dropping them at the
            # projection erased them from the report as well as from the
            # export, with nothing recorded — while the URL carrying the same
            # host survived and was refused at the export with a row. The
            # export still refuses to publish one, and says so.
            #
            # A name only the string sweep produced is the one exception, and
            # it is unchanged: a run of bytes that happens to end in ``.local``
            # is not an observation of anything.
            if source == "strings" and not _is_emittable_domain(value):
                return
            value = value.lower().strip().rstrip(".")
            if not value:
                return
            known = domains.get(value)
            if known is not None:
                # The same name from a second source is the corroboration the
                # indicator rule asks for, so the stronger origin wins.
                if _DOMAIN_SOURCE_RANK[source] > _DOMAIN_SOURCE_RANK[known.source or "strings"]:
                    known.source = source
                return
            verdict = _assess_domain(value)
            domain = NetworkDomain(
                fqdn=value,
                is_suspicious=verdict.suspicious,
                reason=verdict.reason,
                dga_score=verdict.dga_score,
                is_punycode=verdict.is_punycode,
                homograph_target=verdict.homograph_target,
                source=source,
            )
            domains[value] = domain
            network.domains.append(domain)
        elif kind == "ip":
            value = address_key(value)
            known_ip = ips.get(value)
            if known_ip is not None:
                # The same address from a second source, read the way a
                # domain's and a URL's are: the stronger origin wins.
                if _DOMAIN_SOURCE_RANK[source] > _DOMAIN_SOURCE_RANK[known_ip.source or "strings"]:
                    known_ip.source = source
                return
            # A run of digits only the string sweep produced, in a class nothing
            # could act on, is not an address anybody saw and is left out. An
            # address somebody watched is kept whatever its class, the way a
            # watched reserved name is: the export refuses to publish it and
            # the table says so, rather than the address vanishing.
            if source == "strings" and not address_is_publishable(value, source):
                return
            if not _parses_as_an_address(value):
                return
            created_ip = NetworkIP(address=value, source=source)
            ips[value] = created_ip
            network.ips.append(created_ip)
        elif kind == "url":
            # Case-fold the host so one endpoint reached twice under two
            # spellings is one URL, not two.
            value = _fold_url_host(value)
            known_url = urls.get(value)
            if known_url is not None:
                # The same endpoint from a second source, read the way a
                # domain's is: the stronger origin wins, and that is the
                # corroboration the indicator rule asks for.
                if _DOMAIN_SOURCE_RANK[source] > _DOMAIN_SOURCE_RANK[known_url.source or "strings"]:
                    known_url.source = source
                return
            created = NetworkURL(url=value, source=source)
            urls[value] = created
            network.urls.append(created)

    # What the sandbox's own records say about each address it saw: whether a
    # flow to it came from the sample's process tree, from another process, or
    # from a process the report does not name.
    attributed: dict[str, list[bool | None]] = {}
    host_facts: dict[str, dict[str, Any]] = {}

    for data, whole in _sandbox_views(ledger, sandbox_report):
        for key in ("dns", "domains"):
            for row in data.get(key) or []:
                _add("domain", _first_str(row, "request", "hostname", "domain", "name"), "sandbox")
        # An address the sample really reached, labelled as one: the default
        # source is ``strings``, so every observed address was recorded as
        # though a string sweep had produced it, which is the weakest claim
        # there is and the one the publish rule holds back.
        for row in data.get("hosts") or []:
            address = address_key(_first_str(row, "ip", "address", "host"))
            _add("ip", address, "sandbox")
            if isinstance(row, dict) and address:
                host_facts.setdefault(address, {}).update(
                    {k: row[k] for k in ("asn", "country_name") if row.get(k)}
                )
        for key in ("tcp", "udp"):
            for row in data.get(key) or []:
                address = address_key(_first_str(row, "dst", "ip", "address"))
                _add("ip", address, "sandbox")
                if isinstance(row, dict) and address:
                    stated = row.get(SAMPLE_TREE_KEY)
                    # A page of a view cannot say that no flow to an address
                    # came from the tree: the one that did may be on another.
                    attributed.setdefault(address, []).append(
                        stated if whole or stated is True else None
                    )
        for row in data.get("http") or []:
            host = _first_str(row, "host", "hostname")
            _add("domain", host, "sandbox")
            # A request the sample made, and labelled as one: the default
            # source is ``strings``, so an observed URL used to be recorded as
            # though it had been read out of the file's bytes.
            _add("url", _http_url(row, host), "sandbox")

    for _entry, data in _payloads(ledger, "iocs_from_file", "iocs_from_text"):
        for row in data.get("iocs") or []:
            if isinstance(row, dict):
                _add(str(row.get("kind") or ""), str(row.get("value") or ""), "strings")

    kept: dict[tuple[str, str], list[str]] = {}
    for artifact in (
        a for isr in (isrs or {}).values() for a in getattr(isr, "artifacts", None) or []
    ):
        source = str(getattr(artifact, "source", "") or "").strip()
        by = f"an artifact of the {source} analyst" if source else "an analyst artifact"
        for kind, value in kept_network_values(artifact):
            _add(kind, value, "analyst")
            kept_key = (kind, value.strip().lower().rstrip("."))
            if by not in kept.setdefault(kept_key, []):
                kept[kept_key].append(by)

    _state_sandbox_facts(network, attributed, host_facts)
    _state_who_kept(network, kept, isrs)
    return network if (network.domains or network.ips or network.urls) else None


# The artifact kinds that keep a network value as an indicator: the analyst's
# structured list of what it holds to be infrastructure. Nothing else keeps —
# a table of contacted hosts is a transcription of what the sandbox saw, and one
# live run's analysts wrote exactly such observations down while calling them
# noise. Tolerance is on the values, never on the kinds.
_KEEPING_KINDS = frozenset(
    {
        "endpoints",
        "endpoint",
        "network",
        "iocs",
        "ioc",
        "indicators",
        "c2",
        "network_iocs",
        "c2_endpoints",
    }
)
# The kinds where an untyped cell is read as an address, a name or a URL: a
# list of endpoints is nothing but those. An IOC list holds file names, hashes
# and mutexes beside them, so its rows are read only where typed.
_BARE_VALUE_KINDS = frozenset({"endpoints", "endpoint", "c2", "c2_endpoints"})
# The words a row names its value's type by, network and otherwise.
_TYPE_ALIASES = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "address": "ip",
    "ip_address": "ip",
    "ip address": "ip",
    "addr": "ip",
    "domain": "domain",
    "host": "domain",
    "hostname": "domain",
    "fqdn": "domain",
    "domain name": "domain",
    "url": "url",
    "uri": "url",
}
_OTHER_TYPES = frozenset(
    {
        "file",
        "filename",
        "file_name",
        "file name",
        "path",
        "file_path",
        "filepath",
        "mutex",
        "registry",
        "registry_key",
        "key",
        "hash",
        "md5",
        "sha1",
        "sha256",
        "process",
        "command",
        "string",
        "email",
        "other",
    }
)
# A name whose last label is a file's extension is a file, not a host,
# including the extensions that are also top-level domains.
_FILE_LABELS = frozenset(
    {
        "exe",
        "dll",
        "sys",
        "bat",
        "cmd",
        "ps1",
        "psm1",
        "vbs",
        "js",
        "jse",
        "hta",
        "wsf",
        "dat",
        "bin",
        "txt",
        "log",
        "tmp",
        "ini",
        "cfg",
        "conf",
        "json",
        "xml",
        "lnk",
        "scr",
        "ocx",
        "drv",
        "msi",
        "jar",
        "zip",
        "rar",
        "7z",
        "gz",
        "tar",
        "iso",
        "img",
        "cab",
        "py",
        "pyc",
        "sh",
        "so",
        "pl",
        "rs",
        "md",
        "ps",
        "mov",
        "app",
        "apk",
        "dmg",
        "pkg",
        "deb",
        "rpm",
        "elf",
        "doc",
        "docx",
        "docm",
        "xls",
        "xlsx",
        "xlsm",
        "ppt",
        "pptx",
        "pdf",
        "rtf",
        "html",
        "htm",
        "php",
        "asp",
        "aspx",
        "db",
        "sqlite",
        "png",
        "jpg",
        "gif",
        "mp4",
        "mp3",
        "bak",
        "vbe",
        "cpl",
    }
)
_HOST_PORT_RE = re.compile(r"^\[?([0-9a-fA-F:.]+?)\]?:(\d{1,5})$")


def _kind_of(artifact: Any) -> str:
    return re.sub(r"[\s-]+", "_", str(getattr(artifact, "kind", "") or "").strip().lower())


# The headings that name a table's type column and its value column.
_TYPE_HEADINGS = frozenset({"type", "kind", "category", "ioc type", "indicator type"})
_VALUE_HEADINGS = frozenset(
    {"value", "indicator", "ioc", "observable", "address", "host", "domain", "url", "endpoint"}
)
_PORT_SUFFIX_RE = re.compile(r"[:/]\s*port$")


def _type_word(cell: str) -> str | None:
    """The type a cell names, normalised, or ``None`` when it names none.

    Lower-cased, a ``:port`` or ``/port`` suffix taken off and the last word
    read, so "C2 domain" is ``domain``, "IP Address" is ``address`` and
    "ip:port" is ``ip``.
    """
    text = _PORT_SUFFIX_RE.sub("", str(cell or "").strip().lower()).strip()
    if not text:
        return None
    if text in _TYPE_ALIASES or text in _OTHER_TYPES:
        return text
    last = text.split()[-1]
    return last if last in _TYPE_ALIASES or last in _OTHER_TYPES else None


def _heading_columns(artifact: Any) -> tuple[int, int] | None:
    """The type column and the value column a table's headings name, when they name both."""
    headings = [str(h or "").strip().lower() for h in getattr(artifact, "columns", None) or []]
    typed = next((i for i, h in enumerate(headings) if h in _TYPE_HEADINGS), None)
    valued = next((i for i, h in enumerate(headings) if h in _VALUE_HEADINGS), None)
    if typed is None or valued is None or typed == valued:
        return None
    return typed, valued


def kept_network_values(artifact: Any) -> list[tuple[str, str]]:
    """The addresses, names and URLs an analyst's artifact keeps, each as ``(kind, value)``.

    Only an artifact of a keeping kind (``endpoints``, ``network``, ``iocs``,
    ``c2`` and their plain spellings) keeps anything. A row has at most one
    type cell: the column a heading names ``type``, or else the first cell that
    names a type ("C2 domain", "IP Address", "ip:port" included). A type
    applies to one value cell only — the heading's value column, or the cell
    after the type cell (before it when the type is the last cell) — and a name
    typed as a domain, host or URL is the model's statement, kept whatever its
    TLD. A row whose type cell names a non-network type (a file, a path, a
    hash) keeps nothing. Every other cell, and every cell of an untyped row, is
    read untyped, and only in an endpoints or C2 list: an address is kept, a
    name only when it could be a host and does not end in a file's extension.
    """
    kind = _kind_of(artifact)
    if kind not in _KEEPING_KINDS:
        return []
    bare = kind in _BARE_VALUE_KINDS
    rows = _rows_of(artifact)
    single = getattr(artifact, "value", None)
    if not rows and single and bare:
        rows = [[str(single)]]
    headed = _heading_columns(artifact)
    out: list[tuple[str, str]] = []

    def _keep(found: list[tuple[str, str]]) -> None:
        for item in found:
            if item not in out:
                out.append(item)

    for row in rows:
        type_at: int | None
        value_at: int | None
        if headed is not None and max(headed) < len(row):
            type_at, value_at = headed
            word = _type_word(row[type_at])
        else:
            type_at = next((i for i, cell in enumerate(row) if _type_word(cell)), None)
            word = _type_word(row[type_at]) if type_at is not None else None
            if type_at is None:
                value_at = None
            elif type_at + 1 < len(row):
                value_at = type_at + 1
            else:
                value_at = type_at - 1 if type_at > 0 else None
        if word in _OTHER_TYPES:
            continue
        hint = _TYPE_ALIASES.get(word) if word else None
        if hint is not None and value_at is not None:
            _keep(_cell_values(row[value_at], hint))
        if not bare:
            continue
        for index, cell in enumerate(row):
            if index in (type_at, value_at) and hint is not None:
                continue
            if index == type_at:
                continue
            _keep(_cell_values(cell, None))
    return out


def _cell_values(cell: str, hint: str | None) -> list[tuple[str, str]]:
    """What one cell holds: a URL and its host, an address, or a name; nothing otherwise."""
    from maljan.extractors.network_extractor import (
        host_is_public,
        is_well_known_benign_host,
        url_host,
    )

    text = str(cell or "").strip().strip("'\"`")
    if not text or " " in text:
        return []
    if "://" in text:
        host = url_host(text)
        out = [("url", text)]
        as_address = _address_of(host) if host else ""
        if as_address:
            out.append(("ip", as_address))
        elif host and not is_well_known_benign_host(host):
            # A well-known host is kept only as itself, never through a URL on it.
            out.append(("domain", host))
        return out
    as_address = _address_of(text)
    if as_address:
        return [("ip", as_address)]
    name = text.lower().rstrip(".")
    if ":" in name:
        name = name.rsplit(":", 1)[0] if name.rsplit(":", 1)[1].isdigit() else name
    if hint in ("domain", "url"):
        # Typed by the row itself: the model's own statement, kept as written —
        # a private-use name, and a name under a TLD that is also a file extension
        # (.zip, .mov, .app), included. The export's own rule answers the rest.
        return [("domain", name)] if "." in name else []
    # Untyped, in an endpoints or C2 list: a name is a host only when it could
    # be one and does not end in a file's extension.
    if "." not in name or not host_is_public(name):
        return []
    if name.rsplit(".", 1)[-1] in _FILE_LABELS:
        return []
    return [("domain", name)]


def _address_of(text: str) -> str:
    """``text`` as a canonical address, with a port or brackets taken off, or ``""``."""
    candidate = text.strip()
    match = _HOST_PORT_RE.match(candidate)
    if match and (candidate.startswith("[") or candidate.count(":") == 1):
        candidate = match.group(1)
    candidate = candidate.strip("[]")
    return address_key(candidate) if _parses_as_an_address(candidate) else ""


def _state_sandbox_facts(
    network: NetworkIOCs,
    attributed: dict[str, list[bool | None]],
    host_facts: dict[str, dict[str, Any]],
) -> None:
    """Each address's process attribution, resolver fact and AS, as the sandbox recorded them.

    Attributed to the sample's tree when any flow to it came from the tree; to
    another process when every flow the report attributes did; unattributed
    when the report attributes none. A fact the report does not state stays
    ``None``.
    """
    from maljan.extractors.network_extractor import is_public_resolver

    for ip in network.ips:
        answers = attributed.get(ip.address, [])
        if any(answer is True for answer in answers):
            ip.sample_process_tree = True
        elif answers and all(answer is False for answer in answers):
            ip.sample_process_tree = False
        ip.public_resolver = is_public_resolver(ip.address)
        facts = host_facts.get(ip.address, {})
        if facts.get("asn") and not ip.asn:
            ip.asn = str(facts["asn"])
        if facts.get("country_name") and not ip.geo:
            ip.geo = str(facts["country_name"])


def _state_who_kept(
    network: NetworkIOCs,
    kept: dict[tuple[str, str], list[str]],
    isrs: dict[str, AgentISR] | None,
) -> None:
    """Which model kept each address and name as an indicator, and which only mentioned it.

    Kept is an analyst's artifact of endpoints, network values or IOCs: the
    structured place an analyst puts what it holds to be infrastructure. A
    claim holding the value in its text mentions it and keeps nothing: one
    live run's analysts wrote two background addresses into claims calling
    them noise, and reading a mention as a keep published what they discarded.
    The judge sees every claim and keeps what it keeps in its own indicators.
    """
    from maljan.agents._indicator_denylists import whole_value_in

    claims = [
        (str(agent), f"{getattr(c, 'claim', '')} {getattr(c, 'evidence_ref', '')}".lower())
        for agent, isr in (isrs or {}).items()
        for c in getattr(isr, "claims", None) or []
    ]

    def _mentions(value: str) -> list[str]:
        key = value.strip().lower().rstrip(".")
        return list(
            dict.fromkeys(
                f"a claim by the {agent} analyst"
                for agent, text in claims
                if whole_value_in(key, text)
            )
        )

    for ip in network.ips:
        ip.kept_by = list(kept.get(("ip", ip.address.lower()), []))
        ip.mentioned_by = _mentions(ip.address)
    for domain in network.domains:
        domain.kept_by = list(kept.get(("domain", domain.fqdn.lower().rstrip(".")), []))
        domain.mentioned_by = _mentions(domain.fqdn)


def _parses_as_an_address(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return False
    return True


def address_key(value: Any) -> str:
    """An address as one spelling: an IP in its compressed lower-case form, anything else stripped.

    A sandbox may write an IPv6 address in capitals and a model in lower case;
    both are one address, and every lookup keyed on an address uses this form.
    """
    import ipaddress

    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_address(text.strip("[]")))
    except ValueError:
        return text


def _sandbox_views(
    ledger: list[LedgerEntry], sandbox_report: dict[str, Any] | None
) -> list[tuple[dict[str, Any], bool]]:
    """The sandbox network views to project, each with whether it is a whole view.

    The job's report read whole when it holds an observation; otherwise every
    ``sandbox_network`` answer in the ledger, a paged one marked as a page.
    """
    if isinstance(sandbox_report, dict) and sandbox_report:
        from maljan.providers.sandbox_tools import sandbox_network

        view = sandbox_network(sandbox_report)
        if isinstance(view, dict) and not view.get("error"):
            return [(view, True)]
    views: list[tuple[dict[str, Any], bool]] = []
    for entry, data in _payloads(ledger, "sandbox_network"):
        args = entry.args if isinstance(entry.args, dict) else {}
        paged = any(_as_int(args.get(k)) for k in ("offset", "limit")) or any(
            str(k).endswith("_total") or k in ("next_offset", "shortened", "truncated")
            for k in data
        )
        # A shortened or truncated answer is a part of the view, like a page.
        views.append((data, not paged and not getattr(entry, "truncated", False)))
    return views


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def network_from_sandbox_report(report: dict[str, Any] | None) -> NetworkIOCs | None:
    """The network block a sandbox report yields when read through its own tool.

    For a caller holding a raw sandbox report and no ledger — a provider test,
    a mapping check. It asks the same tool an analyst would and gets the same
    block back, so what a probe sees and what the report prints cannot
    disagree.
    """
    from maljan.providers.sandbox_tools import sandbox_network

    if not report:
        return None
    answer = sandbox_network(report)
    entry = build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent="layer0",
        tool="sandbox_network",
        args={},
        server=None,
        output=json.dumps(answer),
    )
    return network_from_ledger([entry])


def _fold_url_host(url: str) -> str:
    """A URL with its host lowercased and its path left exactly as it is."""
    if "://" not in url:
        return url
    scheme, _, rest = url.partition("://")
    host, slash, path = rest.partition("/")
    return f"{scheme.lower()}://{host.lower()}{slash}{path}"


def _http_url(row: Any, host: str) -> str:
    """The full URL of an HTTP row, which sandboxes split into host and path."""
    target = _first_str(row, "url", "uri", "path")
    if not target:
        return ""
    if "://" in target:
        return target
    if not host:
        return ""
    return f"http://{host}{target if target.startswith('/') else '/' + target}"


def _first_str(row: Any, *keys: str) -> str:
    if isinstance(row, str):
        return row
    if not isinstance(row, dict):
        return ""
    for key in keys:
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


# Registry paths that mean "run this again", and the mechanism each one is.
_AUTOSTART_MARKERS: tuple[tuple[str, str], ...] = (
    ("\\currentversion\\run", "registry_run"),
    ("\\currentversion\\runonce", "registry_run"),
    ("\\currentversion\\runservices", "registry_run"),
    ("\\currentversion\\windows\\load", "registry_run"),
    ("\\image file execution options", "image_hijack"),
    ("\\windows nt\\currentversion\\windows\\appinit_dlls", "appinit_dll"),
    ("\\winlogon", "winlogon_helper"),
    ("\\currentcontrolset\\services", "service"),
)


def _autostart_kind(key: str) -> str | None:
    """The persistence mechanism a registry path names, or None when it names none."""
    lowered = key.strip().lower()
    for marker, kind in _AUTOSTART_MARKERS:
        if marker in lowered:
            return kind
    return None


def persistence_from_ledger(
    ledger: list[LedgerEntry], isrs: dict[str, AgentISR] | None = None
) -> list[PersistenceMechanism]:
    """Persistence entries the agents named, plus the Sigma rules that fired.

    Nothing here re-scans a sandbox report for autostart paths: an agent that
    saw a Run key writes it down as an artifact, and a Sigma rule that fired on
    the sandbox events is evidence in its own right.
    """
    out: list[PersistenceMechanism] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, target: str, payload: str, technique: str | None, ref: str) -> None:
        target = (target or "").strip()
        if not target:
            return
        key = (kind, target.lower())
        if key in seen:
            return
        seen.add(key)
        out.append(
            PersistenceMechanism(
                kind=kind,  # type: ignore[arg-type]
                target=target,
                payload=payload,
                technique_id=technique,
                evidence_ref=ref,
            )
        )

    for artifact in _artifacts(isrs, "persistence"):
        ref = ", ".join(getattr(artifact, "evidence_ids", None) or []) or "agent artifact"
        rows = _rows_of(artifact)
        if rows:
            for row in rows:
                kind = row[0].strip().lower() if row else "other"
                _add(
                    kind if kind in _PERSISTENCE_KINDS else "other",
                    row[1] if len(row) > 1 else (row[0] if row else ""),
                    row[2] if len(row) > 2 else "",
                    None,
                    ref,
                )
        elif getattr(artifact, "value", None):
            _add("other", str(artifact.value), "", None, ref)

    # A Run key an agent read through ``sandbox_registry_ops`` is persistence
    # whether or not the agent thought to write an artifact about it.
    for entry, data in _payloads(ledger, "sandbox_registry_ops"):
        for row in data.get("registry") or []:
            if not isinstance(row, dict):
                continue
            key = str(row.get("key") or "")
            autostart = _autostart_kind(key)
            if autostart is None or row.get("operation") == "query":
                continue
            _add(autostart, key, str(row.get("value") or ""), None, entry.id)

    for entry, data in _payloads(ledger, "sandbox_services_and_tasks"):
        for name in data.get("services") or []:
            _add("service", str(name), "", "T1543.003", entry.id)
        for command in data.get("tasks") or []:
            _add("scheduled_task", str(command), "", "T1053.005", entry.id)

    # A Sigma rule that fired is a detection-rule match first. It is a
    # persistence row only when it names an autostart technique and the event
    # it matched names the key: the rule's title is what the rule is called,
    # never a registry target, and one live report filed "LOLBIN Execution From
    # Abnormal Drive" — a rule with no technique at all — as a Run key.
    for entry, data in _payloads(ledger, "sigma_match", "sigma_match_sandbox"):
        for row in data.get("matches") or []:
            if not isinstance(row, dict):
                continue
            technique = next(
                (t for t in sigma_technique_ids(row) if t.startswith(_AUTOSTART_TECHNIQUE)), None
            )
            if technique is None:
                continue
            key = _matched_registry_key(row)
            if not key:
                continue
            _add(
                _autostart_kind(key) or _SIGMA_AUTOSTART_KINDS.get(technique, "other"),
                key,
                _matched_registry_value(row),
                technique,
                entry.id,
            )

    return out


# The ATT&CK technique a Sigma rule has to name to be read as persistence, and
# the kind each of its sub-techniques is when the key itself does not say.
_AUTOSTART_TECHNIQUE = "T1547"
_SIGMA_AUTOSTART_KINDS: dict[str, str] = {
    "T1547.001": "registry_run",
    "T1547.002": "lsa_provider",
    "T1547.004": "winlogon_helper",
    "T1547.005": "lsa_provider",
    "T1547.006": "driver",
}

# The fields a Sigma registry event names its key and its value in.
_SIGMA_KEY_FIELDS = ("TargetObject", "ObjectName", "RegistryKey", "Key")
_SIGMA_VALUE_FIELDS = ("Details", "RegistryValueData", "NewValue")


def _matched_fields(row: dict[str, Any]) -> dict[str, Any]:
    fields = row.get("matched_fields")
    return fields if isinstance(fields, dict) else {}


def _matched_registry_key(row: dict[str, Any]) -> str:
    """The registry key the event a Sigma rule matched names, or ``""``."""
    fields = _matched_fields(row)
    for name in _SIGMA_KEY_FIELDS:
        value = fields.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _matched_registry_value(row: dict[str, Any]) -> str:
    fields = _matched_fields(row)
    for name in _SIGMA_VALUE_FIELDS:
        value = fields.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""
