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
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.reporting.models import (
    DynamicBehavior,
    FileHashes,
    ImportRow,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    PersistenceMechanism,
    PESection,
    ProcessNode,
    SampleIdentity,
    SandboxSignature,
    StaticAnalysis,
    StringIOC,
)
from maljan.schemas.evidence import build_entry, format_entry_id

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
    return SampleIdentity(
        hashes=hashes,
        file_name=file_name or (Path(sample_path).name if sample_path else None),
        file_size_bytes=size,
        file_type=str(facts.get("file_type") or file_type or "unknown"),
        platform=str(facts.get("platform") or platform or "unknown"),  # type: ignore[arg-type]
        mime_type=_opt(facts.get("mime")),
        magic_bytes=str(facts.get("magic_hex") or computed.get("magic_hex") or ""),
    )


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
                ImportRow(
                    dll=str(row.get("dll") or ""),
                    function=str(row.get("function") or ""),
                    category=_opt(row.get("category")),
                    is_suspicious=bool(row.get("category")),
                )
            )
        static.exports.extend(str(name) for name in data.get("exports") or [])
        # An APK's declared permissions are its import table: the same
        # question — what did the author ask the platform for — answered in
        # the vocabulary Android uses.
        static.exports.extend(str(name) for name in data.get("permissions") or [])
        if data.get("pdb_path"):
            static.pdb_path = str(data["pdb_path"])
        packers = [
            str(row.get("name") or row) for row in data.get("packer_signatures") or [] if row
        ]
        if packers and not static.packer_hint:
            static.packer_hint = packers[0]
            static.packer_matches = [
                {"name": name, "kind": "packer", "confidence": 0.5, "method": "section_name"}
                for name in packers
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
    # capability counters and technique hits in front of the layers that read
    # ``static``, rather than folding the bundle into the builder by hand.
    for _entry, data in _payloads(ledger, "capa"):
        for row in data.get("capabilities") or []:
            if not isinstance(row, dict):
                continue
            seen = True
            namespace = str(row.get("namespace") or "")
            top = namespace.split("/", 1)[0] if namespace else "uncategorised"
            static.api_capabilities[top] = static.api_capabilities.get(top, 0) + 1
            for technique in row.get("attck") or []:
                tid = _technique_id(technique)
                if not tid:
                    continue
                static.api_technique_hits.append(
                    {
                        "technique_id": tid,
                        "name": str(row.get("rule") or ""),
                        "confidence": 0.6,
                        "matched_apis": [namespace] if namespace else [],
                        "source": "capa",
                    }
                )

    for artifact in _artifacts(isrs, "imports"):
        for row in _rows_of(artifact):
            if len(row) >= 2:
                seen = True
                static.imports.append(ImportRow(dll=row[0], function=row[1], is_suspicious=True))
    for artifact in _artifacts(isrs, "iocs", "indicators"):
        for row in _rows_of(artifact):
            if len(row) >= 2:
                seen = True
                static.interesting_strings.append(
                    StringIOC(value=row[1], kind=_string_kind(row[0]))  # type: ignore[arg-type]
                )

    if not seen:
        return None
    for category, count in _capability_histogram(static.imports).items():
        static.api_capabilities[category] = static.api_capabilities.get(category, 0) + count
    return static


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


def _capability_histogram(imports: list[ImportRow]) -> dict[str, int]:
    """``{category: count}`` over the imports the tools categorised."""
    counts: dict[str, int] = {}
    for row in imports:
        if row.category:
            counts[row.category] = counts.get(row.category, 0) + 1
    return counts


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
        for row in data.get("processes") or []:
            if not isinstance(row, dict):
                continue
            seen = True
            dynamic.process_tree.append(
                ProcessNode(
                    pid=_int(row.get("pid")),
                    ppid=_int(row.get("ppid")),
                    name=str(row.get("name") or ""),
                    command_line=str(row.get("command_line") or ""),
                )
            )

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


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------


def network_from_ledger(
    ledger: list[LedgerEntry], isrs: dict[str, AgentISR] | None = None
) -> NetworkIOCs | None:
    """``NetworkIOCs`` from the sandbox network tool and the IOC tools.

    Domains are scored by the same assessor the DGA layer reads
    (``extractors.network_extractor``), so ``is_suspicious``, ``dga_score`` and
    the homograph verdict mean here exactly what they meant when a sandbox
    extractor filled this block.
    """
    from maljan.extractors.network_extractor import (
        _assess_domain,
        _is_emittable_domain,
        _is_emittable_ip,
    )

    network = NetworkIOCs()
    domains: set[str] = set()
    ips: set[str] = set()
    urls: set[str] = set()

    def _add(kind: str, value: str) -> None:
        value = (value or "").strip()
        if not value:
            return
        if kind == "domain" and value not in domains:
            if not _is_emittable_domain(value):
                return
            value = value.lower().strip().rstrip(".")
            if value in domains:
                return
            domains.add(value)
            verdict = _assess_domain(value)
            network.domains.append(
                NetworkDomain(
                    fqdn=value,
                    is_suspicious=verdict.suspicious,
                    reason=verdict.reason,
                    dga_score=verdict.dga_score,
                    is_punycode=verdict.is_punycode,
                    homograph_target=verdict.homograph_target,
                )
            )
        elif kind == "ip" and value not in ips:
            if not _is_emittable_ip(value):
                return
            ips.add(value)
            network.ips.append(NetworkIP(address=value))
        elif kind == "url":
            # Case-fold the host so one endpoint reached twice under two
            # spellings is one URL, not two.
            value = _fold_url_host(value)
            if value in urls:
                return
            urls.add(value)
            network.urls.append(NetworkURL(url=value))

    for _entry, data in _payloads(ledger, "sandbox_network"):
        for key in ("dns", "domains"):
            for row in data.get(key) or []:
                _add("domain", _first_str(row, "request", "hostname", "domain", "name"))
        for row in data.get("hosts") or []:
            _add("ip", _first_str(row, "ip", "address", "host"))
        for key in ("tcp", "udp"):
            for row in data.get(key) or []:
                _add("ip", _first_str(row, "dst", "ip", "address"))
        for row in data.get("http") or []:
            host = _first_str(row, "host", "hostname")
            _add("domain", host)
            _add("url", _http_url(row, host))

    for _entry, data in _payloads(ledger, "iocs_from_file", "iocs_from_text"):
        for row in data.get("iocs") or []:
            if isinstance(row, dict):
                _add(str(row.get("kind") or ""), str(row.get("value") or ""))

    for artifact in _artifacts(isrs, "endpoints", "network", "iocs"):
        for row in _rows_of(artifact):
            if len(row) >= 2:
                _add(row[0].strip().lower(), row[1])

    return network if (network.domains or network.ips or network.urls) else None


def network_from_sandbox_report(report: dict[str, Any] | None) -> NetworkIOCs | None:
    """The network block a sandbox report yields when read through its own tool.

    For the Layer-0 scanners, which run before any analyst and therefore before
    there is a ledger to read. They ask the same tool an analyst would and get
    the same block back, so the DGA claim a layer makes and the domains the
    report prints cannot disagree.
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

    for entry, data in _payloads(ledger, "sigma_match", "sigma_match_sandbox"):
        for row in data.get("matches") or []:
            if not isinstance(row, dict):
                continue
            raw_meta = row.get("meta")
            meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
            techniques = row.get("technique_ids") or meta.get("technique_ids") or []
            technique = str(techniques[0]) if techniques else None
            if technique and not technique.startswith("T1547"):
                continue
            _add(
                "registry_run",
                str(row.get("title") or row.get("rule") or row.get("id") or ""),
                "",
                technique,
                entry.id,
            )

    return out
