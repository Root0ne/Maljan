"""Template-based detection signature generator (YARA / Sigma / Suricata).

The deterministic ``MalwareReport`` exposes every IOC the pipeline saw:
hashes, suspicious imports, registry mods, network endpoints, persistence
mechanisms. This module pivots those IOCs into draft detection rules that
SOC teams can paste straight into their tooling.

Three rules at most are produced per report — one per format. Each format
is skipped when the relevant evidence is absent (no network IOCs → no
Suricata rule). Rules are validated when feasible:

  - YARA:    ``yara.compile()`` when ``yara-python`` is installed.
  - Sigma:   ``yaml.safe_load`` parse + minimum-key check.
  - Suricata: textual sanity check (``alert PROTO ...; sid:N; msg:"...";``).

Validation failure does NOT drop the rule body — it sets
``DetectionRule.compile_error`` so the operator can edit and re-validate.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime
from typing import Any

import yaml

from maljan.core.logger import logger
from maljan.reporting.models import (
    DetectionRule,
    MalwareReport,
    NetworkDomain,
    NetworkIP,
    NetworkURL,
    PersistenceMechanism,
    RegistryMod,
    SandboxSignature,
    StringIOC,
)

# yara-python is an optional dependency (C extension). When absent we still
# build the rule body — only the compile-time validation is skipped.
try:
    import yara  # type: ignore[import-untyped]

    _YARA_AVAILABLE = True
except ImportError:
    yara = None  # type: ignore[assignment]
    _YARA_AVAILABLE = False


_MAX_YARA_STRINGS = 25
_MAX_SIGMA_VALUES = 12
_MAX_SURICATA_RULES = 12
_SAFE_RULE_NAME_RE = re.compile(r"[^A-Za-z0-9_]+")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build_detection_rules(report: MalwareReport) -> list[DetectionRule]:
    """Return the YARA / Sigma / Suricata rules derivable from ``report``.

    Each format may return ``None`` (no usable evidence); the orchestrator
    silently filters them out. The list ordering is stable: YARA, Sigma,
    Suricata. Callers can rely on ``DetectionRule.kind`` for dispatch.
    """
    rules: list[DetectionRule] = []
    for builder in (_build_yara, _build_sigma, _build_suricata):
        try:
            rule = builder(report)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "detection_signatures: %s raised (%s); skipping.",
                builder.__name__,
                exc,
            )
            continue
        if rule is not None:
            rules.append(rule)
    logger.info(
        "detection_signatures: generated %d rule(s) (errors=%d).",
        len(rules),
        sum(1 for r in rules if r.compile_error),
    )
    return rules


# ---------------------------------------------------------------------------
# YARA
# ---------------------------------------------------------------------------


def _build_yara(report: MalwareReport) -> DetectionRule | None:
    """Build a single YARA rule that matches the sample by hash and IOC strings.

    Conditions chained with ``or`` so any one fingerprint triggers the rule:
    - ``hash.sha256(0, filesize) == "..."`` always present (sha256 is required)
    - ``pe.imphash() == "..."`` when imphash is known
    - ``N of them`` when at least two string IOCs are collected
    """
    sha256 = report.identity.hashes.sha256
    if not sha256:
        return None

    imphash = report.identity.hashes.imphash
    strings: list[tuple[str, str]] = []  # (slot, value)
    sources: list[str] = [f"sha256:{sha256}"]

    if report.static is not None:
        for ioc in report.static.interesting_strings[:_MAX_YARA_STRINGS]:
            if not _yara_string_eligible(ioc):
                continue
            slot = f"$s{len(strings)}"
            strings.append((slot, ioc.value))
            sources.append(f"string:{ioc.kind}:{ioc.value[:80]}")
        suspicious_imports = [imp for imp in report.static.imports if imp.is_suspicious]
        for imp in suspicious_imports[: max(0, _MAX_YARA_STRINGS - len(strings))]:
            slot = f"$s{len(strings)}"
            strings.append((slot, f"{imp.dll}!{imp.function}"))
            sources.append(f"import:{imp.dll}!{imp.function}")

    safe_name = _safe_rule_name(report.attribution.family or report.malware_category or sha256[:12])
    rule_name = f"Maljan_AutoGen_{safe_name}"

    body = _render_yara(
        rule_name=rule_name,
        sha256=sha256,
        imphash=imphash,
        strings=strings,
        family=report.attribution.family or report.malware_category or "unknown",
        verdict=report.verdict,
        generated_at_iso=report.generated_at.isoformat(),
    )

    compile_error = _validate_yara(body)
    return DetectionRule(
        kind="yara",
        name=rule_name,
        body=body,
        source_evidence=sources[:20],
        compile_error=compile_error,
    )


def _render_yara(
    *,
    rule_name: str,
    sha256: str,
    imphash: str | None,
    strings: list[tuple[str, str]],
    family: str,
    verdict: str,
    generated_at_iso: str,
) -> str:
    lines: list[str] = []
    imports = ['import "hash"']
    if imphash:
        imports.append('import "pe"')
    lines.extend(imports)
    lines.append("")
    lines.append(f"rule {rule_name}")
    lines.append("{")
    lines.append("    meta:")
    lines.append('        author = "Maljan Auto-Generator"')
    verdict_safe = _escape_yara(verdict)
    family_safe = _escape_yara(family)
    lines.append(
        f'        description = "Auto-generated, verdict={verdict_safe}, family={family_safe}"'
    )
    lines.append(f'        sha256 = "{_escape_yara(sha256)}"')
    lines.append(f'        generated_at = "{_escape_yara(generated_at_iso)}"')
    if strings:
        lines.append("    strings:")
        for slot, value in strings:
            lines.append(f'        {slot} = "{_escape_yara(value)}" ascii wide nocase')
    lines.append("    condition:")

    conditions: list[str] = [f'hash.sha256(0, filesize) == "{_escape_yara(sha256)}"']
    if imphash:
        conditions.append(f'pe.imphash() == "{_escape_yara(imphash)}"')
    if len(strings) >= 2:
        threshold = max(2, len(strings) // 3)
        conditions.append(f"{threshold} of them")
    elif len(strings) == 1:
        conditions.append("any of them")

    lines.append("        " + " or ".join(f"({c})" for c in conditions))
    lines.append("}")
    return "\n".join(lines) + "\n"


def _yara_string_eligible(ioc: StringIOC) -> bool:
    """Filter out IOCs that would produce noisy or unsafe YARA strings."""
    if not ioc.value:
        return False
    if len(ioc.value) < 4 or len(ioc.value) > 200:
        return False
    if ioc.kind in {"url", "domain", "ip", "registry", "mutex", "command", "path"}:
        return True
    return False


def _escape_yara(value: str) -> str:
    """Escape backslash + double quote, drop control chars (0x00-0x1F)."""
    # Drop control chars first so we never embed raw newlines.
    cleaned = "".join(c for c in value if c >= " " or c in "\t")
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def _safe_rule_name(value: str) -> str:
    safe = _SAFE_RULE_NAME_RE.sub("_", value)
    safe = safe.strip("_") or "Sample"
    return safe[:64]


def _validate_yara(body: str) -> str | None:
    if not _YARA_AVAILABLE or yara is None:
        return "yara-python not installed; rule body not validated"
    try:
        yara.compile(source=body)
    except Exception as exc:  # noqa: BLE001 - yara.Error not always importable
        return f"yara.compile failed: {exc}"
    return None


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------


def _build_sigma(report: MalwareReport) -> DetectionRule | None:
    """Build a Sigma YAML rule keyed by registry / persistence / sandbox sigs."""
    registry_targets = _collect_registry_targets(report)
    persistence_images = _collect_persistence_images(report.persistence)
    signatures = _collect_signature_names(report)

    if not (registry_targets or persistence_images or signatures):
        return None

    sha256 = report.identity.hashes.sha256
    family = report.attribution.family or report.malware_category or "unknown"
    safe_name = _safe_rule_name(family)
    rule_id = str(uuid.UUID(bytes=hashlib.sha256(sha256.encode()).digest()[:16]))

    selections: dict[str, dict[str, Any]] = {}
    sources: list[str] = []

    if registry_targets:
        selections["selection_registry"] = {
            "TargetObject|contains": registry_targets[:_MAX_SIGMA_VALUES],
        }
        sources.extend(f"registry:{p}" for p in registry_targets[:5])
    if persistence_images:
        selections["selection_persistence"] = {
            "Image|endswith": persistence_images[:_MAX_SIGMA_VALUES],
        }
        sources.extend(f"persistence:{p}" for p in persistence_images[:5])
    if signatures:
        selections["selection_sandbox"] = {
            "Description|contains": signatures[:_MAX_SIGMA_VALUES],
        }
        sources.extend(f"sandbox:{s}" for s in signatures[:5])

    selection_keys = list(selections.keys())
    condition = "1 of selection_*" if len(selection_keys) > 1 else selection_keys[0]

    if registry_targets:
        logsource = {"product": "windows", "category": "registry_event"}
    elif persistence_images:
        logsource = {"product": "windows", "category": "process_creation"}
    else:
        logsource = {"product": "windows", "category": "process_creation"}

    tags = _sigma_tags(report)

    rule_dict: dict[str, Any] = {
        "title": f"Maljan AutoGen - {family}",
        "id": rule_id,
        "status": "experimental",
        "description": f"Auto-generated for sha256 {sha256[:12]}",
        "author": "Maljan Auto-Generator",
        "date": report.generated_at.strftime("%Y/%m/%d"),
        "references": [f"https://www.virustotal.com/gui/file/{sha256}"],
        "logsource": logsource,
        "detection": {**selections, "condition": condition},
        "falsepositives": ["Legitimate software installers", "Unknown"],
        "level": "high",
        "tags": tags,
    }

    body = yaml.safe_dump(rule_dict, sort_keys=False, default_flow_style=False)
    compile_error = _validate_sigma(body)

    return DetectionRule(
        kind="sigma",
        name=f"Maljan_AutoGen_Sigma_{safe_name}",
        body=body,
        source_evidence=sources[:20],
        compile_error=compile_error,
    )


def _collect_registry_targets(report: MalwareReport) -> list[str]:
    if report.dynamic is None:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for reg in report.dynamic.registry_mods:
        key = _registry_full_path(reg)
        lower = key.lower()
        if lower in seen:
            continue
        seen.add(lower)
        out.append(key)
        if len(out) >= _MAX_SIGMA_VALUES:
            break
    return out


def _registry_full_path(reg: RegistryMod) -> str:
    return f"{reg.hive}\\{reg.key}" if reg.key and not reg.key.startswith(reg.hive) else reg.key


def _collect_persistence_images(persistence: list[PersistenceMechanism]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for mech in persistence:
        target = mech.target or mech.payload or ""
        if not target:
            continue
        # Pull a trailing executable name if present.
        match = re.search(r"([^\\/]+\.(?:exe|dll|bat|ps1|vbs|js))", target, re.IGNORECASE)
        if match:
            image = "\\" + match.group(1)
        else:
            image = target if target.startswith("\\") else "\\" + target.lstrip("/").split("/")[-1]
        if image.lower() in seen:
            continue
        seen.add(image.lower())
        out.append(image)
        if len(out) >= _MAX_SIGMA_VALUES:
            break
    return out


def _collect_signature_names(report: MalwareReport) -> list[str]:
    if report.dynamic is None:
        return []
    out: list[str] = []
    seen: set[str] = set()
    sigs: list[SandboxSignature] = sorted(
        report.dynamic.sandbox_signatures, key=lambda s: s.severity, reverse=True
    )
    for sig in sigs[:_MAX_SIGMA_VALUES]:
        text = (sig.description or sig.name).strip()
        if not text or text.lower() in seen:
            continue
        seen.add(text.lower())
        out.append(text[:80])
    return out


def _sigma_tags(report: MalwareReport) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for mapping in report.ttp_mappings[:10]:
        tid = mapping.technique_id
        if not tid:
            continue
        tag = f"attack.{tid.lower()}"
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    for cell in report.capability_matrix[:10]:
        name = cell.tactic_name.lower().replace(" ", "_").replace("&", "and")
        tag = f"attack.{name}" if name else ""
        if tag and tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


def _validate_sigma(body: str) -> str | None:
    try:
        parsed = yaml.safe_load(body)
    except Exception as exc:  # noqa: BLE001
        return f"yaml.safe_load failed: {exc}"
    if not isinstance(parsed, dict):
        return "sigma body did not parse to a mapping"
    required = {"title", "id", "detection", "logsource"}
    missing = required - parsed.keys()
    if missing:
        return f"sigma rule missing keys: {', '.join(sorted(missing))}"
    return None


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------


_SURICATA_SID_BASE = 9_400_000
_SURICATA_MAX_BODY_BYTES = 16_000


def _build_suricata(report: MalwareReport) -> DetectionRule | None:
    if report.network is None:
        return None
    domains = [d for d in report.network.domains if d.is_suspicious] or list(report.network.domains)
    ips = list(report.network.ips)
    urls = list(report.network.urls)

    if not (domains or ips or urls):
        return None

    family = report.attribution.family or report.malware_category or "unknown"
    sha256 = report.identity.hashes.sha256
    rule_name = f"Maljan_AutoGen_Suricata_{_safe_rule_name(family)}"

    sources: list[str] = []
    lines: list[str] = [
        f"# Auto-generated by Maljan for sha256 {sha256}",
        f"# Family: {family}; verdict: {report.verdict}; "
        f"generated_at: {report.generated_at.isoformat()}",
        "# Review and renumber SIDs before deploying to production.",
    ]

    sid = _SURICATA_SID_BASE + (int(sha256[:8], 16) % 100_000) if sha256 else _SURICATA_SID_BASE

    for domain in domains[:_MAX_SURICATA_RULES]:
        rule = _suricata_dns_rule(domain, sid, sha256, family)
        if rule is not None:
            lines.append(rule)
            sources.append(f"domain:{domain.fqdn}")
            sid += 1

    if ips:
        rule = _suricata_ip_rule(ips[:_MAX_SURICATA_RULES], sid, sha256, family)
        if rule is not None:
            lines.append(rule)
            sources.append("ips:" + ",".join(ip.address for ip in ips[:_MAX_SURICATA_RULES]))
            sid += 1

    for url in urls[:_MAX_SURICATA_RULES]:
        rule = _suricata_http_rule(url, sid, sha256, family)
        if rule is not None:
            lines.append(rule)
            sources.append(f"url:{url.url[:80]}")
            sid += 1

    body = "\n".join(lines)
    if len(body.encode("utf-8")) > _SURICATA_MAX_BODY_BYTES:
        body = body[:_SURICATA_MAX_BODY_BYTES] + "\n# (truncated)"

    compile_error = _validate_suricata(body)
    return DetectionRule(
        kind="suricata",
        name=rule_name,
        body=body,
        source_evidence=sources[:20],
        compile_error=compile_error,
    )


_SURICATA_CONTENT_RE = re.compile(r"[^A-Za-z0-9._:/\-?=& ]")


def _suricata_content_escape(value: str) -> str:
    """Escape content values to Suricata's hex-byte syntax for unsafe chars.

    Suricata's ``content:`` directive accepts ASCII plus ``|XX|`` hex bytes.
    We pass through a conservative safe set and hex-encode the rest, so the
    resulting rule cannot break out of the string and inject a directive.
    """
    out: list[str] = []
    for ch in value:
        if _SURICATA_CONTENT_RE.match(ch):
            out.append(f"|{ord(ch):02X}|")
        else:
            out.append(ch)
    return "".join(out)


def _suricata_dns_rule(domain: NetworkDomain, sid: int, sha256: str, family: str) -> str | None:
    fqdn = domain.fqdn.strip()
    if not fqdn:
        return None
    content = _suricata_content_escape(fqdn)
    msg = f"Maljan AutoGen DNS: {fqdn} ({family})"
    return (
        f'alert dns any any -> any any (msg:"{_suricata_msg_escape(msg)}"; '
        f'dns.query; content:"{content}"; nocase; '
        f"classtype:trojan-activity; sid:{sid}; rev:1; "
        f"metadata:auto_generated maljan, sha256 {sha256[:12]};)"
    )


def _suricata_ip_rule(ips: list[NetworkIP], sid: int, sha256: str, family: str) -> str | None:
    valid: list[str] = []
    for ip in ips:
        addr = ip.address.strip()
        if not addr:
            continue
        # Conservative: only IPv4/IPv6 chars and colons/dots.
        if not re.match(r"^[0-9a-fA-F:.]+$", addr):
            continue
        valid.append(addr)
    if not valid:
        return None
    ip_list = "[" + ",".join(valid) + "]"
    msg = f"Maljan AutoGen C2 IP ({family})"
    return (
        f'alert ip any any -> {ip_list} any (msg:"{_suricata_msg_escape(msg)}"; '
        f"classtype:trojan-activity; sid:{sid}; rev:1; "
        f"metadata:auto_generated maljan, sha256 {sha256[:12]};)"
    )


def _suricata_http_rule(url: NetworkURL, sid: int, sha256: str, family: str) -> str | None:
    raw_url = url.url or ""
    if not raw_url:
        return None
    # Decompose into host + path heuristically; the alert keys off both.
    match = re.match(r"^[a-z]+://([^/]+)(/.*)?$", raw_url, re.IGNORECASE)
    if not match:
        return None
    host = match.group(1)
    path = match.group(2) or "/"
    host_content = _suricata_content_escape(host)
    path_content = _suricata_content_escape(path)
    msg = f"Maljan AutoGen HTTP host: {host} ({family})"
    return (
        f'alert http any any -> any any (msg:"{_suricata_msg_escape(msg)}"; '
        f"flow:established,to_server; "
        f'http.host; content:"{host_content}"; nocase; '
        f'http.uri; content:"{path_content}"; nocase; '
        f"classtype:trojan-activity; sid:{sid}; rev:1; "
        f"metadata:auto_generated maljan, sha256 {sha256[:12]};)"
    )


def _suricata_msg_escape(value: str) -> str:
    return value.replace('"', "'").replace("\n", " ").replace(";", ",")


_SURICATA_HEAD_RE = re.compile(r"^alert\s+\S+\s+")
_SURICATA_SID_RE = re.compile(r"\bsid:\s*\d+\b")
_SURICATA_MSG_RE = re.compile(r'\bmsg:"[^"]*"')
_SURICATA_END_RE = re.compile(r";\s*\)$")


def _validate_suricata(body: str) -> str | None:
    """Per-line sanity check (no compiler available).

    A real Suricata binary would validate via ``suricata -T``; the per-rule
    checks here only flag rules that are obviously wrong. Order of options
    inside parentheses does not matter — only their presence.
    """
    bad: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not (
            _SURICATA_HEAD_RE.match(line)
            and _SURICATA_SID_RE.search(line)
            and _SURICATA_MSG_RE.search(line)
            and _SURICATA_END_RE.search(line)
        ):
            bad.append(line[:80])
    if bad:
        return f"sanity check failed for {len(bad)} line(s); first: {bad[0]}"
    return None


# Unused-import suppressors keep the module focused.
_ = (datetime, UTC)
