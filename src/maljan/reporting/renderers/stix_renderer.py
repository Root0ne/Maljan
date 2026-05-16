"""Build an extended STIX 2.1 Bundle from a ``MalwareReport``.

The judge node already emits a minimal Bundle (Malware + AttackPattern +
Relationship). This renderer takes that bundle as a starting point and
augments it with the richer SDO set required by downstream CTI tooling:

  - ``Identity`` for Maljan itself (the report producer)
  - ``Indicator`` for every typed IOC (file hash, domain, IP, URL, mutex)
  - ``ObservedData`` snapshots of the sandbox process tree
  - ``Note`` containing the LLM-generated executive summary
  - ``Report`` top-level container with object_refs to every member

The renderer is **additive** — judge's existing objects are preserved as-is.
Producing this bundle is side-effect free; callers serialise it via
``model_dump(mode="json")``.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from maljan.reporting.models import (
    MalwareReport,
    NetworkDomain,
    NetworkIP,
    NetworkURL,
    ProcessNode,
    StringIOC,
)
from maljan.schemas.stix_models import (
    AttackPattern,
    Bundle,
    Identity,
    Indicator,
    Malware,
    Note,
    ObservedData,
    Relationship,
    Report,
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class ExtendedSTIXRenderer:
    """Augment a minimal Bundle with the SDOs derived from a ``MalwareReport``.

    ``render(report, base_bundle)`` returns a new ``Bundle`` instance — the
    input bundle is treated as immutable.
    """

    def render(self, report: MalwareReport, base_bundle: Bundle | None = None) -> Bundle:
        objects: list[Any] = []

        # 1) Preserve everything the judge already emitted.
        if base_bundle is not None:
            objects.extend(base_bundle.objects)

        # 2) Identity SDO for Maljan itself.
        identity = Identity(
            name="Maljan",
            identity_class="software",
            description="Automated multi-agent malware analysis pipeline",
        )
        objects.append(identity)

        # 3) Locate the Malware object (created by judge or here as fallback).
        malware_id = self._find_malware_id(objects)
        if malware_id is None:
            malware_name = report.attribution.family or report.malware_category or "unknown"
            malware_obj = Malware(
                name=str(malware_name),
                description=f"Sample {report.identity.hashes.sha256}",
                is_family=False,
                malware_types=[report.malware_category] if report.malware_category else [],
            )
            objects.append(malware_obj)
            malware_id = malware_obj.id

        # 4) Indicator for the file hash itself (always present).
        sha256 = report.identity.hashes.sha256
        if sha256 and _SHA256_RE.match(sha256):
            indicator = Indicator(
                name=f"Sample hash {sha256[:12]}",
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                indicator_types=["malicious-activity"],
            )
            objects.append(indicator)
            objects.append(
                Relationship(
                    relationship_type="indicates",
                    source_ref=indicator.id,
                    target_ref=malware_id,
                )
            )

        # 5) StringIOC → Indicator.
        if report.static is not None:
            for ioc in report.static.interesting_strings[:50]:
                pattern = _stix_pattern_for_string_ioc(ioc)
                if pattern is None:
                    continue
                ind = Indicator(
                    name=f"{ioc.kind} {ioc.value[:32]}",
                    pattern=pattern,
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                )
                objects.append(ind)

        # 6) Network domain/IP/URL → Indicator.
        if report.network is not None:
            for domain in report.network.domains[:40]:
                dom_ind = _indicator_for_domain(domain)
                if dom_ind is not None:
                    objects.append(dom_ind)
            for ip in report.network.ips[:40]:
                ip_ind = _indicator_for_ip(ip)
                if ip_ind is not None:
                    objects.append(ip_ind)
            for url in report.network.urls[:40]:
                url_ind = _indicator_for_url(url)
                if url_ind is not None:
                    objects.append(url_ind)

        # 7) ObservedData for the process tree roots.
        if report.dynamic is not None and report.dynamic.process_tree:
            obs_objects = _processes_to_observed(report.dynamic.process_tree)
            if obs_objects:
                observed = ObservedData(
                    first_observed=report.generated_at,
                    last_observed=report.generated_at,
                    number_observed=len(obs_objects),
                    objects=obs_objects,
                )
                objects.append(observed)

        # 8) Note wraps the executive summary; abstract is the verdict.
        summary = report.executive_summary.strip()
        if summary:
            note = Note(
                abstract=f"{report.verdict} — confidence {report.overall_confidence:.2f}",
                content=summary,
                object_refs=[malware_id],
            )
            objects.append(note)

        # 9) Report SDO bundles every object_ref. Pre-existing AttackPattern
        #    objects are referenced too so the report stays the single root.
        report_sdo = Report(
            name=f"Maljan analysis of {sha256[:12] if sha256 else 'sample'}",
            description=(
                f"Verdict: {report.verdict}. "
                f"Severity {report.severity.overall_score}/10 "
                f"({report.severity.rating})."
            ),
            published=report.generated_at,
            report_types=["malware-analysis"],
            object_refs=[obj.id for obj in objects if obj is not identity],
        )
        objects.append(report_sdo)

        return Bundle(objects=objects)

    @staticmethod
    def _find_malware_id(objects: list[Any]) -> str | None:
        for obj in objects:
            if isinstance(obj, Malware):
                return obj.id
            obj_type = getattr(obj, "type", None)
            if obj_type == "malware":
                return getattr(obj, "id", None)
        return None


# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------


def _escape_stix(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _stix_pattern_for_string_ioc(ioc: StringIOC) -> str | None:
    value = _escape_stix(ioc.value)
    if ioc.kind == "url":
        return f"[url:value = '{value}']"
    if ioc.kind == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc.kind == "ip":
        return _ip_pattern(value)
    if ioc.kind == "email":
        return f"[email-addr:value = '{value}']"
    if ioc.kind == "mutex":
        return f"[mutex:name = '{value}']"
    if ioc.kind == "registry":
        return f"[windows-registry-key:key = '{value}']"
    if ioc.kind == "path":
        return f"[file:name = '{value}']"
    return None


def _ip_pattern(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return f"[ipv4-addr:value = '{value}']"
    family = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
    return f"[{family}:value = '{value}']"


def _indicator_for_domain(domain: NetworkDomain) -> Indicator | None:
    fqdn = domain.fqdn.strip()
    if not fqdn:
        return None
    pattern = f"[domain-name:value = '{_escape_stix(fqdn)}']"
    name = f"Domain {fqdn}"
    return Indicator(
        name=name,
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"] if domain.is_suspicious else ["anomalous-activity"],
        description=domain.reason,
    )


def _indicator_for_ip(ip: NetworkIP) -> Indicator | None:
    address = ip.address.strip()
    if not address:
        return None
    pattern = _ip_pattern(_escape_stix(address))
    return Indicator(
        name=f"IP {address}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"] if ip.is_suspicious else ["anomalous-activity"],
    )


def _indicator_for_url(url: NetworkURL) -> Indicator | None:
    if not url.url:
        return None
    pattern = f"[url:value = '{_escape_stix(url.url)}']"
    return Indicator(
        name=f"URL {url.url[:48]}",
        pattern=pattern,
        pattern_type="stix",
        indicator_types=["malicious-activity"],
    )


def _processes_to_observed(roots: list[ProcessNode]) -> dict[str, dict[str, Any]]:
    """Flatten the process tree to a STIX 2.1 ``observed-data`` objects dict."""
    out: dict[str, dict[str, Any]] = {}
    counter = 0

    def _walk(node: ProcessNode) -> None:
        nonlocal counter
        entry: dict[str, Any] = {
            "type": "process",
            "pid": node.pid,
            "name": node.name,
        }
        if node.command_line:
            entry["command_line"] = node.command_line
        out[str(counter)] = entry
        counter += 1
        for child in node.children:
            _walk(child)

    for root in roots[:20]:  # cap to keep ObservedData reasonable
        _walk(root)
    return out


# Type-only re-exports keep linters happy when this module is grepped.
_ = (AttackPattern,)
