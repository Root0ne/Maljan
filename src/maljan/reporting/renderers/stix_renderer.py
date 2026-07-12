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

from maljan.agents._indicator_denylists import (
    COMPILE_ARTIFACT_RE,
    FOREIGN_CLASS_REF_RE,
    IOC_FILE_EXTENSIONS,
    IOC_OS_RESOURCE_PREFIXES,
    MAX_FILE_NAME_INDICATORS,
    MAX_TOTAL_INDICATORS,
    URL_DENY_HOSTS,
)
from maljan.core.logger import logger
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
    get_utcnow,
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
            self._normalize_judge_timestamps(base_bundle.objects)
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

        # Wave 9 (2026-05-29): collect indicators per-kind, then apply
        # MAX_TOTAL_INDICATORS as a hard cap with priority order
        # (hashes > network > file:name strings). The 2026-05-29 Linux
        # ELF audit found 19 indicators leaking past G-FP-4's ≤15 ceiling
        # because the per-kind cap (MAX_FILE_NAME_INDICATORS=10) ignored
        # hashes and network IOCs.
        # ``hash_inds`` always pairs an Indicator with its "indicates"
        # Relationship; the tuple shape is explicit so mypy can narrow.
        hash_inds: list[tuple[Indicator, Relationship]] = []
        network_inds: list[Indicator] = []
        string_inds: list[Indicator] = []

        # 4) Indicator for the file hash itself (always present).
        sha256 = report.identity.hashes.sha256
        if sha256 and _SHA256_RE.match(sha256):
            indicator = Indicator(
                name=f"Sample hash {sha256[:12]}",
                pattern=f"[file:hashes.'SHA-256' = '{sha256}']",
                pattern_type="stix",
                indicator_types=["malicious-activity"],
            )
            rel = Relationship(
                relationship_type="indicates",
                source_ref=indicator.id,
                target_ref=malware_id,
            )
            hash_inds.append((indicator, rel))

        # 5) StringIOC → Indicator.
        #
        # Wave 4 Step 5 (2026-05-28): apply the same acceptance-based filter
        # used by the judge bundle postprocess (J-02) so deterministic
        # interesting_strings can't smuggle noise (NDK build paths, bundled
        # bytecode class refs, random short strings) into the public STIX
        # bundle. Without this, the 2026-05-23 noise audit's 49-noisy-paths
        # FP reappears for every sample that bundles NDK-compiled libraries.
        if report.static is not None:
            file_name_kept = 0
            for ioc in report.static.interesting_strings[:50]:
                pattern = _stix_pattern_for_string_ioc(ioc)
                if pattern is None:
                    continue
                if not _accept_string_ioc(ioc, pattern, file_name_kept):
                    continue
                is_file_name = pattern.lstrip().startswith("[file:name")
                if is_file_name:
                    file_name_kept += 1
                ind = Indicator(
                    name=f"{ioc.kind} {ioc.value[:32]}",
                    pattern=pattern,
                    pattern_type="stix",
                    # file:name string IOCs are the FP-prone kind (heavily
                    # capped/filtered upstream); mark them anomalous-activity so
                    # consumers can weight them below high-confidence hash/C2 IOCs.
                    indicator_types=(
                        ["anomalous-activity"] if is_file_name else ["malicious-activity"]
                    ),
                )
                string_inds.append(ind)

        # 6) Network domain/IP/URL → Indicator.
        if report.network is not None:
            for domain in report.network.domains[:40]:
                dom_ind = _indicator_for_domain(domain)
                if dom_ind is not None:
                    network_inds.append(dom_ind)
            for ip in report.network.ips[:40]:
                ip_ind = _indicator_for_ip(ip)
                if ip_ind is not None:
                    network_inds.append(ip_ind)
            for url in report.network.urls[:40]:
                url_ind = _indicator_for_url(url)
                if url_ind is not None:
                    network_inds.append(url_ind)

        # 6.5) Apply the total-indicator cap with priority order.
        budget = MAX_TOTAL_INDICATORS
        dropped_counts = {"hash": 0, "network": 0, "string": 0}
        for ind, rel in hash_inds:
            if budget > 0:
                objects.append(ind)
                objects.append(rel)
                budget -= 1
            else:
                dropped_counts["hash"] += 1
        for ind in network_inds:
            if budget > 0:
                objects.append(ind)
                budget -= 1
            else:
                dropped_counts["network"] += 1
        for ind in string_inds:
            if budget > 0:
                objects.append(ind)
                budget -= 1
            else:
                dropped_counts["string"] += 1
        if sum(dropped_counts.values()):
            logger.warning(
                "stix_renderer: total indicator cap (%d) exceeded; dropped "
                "hash=%d network=%d string=%d",
                MAX_TOTAL_INDICATORS,
                dropped_counts["hash"],
                dropped_counts["network"],
                dropped_counts["string"],
            )

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

        # Final referential-integrity + dedup pass over the assembled bundle —
        # also collapses indicators duplicated across the judge base bundle and
        # the renderer's synthesized set, and prunes any ref dangling from
        # upstream drops. See judge_postprocess.enforce_bundle_integrity.
        from maljan.agents.judge_postprocess import enforce_bundle_integrity

        return Bundle(objects=enforce_bundle_integrity(objects))

    @staticmethod
    def _normalize_judge_timestamps(objects: list[Any]) -> None:
        """Stamp the judge's SDOs with a real ``created``/``modified`` time.

        The judge Bundle is emitted by the LLM, which copies STIX documentation
        examples verbatim — the Malware and AttackPattern objects land on the
        placeholder ``2023-01-01T00:00:00Z`` epoch (audit L7) instead of the
        analysis time, and a downstream CTI consumer would trust that bogus
        date. The model cannot know the wall clock, so its timestamps are never
        authoritative; overwrite them with the render time (matching every
        renderer-produced SDO, which already uses ``get_utcnow``). Object ids
        are left untouched so intra-bundle relationship refs stay valid.
        """
        now = get_utcnow()
        for obj in objects:
            if hasattr(obj, "created"):
                obj.created = now
            if hasattr(obj, "modified"):
                obj.modified = now

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


def _accept_string_ioc(ioc: StringIOC, pattern: str, file_name_kept: int) -> bool:
    """Wave 4 Step 5: gate StringIOC → Indicator emission.

    Mirrors :func:`maljan.agents.judge_postprocess._admit_indicator` so the
    extended renderer can't bypass the J-02 noise floor. Mocking out the
    LLM (or any judge bundle path) no longer means the bundle ships with
    NDK build paths / bundled bytecode class refs / random short strings.
    """
    stripped = pattern.lstrip()
    value = (ioc.value or "").strip()

    # URLs: denylist developer/build hosts.
    if stripped.startswith("[url:value"):
        host = _extract_url_host(value)
        if host and any(host.endswith(d) or d in host for d in URL_DENY_HOSTS):
            return False
        return True

    # file:name: acceptance-based admission + per-report cap.
    if stripped.startswith("[file:name"):
        if file_name_kept >= MAX_FILE_NAME_INDICATORS:
            return False
        if not value:
            return False
        if COMPILE_ARTIFACT_RE.search(value):
            return False
        if FOREIGN_CLASS_REF_RE.match(value):
            return False
        return _looks_like_real_path(value)

    return True


def _extract_url_host(raw_url: str) -> str | None:
    if not raw_url:
        return None
    try:
        from urllib.parse import urlparse

        parsed = urlparse(raw_url)
        if parsed.hostname:
            return parsed.hostname.lower()
    except (ValueError, TypeError):
        pass
    return None


def _looks_like_real_path(value: str) -> bool:
    lit_lower = value.lower()
    for ext in IOC_FILE_EXTENSIONS:
        if lit_lower.endswith(ext):
            return True
    for prefix in IOC_OS_RESOURCE_PREFIXES:
        if value.startswith(prefix):
            return True
    return False


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
