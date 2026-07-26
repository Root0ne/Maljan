"""Render a ``MalwareReport`` to GitHub-flavoured markdown.

The renderer is pure-string — no markdown library is pulled in. Section order
is fixed and documented in ``docs/REPORTING.md``; tests pin the section
headings so renderer regressions surface immediately.

Severity badge convention: text in square brackets (``[CRITICAL]``,
``[HIGH]``, ...). Emoji are intentionally avoided so the output renders
cleanly on terminals, PDFs and ticket systems alike.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import (
    DefensiveRecommendation,
    DetectionRule,
    MalwareReport,
    NetworkDomain,
    NetworkIP,
    NetworkURL,
    PersistenceMechanism,
    ProcessNode,
    RegistryMod,
    SandboxSignature,
    SeverityAssessment,
    StringIOC,
)


class MarkdownRenderer:
    """Render a complete ``MalwareReport`` as a single markdown string."""

    # Section order is kept in one place; each ``_section_*`` call returns
    # a block with one or two headings.

    def render(self, report: MalwareReport) -> str:
        # Wave 9 (2026-05-29): each section is wrapped in _safe_section so a
        # single malformed subtree (e.g. degraded-mode runs where
        # ``dynamic.notable_apis`` contains non-dict entries) cannot 500 the
        # entire ``/reports/{id}/markdown`` endpoint. The 2026-05-29 Linux
        # ELF audit hit exactly this — see G-FP report f072cd22.
        sections: list[str] = [
            self._safe_section("header", lambda: self._section_header(report)),
            self._safe_section("identity", lambda: self._section_identity(report)),
            self._safe_section("severity", lambda: self._section_severity(report.severity)),
            self._safe_section(
                "executive_summary", lambda: self._section_executive_summary(report)
            ),
            self._safe_section(
                "capabilities_narrative",
                lambda: self._section_capabilities_narrative(report),
            ),
            self._safe_section("static_analysis", lambda: self._section_static_analysis(report)),
            self._safe_section("dynamic_behavior", lambda: self._section_dynamic_behavior(report)),
            self._safe_section("network", lambda: self._section_network(report)),
            self._safe_section(
                "persistence", lambda: self._section_persistence(report.persistence)
            ),
            self._safe_section(
                "attack_matrix",
                lambda: self._section_attack_matrix(report),
            ),
            self._safe_section("attribution", lambda: self._section_attribution(report)),
            self._safe_section(
                "detection_signatures",
                lambda: self._section_detection_signatures(report.detection_signatures),
            ),
            self._safe_section(
                "defensive_recommendations",
                lambda: self._section_defensive_recommendations(report.defensive_recommendations),
            ),
            self._safe_section("references", lambda: self._section_references(report)),
            self._safe_section(
                "run_summary", lambda: self._section_run_summary(report.run_summary)
            ),
        ]
        return "\n\n".join(s.rstrip() for s in sections if s).rstrip() + "\n"

    @staticmethod
    def _safe_section(name: str, fn: Callable[[], str]) -> str:
        """Run a section renderer, return a stub on failure."""
        try:
            return fn()
        except Exception:  # noqa: BLE001 — markdown is non-critical UX surface
            logger.exception("markdown_renderer: section '%s' raised; substituting stub.", name)
            return f"<!-- section '{name}' rendering failed — see server logs -->"

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _section_header(self, report: MalwareReport) -> str:
        badge = self._verdict_badge(report.verdict)
        sha256 = report.identity.hashes.sha256 or "unknown"
        generated = report.generated_at.isoformat()
        header = (
            f"# Malware Analysis Report\n\n"
            f"**Verdict**: {badge}  \n"
            f"**Sample SHA256**: `{sha256}`  \n"
            f"**Generated**: {generated}  \n"
            f"**Overall Confidence**: {report.overall_confidence:.2f}"
        )
        if report.degraded_mode:
            reasons = "; ".join(report.degradation_reasons) or "low analyst/sandbox data"
            header += (
                "\n\n> **[DEGRADED RUN]** This analysis ran with limited data, so the "
                "verdict, confidence and severity below should be treated as tentative "
                f"and corroborated manually.  \n> Reasons: {reasons}"
            )
        return header

    def _section_identity(self, report: MalwareReport) -> str:
        ident = report.identity
        hashes = ident.hashes
        lines = ["## Sample Identification", ""]
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f"| File name | `{ident.file_name or 'unknown'}` |")
        lines.append(f"| File size | {ident.file_size_bytes:,} bytes |")
        lines.append(f"| File type | {ident.file_type} |")
        if ident.mime_type:
            lines.append(f"| MIME | {ident.mime_type} |")
        if ident.compile_timestamp:
            lines.append(f"| Compile timestamp | {ident.compile_timestamp.isoformat()} |")
        if ident.language_or_compiler:
            lines.append(f"| Language / compiler | {ident.language_or_compiler} |")
        lines.append(f"| Signed | {'yes' if ident.signing.is_signed else 'no'} |")
        if ident.signing.signer_subject:
            lines.append(f"| Signer | {ident.signing.signer_subject} |")
        lines.append("")
        lines.append("**Hashes:**")
        lines.append("")
        lines.append("| Algorithm | Digest |")
        lines.append("|---|---|")
        for algo, value in (
            ("MD5", hashes.md5),
            ("SHA1", hashes.sha1),
            ("SHA256", hashes.sha256),
            ("SHA512", hashes.sha512),
            ("imphash", hashes.imphash),
            ("ssdeep", hashes.ssdeep),
            ("tlsh", hashes.tlsh),
        ):
            if value:
                lines.append(f"| {algo} | `{value}` |")
        return "\n".join(lines)

    def _section_severity(self, severity: SeverityAssessment) -> str:
        lines = ["## Severity & Impact", ""]
        lines.append(f"**Rating**: `[{severity.rating.upper()}]` ({severity.overall_score:.1f}/10)")
        if severity.business_impact:
            lines.extend(["", severity.business_impact])
        if severity.affected_platforms:
            lines.extend(["", "**Affected platforms**: " + ", ".join(severity.affected_platforms)])
        if severity.likely_targets:
            lines.extend(["", "**Likely targets**: " + ", ".join(severity.likely_targets)])
        return "\n".join(lines)

    def _section_executive_summary(self, report: MalwareReport) -> str:
        body = report.executive_summary.strip() or "_Pending narrative generation._"
        return f"## Executive Summary\n\n{body}"

    def _section_capabilities_narrative(self, report: MalwareReport) -> str:
        lines = ["## Capabilities Narrative", ""]
        if not report.capabilities_narrative:
            lines.append("_No narrative generated._")
        else:
            for paragraph in report.capabilities_narrative:
                lines.append(paragraph.strip())
                lines.append("")
        return "\n".join(lines).rstrip()

    def _section_static_analysis(self, report: MalwareReport) -> str:
        static = report.static
        lines = ["## Static Analysis", ""]
        if static is None:
            lines.append("_No static analysis available (sample bytes unreachable)._")
            return "\n".join(lines)

        if static.packer_hint:
            lines.append(f"**Packer hint**: {static.packer_hint}")
            lines.append("")
        if static.obfuscation_indicators:
            lines.append("**Obfuscation indicators**: " + ", ".join(static.obfuscation_indicators))
            lines.append("")

        if static.sections:
            lines.append("### Sections")
            lines.append("")
            lines.append("| Name | VA | Virtual size | Raw size | Entropy | Notes |")
            lines.append("|---|---|---|---|---|---|")
            for sec in static.sections:
                flag = "[HIGH ENTROPY]" if sec.entropy > 7.0 else ""
                if sec.is_suspicious and not flag:
                    flag = "[SUSPICIOUS]"
                lines.append(
                    f"| `{sec.name}` | {sec.virtual_address} | {sec.virtual_size} | "
                    f"{sec.raw_size} | {sec.entropy:.2f} | {flag} |"
                )
            lines.append("")

        suspicious_imports = [i for i in static.imports if i.is_suspicious]
        if suspicious_imports:
            lines.append("### Suspicious Imports")
            lines.append("")
            lines.append("| DLL | Function | Category |")
            lines.append("|---|---|---|")
            for imp in suspicious_imports[:40]:
                lines.append(f"| `{imp.dll}` | `{imp.function}` | {imp.category or '-'} |")
            lines.append("")

        if static.exports:
            lines.append("### Exports")
            lines.append("")
            for exp in static.exports[:30]:
                lines.append(f"- `{exp}`")
            lines.append("")

        if static.interesting_strings:
            lines.append("### Indicator Strings")
            lines.append("")
            lines.append("| Kind | Value |")
            lines.append("|---|---|")
            for ioc in static.interesting_strings[:50]:
                lines.append(f"| {ioc.kind} | `{_truncate(ioc.value, 100)}` |")
            lines.append("")

        if static.embedded_resources:
            lines.append("### Embedded Resources")
            lines.append("")
            for res in static.embedded_resources[:20]:
                kind = res.get("type") or res.get("kind") or "resource"
                size = res.get("size")
                size_part = f" ({size} bytes)" if size else ""
                lines.append(f"- {kind}{size_part}")
            lines.append("")

        return "\n".join(lines).rstrip()

    def _section_dynamic_behavior(self, report: MalwareReport) -> str:
        dyn = report.dynamic
        lines = ["## Dynamic Behavior", ""]
        if dyn is None:
            lines.append("_No sandbox dynamic data available._")
            return "\n".join(lines)

        if dyn.process_tree:
            lines.append("### Process Tree")
            lines.append("")
            lines.append("```")
            for root in dyn.process_tree:
                lines.extend(_process_tree_lines(root, 0))
            lines.append("```")
            lines.append("")

        if dyn.registry_mods:
            lines.append("### Registry Modifications")
            lines.append("")
            lines.append("| Hive | Key | Value | Operation |")
            lines.append("|---|---|---|---|")
            for reg in dyn.registry_mods[:40]:
                lines.append(_registry_row(reg))
            lines.append("")

        if dyn.file_operations:
            lines.append("### File Operations")
            lines.append("")
            lines.append("| Path | Op | API |")
            lines.append("|---|---|---|")
            for op in dyn.file_operations[:40]:
                if not isinstance(op, dict):
                    continue
                lines.append(
                    f"| `{_truncate(str(op.get('path', '')), 80)}` | "
                    f"{op.get('operation', '-')} | {op.get('api', '-')} |"
                )
            lines.append("")

        if dyn.notable_apis:
            lines.append("### Notable APIs")
            lines.append("")
            lines.append("| API | Category | Process | Count |")
            lines.append("|---|---|---|---|")
            for api in dyn.notable_apis[:20]:
                if not isinstance(api, dict):
                    continue
                lines.append(
                    f"| `{api.get('api', '-')}` | {api.get('category', '-')} | "
                    f"`{api.get('process', '-')}` | {api.get('count', 0)} |"
                )
            lines.append("")

        if dyn.sandbox_signatures:
            lines.append("### Sandbox Signatures")
            lines.append("")
            lines.append("| Name | Severity | ATT&CK | Marks |")
            lines.append("|---|---|---|---|")
            for sig in dyn.sandbox_signatures[:30]:
                lines.append(_signature_row(sig))
            lines.append("")

        return "\n".join(lines).rstrip()

    def _section_network(self, report: MalwareReport) -> str:
        net = report.network
        lines = ["## Network IOCs", ""]
        if net is None:
            lines.append("_No network observations available._")
            return "\n".join(lines)

        if net.domains:
            lines.append("### Domains")
            lines.append("")
            lines.append("| FQDN | Suspicious | Reason | Resolved IPs |")
            lines.append("|---|---|---|---|")
            for d in net.domains[:40]:
                lines.append(_domain_row(d))
            lines.append("")

        if net.ips:
            lines.append("### IPs")
            lines.append("")
            lines.append("| Address | Port | Transport | ASN | Geo |")
            lines.append("|---|---|---|---|---|")
            for ip in net.ips[:40]:
                lines.append(_ip_row(ip))
            lines.append("")

        if net.urls:
            lines.append("### URLs")
            lines.append("")
            lines.append("| Method | URL | Status | User-Agent |")
            lines.append("|---|---|---|---|")
            for url in net.urls[:40]:
                lines.append(_url_row(url))
            lines.append("")

        if net.user_agents:
            lines.append("### User Agents")
            lines.append("")
            for ua in net.user_agents[:20]:
                lines.append(f"- `{ua}`")
            lines.append("")

        if net.ja3_fingerprints:
            lines.append("### JA3 Fingerprints")
            lines.append("")
            for ja3 in net.ja3_fingerprints[:20]:
                lines.append(f"- `{ja3}`")
            lines.append("")

        if net.ja3s_fingerprints:
            lines.append("### JA3S Fingerprints")
            lines.append("")
            for ja3s in net.ja3s_fingerprints[:20]:
                lines.append(f"- `{ja3s}`")
            lines.append("")

        return "\n".join(lines).rstrip()

    def _section_persistence(self, mechanisms: list[PersistenceMechanism]) -> str:
        lines = ["## Persistence Mechanisms", ""]
        if not mechanisms:
            lines.append("_No persistence mechanisms detected._")
            return "\n".join(lines)
        lines.append("| Kind | Target | Payload | ATT&CK |")
        lines.append("|---|---|---|---|")
        for mech in mechanisms[:40]:
            lines.append(
                f"| {mech.kind} | `{_truncate(mech.target, 80)}` | "
                f"`{_truncate(mech.payload, 80)}` | {mech.technique_id or '-'} |"
            )
        return "\n".join(lines)

    def _section_attack_matrix(self, report: MalwareReport) -> str:
        """Single ATT&CK section: the summary table + per-technique evidence.

        2026-07 audit (Bulgu #15): the report previously carried two H2 sections
        ("MITRE ATT&CK Matrix" and "Capability Matrix (evidence)") that listed
        the same techniques twice. They are merged here — one table, with the
        evidence quotes rendered underneath as an ``### Evidence`` subsection —
        so each technique appears once.
        """
        cells = report.capability_matrix
        mappings = report.ttp_mappings
        lines = ["## MITRE ATT&CK Matrix", ""]
        if not cells and not mappings:
            lines.append("_No ATT&CK techniques mapped._")
            return "\n".join(lines)

        if cells:
            lines.append("| Tactic | Technique | Confidence | Layers |")
            lines.append("|---|---|---|---|")
            for cell in cells:
                tactic = f"{cell.tactic_name} ({cell.tactic})" if cell.tactic else cell.tactic_name
                layers = ", ".join(cell.contributing_layers) or "-"
                lines.append(
                    f"| {tactic} | {cell.technique_id} {cell.technique_name} | "
                    f"{cell.confidence:.2f} | {layers} |"
                )
            lines.append("")

        if mappings:
            lines.append("### Evidence")
            lines.append("")
            for mapping in mappings:
                corroborated = "corroborated" if mapping.is_corroborated else "single-source"
                lines.append(
                    f"**{mapping.technique_id} — {mapping.technique_name}**  "
                    f"`(conf={mapping.confidence:.2f}, {corroborated})`"
                )
                lines.append("")
                for quote in mapping.evidence_quotes[:6]:
                    lines.append(f"> {_truncate(quote, 240)}")
                lines.append("")
        return "\n".join(lines).rstrip()

    def _section_attribution(self, report: MalwareReport) -> str:
        attr = report.attribution
        lines = ["## Family Attribution", ""]
        # 2026-07 audit (Bulgu #6/#7): the behavioural *category* is a distinct
        # classification, never a family — do NOT fall back to it as the family
        # name (that produced the contradictory "Family: dropper (0.00)" line).
        family = attr.family
        if not family or str(family).lower() == "unknown":
            # No family candidate at all — render plainly, without a noisy
            # "confidence 0.00" that reads as an (un)confident verdict.
            lines.append("**Family**: not determined")
        else:
            grounded_note = (
                ""
                if attr.family_grounded
                else " _(ungrounded — no YARA/deterministic corroboration)_"
            )
            lines.append(
                f"**Family**: {family} (confidence {attr.family_confidence:.2f}){grounded_note}"
            )
        # Surface the behavioural category on its own line so the reader sees the
        # classification without mistaking it for a family attribution.
        if report.malware_category and str(report.malware_category).lower() != "unknown":
            lines.append(
                f"**Category**: {report.malware_category} _(behavioural class, not a family)_"
            )
        if attr.actor:
            lines.append(f"**Actor**: {attr.actor}")
        if attr.campaign:
            lines.append(f"**Campaign**: {attr.campaign}")
        if attr.similar_samples:
            lines.append("")
            lines.append("**Similar samples (LTM nearest neighbours):**")
            lines.append("")
            lines.append("| SHA256 | Distance | Source |")
            lines.append("|---|---|---|")
            for sample in attr.similar_samples[:10]:
                sha = str(sample.get("sha256", "?"))
                dist = sample.get("distance")
                dist_str = f"{dist:.3f}" if isinstance(dist, int | float) else "-"
                lines.append(f"| `{sha}` | {dist_str} | {sample.get('source', '-')} |")
        return "\n".join(lines)

    def _section_detection_signatures(self, rules: list[DetectionRule]) -> str:
        lines = ["## Detection Signatures", ""]
        if not rules:
            lines.append("_No detection signatures generated._")
            return "\n".join(lines)
        for rule in rules:
            lines.append(f"### {rule.kind.upper()} — `{rule.name}`")
            if rule.compile_error:
                lines.append(f"_Compile error: {rule.compile_error}_")
            lines.append("")
            fence = rule.kind if rule.kind in {"yara", "sigma"} else ""
            lines.append(f"```{fence}")
            lines.append(rule.body.rstrip())
            lines.append("```")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _section_defensive_recommendations(self, recs: list[DefensiveRecommendation]) -> str:
        lines = ["## Defensive Recommendations", ""]
        if not recs:
            lines.append("_No defensive recommendations._")
            return "\n".join(lines)
        priority_order = {"P0": 0, "P1": 1, "P2": 2}
        ordered = sorted(recs, key=lambda r: priority_order.get(r.priority, 9))
        for rec in ordered:
            lines.append(f"### [{rec.priority}] {rec.category}")
            lines.append("")
            lines.append(f"**Action**: {rec.action}")
            lines.append("")
            lines.append(f"_Rationale_: {rec.rationale}")
            lines.append("")
        return "\n".join(lines).rstrip()

    def _section_references(self, report: MalwareReport) -> str:
        lines = ["## References", ""]
        if not report.references:
            lines.append("_No external references._")
            return "\n".join(lines)
        for ref in report.references:
            note = f" — {ref.note}" if ref.note else ""
            lines.append(f"- [{ref.source}]({ref.url}){note}")
        return "\n".join(lines)

    def _section_run_summary(self, run_summary: dict[str, Any]) -> str:
        # ``run_summary`` is the serialised RunSummary dict — embed a flat
        # version. Full markdown rendering is provided by RunSummary itself but
        # we may only have a dict here.
        lines = ["## Run Summary", ""]
        if not run_summary:
            lines.append("_Run summary unavailable._")
            return "\n".join(lines)

        elapsed = run_summary.get("elapsed_seconds")
        if elapsed is not None:
            lines.append(f"- Elapsed: {float(elapsed):.1f}s")
        verdict = run_summary.get("final_decision")
        if verdict:
            lines.append(f"- Verdict: {verdict}")
        negotiation = run_summary.get("negotiation") or {}
        if negotiation:
            rounds = negotiation.get("rounds_completed")
            reason = negotiation.get("termination_reason")
            final_conf = negotiation.get("final_confidence")
            if rounds is not None:
                lines.append(f"- Negotiation rounds: {rounds}")
            if reason:
                lines.append(f"- Termination reason: `{reason}`")
            if final_conf is not None:
                try:
                    lines.append(f"- Final confidence: {float(final_conf):.3f}")
                except (TypeError, ValueError):
                    pass
        cascade = run_summary.get("cascade") or {}
        if cascade:
            total = cascade.get("total_techniques")
            corr = cascade.get("corroborated_count")
            cons = cascade.get("consensus_count")
            if total is not None:
                lines.append(
                    f"- TTPs: {total} total, {corr or 0} corroborated, {cons or 0} consensus"
                )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _verdict_badge(verdict: str) -> str:
        return f"`[{verdict.upper()}]`"


# ---------------------------------------------------------------------------
# Module-level helpers (kept private to keep MarkdownRenderer focused)
# ---------------------------------------------------------------------------


def _truncate(value: str, length: int) -> str:
    if value is None:
        return ""
    s = str(value)
    if len(s) <= length:
        return s
    return s[: length - 1] + "…"


def _process_tree_lines(node: ProcessNode, depth: int) -> list[str]:
    indent = "  " * depth
    prefix = "└─ " if depth > 0 else ""
    label = node.name or f"pid={node.pid}"
    extra = f"  ({node.command_line})" if node.command_line else ""
    line = f"{indent}{prefix}pid={node.pid} ppid={node.ppid} {label}{extra}"
    out = [line]
    if node.injected_into:
        out.append(f"{indent}    [injected_into={', '.join(str(p) for p in node.injected_into)}]")
    for child in node.children:
        out.extend(_process_tree_lines(child, depth + 1))
    return out


def _registry_row(reg: RegistryMod) -> str:
    value_name = reg.value_name or "-"
    return (
        f"| {reg.hive} | `{_truncate(reg.key, 80)}` | `{_truncate(value_name, 40)}` | "
        f"{reg.operation} |"
    )


def _signature_row(sig: SandboxSignature) -> str:
    ttps = ", ".join(sig.technique_ids) if sig.technique_ids else "-"
    desc = _truncate(sig.description or sig.name, 60)
    return f"| {sig.name} ({desc}) | {sig.severity} | {ttps} | {len(sig.marks)} |"


def _domain_row(d: NetworkDomain) -> str:
    flag = "yes" if d.is_suspicious else "no"
    reason = d.reason or "-"
    ips = ", ".join(d.resolved_ips[:4]) or "-"
    return f"| `{d.fqdn}` | {flag} | {reason} | {ips} |"


def _ip_row(ip: NetworkIP) -> str:
    return (
        f"| `{ip.address}` | {ip.port or '-'} | {ip.transport or '-'} | "
        f"{ip.asn or '-'} | {ip.geo or '-'} |"
    )


def _url_row(u: NetworkURL) -> str:
    return (
        f"| {u.method} | `{_truncate(u.url, 120)}` | {u.status or '-'} | "
        f"{_truncate(u.user_agent or '-', 60)} |"
    )


# Suppress unused-import warnings for type-only imports.
_ = StringIOC
