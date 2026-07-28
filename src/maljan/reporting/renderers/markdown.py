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
            # The composer runs by default (`composer_enabled = True`) and
            # spends an LLM call per prose section. Until 2026-07-28 no renderer
            # read a single field it wrote, so every one of those calls was
            # billed and discarded. These four sections are that output.
            self._safe_section("intro_background", lambda: self._section_intro_background(report)),
            self._safe_section(
                "technical_analysis", lambda: self._section_technical_analysis(report)
            ),
            self._safe_section("c2_channels", lambda: self._section_c2_channels(report)),
            self._safe_section("conclusion", lambda: self._section_conclusion(report)),
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
        # Extracted since the model existed and printed nowhere. It is what
        # lets a reader disagree with `file_type`: a .doc whose first bytes are
        # `4d5a` is the finding, and the type string alone hides it.
        if ident.magic_bytes:
            lines.append(f"| Magic bytes | `{ident.magic_bytes}` |")
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

        if static.packer_matches:
            lines.append("**Packer / protector**:")
            lines.append("")
            lines.append("| Name | Kind | Confidence | Evidence |")
            lines.append("|---|---|---|---|")
            for pm in static.packer_matches[:6]:
                evidence = ", ".join(f"`{e}`" for e in (pm.get("evidence") or [])[:4]) or "-"
                lines.append(
                    f"| {pm.get('name', '?')} | {pm.get('kind', '-')} | "
                    f"{float(pm.get('confidence') or 0.0):.2f} ({pm.get('method', '-')}) "
                    f"| {evidence} |"
                )
            lines.append("")
        elif static.packer_hint:
            lines.append(f"**Packer hint**: {static.packer_hint}")
            lines.append("")
        if static.obfuscation_indicators:
            lines.append("**Obfuscation indicators**: " + ", ".join(static.obfuscation_indicators))
            lines.append("")
        if static.pdb_path:
            lines.append(f"**Debug PDB path**: `{static.pdb_path}`")
            lines.append("")

        if static.api_capabilities:
            ordered = sorted(static.api_capabilities.items(), key=lambda kv: -kv[1])
            lines.append(
                "**Import capability profile**: "
                + ", ".join(f"{cat} ×{count}" for cat, count in ordered)
            )
            lines.append("")

        if static.api_technique_hits:
            lines.append("### ATT&CK Techniques Derived From Imports")
            lines.append("")
            lines.append(
                "_Deterministic: each row is the import table alone — no sandbox, "
                "no model. This is the audit trail behind the capability matrix._"
            )
            lines.append("")
            lines.append("| Technique | Name | Confidence | Imports |")
            lines.append("|---|---|---|---|")
            for hit in sorted(
                static.api_technique_hits,
                key=lambda h: -float(h.get("confidence") or 0.0),
            )[:25]:
                apis = ", ".join(f"`{a}`" for a in (hit.get("matched_apis") or [])[:6])
                lines.append(
                    f"| {hit.get('technique_id', '?')} | {hit.get('name', '-')} "
                    f"| {float(hit.get('confidence') or 0.0):.2f} | {apis} |"
                )
            lines.append("")

        if static.sections:
            lines.append("### Sections")
            lines.append("")
            # Raw offset is PointerToRawData. It was extracted and stored from
            # the start and printed nowhere, which made the carved-payload table
            # below harder to use than it needed to be: those rows carry a file
            # offset, and without this column there is nothing to match it
            # against to say which section a payload came out of.
            lines.append("| Name | VA | Virtual size | Raw size | Raw offset | Entropy | Notes |")
            lines.append("|---|---|---|---|---|---|---|")
            for sec in static.sections:
                flag = "[HIGH ENTROPY]" if sec.entropy > 7.0 else ""
                if sec.is_suspicious and not flag:
                    flag = "[SUSPICIOUS]"
                raw_offset = f"0x{sec.raw_offset:x}" if isinstance(sec.raw_offset, int) else "-"
                lines.append(
                    f"| `{sec.name}` | {sec.virtual_address} | {sec.virtual_size} | "
                    f"{sec.raw_size} | {raw_offset} | {sec.entropy:.2f} | {flag} |"
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
            carved = [r for r in static.embedded_resources if r.get("carved")]
            plain = [r for r in static.embedded_resources if not r.get("carved")]

            # Carved payloads get a table of their own. They are a different
            # kind of finding from a resource directory entry — a nested
            # executable is the actual malware in a dropper — and a reader needs
            # the offset and hash to go and look at it, neither of which
            # survives a one-line bullet.
            if carved:
                lines.append("**Carved payloads** — nested executables found inside the sample:")
                lines.append("")
                lines.append("| Type | Location | Size | Entropy | SHA-256 |")
                lines.append("|---|---|---|---|---|")
                for res in carved[:10]:
                    lines.append(
                        f"| {res.get('type', '?')} | `{res.get('id', '?')}` "
                        f"({res.get('source', '-')}) | {res.get('size', 0)} bytes "
                        f"| {res.get('entropy', 0.0)} | `{str(res.get('sha256', ''))[:32]}…` |"
                    )
                lines.append("")

            for res in plain[:20]:
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
            lines.append("| FQDN | Suspicious | Reason | Resolved IPs | Queried by |")
            lines.append("|---|---|---|---|---|")
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
        # The evidence behind the family name on a run with no sandbox. Without
        # it the reader sees "Family: CobaltStrike" and has nothing to check it
        # against — which is the same position a sandbox-derived family left
        # them in, and the reason to show the markers rather than just the
        # conclusion.
        if attr.tool_artifact_matches:
            lines.append("")
            lines.append("**Offensive-tool artifacts (static byte markers):**")
            lines.append("")
            lines.append("| Tool | Family | Kind | Confidence | Markers |")
            lines.append("|---|---|---|---|---|")
            for match in attr.tool_artifact_matches[:10]:
                markers = ", ".join(f"`{m}`" for m in (match.get("markers") or [])[:4]) or "-"
                lines.append(
                    f"| {match.get('tool', '?')} | {match.get('family', '-')} "
                    f"| {match.get('kind', '-')} "
                    f"| {float(match.get('confidence') or 0.0):.2f} | {markers} |"
                )
        # The other three evidence sources behind the same name. All three were
        # produced by the judge, carried through AnalysisState and stored on the
        # model, and printed by no renderer — so the report showed a family and
        # withheld every deterministic reason for it. Function-hash matches are
        # the strongest of the four: an exact normalized-opcode hash shared with
        # a previously analysed sample is code reuse, not resemblance.
        if attr.function_hash_matches:
            lines.append("")
            lines.append("**Function-hash matches (shared code with prior samples):**")
            lines.append("")
            lines.append("| Family | Confidence | Shared functions | Example functions |")
            lines.append("|---|---|---|---|")
            for match in attr.function_hash_matches[:10]:
                examples = (
                    ", ".join(f"`{f}`" for f in (match.get("example_functions") or [])[:3]) or "-"
                )
                lines.append(
                    f"| {match.get('family', '?')} "
                    f"| {float(match.get('confidence') or 0.0):.2f} "
                    f"| {match.get('shared_functions', '-')} | {examples} |"
                )
        if attr.family_rag_candidates:
            lines.append("")
            lines.append("**Family-feature RAG candidates (static-feature similarity):**")
            lines.append("")
            lines.append("| Family | Similarity | Category | Samples in catalog |")
            lines.append("|---|---|---|---|")
            for cand in attr.family_rag_candidates[:10]:
                lines.append(
                    f"| {cand.get('family', '?')} "
                    f"| {float(cand.get('similarity') or 0.0):.3f} "
                    f"| {cand.get('malware_category', '-')} "
                    f"| {cand.get('sample_count', '-')} |"
                )
        if attr.attck_case_candidates:
            lines.append("")
            lines.append("**ATT&CK case priors (techniques recurring in similar prior cases):**")
            lines.append("")
            lines.append(
                "_Advisory only — these are priors from past runs, not evidence from this sample._"
            )
            lines.append("")
            lines.append("| Technique | Support | Similarity |")
            lines.append("|---|---|---|")
            for cand in attr.attck_case_candidates[:10]:
                lines.append(
                    f"| {cand.get('technique_id', '?')} "
                    f"| {cand.get('support', '-')} "
                    f"| {float(cand.get('similarity') or 0.0):.3f} |"
                )
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

    # ------------------------------------------------------------------
    # Composed long-form sections
    # ------------------------------------------------------------------
    # Each returns "" when its field is empty, and `render` drops empty
    # sections — so a run with the composer disabled produces exactly the
    # report it produced before.

    # Every composed section carries this. The first report rendered after the
    # composer output became visible asserted the sample was a .NET executable
    # calling `_CorExeMain` from `mscoree.dll`; the same report's identity
    # section said Microsoft Visual C++ and its import table contained no
    # `mscoree` at all. The prose is written from evidence bundles and is not
    # checked against the report it sits in, and a reader has no way to know
    # that from the prose alone — it reads exactly like the deterministic
    # sections above it. Same convention as the "(unverified)" family badge.
    _COMPOSED_NOTE = (
        "_Composed by the report LLM from the evidence bundles. Not "
        "cross-checked against the deterministic sections above — verify "
        "against them before quoting._"
    )

    def _section_intro_background(self, report: MalwareReport) -> str:
        if not report.intro_background:
            return ""
        return (
            "## Introduction & Background\n\n"
            f"{self._COMPOSED_NOTE}\n\n{report.intro_background.strip()}"
        )

    def _section_technical_analysis(self, report: MalwareReport) -> str:
        ta = report.technical_analysis
        if ta is None:
            return ""
        lines: list[str] = ["## Technical Analysis", "", self._COMPOSED_NOTE, ""]

        for attr in (
            "packing_obfuscation",
            "string_resolution",
            "discovery",
            "persistence_detail",
            "message_packet_structure",
            "evasion_antiforensics",
        ):
            sub = getattr(ta, attr, None)
            if sub is None or not sub.body:
                continue
            lines.append(f"### {sub.title or attr.replace('_', ' ').title()}")
            lines.append("")
            lines.append(sub.body.strip())
            if sub.evidence_refs:
                # Without these the prose is indistinguishable from an LLM
                # writing plausibly, which is the failure the whole grounding
                # apparatus exists to prevent.
                refs = ", ".join(f"`{r}`" for r in sub.evidence_refs[:8])
                lines.append("")
                lines.append(f"_Evidence: {refs}_")
            lines.append("")

        if ta.cli_flags:
            lines.append("### Command-line Flags")
            lines.append("")
            lines.append("| Flag | Meaning |")
            lines.append("|---|---|")
            for flag in ta.cli_flags[:20]:
                lines.append(f"| `{flag.flag}` | {flag.description or '-'} |")
            lines.append("")

        spk = ta.service_process_kill
        if spk is not None and (spk.kill_list or spk.white_list or spk.mechanism):
            lines.append("### Services & Processes Terminated")
            lines.append("")
            if spk.mechanism:
                lines.append(f"**Mechanism**: {spk.mechanism}")
                lines.append("")
            if spk.kill_list:
                lines.append("**Kill list**: " + ", ".join(f"`{x}`" for x in spk.kill_list[:30]))
                lines.append("")
            if spk.white_list:
                # The exclusions are often the more identifying half: a list
                # that spares the attacker's own tooling names it.
                lines.append("**Spared**: " + ", ".join(f"`{x}`" for x in spk.white_list[:30]))
                lines.append("")

        if ta.shadow_copy_destruction:
            lines.append("### Shadow Copy Destruction")
            lines.append("")
            for cmd in ta.shadow_copy_destruction[:10]:
                lines.append(f"- `{cmd}`")
            lines.append("")

        enc = ta.encryption_scheme
        if enc is not None:
            rows = [
                ("Cipher", enc.cipher),
                ("Mode", enc.mode),
                ("Library", enc.library),
                ("Key source", enc.key_source),
                ("Key management", enc.key_management),
                ("IV", enc.iv),
                ("File marker", enc.file_marker),
                ("Extension", enc.extension),
                ("Partial-encryption threshold", enc.partial_threshold),
                (
                    "Per-file key",
                    None if enc.per_file_key is None else ("yes" if enc.per_file_key else "no"),
                ),
            ]
            present = [(label, value) for label, value in rows if value]
            if present:
                lines.append("### Encryption Scheme")
                lines.append("")
                lines.append("| Property | Value |")
                lines.append("|---|---|")
                for label, value in present:
                    lines.append(f"| {label} | {value} |")
                lines.append("")

        note = ta.ransom_note
        if note is not None and (note.filename or note.verbatim_content or note.sections):
            lines.append("### Ransom Note")
            lines.append("")
            if note.filename:
                lines.append(f"**Filename**: `{note.filename}`")
                lines.append("")
            if note.company_id_hash:
                lines.append(f"**Victim/company ID**: `{note.company_id_hash}`")
                lines.append("")
            if note.verbatim_content:
                # Fenced, not inlined: note text routinely contains markdown
                # characters and onion URLs, and the verbatim wording is what
                # links one incident to another.
                lines.append("```text")
                lines.append(note.verbatim_content.strip()[:4000])
                lines.append("```")
                lines.append("")
            elif note.sections:
                for part in note.sections[:10]:
                    lines.append(f"- {part}")
                lines.append("")

        body = "\n".join(lines).rstrip()
        # Heading and note alone mean the composer produced nothing usable.
        empty = "\n".join(["## Technical Analysis", "", self._COMPOSED_NOTE]).rstrip()
        return "" if body == empty else body

    def _section_c2_channels(self, report: MalwareReport) -> str:
        if not report.c2_channels:
            return ""
        lines = ["## C2 Channels", ""]
        lines.append("| Channel | Protocol | Encryption | Packet layout | Beacon format |")
        lines.append("|---|---|---|---|---|")
        for ch in report.c2_channels[:10]:
            lines.append(
                f"| {ch.name} | {ch.protocol or '-'} | {ch.encryption or '-'} "
                f"| {ch.packet_layout or '-'} | {ch.beacon_format or '-'} |"
            )
        return "\n".join(lines)

    def _section_conclusion(self, report: MalwareReport) -> str:
        concl = report.conclusion
        if concl is None or not concl.text:
            return ""
        lines = ["## Conclusion", "", self._COMPOSED_NOTE, ""]
        if concl.sophistication_rating:
            lines.append(f"**Sophistication**: {concl.sophistication_rating}")
            lines.append("")
        lines.append(concl.text.strip())
        return "\n".join(lines)

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
    # DGA score and the homograph verdict were computed by network_extractor
    # and rendered nowhere. Folded into the reason column rather than given
    # their own columns, because they are only ever interesting when they fire
    # and an always-present "DGA: -" column would push the resolved IPs off the
    # side of the table for every ordinary domain.
    notes = [d.reason] if d.reason else []
    if isinstance(d.dga_score, int | float) and d.dga_score > 0:
        notes.append(f"DGA score {float(d.dga_score):.2f}")
    if d.is_punycode:
        # A punycode label that renders as a familiar brand is the whole point
        # of registering it; saying only "punycode" would bury the finding.
        target = f" impersonating `{d.homograph_target}`" if d.homograph_target else ""
        notes.append(f"punycode{target}")
    reason = "; ".join(notes) or "-"
    ips = ", ".join(d.resolved_ips[:4]) or "-"
    # Which process asked. Only populated from sandbox telemetry, so usually
    # "-" here — but when a dropped child resolves the C2 rather than the
    # parent, this column is the whole story and it was not being printed.
    pids = ", ".join(str(p) for p in d.queried_pids[:6]) or "-"
    return f"| `{d.fqdn}` | {flag} | {reason} | {ips} | {pids} |"


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
