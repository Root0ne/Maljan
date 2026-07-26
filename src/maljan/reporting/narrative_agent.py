"""Single-round LLM narrative generation for ``MalwareReport``.

The deterministic ``MalwareReportBuilder`` produces every section of the
report except the prose:

  - ``executive_summary``        — one paragraph SOC-handover style summary
  - ``capabilities_narrative``   — 3-5 paragraphs describing each kill-chain
                                   capability with ATT&CK references
  - ``defensive_recommendations``— 3-8 P0/P1/P2 actions

``NarrativeAgent.generate()`` runs **once** and falls back gracefully on
any LLM error. The caller (``report_node``) then dispatches between
``MalwareReportBuilder.apply_narrative`` (success) and
``apply_fallback_narrative`` (failure / mock).

The implementation deliberately mirrors the structured-output pattern in
``judge_agent.py:_extract_mediator_verdict`` so the operational behaviour is
familiar to anyone debugging existing agents.
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field

from maljan.core.logger import logger
from maljan.reporting.models import DefensiveRecommendation, MalwareReport
from maljan.utils.json_cleaner import safe_parse_json

# ---------------------------------------------------------------------------
# Structured output schema
# ---------------------------------------------------------------------------


class NarrativeOutput(BaseModel):
    """LLM output schema. ``DefensiveRecommendation`` is reused as-is."""

    # ``extra="ignore"`` so a chatty LLM that produces extra metadata fields
    # (e.g. "confidence_in_narrative") does not cause validation to crash.
    model_config = ConfigDict(extra="ignore")

    executive_summary: str = Field(min_length=120, max_length=1200)
    capabilities_narrative: list[str] = Field(min_length=3, max_length=5)
    defensive_recommendations: list[DefensiveRecommendation] = Field(min_length=3, max_length=8)


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------


_SYSTEM_PROMPT = (
    "You are a senior malware reverse engineer producing a CTI analyst report. "
    "Write in calm, technical prose suitable for a SOC handover. "
    "STRICT RULES:\n"
    "1. DO NOT invent capabilities, families, or TTPs. Only describe what the "
    "deterministic evidence below supports.\n"
    "2. Every MITRE ATT&CK technique you cite must appear in parentheses with "
    "its ID, e.g. 'process injection (T1055)'.\n"
    "3. executive_summary: 120-900 characters, one paragraph, no headings. This "
    "is a verdict/impact briefing ONLY — state the classification, the severity, "
    "the single most important risk, and the containment call to action. Do NOT "
    "enumerate individual techniques or restate the capability narrative here.\n"
    "4. capabilities_narrative: 3-5 paragraphs (one item per paragraph). Each "
    "paragraph covers a single kill-chain phase or capability cluster and its "
    "supporting evidence. This is the ONLY place technique detail belongs — do "
    "NOT repeat the executive_summary, and do NOT include defensive/remediation "
    "advice here (that belongs solely in defensive_recommendations).\n"
    "5. defensive_recommendations: 3-8 entries. Priority P0 only for active "
    "C2 / exfiltration / wiper-grade prevention. P1 for hardening, P2 for hunt "
    "/ telemetry tasks. Each entry is a distinct, non-overlapping action; do not "
    "duplicate an action already implied by the narrative prose. For EACH "
    "recommendation you MUST set: (a) `technique_id` = the ATT&CK technique it "
    "defends against, chosen from the 'Top ATT&CK techniques' list above (or "
    "null only if none applies); (b) `detection` = CONCRETE, technical detection "
    "guidance — name the specific API call, registry key, telemetry source "
    "(e.g. Sysmon EventID 3 for network, EventID 13 for registry), or a "
    "sigma/yara pointer. Do NOT write generic advice like 'monitor for "
    "suspicious activity'; cite the exact observable.\n"
    "6. The three fields must NOT restate one another — a reader should be able "
    "to read all three with no repeated sentences.\n"
    "7. Output MUST conform to the provided JSON schema."
)


def _truncate(value: str, max_len: int) -> str:
    if not value:
        return ""
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def build_prompt_text(report: MalwareReport) -> str:
    """Return the human-readable prompt body (used by ``_build_prompt`` and tests).

    The text is intentionally compact — token budget ≈ 1.5-3K depending on
    report content.
    """
    lines: list[str] = [
        "DETERMINISTIC FINDINGS",
        "----------------------",
        f"Verdict: {report.verdict}",
        f"Overall confidence: {report.overall_confidence:.2f}",
        f"Severity: {report.severity.rating} ({report.severity.overall_score:.1f}/10)",
        f"Malware category: {report.malware_category or 'unknown'}",
        (
            f"Attribution family: {report.attribution.family or 'unknown'} "
            f"(confidence {report.attribution.family_confidence:.2f})"
        ),
        "",
    ]

    # --- TTPs (top 8) -------------------------------------------------
    lines.append("Top ATT&CK techniques (max 8):")
    if not report.ttp_mappings:
        lines.append("  (none mapped)")
    else:
        for mapping in report.ttp_mappings[:8]:
            quote = mapping.evidence_quotes[0] if mapping.evidence_quotes else ""
            layers = ",".join(mapping.contributing_layers) or "-"
            lines.append(
                f"  - {mapping.technique_id} {mapping.technique_name} "
                f"(conf={mapping.confidence:.2f}, layers={layers}): "
                f"{_truncate(quote, 120)}"
            )
    lines.append("")

    # --- Sandbox signatures (top 5 by severity) -----------------------
    lines.append("Sandbox signatures (top 5):")
    if report.dynamic and report.dynamic.sandbox_signatures:
        for sig in report.dynamic.sandbox_signatures[:5]:
            ttps = ",".join(sig.technique_ids) or "-"
            lines.append(f"  - {sig.name} (severity {sig.severity}, ATT&CK={ttps})")
    else:
        lines.append("  (none)")
    lines.append("")

    # --- Suspicious imports (top 5) -----------------------------------
    lines.append("Suspicious imports (top 5):")
    if report.static:
        suspicious = [imp for imp in report.static.imports if imp.is_suspicious][:5]
        if suspicious:
            for imp in suspicious:
                cat = imp.category or "-"
                lines.append(f"  - {imp.dll}!{imp.function} ({cat})")
        else:
            lines.append("  (none flagged)")
    else:
        lines.append("  (no static analysis)")
    lines.append("")

    # --- Network IOCs (top 3 each) ------------------------------------
    lines.append("Network IOCs:")
    if report.network:
        sus_domains = [d for d in report.network.domains if d.is_suspicious][:3]
        if not sus_domains:
            sus_domains = report.network.domains[:3]
        for dom in sus_domains:
            reason = dom.reason or "observed"
            lines.append(f"  - domain: {dom.fqdn} ({reason})")
        for ip in report.network.ips[:3]:
            note = ip.reputation.get("_heuristic_reason") if ip.reputation else None
            tag = note or ("suspicious" if ip.is_suspicious else "observed")
            lines.append(f"  - ip: {ip.address} ({tag})")
    else:
        lines.append("  (no network data)")
    lines.append("")

    # --- Persistence (top 3) ------------------------------------------
    lines.append("Persistence (top 3):")
    if report.persistence:
        for mech in report.persistence[:3]:
            lines.append(
                f"  - {mech.kind}: {_truncate(mech.target, 100)} "
                f"({mech.technique_id or 'no-ATT&CK-id'})"
            )
    else:
        lines.append("  (none detected)")
    lines.append("")

    # --- Static hints --------------------------------------------------
    if report.static:
        if report.static.packer_hint:
            lines.append(f"Packer hint: {report.static.packer_hint}")
        if report.static.obfuscation_indicators:
            ind = ", ".join(report.static.obfuscation_indicators[:5])
            lines.append(f"Obfuscation indicators: {ind}")
        lines.append("")

    lines.extend(
        [
            "TASK",
            "----",
            "Write the three narrative fields described in the system prompt. "
            "Return ONLY the JSON object that matches the schema.",
        ]
    )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------


class NarrativeAgent:
    """One LLM round producing ``NarrativeOutput``. Async, no retry."""

    def __init__(
        self,
        llm: BaseChatModel,
        max_input_tokens: int = 3000,
        token_ledger: Any | None = None,
    ) -> None:
        self.llm = llm
        self.max_input_tokens = max_input_tokens
        # 2026-07 audit (Bulgu #10, G1): the narrative round is a real LLM call
        # and must count toward run_summary token metrics. Recorded on the raw
        # path below (the structured path hides usage behind the parser).
        self.token_ledger = token_ledger

    async def generate(self, report: MalwareReport) -> NarrativeOutput | None:
        """Return a ``NarrativeOutput`` or ``None`` if both paths fail.

        Path 1 — ``with_structured_output(NarrativeOutput).ainvoke(messages)``
        Path 2 — raw chat → ``safe_parse_json`` → ``model_validate``
        Both surfaces are wrapped in broad ``except`` so the report node can
        always rely on the fallback narrative.
        """
        messages = self._build_prompt(report)

        try:
            structured = self.llm.with_structured_output(NarrativeOutput)
            result = await structured.ainvoke(messages)
            if isinstance(result, NarrativeOutput):
                return result
            # Some providers return a dict — coerce defensively.
            if isinstance(result, dict):
                return NarrativeOutput.model_validate(result)
            logger.warning(
                "NarrativeAgent: unexpected structured-output type %s; "
                "falling back to manual parse.",
                type(result).__name__,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "NarrativeAgent: structured_output path failed (%s); trying manual JSON parse.",
                exc,
            )

        # Manual-parse fallback (single attempt). Useful for local llama.cpp
        # servers that occasionally return text wrapped in ```json fences.
        try:
            raw = await self.llm.ainvoke(messages)
            if self.token_ledger is not None:
                try:
                    from maljan.core.token_ledger import record_response_usage

                    record_response_usage(self.token_ledger, raw)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("NarrativeAgent: token usage not recorded (%s).", exc)
            payload = safe_parse_json(_message_text(raw))
            if not payload:
                return None
            return NarrativeOutput.model_validate(payload)
        except Exception as exc:  # noqa: BLE001
            logger.warning("NarrativeAgent: manual-parse fallback failed (%s).", exc)
            return None

    def _build_prompt(self, report: MalwareReport) -> list[BaseMessage]:
        return [
            SystemMessage(content=_SYSTEM_PROMPT),
            HumanMessage(content=build_prompt_text(report)),
        ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _message_text(message: Any) -> str:
    """Extract a string from a LangChain message-like object."""
    if message is None:
        return ""
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Handle multi-part content (rare for chat LLMs but possible)
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                text = item.get("text") or item.get("content")
                if text:
                    parts.append(str(text))
        return "".join(parts)
    return str(content)
