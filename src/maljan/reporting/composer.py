"""Section-wise Report Composer — authors the professional technical spine.

Report-reshaping Phase 4. The deterministic builder fills every factual table;
the existing ``NarrativeAgent`` writes the exec-summary / capabilities / defensive
recommendations in one round. The Composer authors the NEW professional sections
(introduction, technical-analysis spine, C2 channels, conclusion) **one section
per LLM call**, each grounded ONLY in that section's evidence bundle
(``evidence_bundles.bundle_for``).

Why per-section and not one big call: the local Qwen3.6-35B/SWA model stalls and
hallucinates on long single-shot generation (documented in
docs/academic-article/findings-log.md). Bounded prompts (≤~1K tokens), a hard
per-section timeout, and a deterministic skip-on-empty keep it stable. The
cardinal rule mirrors the reference spec: **cite the evidence; if a section has
no evidence, leave it empty — never invent** (the renderer states absence).
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from pydantic import BaseModel, ConfigDict, Field

from maljan.agents.base_agent import retry_on_connection_error
from maljan.core.logger import logger
from maljan.reporting.evidence_bundles import bundle_for, is_empty
from maljan.reporting.models import (
    C2Channel,
    CliFlag,
    Conclusion,
    EncryptionScheme,
    MalwareReport,
    RansomNote,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.utils.json_cleaner import safe_parse_json

# ---------------------------------------------------------------------------
# Per-section output schemas
# ---------------------------------------------------------------------------


class _ProseOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    body: str = Field("", max_length=2500)
    evidence_refs: list[str] = Field(default_factory=list)


class _IntroOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    text: str = Field("", max_length=1800)


class _CliFlagsOut(BaseModel):
    model_config = ConfigDict(extra="ignore")
    flags: list[CliFlag] = Field(default_factory=list)


class _C2Out(BaseModel):
    model_config = ConfigDict(extra="ignore")
    channels: list[C2Channel] = Field(default_factory=list)


_SYSTEM = (
    "You are a senior malware reverse engineer writing ONE section of a technical "
    "analysis report. STRICT RULES:\n"
    "1. Use ONLY the evidence provided below. Do NOT invent capabilities, function "
    "names, flags, crypto details, C2 endpoints, or file names.\n"
    "2. If the evidence does not support a field, leave it empty/null. Never guess.\n"
    "3. Be concise and technical; cite concrete artifacts (function name, API, "
    "string, tool output) where possible.\n"
    "4. Output MUST conform to the provided JSON schema."
)

# Narrative technical subsections authored as free prose (TechnicalSubsection).
_PROSE_SECTIONS: dict[str, str] = {
    "packing_obfuscation": "Packing & Obfuscation",
    "discovery": "Discovery & Enumeration",
    "persistence_detail": "Persistence",
    "evasion_antiforensics": "Defense Evasion & Anti-Forensics",
}


def _bundle_text(section: str, bundle: dict[str, Any]) -> str:
    """Render an evidence bundle into a compact prompt body."""
    lines: list[str] = [f"SECTION: {section}", ""]
    facts = bundle.get("facts") or {}
    if facts:
        lines.append("DETERMINISTIC FACTS:")
        for k, v in facts.items():
            if v:
                lines.append(f"- {k}: {v}")
        lines.append("")
    claims = bundle.get("claims") or []
    if claims:
        lines.append("ANALYST CLAIMS (claim — evidence):")
        for c in claims[:10]:
            lines.append(f"- {c.get('claim', '')} — {c.get('evidence_ref', '')}")
        lines.append("")
    tools = bundle.get("tool_outputs") or []
    if tools:
        lines.append("CAPTURED TOOL OUTPUT:")
        for t in tools[:6]:
            sym = f" [{t.get('symbol')}]" if t.get("symbol") else ""
            lines.append(f"- {t.get('tool', '')}{sym}: {t.get('output', '')[:1200]}")
        lines.append("")
    return "\n".join(lines)


class ReportComposer:
    """Authors the professional spine section-by-section. Async; per-section
    timeout + deterministic skip. Never raises to the caller."""

    def __init__(
        self,
        llm: BaseChatModel,
        section_max_tokens: int = 900,
        per_section_timeout: int = 120,
        token_ledger: Any | None = None,
    ) -> None:
        self.llm = llm
        self.section_max_tokens = section_max_tokens
        self.per_section_timeout = per_section_timeout
        self.token_ledger = token_ledger

    async def compose(
        self, report: MalwareReport, isr_reports: dict[str, Any] | None = None
    ) -> None:
        """Fill report.intro_background / technical_analysis / c2_channels /
        conclusion. Mutates ``report`` in place; each section is best-effort."""
        ta = report.technical_analysis or TechnicalAnalysis()
        authored = 0

        # 1. Introduction / background.
        intro = await self._author(
            "introduction", report, isr_reports, _IntroOut, "Write a 2-4 sentence intro."
        )
        if intro and isinstance(intro, _IntroOut) and intro.text.strip():
            report.intro_background = intro.text.strip()
            authored += 1

        # 2. Free-prose technical subsections (only when evidence exists).
        for section, title in _PROSE_SECTIONS.items():
            out = await self._author(
                section, report, isr_reports, _ProseOut, f"Write the '{title}' subsection."
            )
            if out and isinstance(out, _ProseOut) and out.body.strip():
                sub = TechnicalSubsection(
                    title=title, body=out.body.strip(), evidence_refs=out.evidence_refs[:8]
                )
                setattr(ta, section, sub)
                authored += 1

        # 3. Structured extractions (crypto / CLI flags / ransom note).
        enc = await self._author(
            "encryption_scheme",
            report,
            isr_reports,
            EncryptionScheme,
            "Extract the encryption scheme.",
        )
        if enc and isinstance(enc, EncryptionScheme) and _has_content(enc):
            ta.encryption_scheme = enc
            authored += 1

        cli = await self._author(
            "cli_flags", report, isr_reports, _CliFlagsOut, "Extract command-line flags."
        )
        if cli and isinstance(cli, _CliFlagsOut) and cli.flags:
            ta.cli_flags = cli.flags[:30]
            authored += 1

        note = await self._author(
            "ransom_note", report, isr_reports, RansomNote, "Extract the ransom note."
        )
        if note and isinstance(note, RansomNote) and _has_content(note):
            ta.ransom_note = note
            authored += 1

        # 4. Communications / C2 channels.
        c2 = await self._author(
            "communications", report, isr_reports, _C2Out, "Describe the C2 channel(s)."
        )
        if c2 and isinstance(c2, _C2Out) and c2.channels:
            report.c2_channels = c2.channels[:6]
            authored += 1

        # 5. Conclusion (graded sophistication).
        concl = await self._author(
            "conclusion", report, isr_reports, Conclusion, "Write a graded conclusion."
        )
        if concl and isinstance(concl, Conclusion) and concl.text.strip():
            report.conclusion = concl
            authored += 1

        if _has_content(ta):
            report.technical_analysis = ta
        logger.info("ReportComposer: authored %d professional section(s).", authored)

    async def _author(
        self,
        section: str,
        report: MalwareReport,
        isr_reports: dict[str, Any] | None,
        schema: type[BaseModel],
        instruction: str,
    ) -> BaseModel | None:
        """Author one section from its isolated bundle. Skips empty bundles;
        structured-output → manual-parse → None; hard per-section timeout."""
        bundle = bundle_for(section, report, report.technical_evidence, isr_reports)
        if is_empty(bundle):
            return None
        messages = [
            SystemMessage(content=_SYSTEM),
            HumanMessage(content=f"{instruction}\n\n{_bundle_text(section, bundle)}"),
        ]
        try:
            return await asyncio.wait_for(
                self._invoke(messages, schema), timeout=float(self.per_section_timeout)
            )
        except TimeoutError:
            logger.warning("ReportComposer: section '%s' timed out; skipping.", section)
            return None
        except Exception as exc:  # noqa: BLE001
            # ``error``, not ``warning``: a dropped section is missing content
            # in a delivered report, and at warning level in a noisy worker log
            # nobody ever noticed one had gone.
            logger.error("ReportComposer: section '%s' failed (%s); SKIPPED.", section, exc)
            return None

    async def _invoke(
        self, messages: list[BaseMessage], schema: type[BaseModel]
    ) -> BaseModel | None:
        try:
            structured = self.llm.with_structured_output(schema)
            result = await retry_on_connection_error(
                lambda: structured.ainvoke(messages), what="ReportComposer structured"
            )
            if isinstance(result, schema):
                return result
            if isinstance(result, dict):
                return schema.model_validate(result)
        except Exception as exc:  # noqa: BLE001
            logger.debug("ReportComposer: structured path failed (%s); manual parse.", exc)
        # Manual JSON fallback for local servers returning fenced JSON.
        raw = await retry_on_connection_error(
            lambda: self.llm.ainvoke(messages), what="ReportComposer raw"
        )
        if self.token_ledger is not None:
            try:
                from maljan.core.token_ledger import record_response_usage

                record_response_usage(self.token_ledger, raw)
            except Exception as exc:  # noqa: BLE001
                logger.debug("ReportComposer: token usage not recorded (%s).", exc)
        payload = safe_parse_json(_message_text(raw))
        if not payload:
            return None
        return schema.model_validate(payload)


def _message_text(msg: Any) -> str:
    content = getattr(msg, "content", msg)
    return content if isinstance(content, str) else str(content)


def _has_content(model: BaseModel) -> bool:
    """True when any field on a structured model carries real content."""
    for value in model.model_dump().values():
        if isinstance(value, bool):
            continue
        if value:
            return True
    return False
