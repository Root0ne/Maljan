"""Abstract base class for all domain expert analyst agents.

Phase 1b additions:
  - analyze_isr(): Returns a structured AgentISR instead of raw text.
    Subclasses override this to provide evidence-backed claims.
  - revise_isr(): Returns a revised AgentISR with updated dissent_items.
  - safe_analyze_isr() / safe_revise_isr(): Error-handled wrappers.

Backward compatibility: analyze() and revise() (returning str) are still
abstract and must be implemented. ISR methods have a default implementation
that wraps the text output into a minimal AgentISR, so existing subclasses
work without modification until they opt-in to full ISR support.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Literal

import tiktoken
from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import settings
from maljan.core.exceptions import AnalystError
from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# Regex: matches MITRE ATT&CK technique IDs like T1055 or T1055.001
_TECHNIQUE_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


def _extract_technique_ids(text: str) -> list[str]:
    """Extract all unique MITRE ATT&CK technique IDs mentioned in text."""
    return list(dict.fromkeys(_TECHNIQUE_RE.findall(text)))


class BaseAnalyst(ABC):
    """Abstract base class for expert agents."""

    def __init__(self, llm: BaseChatModel, name: str, tools: list | None = None) -> None:
        self.llm = llm
        self.name = name
        self.tools = tools or []
        self.logger = logger.getChild(self.name.lower())

    def execute_tool_loop(self, prompt_messages: list) -> str:
        """Executes a tool-calling ReAct loop if tools are available."""
        from langchain_core.prompts import ChatPromptTemplate

        if not self.tools:
            # Fallback to simple invocation
            prompt = ChatPromptTemplate.from_messages(prompt_messages)
            response = (prompt | self.llm).invoke({})
            return str(response.content)

        from langchain_core.messages import HumanMessage, SystemMessage
        from langgraph.prebuilt import create_react_agent

        self.logger.info("Starting ReAct agent loop with %d tools...", len(self.tools))

        # Limit recursion to prevent infinite tool-calling loops with many tools.
        agent_executor = create_react_agent(self.llm, self.tools)

        messages = []
        for role, content in prompt_messages:
            if role == "system":
                messages.append(SystemMessage(content=content))
            elif role == "human":
                messages.append(HumanMessage(content=content))

        import asyncio

        async def _run_with_timeout() -> dict:
            timeout = settings.react_agent_timeout
            self.logger.info(
                "Invoking ReAct agent (timeout=%ds, tools=%d)...",
                timeout,
                len(self.tools),
            )
            try:
                result = await asyncio.wait_for(
                    agent_executor.ainvoke(
                        {"messages": messages},
                        {"recursion_limit": settings.react_agent_max_steps},
                    ),
                    timeout=timeout,
                )
                msg_count = len(result.get("messages", []))
                self.logger.info("ReAct loop completed: %d messages in conversation.", msg_count)
                return result
            except TimeoutError:
                self.logger.error(
                    "ReAct agent timed out after %ds. Returning partial result.", timeout
                )
                raise

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None and loop.is_running():
            import nest_asyncio

            nest_asyncio.apply()
            result = loop.run_until_complete(_run_with_timeout())
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(_run_with_timeout())
            finally:
                loop.close()

        final_message = result["messages"][-1]
        return str(final_message.content)

    # ------------------------------------------------------------------
    # Abstract text interface (must be implemented by subclasses)
    # ------------------------------------------------------------------

    @abstractmethod
    def analyze(self, data: str) -> str:
        """Core analysis logic that translates raw data into a first-pass report."""
        pass

    @abstractmethod
    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise the agent's own report based on peer reports and mediator feedback."""
        pass

    # ------------------------------------------------------------------
    # ISR interface (Phase 1b — subclasses may override for richer output)
    # ------------------------------------------------------------------

    def analyze_isr(self, data: str) -> AgentISR:
        """Return a structured AgentISR from initial analysis.

        Default: calls analyze() and wraps the text output into a minimal ISR.
        Subclasses should override to extract proper ClaimEvidence objects.
        """
        report_text = self.analyze(data)
        return self._text_to_isr(report_text, revision_round=0)

    def revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Return (revised_text, AgentISR) from a revision round.

        Default: calls revise() and wraps the text into a minimal ISR.
        Subclasses should override to extract dissent_items from the LLM response.
        """
        revised_text = self.revise(original_data, own_report, peer_reports, mediator_feedback)
        isr = self._text_to_isr(revised_text, revision_round=revision_round)
        return revised_text, isr

    # ------------------------------------------------------------------
    # Safe wrappers (error handling + token protection)
    # ------------------------------------------------------------------

    def safe_analyze(self, data: str) -> str:
        """Wrapper around analyze() with error handling and token protection."""
        try:
            truncated = self._truncate_input(data)
            return self.analyze(truncated)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error("Analysis failed: %s", e)
            raise AnalystError(f"{self.name} analysis failed: {e}") from e

    def safe_analyze_isr(self, data: str) -> AgentISR:
        """Wrapper around analyze_isr() with error handling and token protection."""
        try:
            truncated = self._truncate_input(data)
            return self.analyze_isr(truncated)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error("ISR analysis failed: %s", e)
            raise AnalystError(f"{self.name} ISR analysis failed: {e}") from e

    def safe_analyze_isr_chunked(self, chunks: list) -> AgentISR:
        """Analyze a list of TextChunk objects, merging their ISRs.

        When the input data exceeds the token limit, the pipeline splits it
        into overlapping chunks via BinaryChunker. This method runs
        analyze_isr() on each chunk independently and merges the resulting
        per-chunk ISRs into a single authoritative ISR using merge_chunk_isrs().

        If only one chunk is provided, it falls through to safe_analyze_isr()
        to avoid merge overhead.

        Args:
            chunks: Ordered list of TextChunk objects from BinaryChunker.chunk().

        Returns:
            A merged AgentISR representing findings across all chunks.

        Raises:
            AnalystError: If analysis fails on all chunks.
        """
        from maljan.analysis.chunk_merger import merge_chunk_isrs

        if not chunks:
            return AgentISR(
                agent_id=self.name,
                domain=self._infer_domain(),
                claims=[],
                dissent_items=[],
                revision_round=0,
            )

        if len(chunks) == 1:
            return self.safe_analyze_isr(chunks[0].content)

        self.logger.info("Chunked analysis: %d chunks for agent='%s'.", len(chunks), self.name)

        chunk_isrs: list[AgentISR] = []
        errors: list[str] = []

        for chunk in chunks:
            prompt_text = f"{chunk.to_prompt_header()}\n\n{chunk.content}"
            try:
                isr = self.analyze_isr(prompt_text)
                chunk_isrs.append(isr)
                self.logger.debug(
                    "Chunk %d/%d analyzed: %d claims.",
                    chunk.index + 1,
                    chunk.total,
                    len(isr.claims),
                )
            except Exception as exc:
                errors.append(f"chunk {chunk.index + 1}: {exc}")
                self.logger.warning("Chunk %d/%d failed: %s.", chunk.index + 1, chunk.total, exc)

        if not chunk_isrs:
            raise AnalystError(
                f"{self.name} chunked analysis failed on all chunks: {'; '.join(errors)}"
            )

        if errors:
            self.logger.warning(
                "%d/%d chunks failed for '%s'. Merging %d successful results.",
                len(errors),
                len(chunks),
                self.name,
                len(chunk_isrs),
            )

        return merge_chunk_isrs(chunk_isrs)

    def safe_revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Wrapper around revise() with error handling."""
        try:
            truncated = self._truncate_input(original_data)
            return self.revise(truncated, own_report, peer_reports, mediator_feedback)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error("Revision failed: %s", e)
            raise AnalystError(f"{self.name} revision failed: {e}") from e

    def safe_revise_isr(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
        revision_round: int = 1,
    ) -> tuple[str, AgentISR]:
        """Wrapper around revise_isr() with error handling."""
        try:
            truncated = self._truncate_input(original_data)
            return self.revise_isr(
                truncated, own_report, peer_reports, mediator_feedback, revision_round
            )
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error("ISR revision failed: %s", e)
            raise AnalystError(f"{self.name} ISR revision failed: {e}") from e

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _text_to_isr(self, text: str, revision_round: int) -> AgentISR:
        """Convert a free-text report into a minimal AgentISR.

        Extracts any MITRE technique IDs mentioned in the text and creates
        one ClaimEvidence per sentence (up to 10) as a best-effort parse.
        This is the fallback; subclasses produce richer ISRs via prompt engineering.
        """
        domain = self._infer_domain()
        technique_ids = _extract_technique_ids(text)

        # Split into sentences — take first 10 as claims
        raw_sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if len(s.strip()) > 20]
        claims: list[ClaimEvidence] = []
        for i, sentence in enumerate(raw_sentences[:10]):
            tid = technique_ids[i] if i < len(technique_ids) else None
            claims.append(
                ClaimEvidence(
                    claim=sentence[:200],  # cap length
                    evidence_ref=f"text-extracted from {self.name} report",
                    confidence=0.5,  # neutral default for text-extracted claims
                    technique_id=tid,
                )
            )

        return AgentISR(
            agent_id=self.name,
            domain=domain,
            claims=claims,
            dissent_items=[],
            revision_round=revision_round,
        )

    def _infer_domain(self) -> Literal["static", "dynamic", "network"]:
        """Infer the ISR domain from the agent's registered name."""
        name_lower = self.name.lower()
        if "static" in name_lower:
            return "static"
        if "dynamic" in name_lower:
            return "dynamic"
        return "network"

    def _truncate_input(self, text: str) -> str:
        """Truncates input text to stay within the configured token limit."""
        limit = settings.max_token_limit
        try:
            enc = tiktoken.get_encoding("cl100k_base")
            tokens = enc.encode(text)
            if len(tokens) > limit:
                self.logger.warning("Input truncated from %d to %d tokens", len(tokens), limit)
                return enc.decode(tokens[:limit])
        except Exception:
            # Fallback: rough character-based truncation (4 chars ~ 1 token)
            char_limit = limit * 4
            if len(text) > char_limit:
                self.logger.warning("Input truncated (fallback) to ~%d tokens", limit)
                return text[:char_limit]
        return text
