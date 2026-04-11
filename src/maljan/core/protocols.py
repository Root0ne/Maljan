"""Interface contracts for all pluggable subsystems.

Every subsystem in Maljan (agents, parsers, LLM providers, data loaders)
is defined by a Protocol so that concrete implementations can be swapped,
mocked, or extended without modifying consumer code.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from langchain_core.language_models.chat_models import BaseChatModel

# ---------------------------------------------------------------------------
# Agent Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class AnalystProtocol(Protocol):
    """Contract that every expert analyst must satisfy."""

    name: str

    def analyze(self, data: str) -> str:
        """Produce a first-pass analysis report from raw data."""
        ...

    def revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Revise own report after reading peer reports and mediator feedback."""
        ...

    def safe_analyze(self, data: str) -> str:
        """Error-handled wrapper around analyze()."""
        ...

    def safe_revise(
        self,
        original_data: str,
        own_report: str,
        peer_reports: dict[str, str],
        mediator_feedback: str,
    ) -> str:
        """Error-handled wrapper around revise()."""
        ...


# ---------------------------------------------------------------------------
# Parser Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class ParserProtocol(Protocol):
    """Contract that every data parser must satisfy."""

    def parse(self, raw_data: Any) -> str:
        """Transform raw tool output into a refined Markdown summary."""
        ...


# ---------------------------------------------------------------------------
# LLM Provider Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMProviderProtocol(Protocol):
    """Contract for LLM provider backends (OpenAI, Anthropic, Ollama, ...)."""

    name: str

    def build_model(
        self,
        model: str,
        temperature: float,
        **kwargs: Any,
    ) -> BaseChatModel:
        """Instantiate and return a configured LangChain ChatModel."""
        ...


# ---------------------------------------------------------------------------
# Data Loader Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class DataLoaderProtocol(Protocol):
    """Contract for loading analysis data from any source."""

    def load(self, sample_id: str, data_type: str) -> str:
        """Load and parse data for a given sample and data type.

        Args:
            sample_id: Hash or identifier for the sample.
            data_type: One of the registered agent names (e.g. "static").

        Returns:
            Parsed string ready for LLM consumption.
        """
        ...
