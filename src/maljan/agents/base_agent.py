from abc import ABC, abstractmethod

import tiktoken
from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.config import settings
from maljan.core.exceptions import AnalystError
from maljan.core.logger import logger


class BaseAnalyst(ABC):
    """Abstract base class for expert agents."""

    def __init__(self, llm: BaseChatModel, name: str) -> None:
        self.llm = llm
        self.name = name
        self.logger = logger.getChild(self.name.lower())

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
        """Revise the agent's own report based on peer reports and mediator contradiction feedback.

        This is the core of the multi-agent negotiation: the agent reads what other
        experts found, considers the mediator's identified contradictions, and produces
        an updated analysis that addresses gaps or rebuts criticism.
        """
        pass

    def safe_analyze(self, data: str) -> str:
        """Wrapper around analyze() with error handling and token protection."""
        try:
            truncated = self._truncate_input(data)
            return self.analyze(truncated)
        except AnalystError:
            raise
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise AnalystError(f"{self.name} analysis failed: {e}") from e

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
            self.logger.error(f"Revision failed: {e}")
            raise AnalystError(f"{self.name} revision failed: {e}") from e

    def _truncate_input(self, text: str) -> str:
        """Truncates input text to stay within the configured token limit."""
        limit = settings.max_token_limit
        try:
            enc = tiktoken.get_encoding("cl100k_base")
            tokens = enc.encode(text)
            if len(tokens) > limit:
                self.logger.warning(
                    f"Input truncated from {len(tokens)} to {limit} tokens"
                )
                return enc.decode(tokens[:limit])
        except Exception:
            # Fallback: rough character-based truncation (4 chars ~ 1 token)
            char_limit = limit * 4
            if len(text) > char_limit:
                self.logger.warning(f"Input truncated (fallback) to ~{limit} tokens")
                return text[:char_limit]
        return text
