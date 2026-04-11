from abc import ABC, abstractmethod

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.core.logger import logger


class BaseAnalyst(ABC):
    """Abstract base class for expert agents."""

    def __init__(self, llm: BaseChatModel, name: str) -> None:
        self.llm = llm
        self.name = name
        self.logger = logger.getChild(self.name.lower())

    @abstractmethod
    def analyze(self, data: str) -> str:
        """Core analysis logic that translates data into a report."""
        pass
