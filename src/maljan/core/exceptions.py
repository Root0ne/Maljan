class MaljanError(Exception):
    """Base exception for all Maljan-related errors."""

    pass


class DataLoadError(MaljanError):
    """Raised when analysis data (JSON/logs) cannot be loaded."""

    pass


class AnalystError(MaljanError):
    """Raised when an expert analyst fails to process its data."""

    pass


class LLMError(MaljanError):
    """Raised when the LLM service returns an invalid or empty response."""

    pass


class WorkflowError(MaljanError):
    """Raised when the LangGraph orchestration fails."""

    pass
