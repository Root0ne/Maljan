"""Maljan exception hierarchy.

All Maljan-specific errors derive from :class:`MaljanError` so callers can
write a single ``except MaljanError`` to catch any pipeline-related failure
without also catching unrelated standard-library exceptions.
"""


class MaljanError(Exception):
    """Base exception for all Maljan-related errors."""


class DataLoadError(MaljanError):
    """Raised when analysis data (JSON/logs/sample binaries) cannot be loaded."""


class AnalystError(MaljanError):
    """Raised when an analyst agent fails to process its data."""


class AgentLoopCancelled(AnalystError):
    """An agent coroutine was cancelled from the inside, not by our timeout.

    The distinction is the point. When *we* cancel a coroutine because it blew
    its wall-clock budget, that is a ``TimeoutError`` and the operator should go
    looking at latency. When the coroutine cancels *itself* — an ``mcp``
    transport dying inside its anyio task group because the peer accepted the
    connection and immediately closed it, i.e. a stale port-forward — the
    correct reading is "that service is unreachable", and no amount of waiting
    would have helped.

    Both used to arrive at the same place looking identical, and worse than
    identical: ``concurrent.futures.CancelledError`` is an ``Exception`` with an
    *empty* message, so it was logged as the single word ``CancelledError`` with
    no cause, no service name and no URL. Every dynamic-analyst failure in the
    database says exactly that and nothing more.

    Subclasses ``AnalystError`` so the pipeline's existing fault-isolation
    boundary keeps treating it as a degraded analyst rather than a crash.
    """


class LLMError(MaljanError):
    """Raised when the LLM service returns an invalid or empty response."""


class SandboxError(MaljanError):
    """Raised when a sandbox client fails (submission / polling / fetch)."""


class MemoryStoreError(MaljanError):
    """Raised when the long-term memory store cannot satisfy a request."""


class ConfigurationError(MaljanError):
    """Raised when configuration is missing, invalid, or contradictory."""


class ProjectRootNotFoundError(MaljanError):
    """Raised when the project root marker cannot be located on the filesystem."""


class UnsafePathError(MaljanError):
    """Raised when a caller-provided path/identifier fails safety validation."""


class UnsupportedSampleError(MaljanError):
    """Raised when a sample targets an OS outside the supported set.

    OS-support scope (2026-06-02): Windows and Linux only. A sample whose
    magic bytes / extension identify a foreign (non-Win/Linux) executable
    format is rejected at the pipeline entry rather than routed to an
    unsupported sandbox.
    """
