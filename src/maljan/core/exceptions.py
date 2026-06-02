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
