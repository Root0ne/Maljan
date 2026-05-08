"""SandboxClient abstraction layer — Phase 6: CAPEv2 Sandbox Integration.

Defines the SandboxClient Protocol and SubmissionResult dataclass that all
sandbox backend implementations must satisfy.

Design goals:
  - Zero external dependencies in this module.
  - Protocol-based: MockSandboxClient and CAPEv2Client are interchangeable.
  - SubmissionResult carries the raw JSON report dict that parsers already
    understand — no new data shapes required in the rest of the pipeline.
  - All fields in SubmissionResult map directly to the existing fixture JSON
    schema (behavior.*, target.*), ensuring DynamicParser and NetworkParser
    work without modification.

Sandbox integration flow:
  1. FileDataLoader.load_from_sandbox() calls SandboxClient.submit()
     with the sample file path and returns a task ID.
  2. SandboxClient.wait_for_completion() polls until the task finishes.
  3. SandboxClient.fetch_report() returns a SubmissionResult containing
     the full CAPEv2 JSON report.
  4. The report is passed to the DynamicParser / NetworkParser as if it
     were a local fixture file — zero parser changes required.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# SubmissionResult
# ---------------------------------------------------------------------------


@dataclass
class SubmissionResult:
    """Result of a completed sandbox analysis.

    Attributes:
        task_id:       Sandbox task identifier.
        sample_sha256: SHA-256 of the submitted sample.
        sample_name:   Original filename of the submitted sample.
        status:        Final task status string (e.g. "reported", "failed").
        report:        Full sandbox JSON report dict. Matches the structure
                       of existing fixture files under data/samples/:
                         report["behavior"]  -> DynamicParser / NetworkParser
                         report["target"]    -> metadata (sha256, name, md5)
                         report["signatures"]-> behavioral signature matches
        error:         Error message when status != "reported". Empty string
                       on success.
    """

    task_id: str
    sample_sha256: str = ""
    sample_name: str = ""
    status: str = "reported"
    report: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def succeeded(self) -> bool:
        """True when the sandbox task completed with a usable report."""
        return self.status == "reported" and bool(self.report)



# ---------------------------------------------------------------------------
# SandboxClient Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SandboxClient(Protocol):
    """Backend-agnostic interface for sandbox submission and report retrieval.

    All concrete implementations (MockSandboxClient, CAPEv2Client) must
    satisfy this Protocol. The @runtime_checkable decorator enables
    isinstance() checks in tests and container code.

    Implementations:
        MockSandboxClient -- returns local fixture JSON (no network required)
        CAPEv2Client      -- submits to a live CAPEv2 REST API instance
    """

    def submit(self, sample_path: str | Path) -> str:
        """Submit a sample file to the sandbox and return the task ID.

        Args:
            sample_path: Path to the sample file to analyse.

        Returns:
            Task ID string assigned by the sandbox.

        Raises:
            SandboxError: When submission fails.
        """
        ...

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int = 300,
        poll_interval_seconds: int = 10,
    ) -> str:
        """Poll until the task finishes and return its final status string.

        Args:
            task_id:                Task ID returned by submit().
            timeout_seconds:        Maximum wait time before raising SandboxTimeoutError.
            poll_interval_seconds:  Time between status polls.

        Returns:
            Final status string (e.g. "reported", "failed", "pending").

        Raises:
            SandboxTimeoutError: When the task does not complete within timeout_seconds.
            SandboxError:        On API or network errors.
        """
        ...

    def fetch_report(self, task_id: str) -> SubmissionResult:
        """Fetch the completed analysis report for a task.

        Args:
            task_id: Task ID returned by submit().

        Returns:
            SubmissionResult with the full report dict.

        Raises:
            SandboxError: When the report is unavailable or the request fails.
        """
        ...


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SandboxError(RuntimeError):
    """Base exception for sandbox client errors."""


class SandboxTimeoutError(SandboxError):
    """Raised when a task does not complete within the configured timeout."""


class SandboxNotAvailableError(ImportError):
    """Raised when required sandbox client dependencies are not installed."""
