"""Contracts every static-analysis and sandbox provider implements.

Two dataclass families and two ABCs. The dataclasses are the whole vocabulary
the pipeline is allowed to branch on: a capability flag, a job context, an
evidence bundle, a probe result. Neither ABC's default method bodies name a
concrete tool — an adapter overrides only the methods its backend actually
supports, and the pipeline reads ``capabilities`` rather than checking
``isinstance`` or a provider id.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from langchain_core.tools import BaseTool

from maljan.providers.errors import ProviderError

if TYPE_CHECKING:
    from maljan.core.config import Settings
    from maljan.schemas.sandbox_report import SandboxRun


@dataclass(frozen=True)
class StaticCapabilities:
    provides_tools: bool = False
    provides_evidence: bool = False
    provides_function_hashes: bool = False
    needs_sample_mirror: bool = False
    supports_tool_curation: bool = False
    degrade_on_failure: bool = False


@dataclass(frozen=True)
class SandboxCapabilities:
    can_submit: bool = False
    can_poll: bool = False
    can_fetch_report: bool = True
    can_fetch_pcap: bool = False
    accepts_uploaded_report: bool = False
    provides_tools: bool = False
    report_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"] = "generic"
    degrade_on_failure: bool = True


@dataclass(frozen=True)
class MirrorSpec:
    work_subdir: str
    container_prefix: str


@dataclass(frozen=True)
class StaticJobContext:
    host_sample_path: str | None = None
    mirror_sample_path: str | None = None  # today's state["static_sample_path"]
    sha256: str = ""
    file_type: str = "unknown"
    platform: str = "unknown"
    capability_categories: frozenset[str] = frozenset()
    output_guardrail: Callable[[str], str] | None = None
    max_output_chars: int = 8000
    truncation_ledger: Any | None = None


@dataclass(frozen=True)
class StaticEvidenceBundle:
    api_capabilities: dict[str, int] = field(default_factory=dict)
    technique_hits: list[dict[str, Any]] = field(default_factory=list)
    strings: list[dict[str, Any]] = field(default_factory=list)
    technical_evidence: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderProbe:
    ok: bool
    detail: str
    latency_ms: int = 0


class StaticProvider(ABC):
    """One static-analysis tool, as the pipeline sees it.

    Lifecycle: ``from_settings`` (cheap, no I/O) -> ``probe`` (optional, the
    UI's connection test) -> ``open(job)`` (attach, once per sample) -> work ->
    ``close()``. Everything the pipeline branches on is a capability flag, so
    the pipeline never names a provider.
    """

    id: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> StaticProvider: ...

    @property
    @abstractmethod
    def capabilities(self) -> StaticCapabilities: ...

    async def probe(self) -> ProviderProbe:
        return ProviderProbe(ok=True, detail="no connection test for this provider")

    def open(self, job: StaticJobContext) -> None:
        """Attach to the tool for one sample. Idempotent."""
        return None

    def get_tools(self) -> list[BaseTool]:
        return []

    def select_tools(
        self, tools: list[BaseTool], categories: set[str] | None = None
    ) -> list[BaseTool]:
        return list(tools)

    def prompt_fragment(self) -> str:
        """The tool-facing body of the static system prompt for this provider."""
        return ""

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        return None

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        return []

    def mirror_spec(self) -> MirrorSpec | None:
        return None

    def close(self) -> None:
        return None


class SandboxProvider(ABC):
    """One dynamic-analysis (sandbox) backend, as the pipeline sees it.

    Mirrors ``StaticProvider``: ``from_settings`` (cheap, no I/O) -> ``probe``
    (optional, the UI's connection test) -> ``open`` (attach, once per job) ->
    work -> ``close()``. Everything the pipeline branches on is a capability
    flag, so the pipeline never names a provider. Methods with no safe empty
    return value (``submit``, ``wait_for_completion``, ``fetch``) default to
    raising ``ProviderError``; callers are expected to check ``capabilities``
    first, the same way they must for ``attach_report``.
    """

    id: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> SandboxProvider: ...

    @property
    @abstractmethod
    def capabilities(self) -> SandboxCapabilities: ...

    async def probe(self) -> ProviderProbe:
        return ProviderProbe(ok=True, detail="no connection test for this provider")

    def open(self) -> None:
        """Attach to the backend for one job. Idempotent."""
        return None

    def submit(self, sample_path: str) -> str:
        raise ProviderError("this sandbox does not accept job submissions")

    def wait_for_completion(
        self, task_id: str, timeout_seconds: int, poll_interval_seconds: int
    ) -> str:
        raise ProviderError("this sandbox does not support polling")

    def fetch(self, task_id: str) -> SandboxRun:
        raise ProviderError("this sandbox does not provide reports")

    def fetch_pcap(self, task_id: str, dest_dir: str) -> str | None:
        return None

    def attach_report(self, blob: bytes, *, filename: str) -> SandboxRun:
        raise ProviderError("this sandbox does not accept uploaded reports")

    def dynamic_tools(self) -> list[BaseTool]:
        return []

    def dynamic_prompt_fragment(self) -> str:
        return ""

    def close(self) -> None:
        return None
