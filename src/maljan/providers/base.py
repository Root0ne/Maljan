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
    # The job this context belongs to, as the container knows it. A provider
    # that starts a tool server passes this as the server's job identity, and
    # that identity is what names the directory the server may stage in: with
    # the sample's digest there instead, two jobs on one sample shared a
    # directory and neither job's teardown could name it.
    job_key: str = ""
    sha256: str = ""
    file_type: str = "unknown"
    platform: str = "unknown"
    output_guardrail: Callable[[str], str] | None = None
    # Zero means the cap is derived from the served model's context window at
    # the moment of each call; a positive number is the operator's own cap.
    max_output_chars: int = 0
    truncation_ledger: Any | None = None
    # The job's context budget, which answers what zero above means.
    context_budget: Any | None = None


@dataclass(frozen=True)
class StaticEvidenceBundle:
    technique_hits: list[dict[str, Any]] = field(default_factory=list)
    strings: list[dict[str, Any]] = field(default_factory=list)
    technical_evidence: dict[str, str] = field(default_factory=dict)
    # The rule hits themselves, in the shape the ``capa`` and ``yara_scan``
    # tools return them. A provider with no tool loop still has to reach the
    # report the way every other tool does — as ledger entries — and a
    # rendered Markdown table is not something the section builders can read.
    capa_rules: list[dict[str, Any]] = field(default_factory=list)
    yara_matches: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ProviderProbe:
    ok: bool
    detail: str
    latency_ms: int = 0


# The provider-neutral instructions every static provider fragment opens with:
# what a claim must cite and which techniques to look for. A provider with no
# tools of its own, and one whose tools did not attach, say only this and what
# the provider is.
STATIC_EVIDENCE_INSTRUCTIONS = (
    "Analyze the deterministic static evidence you are given. "
    "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
    "string offset (.data+0xNN), API import, or hex pattern. "
    "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
    "T1055 (Process Injection), T1140 (Deobfuscation)."
)


def absent_provider_fragment(label: str, guidance: str = STATIC_EVIDENCE_INSTRUCTIONS) -> str:
    """The static fragment for a provider none of whose tools reached the request.

    The provider's tool-independent ``guidance`` — what a claim cites, the
    confidence discipline — and the sentence saying it is not attached.
    """
    return (
        guidance.rstrip()
        + "\n\n"
        + f"The {label} static provider is configured, but none of its tools is "
        "attached to this request, so no disassembler or decompiler comes with it."
    )


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

    async def readiness(self) -> ProviderProbe:
        """Whether a job that needs this provider can start, without analysing anything.

        Asked before a job is accepted, for a provider that does not degrade
        (``capabilities.degrade_on_failure`` false): a run that cannot open it
        fails mid-way, so the submit is refused instead. The connection test by
        default; a provider overrides it where its connection test is not the
        whole answer (a transport with nothing to reach before the job).
        """
        return await self.probe()

    def address(self) -> str:
        """Where this provider is reached, safe to show any user: ``""`` when nowhere."""
        return ""

    def switched_off(self) -> bool:
        """Whether the operator turned this provider off, so it attaches nothing.

        A provider switched off does not fail a run; the analyst runs without
        its tools and its prompt says the provider is not attached.
        """
        return False

    def open(self, job: StaticJobContext) -> None:
        """Attach to the tool for one sample. Idempotent."""
        return None

    def get_tools(self) -> list[BaseTool]:
        return []

    def prompt_fragment(self) -> str:
        """The tool-facing body of the static system prompt, with this provider attached."""
        return ""

    @property
    def label(self) -> str:
        """What a prompt calls this provider."""
        return self.id or "static"

    def absent_fragment(self) -> str:
        """The body of the static system prompt when none of this provider's tools is attached.

        A provider whose tools did not reach the request — disabled, degraded,
        or not yet opened — is not described by ``prompt_fragment``, which
        walks the model through calls it cannot make. This says what the
        provider is and that it is not attached; what the request does carry is
        said by the tool statement beside it.
        """
        return absent_provider_fragment(self.label, self.guidance_fragment())

    def guidance_fragment(self) -> str:
        """What this provider's fragment says about claims, whatever the tools.

        The part of ``prompt_fragment`` that is not a tool workflow: every
        call on a run with this provider carries it, the tools-free ones too.
        """
        return STATIC_EVIDENCE_INSTRUCTIONS

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
