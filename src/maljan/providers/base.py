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
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Literal

from langchain_core.tools import BaseTool

from maljan.providers.errors import ProviderError

if TYPE_CHECKING:
    from maljan.core.config import Settings
    from maljan.core.report_formats import ReportFormat, SignatureScale
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
    """Where the worker copies the sample for one server, and where that server sees it.

    ``work_subdir`` is the directory under the worker's samples directory the
    copy goes into. ``container_prefix`` is the server's declared
    ``sample_mount``: the absolute path inside the server that the samples
    directory is mounted at, or empty when the server reads the worker's own
    filesystem and is handed the copy's host path as it is.
    """

    work_subdir: str
    container_prefix: str

    @classmethod
    def of(cls, declaration: Any, *, default_mount: str = "") -> MirrorSpec:
        """The spec a server block declares (its ``work_dir`` and ``sample_mount``).

        A block that names no work directory of its own is copied into the
        shared ``DEFAULT_WORK_DIR``; ``default_mount`` is the mount a server of
        this kind has when its block declares none.
        """
        work = str(getattr(declaration, "work_dir", "") or "") or DEFAULT_WORK_DIR
        mount = str(getattr(declaration, "sample_mount", "") or "") or default_mount
        return cls(work_subdir=work, container_prefix=mount)


# The mirror directory of a server whose declaration names none of its own.
# Hidden on purpose: it is the worker's scratch, not part of the corpus.
DEFAULT_WORK_DIR = ".work"


def path_in_server(spec: MirrorSpec, host_path: str | Path) -> str:
    """The path a server opens the worker's copy at ``host_path`` under.

    The one translation from a mirror copy on the worker to the path its
    server is handed: the host path itself for a server on the worker's own
    filesystem (an empty ``container_prefix``), otherwise the copy's place
    under the server's own mount of the samples directory.
    """
    if not spec.container_prefix:
        return str(host_path)
    prefix = spec.container_prefix.rstrip("/")
    host = Path(host_path)
    # The copy's own directory and name, so the path handed over and the copy
    # written can never name two different directories.
    return f"{prefix}/{host.parent.name}/{host.name}"


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
class EvidenceAnswer:
    """One answer an evidence-only provider found, keyed by the kind of fact it is.

    ``kind`` is a declared answer kind (``core.tool_declarations.ToolFacts``)
    and ``payload`` is in that kind's shape; ``tool`` is the name the
    provider's own declaration gives a tool of that kind, which the ledger
    entry is recorded under so every reader finds it by its declaration.
    """

    tool: str
    kind: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class StaticEvidenceBundle:
    technique_hits: list[dict[str, Any]] = field(default_factory=list)
    strings: list[dict[str, Any]] = field(default_factory=list)
    technical_evidence: dict[str, str] = field(default_factory=dict)
    # The answers themselves, by kind. A provider with no tool loop still has
    # to reach the report the way every other tool does — as ledger entries —
    # and a rendered Markdown table is not something the section builders can
    # read.
    entries: tuple[EvidenceAnswer, ...] = ()
    # The legacy form of the two rule answers (capability rules, signature
    # rules), read by :meth:`answers` for a bundle built before ``entries``.
    capa_rules: list[dict[str, Any]] = field(default_factory=list)
    yara_matches: list[dict[str, Any]] = field(default_factory=list)

    def answers(self, source: str = "provider:capa_yara") -> tuple[EvidenceAnswer, ...]:
        """Every answer of the bundle: ``entries``, then the legacy rule fields as answers.

        A legacy field becomes the answer of its kind under the tool
        ``source``'s declaration names for that kind.
        """
        legacy: list[EvidenceAnswer] = []
        for kind, payload in (
            ("capability_rules", {"capabilities": self.capa_rules} if self.capa_rules else None),
            (
                "signature_rules",
                {
                    "matches": self.yara_matches,
                    "rule_count": len(self.yara_matches),
                    "filtered": 0,
                }
                if self.yara_matches
                else None,
            ),
        ):
            tool = declared_tool_of_kind(source, kind)
            if payload is not None and tool:
                legacy.append(EvidenceAnswer(tool=tool, kind=kind, payload=payload))
        return (*self.entries, *legacy)


def evidence_entries(
    bundle: StaticEvidenceBundle, counter: Any, stage: str, *, source: str, agent: str
) -> list[Any]:
    """An evidence-only provider's bundle as evidence-ledger entries, one per answer, by kind.

    Each answer is recorded under the tool the provider's declaration
    (``source``) names for its kind, so every reader finds it by that
    declaration; a bundle in the legacy form is read by
    :meth:`StaticEvidenceBundle.answers`.

    A provider without a tool loop has no seam that records its calls, so it
    records them itself. Timing is not available after the fact and is left at
    zero rather than invented; what matters is that the rows are citable and
    reach the report's sections through the same path a tool call does.

    ``stage`` is the team stage the entries were recorded in: the report node
    writes them, so it is that stage's key.
    """
    import json

    from maljan.schemas.evidence import build_entry

    out: list[Any] = []
    for answer in bundle.answers(source):
        entry_id, seq = counter.next_id()
        out.append(
            build_entry(
                entry_id=entry_id,
                seq=seq,
                agent=agent,
                tool=answer.tool,
                args={},
                server=None,
                source=source,
                output=json.dumps(answer.payload),
                stage=stage,
            )
        )
    return out


def declared_tool_of_kind(source: str, kind: str) -> str:
    """The first tool ``source``'s declaration names under ``kind``, ``""`` for none."""
    from maljan.core.declared_reading import declarations

    held = declarations().source(source)
    for name, facts in held.tools.items() if held is not None else ():
        if facts.kind == kind:
            return name
    return ""


@dataclass(frozen=True)
class ProviderProbe:
    ok: bool
    detail: str
    latency_ms: int = 0
    # The tool names the provider's server offered, where the test read them.
    tools: list[str] | None = None


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
    # What the console calls this provider, the sentence it says about it, the
    # label of its connection test (empty: it has none of its own), and the
    # sentence above its settings.
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    probe_label: ClassVar[str] = ""
    settings_intro: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> StaticProvider: ...

    @property
    def declaration_source(self) -> str:
        """Where this provider's tools are declared (``core.tool_declarations``).

        Recorded on every ledger entry its tools write. ``provider:<id>`` names
        the provider's own block; a provider that drives a tool server of the
        registry names that server instead.
        """
        return f"provider:{self.id}"

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

    def pin_sample(self, path: str | None) -> None:
        """The path this provider's tools open the sample by, set after an early attach.

        A no-op by default; a provider whose tools take the sample path and
        can hold a model to it overrides this.
        """
        return None

    def open_sample(self, path: str | None = None) -> bool:
        """Open the sample in the provider's session before an analyst's loop, where it has one.

        A no-op returning ``False`` by default; a provider whose tools refuse
        every call until a file is open (radare2's) overrides it. ``path`` is
        the provider's own mirror; ``None`` reads the pinned one.
        """
        return False

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
    # What the console calls this provider, the sentence it says about it, the
    # label of its connection test (empty: it has none of its own), and the
    # sentence above its settings.
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    probe_label: ClassVar[str] = ""
    settings_intro: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> SandboxProvider: ...

    @property
    def declaration_source(self) -> str:
        """Where this provider's tools are declared (``core.tool_declarations``).

        Recorded on every ledger entry its tools write. ``provider:<id>`` names
        the provider's own block; a provider that drives a tool server of the
        registry names that server instead.
        """
        return f"provider:{self.id}"

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

    def set_pending_blob(
        self, blob: bytes, *, filename: str = "report.json", report_format: str | None = None
    ) -> None:
        """Hand over an attached report's bytes and the format its upload row recorded.

        A provider that declares ``accepts_uploaded_report`` reads the blob as
        ``report_format`` when one is given, and refuses in words a format it
        cannot read; the worker calls this before the run starts.
        """
        raise ProviderError("this sandbox does not accept uploaded reports")

    def signature_scale(
        self, run: SandboxRun, formats: Iterable[ReportFormat] | None = None
    ) -> SignatureScale | None:
        """What a signature's severity number means in ``run``'s report, or ``None``.

        The scale the report format of the report's ``source_format`` declares
        among ``formats``, the effective declarations
        (``report_formats.effective_formats`` over ``sandbox.report_formats``;
        ``None`` reads the built-ins alone). A provider whose scale is declared
        elsewhere (a REST mapping, an uploaded report's own format) answers
        from that declaration instead.
        """
        from maljan.core.report_formats import format_named

        found = format_named(run.report.source_format, formats)
        return found.signature_scale if found is not None else None

    def dynamic_tools(self) -> list[BaseTool]:
        return []

    def dynamic_prompt_fragment(self) -> str:
        return ""

    def close(self) -> None:
        return None
