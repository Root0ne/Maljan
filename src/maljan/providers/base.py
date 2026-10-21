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
from typing import TYPE_CHECKING, Any, ClassVar

from langchain_core.tools import BaseTool

from maljan.providers.errors import ProviderError

if TYPE_CHECKING:
    from maljan.analysis.anti_analysis import AntiAnalysisScan
    from maljan.analysis.sink_reachability import CallGraph, SuspiciousFunction
    from maljan.core.config import Settings
    from maljan.core.report_formats import ReportFormat, SignatureScale
    from maljan.schemas.sandbox_report import SandboxRun


# The static provider id that means "no static provider": a run analysed with
# no static tool. Not a tool's name; the null provider registers under it.
NO_STATIC_PROVIDER = "none"


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
    # The id of the registered report reader (``providers.sandbox.readers``)
    # this provider's reports are read by.
    report_format: str = "generic"
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


def requested_host(base_url: object, path: object) -> str:
    """The host a request for ``path`` reaches on an HTTP client built with ``base_url``.

    Merged as httpx merges them: an absolute URL (a scheme and a host) is sent
    as it is, so it names its own host; anything else is appended to the base
    URL and reaches the base's host. ``""`` where neither names a host.
    """
    import httpx

    from maljan.core.host_locality import host_of

    try:
        url = httpx.URL(str(path or ""))
    except Exception:  # noqa: BLE001 — a path httpx refuses reaches no host
        return ""
    if url.is_absolute_url:
        return host_of(str(url))
    return host_of(base_url)


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
    # When the stage or job this work runs in must end, as a ``time.monotonic``
    # instant, where the pipeline has a deadline for it; ``None`` where none.
    deadline: float | None = None


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

    def answers(self, source: str) -> tuple[EvidenceAnswer, ...]:
        """Every answer of the bundle: ``entries``, then the legacy rule fields as answers.

        A legacy field becomes the answer of its kind under the tool
        ``source``'s declaration names for that kind; ``source`` is the
        declaration source of the provider that built the bundle
        (``StaticProvider.declaration_source``), never assumed.
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


# What a static claim must cite, and which techniques to look for. The two
# sentences are kept apart so an agent whose definition turns the technique
# line off (``AgentDefinition.attck_techniques``) is sent the first alone
# (``without_attck_focus``); joined, they are the text every provider sends.
CLAIM_ARTIFACT_CITATION = (
    "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
    "string offset (.data+0xNN), API import, or hex pattern."
)
ATTCK_FOCUS = (
    "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
    "T1055 (Process Injection), T1140 (Deobfuscation)."
)
CLAIM_CITATION = CLAIM_ARTIFACT_CITATION + " " + ATTCK_FOCUS


def without_attck_focus(text: str) -> str:
    """``text`` without the sentence that points claims at ATT&CK techniques.

    For a provider's text sent to an agent whose definition turns the technique
    line off. Only the platform's own sentence (``ATTCK_FOCUS``) is taken out,
    wherever a provider's text carries it; the rest of the text is unchanged.
    """
    return text.replace(" " + ATTCK_FOCUS, "").replace(ATTCK_FOCUS, "")


# The opening sentence of a provider that brings no tools of its own (and of a
# provider whose tools did not attach): it says where the evidence comes from.
STATIC_EVIDENCE_LEAD = "Analyze the deterministic static evidence you are given. "

# How confident a static claim may be, whatever the provider: the cap without a
# falsification, the two loci a High claim needs, and the idiom that is not
# obfuscation. It is about claims, not about any tool: its one sentence about a
# check says "no tool that runs one is attached", so it holds on any provider,
# with tools or none. Every static analyst carries it (``guidance_fragment``,
# ``static_provider_parts``). Worded generically, with no named algorithm or
# technique id: the leak test scans it whole. Ghidra's declaration keeps the
# discipline it has always shown, with its own examples
# (``core.builtin_declarations.GHIDRA_VERIFICATION_DISCIPLINE``).
DISCIPLINE_HEADING = "=== VERIFICATION DISCIPLINE (suppresses confidently-wrong attribution) ==="
VERIFICATION_DISCIPLINE = (
    DISCIPLINE_HEADING + "\n"
    "- A SPECIFIC claim (a named algorithm, a decoding or cipher routine, a\n"
    "  constant or key, or a hash-resolved API) may reach CONFIDENCE >= 0.8 only if\n"
    "  you FALSIFIED it first: an emulation with a known input against the expected\n"
    "  output, OR a backward data-flow trace confirming its origin. If no such\n"
    "  check ran — the code is non-leaf or has syscall/heap side effects, or no\n"
    "  tool that runs one is attached to this request — cap CONFIDENCE at 0.7.\n"
    "- A hash-resolution result: read the FULL list of matches. If more than one\n"
    "  API name collides, do NOT blindly take the best match — disambiguate via\n"
    "  the likely source DLL, or emit CONFIDENCE <= 0.5.\n"
    "- A claim is High (>= 0.8) only with >= 2 independent evidence loci (e.g. an\n"
    "  import AND its call-site). A single locus caps at 0.7. Reconcile any\n"
    "  contradictory signals before emitting.\n"
    "- A dynamic-resolution pattern alone is not obfuscation: resolving APIs at\n"
    "  run time is the ORDINARY Windows idiom for optional or delay-loaded DLLs.\n"
    "  Only claim obfuscation when you observe a REAL obfuscation mechanism: a\n"
    "  hashing/decrypt loop over API names, a high-entropy/packed section, an\n"
    "  unpacking stub, or a sparse import table that hides the real APIs. A rich,\n"
    "  fully-named import table (dozens of imports across several DLLs) argues\n"
    "  AGAINST packing. Do not inflate a plain run-time resolution into an\n"
    "  obfuscation claim."
)

# What every static provider's fragment says about claims: what a claim cites,
# then the confidence discipline.
CLAIM_GUIDANCE = CLAIM_CITATION + "\n\n" + VERIFICATION_DISCIPLINE


def with_claim_guidance(lead: str, workflow: str = "") -> str:
    """A static provider's fragment: its ``lead`` sentence, the claim guidance, its ``workflow``.

    ``workflow`` is the attached server's own text (its declared
    ``prompt_fragment``), shown after the guidance; empty, the fragment ends
    with the guidance.
    """
    text = lead + CLAIM_GUIDANCE
    return text + "\n\n" + workflow if workflow.strip() else text


def holding_the_discipline(body: str) -> str:
    """``body`` with the verification discipline after it, unless it already holds it.

    A provider that writes its whole fragment itself still reaches the model
    with the discipline every static analyst is held to.
    """
    # A provider that carries a discipline of its own (Ghidra's, worded with
    # its own examples) carries it under the same heading.
    if DISCIPLINE_HEADING in body:
        return body
    return body.rstrip() + "\n\n" + VERIFICATION_DISCIPLINE if body.strip() else body


def absent_provider_fragment(
    label: str, guidance: str = STATIC_EVIDENCE_LEAD + CLAIM_GUIDANCE
) -> str:
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
    # Where the provider stands among the settings selector's choices; lower first.
    choice_order: ClassVar[int] = 100
    # The words a reader choosing how to analyse a sample sees (the submit
    # dialog), beside the id; empty reads the title.
    choice_label: ClassVar[str] = ""
    # The leaves of the provider's own block (relative to it; one ending in
    # "." names every leaf under it) the setup guide shows up front, and those
    # it folds under "Advanced". Neither declared: the guide shows the whole
    # block by each entry's own advanced flag.
    guide_leaves: ClassVar[tuple[str, ...]] = ()
    guide_advanced_leaves: ClassVar[tuple[str, ...]] = ()
    # The sentence after the priority-functions list (``prepare_sample``): what
    # to do with those functions, in this provider's own tools' words. Empty
    # reads the neutral sentence (``sink_reachability.FOLLOW_UP``).
    priority_follow_up: ClassVar[str] = ""
    # The environment variable names this provider's own sentences name that are
    # not secrets, which published text keeps whole (``pipeline.events``); read
    # from the registered class, never from a run's settings.
    variable_names: ClassVar[tuple[str, ...]] = ()
    # The dotted settings path of a server block of this provider's own, whose
    # declaration its tools are read by as a built-in's block is
    # (``core.tool_declarations.provider_blocks``); empty for none.
    declaration_block: ClassVar[str] = ""
    # What this provider's anti-analysis scan checks, as the triage pack's line
    # says it in short; empty names the scan alone.
    scan_checks_short: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> StaticProvider: ...

    @classmethod
    def declaration(cls, cfg: Settings) -> Any:
        """This provider's own declaration of its tools, or ``None`` for none.

        The declaration fields of an ``MCPServerConfig`` (``tool_facts``,
        ``roles``, ``prompt_fragment`` …), as an object or a mapping, read
        under ``provider:<id>`` (``core.tool_declarations``) wherever a
        built-in's block is read, so a provider registered at runtime declares
        its tools the way the built-ins do. Read for a provider whose block is
        not a provider block (``provider_blocks``); a provider that drives a server of the
        registry (``declaration_source`` ``mcp:<key>``) is declared by that
        server.
        """
        return None

    @classmethod
    def display_name(cls) -> str:
        """What published text calls this provider: its choice label, else its title or id."""
        return cls.choice_label or cls.title or cls.id or "static"

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
        every call until a file is open overrides it. ``path`` is the
        provider's own mirror; ``None`` reads the pinned one. A provider that
        knows the sample cannot be opened raises
        :class:`~maljan.core.exceptions.SampleNotOpened`, which stops the
        agent's loop before a model turn is spent, and remembers it
        (``sample_failure``); any other failure is the provider's to log, and
        the model's own open is still there.
        """
        return False

    def preprocessing(self) -> Any:
        """The preprocessing settings this provider's pre-passes read.

        The deployment's by default; a provider built with its own copy of
        them answers with that one.
        """
        from maljan.core.config import get_settings

        return get_settings().preprocessing

    def withheld_reasons(self) -> list[str]:
        """Why each tool this provider holds back from its agents is withheld, for the run.

        Empty by default. A provider that withholds a tool (on a server other
        jobs share, one it cannot hold to the job's own program) says why
        here, and the agent attaching its tools puts each reason on the job's
        degraded record (``record_provider_withheld``).
        """
        return []

    def call_graph(self, path: str) -> CallGraph | None:
        """The opened program's call graph in the neutral shape, or ``None`` without one.

        ``None`` by default: a provider that can read a program's call graph
        overrides it, and its agents get the priority-functions pre-pass
        (``prepare_sample``). A failure raises; the pre-pass is fail-safe.
        """
        return None

    def priority_functions(self, path: str) -> list[SuspiciousFunction] | None:
        """The functions of the opened program nearest the sensitive sinks, ranked.

        ``None`` where there is no pre-pass to make: the provider gives no call
        graph, or ``preprocessing.use_sink_reachability`` is off. An empty list
        is a graph with no named sink reachable. At most
        ``preprocessing.sink_reachability_max_funcs`` functions. Fail-safe: a
        call graph that could not be read is ``None``, with a warning.
        """
        from maljan.analysis.sink_reachability import rank_suspicious_functions
        from maljan.core.logger import logger

        pre = self.preprocessing()
        if not getattr(pre, "use_sink_reachability", False):
            return None
        try:
            graph = self.call_graph(path)
            if graph is None:
                return None
            return rank_suspicious_functions(graph, max_funcs=pre.sink_reachability_max_funcs)
        except Exception as exc:  # noqa: BLE001 — never break analysis over a hint
            logger.warning(
                "Sink-reachability pre-pass failed (%s); continuing without hint.",
                type(exc).__name__,
            )
            return None

    def anti_analysis_scan(
        self, job: StaticJobContext, *, notes: Any = None, call_budget: float = 0.0
    ) -> AntiAnalysisScan | None:
        """This job's anti-analysis scan for the triage pack, or ``None`` where it has none.

        ``None`` by default. A provider whose tools can scan a program for
        anti-analysis code overrides it and answers with an object in the
        shape ``analysis.anti_analysis.AntiAnalysisScan`` names: one that says
        why it cannot scan (``unavailable``), or scans ``job.mirror_sample_path``.
        ``notes`` is the job's note of opened samples (``providers.sample_open``)
        and ``call_budget`` what one call to the provider's server may take
        (:meth:`call_budget`; zero: as long as the tool takes).
        """
        return None

    @classmethod
    def registry_servers(cls, cfg: Any) -> frozenset[str]:
        """The ``mcp.servers`` keys this provider calls for a job, read from ``cfg``.

        Asked without building the provider, so a submission can tell which
        stored server settings a job will read. None by default: a provider
        that drives an operator's registry server names it.
        """
        return frozenset()

    def server_block(self) -> Any:
        """The settings block of the server this provider drives, or ``None`` for none."""
        return getattr(self, "_cfg", None)

    def call_budget(self, cfg: Any) -> float:
        """What one call to this provider's server may take (zero: as long as it takes).

        The operator's ``mcp.breaker.call_timeout_seconds`` when set, else the
        ``call_timeout_seconds`` the server's own block declares
        (``server_guard.server_call_budget``).
        """
        from maljan.providers.server_guard import server_call_budget

        return server_call_budget(cfg, self.server_block())

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
        """The tool-facing body of the static system prompt, with this provider attached.

        The provider's lead sentence, the claim guidance every static provider
        gives, then the workflow its server declares (``workflow_fragment``).
        """
        return with_claim_guidance(self.prompt_lead(), self.workflow_fragment())

    def prompt_lead(self) -> str:
        """The sentence the fragment opens with: what the analyst works with."""
        return STATIC_EVIDENCE_LEAD

    def workflow_fragment(self) -> str:
        """The attached server's own workflow text (its declared ``prompt_fragment``), or ""."""
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
        return STATIC_EVIDENCE_LEAD + CLAIM_GUIDANCE

    def collect_evidence(self, sample_path: str) -> StaticEvidenceBundle | None:
        return None

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        return []

    def mirror_spec(self) -> MirrorSpec | None:
        return None

    def close(self) -> None:
        return None


def preprocessing_of(provider: Any) -> Any:
    """The preprocessing settings ``provider`` reads (``StaticProvider.preprocessing``).

    The deployment's for an object that does not answer the question itself.
    """
    own = getattr(provider, "preprocessing", None)
    if callable(own):
        return own()
    from maljan.core.config import get_settings

    return get_settings().preprocessing


def prepare_sample(provider: StaticProvider | None, path: str, log: Any = None) -> str:
    """Open the job's sample on an agent's static provider, then its priority-functions hint.

    The one pre-pass every analyst on a static provider runs before its loop,
    whatever the provider: the provider opens the sample where its session
    needs it (``open_sample``; a sample it cannot open raises
    :class:`~maljan.core.exceptions.SampleNotOpened` before any model turn),
    then, where it gives a call graph, the functions that reach sensitive sinks
    are rendered as a hint so the loop reads the malicious core first
    (``analysis.sink_reachability``), followed by the provider's own sentence
    on what to do with them. ``""`` for no provider, no call graph, the
    pre-pass switched off, or no named sink reachable.
    """
    import logging

    from maljan.analysis.sink_reachability import FOLLOW_UP, priority_hint
    from maljan.core.exceptions import SampleNotOpened

    logger_ = log if log is not None else logging.getLogger(__name__)
    if provider is None:
        return ""
    opener = getattr(provider, "open_sample", None)
    try:
        if callable(opener):
            opener(path)
    except SampleNotOpened:
        raise
    except Exception as exc:  # noqa: BLE001 — the model's own open is still there
        logger_.debug("the provider did not open the sample early: %s", type(exc).__name__)
    rank = getattr(provider, "priority_functions", None)
    try:
        ranked = rank(path) if callable(rank) else None
        if ranked is None:
            return ""
        follow_up = str(getattr(provider, "priority_follow_up", "") or "") or FOLLOW_UP
        hint = priority_hint(list(ranked), follow_up=follow_up)
    except Exception as exc:  # noqa: BLE001 — never break analysis over a hint
        logger_.warning(
            "Sink-reachability pre-pass failed (%s); continuing without hint.",
            type(exc).__name__,
        )
        return ""
    if hint:
        logger_.info(
            "Sink-reachability pre-pass: priority-functions hint built (%d chars).", len(hint)
        )
    else:
        logger_.info(
            "Sink-reachability pre-pass: no named sink APIs reachable "
            "(stripped/static binary?) — no hint emitted."
        )
    return hint


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
    # Where the provider stands among the settings selector's choices; lower first.
    choice_order: ClassVar[int] = 100
    # The words a reader choosing how to analyse a sample sees (the submit
    # dialog), beside the id; empty reads the title.
    choice_label: ClassVar[str] = ""
    # The leaves of the provider's own block (relative to it; one ending in
    # "." names every leaf under it) the setup guide shows up front, and those
    # it folds under "Advanced". Neither declared: the guide shows the whole
    # block by each entry's own advanced flag.
    guide_leaves: ClassVar[tuple[str, ...]] = ()
    guide_advanced_leaves: ClassVar[tuple[str, ...]] = ()
    # Whether the provider hands its report reader the per-task reports it
    # fetched beside the report itself, so a stored report that does not say
    # what was read (``SandboxReport.read_from``) is read as having had them.
    FETCHES_TASK_REPORTS: ClassVar[bool] = False
    # The non-secret environment variable names this provider's own sentences
    # name, kept whole in published text (as ``StaticProvider.variable_names``).
    variable_names: ClassVar[tuple[str, ...]] = ()
    # A server block of this provider's own (as ``StaticProvider.declaration_block``).
    declaration_block: ClassVar[str] = ""

    @classmethod
    @abstractmethod
    def from_settings(cls, cfg: Settings) -> SandboxProvider: ...

    def submission_address(self) -> str | None:
        """The host a submission sends the sample to, as this provider resolves its URL.

        Read by the run's disclosure block (``analysis.disclosure``) when the
        sample is submitted. ``None`` for a submission that never leaves the
        worker, such as recorded fixtures read in place; ``""`` where the
        provider does not say, which the block states as a host it cannot
        name.
        """
        return ""

    @classmethod
    def declaration(cls, cfg: Settings) -> Any:
        """This provider's own declaration of its tools, or ``None`` for none.

        The declaration fields of an ``MCPServerConfig`` (``tool_facts``,
        ``roles``, ``prompt_fragment`` …), as an object or a mapping, read
        under ``provider:<id>`` (``core.tool_declarations``) wherever a
        built-in's block is read, so a provider registered at runtime declares
        its tools the way the built-ins do. Read for a provider whose block is
        not a provider block (``provider_blocks``); a provider that drives a server of the
        registry (``declaration_source`` ``mcp:<key>``) is declared by that
        server.
        """
        return None

    @classmethod
    def display_name(cls) -> str:
        """What a prompt calls this sandbox: its title, else its choice label or id."""
        return cls.title or cls.choice_label or cls.id or "sandbox"

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
        if found is not None:
            return found.signature_scale
        # No declaration under the reader's id: the scale the reader set on
        # the report from its own declaration, if any.
        return run.report.signature_scale

    def dynamic_tools(self) -> list[BaseTool]:
        return []

    def dynamic_prompt_fragment(self) -> str:
        return ""

    def close(self) -> None:
        return None


def record_provider_withheld(provider: Any, registry: Any, own: list[str] | None = None) -> None:
    """Put each tool ``provider`` withholds, with its reason, on the job's degraded record.

    ``registry`` is the job's server registry, whose ``degradation_reasons``
    the run summary reads; ``own``, when given, an agent's own list, which
    is extended in place. Each reason is put once.
    """
    reader = getattr(provider, "withheld_reasons", None)
    reasons = reader() if callable(reader) else []
    held = getattr(registry, "degradation_reasons", None)
    for reason in reasons if isinstance(reasons, list) else []:
        if own is not None and reason not in own:
            own.append(reason)
        if isinstance(held, list) and reason not in held:
            held.append(reason)
