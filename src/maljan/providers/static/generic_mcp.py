"""Generic MCP-server static analysis: any tool server the operator configures.

This is the whole point of the provider layer — how somebody plugs in a
reverse-engineering (or any other) MCP tool Maljan has never heard of, with
nothing more than ``static.generic.server`` naming an entry in
``mcp.servers``. It is also the class ``R2StaticProvider`` subclasses with
radare2-specific defaults (command, prompt fragment): everything below is
deliberately ignorant of what its server's tools are called.

The only tool allow-list is ``MCPServerConfig.tools``: ``None`` exposes every
tool the server advertises (what the built-ins do, and what a server attached
purely from ``static.generic.server`` keeps until the operator narrows it
from its probe result), and a list narrows to those names.
``ServerHandle.tools()`` applies that setting; the provider adds no narrowing
of its own.

Unlike Ghidra, this provider degrades rather than raising
(``StaticCapabilities.degrade_on_failure=True``): an operator's own MCP
server going down should not fail an entire analysis when the deterministic
PE extraction is still there to fall back on. ``open()`` itself still lets a
failed attach propagate — exactly like ``GhidraStaticProvider.open`` — the
degrade decision belongs to the analyst's shared ``_try_initialize_mcp``,
which reads the capability flag; the provider's job is only to say what that
flag should be.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool

from maljan.analysis.anti_analysis import PassFailed
from maljan.core.logger import logger
from maljan.providers.base import (
    MirrorSpec,
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
    with_claim_guidance,
)
from maljan.providers.registry import register_static_provider
from maljan.providers.servers import ServerHandle
from maljan.providers.static.declared_prepass import (
    PROGRAM_ROLE,
    DeclaredPassFailed,
    DeclaredScan,
    answer_value,
    block_declaration,
    call_arguments,
    call_graph_of,
    declared_tool,
    function_hashes_of,
)
from maljan.tools.errors import error_parts

if TYPE_CHECKING:
    from maljan.analysis.sink_reachability import CallGraph
    from maljan.core.config import MCPServerConfig, Settings

# The samples directory's mount inside a server reached over the network that
# declares no ``sample_mount`` of its own: the right-hand side of the samples
# bind mount in ``docker/docker-compose.yml``.
REMOTE_SAMPLE_MOUNT = "/data/samples"


@register_static_provider("generic_mcp")
class GenericMCPStaticProvider(StaticProvider):
    """Any MCP tool server, attached through a ``ServerHandle``.

    ``label`` names the server in logs and in the generated prompt fragment.
    The fragment is the opening sentence (``prompt_lead_text``, else one naming
    the label), the claim guidance every static analyst is given, then the
    workflow the server declares (its ``prompt_fragment``), or, where it
    declares none, what the server served about itself (its MCP
    ``instructions``, quoted), or, where it served none either, a generated
    paragraph listing its tools.
    ``prompt_fragment_text`` lets a caller supply the whole fragment instead.

    The constructor accepts either a ready ``ServerHandle`` (the normal path,
    built by ``from_settings`` from an ``mcp.servers`` entry) or a bare
    ``MCPServerConfig`` (the path ``R2StaticProvider`` and the header tests
    still use, since ``static.r2`` is its own config leaf rather than a
    registry entry) — the latter is wrapped in a handle this class builds and
    owns.
    """

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "Any MCP tool server"
    choice_order = 3
    title = "Generic MCP server"
    description = "A server from the tool-server registry supplies the static tools."
    settings_intro = "Which configured tool server drives the static analyst."

    def __init__(
        self,
        cfg: MCPServerConfig | ServerHandle,
        *,
        label: str = "MCP",
        prompt_fragment_text: str = "",
        prompt_lead_text: str = "",
    ) -> None:
        if isinstance(cfg, ServerHandle):
            self._handle = cfg
            self._cfg = cfg.config
        else:
            self._cfg = cfg
            self._handle = self._build_handle(label or "generic", cfg)
        self.rests: list[dict[str, Any]] = []
        # The job's event sink, set by the container once it is known.
        self.event_sink: Any = None
        self._guard_cfg: Any = None
        self._attach_guard()
        self._label = label
        self._prompt_fragment_text = prompt_fragment_text
        self._prompt_lead_text = prompt_lead_text
        self._job = StaticJobContext()
        self.tools: list[Any] = []
        # A declared error's remediation may name the path the server can open
        # for the job's sample: the job's mirror.
        self._handle.error_sample_path = self._mirror_path
        # A job's server: its process is measured, under the block its calls
        # are recorded under, for the run's isolation part.
        self._handle.declared_source = self.declaration_source
        self._handle.measures_isolation = True

    def _rested(self, record: dict[str, Any]) -> None:
        """Keep one breaker opening for the run summary and announce it."""
        from maljan.pipeline.events import emit_tool_server_rested

        self.rests.append(dict(record))
        emit_tool_server_rested(self.event_sink, record)

    def _regard(self, cfg: Any) -> None:
        """Rebuild the guard from ``cfg``, the settings this provider was built from."""
        self._handle.guard = None
        self._attach_guard(cfg)

    def _attach_guard(self, cfg: Any = None) -> None:
        """Give a handle the registry did not build a guard limiting only what the operator set."""
        if getattr(self._handle, "guard", None) is not None:
            return
        from maljan.providers.server_guard import operator_guard
        from maljan.providers.static.ghidra.provider import get_settings_or_none

        cfg = cfg if cfg is not None else get_settings_or_none()
        block = self._handle.config
        self._handle.guard = operator_guard(
            self._handle.name,
            cfg,
            block=block,
            on_open=self._rested,
            sample_open=getattr(block, "sample_open", None),
            label=str(getattr(block, "label", "") or ""),
        )

    def _mirror_path(self) -> str | None:
        """The path the server can open for the job's sample, ``None`` before a job."""
        held = getattr(self._job, "mirror_sample_path", None)
        return held if isinstance(held, str) and held else None

    @property
    def sample_notes(self) -> Any:
        """The job's note of the paths this provider's server opened (``providers.sample_open``)."""
        return self._handle.sample_notes

    @sample_notes.setter
    def sample_notes(self, notes: Any) -> None:
        self._handle.sample_notes = notes

    def _build_handle(self, name: str, cfg: MCPServerConfig) -> ServerHandle:
        """Wrap a directly-supplied config in a handle, honouring ``server_command``.

        ``R2StaticProvider`` (and any future subclass that names its
        executable under its own field, like ``binary_path``) overrides
        ``server_command`` rather than writing to ``MCPServerConfig.command``
        itself — the config is the shared, user-editable ``Settings`` leaf
        that ``settings_snapshot()`` persists into the job's run summary, so
        writing to it here would show the operator a value they never set.
        The handle gets a private copy with ``command`` resolved instead.
        """
        command = self.server_command()
        if command == cfg.command:
            return ServerHandle(name, cfg)
        return ServerHandle(name, cfg.model_copy(update={"command": command}))

    @classmethod
    def registry_servers(cls, cfg: Any) -> frozenset[str]:
        """The registry entry ``static.generic.server`` names, when it names one."""
        name = cfg.static.generic.server
        return frozenset({str(name)}) if name else frozenset()

    @classmethod
    def from_settings(cls, cfg: Settings) -> GenericMCPStaticProvider:
        """The registry entry ``static.generic.server`` names, or an inert handle.

        An unset (or unknown) reference is not an error here: the provider is
        constructed eagerly by the container, and an operator who selected
        generic_mcp without picking a server should learn that from the probe,
        not from a container that refuses to build.
        """
        from maljan.core.config import MCPServerConfig

        name = cfg.static.generic.server
        entry = cfg.mcp.servers.get(name) if name else None
        if entry is None:
            if name:
                logger.warning(
                    "static.generic.server names %r, which is not in mcp.servers; "
                    "the generic_mcp provider has nothing to attach.",
                    name,
                )
            return cls(ServerHandle(name or "generic", MCPServerConfig()))
        provider = cls(ServerHandle(name, entry), label=entry.label or name)
        provider._regard(cfg)
        return provider

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(
            provides_tools=True,
            provides_evidence=False,
            # Only where the block names its function-hash tool (``prepass_tools``).
            provides_function_hashes=bool(declared_tool(self._cfg, "function_hashes")),
            needs_sample_mirror=True,
            degrade_on_failure=True,
        )

    @property
    def label(self) -> str:
        return self._label or self.id or "MCP"

    def prompt_fragment(self) -> str:
        if self._prompt_fragment_text:
            return self._prompt_fragment_text
        return with_claim_guidance(self.prompt_lead(), self.workflow_fragment())

    def prompt_lead(self) -> str:
        named = f"Analyze the binary using the {self._label} tools available to you. "
        return self._prompt_lead_text or named

    def workflow_fragment(self) -> str:
        """The server's declared workflow text, else its own words, else a paragraph of its tools.

        With no ``prompt_fragment`` declared, a server that served MCP
        ``instructions`` when this attach initialised it is described by
        them and by its offered tools' own descriptions, each quoted as the
        server's data under the lead every undeclared registry server gets
        (``prompt_fragments.undeclared_server_text``). Only a server that
        served none gets the generated paragraph naming its tools.
        """
        declared = str(getattr(self._cfg, "prompt_fragment", "") or "")
        if declared.strip():
            return declared
        # The server's own descriptions, without the notes the platform adds
        # (``_with_aggregate_notes``): quoted below as the server's words.
        tools = self._handle.tools()
        served = str(getattr(self._handle, "server_instructions", "") or "")
        if served.strip():
            from maljan.agents.prompt_fragments import undeclared_server_text

            return undeclared_server_text(self.server_name, served, tools)
        names = [t.name for t in tools]
        # Every tool name: the list is the model's map of what it can call.
        listed = ", ".join(f"`{n}`" for n in names) if names else "the tools you are given"
        return (
            "=== TOOL USAGE WORKFLOW ===\n"
            f"Available tools: {listed}.\n"
            "Load or open the sample first, enumerate what the binary imports and "
            "contains, then examine in depth the functions that matter for the question. "
            "Prefer one summarising call over many narrow ones.\n"
        )

    def server_command(self) -> str:
        """The executable to launch for the stdio transport.

        A plain read of the configured command; a subclass whose config names
        the executable under a different field (``R2StaticProvider``'s
        ``binary_path``, since ``StaticR2Config`` reads better in the settings
        UI than a bare ``command``) overrides only this method rather than
        mutating ``self._cfg`` — the config object is the shared, user-editable
        ``Settings`` leaf that ``settings_snapshot()`` later persists into the
        job's run summary, so writing to it here would show the operator a
        value they never set.
        """
        return self._cfg.command

    @property
    def server_name(self) -> str:
        """The registry key this provider owns; the static analyst excludes it."""
        return self._handle.name

    @property
    def declaration_source(self) -> str:
        """The registry server this provider drives: its tools are that server's.

        Recorded when an entry is written, so a later re-pointing of
        ``static.generic.server`` does not change which declaration a stored
        entry is read by.
        """
        return f"mcp:{self.server_name}"

    def open(self, job: StaticJobContext) -> None:
        """Attach to the configured MCP server for ``job``. Idempotent, per the base contract.

        Same shape as ``GhidraStaticProvider.open``, for the same reason: a
        multi-chunk static run calls this once per chunk on one memoized
        provider instance, re-deriving a *fresh but equal* ``StaticJobContext``
        each time (same sample) rather than the literal same
        object. A repeat call whose job compares equal to the one already
        attached is a no-op; a call for a genuinely different job closes the
        previous toolkit before reattaching, so there is never a point where
        two toolkits — two clients or subprocesses — are live at once.
        """
        if self._handle.is_open:
            if job == self._job:
                return
            self._handle.close()
        self._job = job
        # The job, not the sample. This string becomes the name of the
        # directory the server may stage in, and two jobs on one sample are
        # exactly the case a per-job directory exists for; the sample's digest
        # is the fallback for a caller that has no job to give, and it is then
        # the caller's to clean up.
        self._handle.open(
            job.job_key or job.sha256 or "static",
            output_guardrail=job.output_guardrail,
            max_output_chars=job.max_output_chars,
            truncation_ledger=job.truncation_ledger,
            context_budget=job.context_budget,
        )
        self.tools = self.get_tools()

    def get_tools(self) -> list[BaseTool]:
        return self._with_aggregate_notes(self._handle.tools())

    def _with_aggregate_notes(self, tools: list[BaseTool]) -> list[BaseTool]:
        """``tools`` with the note each declared aggregate tool carries (``aggregate_of``).

        A provider's tools are offered under their own names, so each note
        names the aggregated tools the provider offers as they are named.
        """
        from maljan.core.undeclared_tools import aggregates_of, with_aggregate_notes

        aggregates = aggregates_of(
            getattr(getattr(self._handle, "config", None), "tool_facts", None)
        )
        if not aggregates:
            return tools
        return with_aggregate_notes(tools, aggregates, {t.name: t.name for t in tools})

    # -- the passes the server declares tools for (``prepass_tools``) --------

    @contextmanager
    def _attached_for_pass(self, key: str) -> Iterator[tuple[bool, bool]]:
        """``(attached, attached here)`` for a pass: the server is attached here, and let go
        after, when it was not (the triage pack runs before any analyst attaches it)."""
        if self._handle.is_open:
            yield True, False
            return
        if not bool(getattr(self._cfg, "enabled", True)):
            yield False, False
            return
        self._handle.open(key or "static")
        try:
            yield self._handle.is_open, True
        finally:
            self._handle.close()

    def _pass_notes(self, attached_here: bool) -> Any:
        """The note a pass's open of the sample is kept in.

        The handle's own (the job's) while the server stays attached, or is one
        other jobs share at an address, whose opens outlive this attach. A pass
        that attached a server of its own and lets it go after keeps a note of
        its own: what that attach opened goes with it, and a later attach must
        open the sample afresh rather than be answered from a stale note.
        """
        from maljan.providers.sample_open import SampleNotes, is_shared_address

        notes = self._handle.sample_notes
        if attached_here and not is_shared_address(self._cfg):
            return SampleNotes()
        return notes if isinstance(notes, SampleNotes) else SampleNotes()

    def _call_raw(self, tool: str, arguments: dict[str, Any], budget: float) -> Any:
        """One call of the server's ``tool`` as it advertises it, within ``budget`` seconds."""
        from maljan.agents.base_agent import run_coro_blocking

        found = self._handle.advertised_tool(tool)
        if found is None:
            raise DeclaredPassFailed(f"the {self.label} server offers no tool {tool}")
        return run_coro_blocking(
            found.ainvoke(arguments),
            hard_timeout=budget if budget > 0 else None,
            label=f"{self.server_name}-{tool}",
        )

    def _program_of(self, path: str, budget: float, notes: Any) -> tuple[str | None, str]:
        """``(name, refusal)``: the name the server gave its open of ``path``, opened through
        the block's declared ``sample_open`` once per note, and the server's answer when it
        refused the open (``""`` otherwise). ``(None, "")`` with no ``sample_open``."""
        from maljan.providers.sample_open import SampleOpener, declared, is_refusal

        spec = getattr(self._cfg, "sample_open", None)
        if not declared(spec):
            return None, ""
        opener = SampleOpener(self._handle.note_key, spec, notes)
        answer = opener.open(path, lambda tool, args: self._call_raw(tool, args, budget), held=path)
        if is_refusal(answer):
            return None, str(answer)
        return opener.name_of(path), ""

    def _declared_call(
        self, which: str, path: str | None, budget: float, *, attached_here: bool = False
    ) -> Any:
        """The raw answer of the tool the block declares for the pass ``which``, made on ``path``.

        The sample is opened first only for a tool that names it by its program
        (role ``program``) or names it by no argument at all (a server that
        keeps the opened sample as its session). ``None`` when the tool declares
        an argument role the job has no value for (no call is made); a refused
        open of a tool that needs the program, or a failed call, raises.
        """
        tool = declared_tool(self._cfg, which)
        facts = block_declaration(self._cfg, tool)
        roles = facts.arguments if facts is not None else {}
        program = None
        if path and (PROGRAM_ROLE in roles or not roles):
            program, refusal = self._program_of(path, budget, self._pass_notes(attached_here))
            if refusal and PROGRAM_ROLE in roles:
                raise DeclaredPassFailed(
                    f"the {self.label} server refused to open {path}: {refusal[:300]}"
                )
        arguments = call_arguments(facts, path=path, program=program)
        if arguments is None:
            return None
        return self._call_raw(tool, arguments, budget)

    def call_graph(self, path: str) -> CallGraph | None:
        """The program's call graph from the tool the block declares for it, else ``None``."""
        if not declared_tool(self._cfg, "call_graph"):
            return None
        budget = self.call_budget(_settings_or_none())
        with self._attached_for_pass(self._job.job_key or self._job.sha256) as (attached, here):
            raw = (
                self._declared_call("call_graph", path, budget, attached_here=here)
                if attached
                else None
            )
        if raw is None:
            return None
        parts = error_parts(raw)
        if parts is not None:
            raise DeclaredPassFailed(f"the {self.label} server refused its call graph: {parts[1]}")
        tool = declared_tool(self._cfg, "call_graph")
        return call_graph_of(
            answer_value(raw),
            block_declaration(self._cfg, tool),
            getattr(self._cfg, "auto_name_prefixes", None) or (),
        )

    def function_hashes(self, job: StaticJobContext) -> list[tuple[str, str]]:
        """The functions' hashes from the tool the block declares for them, else none.

        A read that could not be made says why (``FunctionHashes.unavailable``),
        never an empty list that passes for a program with no function.
        """
        from maljan.providers.static.ghidra.function_hashes import FunctionHashes

        tool = declared_tool(self._cfg, "function_hashes")
        if not tool or not job.mirror_sample_path:
            return []
        budget = self.call_budget(_settings_or_none())
        try:
            with self._attached_for_pass(job.job_key or job.sha256) as (attached, here):
                raw = (
                    self._declared_call(
                        "function_hashes", job.mirror_sample_path, budget, attached_here=here
                    )
                    if attached
                    else None
                )
        except PassFailed as failure:
            return FunctionHashes(unavailable=str(failure)[:300])
        except Exception as exc:  # noqa: BLE001 - said as the reason, never raised
            return FunctionHashes(
                unavailable=f"the {self.label} server did not answer {tool} ({type(exc).__name__})"
            )
        if raw is None:
            return FunctionHashes(
                unavailable=f"the {self.label} server was not attached, or {tool} takes an "
                "argument this job has no value for"
            )
        parts = error_parts(raw)
        if parts is not None:
            return FunctionHashes(unavailable=f"{tool} refused: {parts[1][:300]}")
        return FunctionHashes(
            function_hashes_of(answer_value(raw), block_declaration(self._cfg, tool))
        )

    def anti_analysis_scan(
        self, job: StaticJobContext, *, notes: Any = None, call_budget: float = 0.0
    ) -> DeclaredScan | None:
        """The scan by the tool the block declares for it, or ``None`` with none declared.

        It reads the formats the tool's declaration names (``routed_formats``),
        every routed format where it names none. ``notes`` is not read: the
        server's opens are noted on its own handle.
        """
        from maljan.extractors.sample_identity import routed_formats

        tool = declared_tool(self._cfg, "anti_analysis")
        if not tool:
            return None
        facts = block_declaration(self._cfg, tool)
        formats = frozenset(
            facts.routed_formats if facts and facts.routed_formats else routed_formats()
        )
        path = job.mirror_sample_path
        scan = DeclaredScan(
            provider=self.id, formats=formats, sample_path=path or "", tool=tool, facts=facts
        )
        if not bool(getattr(self._cfg, "enabled", True)):
            scan.unavailable = f"the {self.label} server is switched off"
        elif not path:
            scan.unavailable = (
                f"no copy of the sample stands where the {self.label} server reads, so its "
                "declared scan was not made"
            )
        else:

            def call() -> Any:
                with self._attached_for_pass(job.job_key or job.sha256) as (attached, here):
                    raw = (
                        self._declared_call("anti_analysis", path, call_budget, attached_here=here)
                        if attached
                        else None
                    )
                if raw is None:
                    raise DeclaredPassFailed(
                        f"the {self.label} server was not attached, or {tool} takes an argument "
                        "this job has no value for"
                    )
                return raw

            scan.call = call
        return scan

    def mirror_spec(self) -> MirrorSpec:
        """Where the sample is mirrored, and under which path the server sees it.

        Both come from the server's own declaration: its ``work_dir`` and its
        ``sample_mount``. A stdio server is spawned by the worker and reads
        the worker's own filesystem, so with no mount declared it is handed
        the host path. An http/streamable-http/sse server is somewhere else
        with its own mount (BUG 4, live run S4); with none declared it is
        taken to see the samples directory at ``REMOTE_SAMPLE_MOUNT``, the
        mount the shipped compose file writes.
        """
        default = "" if self._cfg.transport == "stdio" else REMOTE_SAMPLE_MOUNT
        return MirrorSpec.of(self._cfg, default_mount=default)

    def close(self) -> None:
        self.tools = []
        self._handle.close()


def _settings_or_none() -> Any:
    """The deployment's settings, or ``None`` where none can be read (a probe, a test)."""
    from maljan.providers.static.ghidra.provider import get_settings_or_none

    return get_settings_or_none()
