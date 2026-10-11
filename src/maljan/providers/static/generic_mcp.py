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

from typing import TYPE_CHECKING, Any

from langchain_core.tools import BaseTool

from maljan.core.logger import logger
from maljan.providers.base import (
    MirrorSpec,
    StaticCapabilities,
    StaticJobContext,
    StaticProvider,
)
from maljan.providers.registry import register_static_provider
from maljan.providers.servers import ServerHandle

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, Settings

# The samples directory's mount inside a server reached over the network that
# declares no ``sample_mount`` of its own: the right-hand side of the samples
# bind mount in ``docker/docker-compose.yml``.
REMOTE_SAMPLE_MOUNT = "/data/samples"


@register_static_provider("generic_mcp")
class GenericMCPStaticProvider(StaticProvider):
    """Any MCP tool server, attached through a ``ServerHandle``.

    ``label`` names the server in logs and in the generated prompt fragment.
    ``prompt_fragment_text`` lets a caller supply real tool-specific guidance
    instead of the generated, tool-name-listing paragraph.

    The constructor accepts either a ready ``ServerHandle`` (the normal path,
    built by ``from_settings`` from an ``mcp.servers`` entry) or a bare
    ``MCPServerConfig`` (the path ``R2StaticProvider`` and the header tests
    still use, since ``static.r2`` is its own config leaf rather than a
    registry entry) — the latter is wrapped in a handle this class builds and
    owns.
    """

    # What the console calls this provider and says about it, and its test's label.
    title = "Generic MCP server"
    description = "A server from the tool-server registry supplies the static tools."
    settings_intro = "Which configured tool server drives the static analyst."

    def __init__(
        self,
        cfg: MCPServerConfig | ServerHandle,
        *,
        label: str = "MCP",
        prompt_fragment_text: str = "",
    ) -> None:
        if isinstance(cfg, ServerHandle):
            self._handle = cfg
            self._cfg = cfg.config
        else:
            self._cfg = cfg
            self._handle = self._build_handle(label or "generic", cfg)
        self._label = label
        self._prompt_fragment_text = prompt_fragment_text
        self._job = StaticJobContext()
        self.tools: list[Any] = []
        # A declared error's remediation may name the path the server can open
        # for the job's sample: the job's mirror.
        self._handle.error_sample_path = self._mirror_path

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
        return cls(ServerHandle(name, entry), label=entry.label or name)

    @property
    def capabilities(self) -> StaticCapabilities:
        return StaticCapabilities(
            provides_tools=True,
            provides_evidence=False,
            provides_function_hashes=False,
            needs_sample_mirror=True,
            degrade_on_failure=True,
        )

    @property
    def label(self) -> str:
        return self._label or self.id or "MCP"

    def prompt_fragment(self) -> str:
        if self._prompt_fragment_text:
            return self._prompt_fragment_text
        names = [t.name for t in self.get_tools()]
        # Every tool name: the list is the model's map of what it can call.
        listed = ", ".join(f"`{n}`" for n in names) if names else "the tools you are given"
        return (
            f"Analyze the binary using the {self._label} tools available to you. "
            "For EVERY claim you make, you MUST cite a concrete artifact: a function name, "
            "string offset (.data+0xNN), API import, or hex pattern. "
            "Focus on MITRE ATT&CK: T1027 (Obfuscation), T1106 (Native API), "
            "T1055 (Process Injection), T1140 (Deobfuscation).\n\n"
            "=== TOOL USAGE WORKFLOW ===\n"
            f"Available tools: {listed}.\n"
            "Load or open the sample first, enumerate what the binary imports and "
            "contains, then examine the few most suspicious functions in depth. "
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
        self.tools = self._handle.tools()

    def get_tools(self) -> list[BaseTool]:
        return self._handle.tools()

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
