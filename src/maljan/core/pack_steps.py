"""The triage pack's steps, declared as data.

The pack (``pipeline.triage_pack``) runs a list of steps over every sample
before any analyst starts. Each step is declared here as a :class:`PackStep`:

* ``id``: the step's name, unique in the list. A later step names an earlier
  one by it (``after``, ``starts_after``, ``beside``).
* ``tool`` and ``server``: what the step calls. With no ``server`` the step is
  one of the platform's own, run in-process, named by its shipped id; with
  a ``server`` it is that tool server's tool, called through the tool server
  registry exactly as an agent's call is and recorded under that server, so
  any MCP tool an operator plugs in can do work that would otherwise be left
  to a model.
* ``arguments``: a server step's argument template. A string value may hold
  ``{sample_path}`` (the path that server opens the sample at), ``{sha256}``
  and ``{file_type}`` (the routed format). With no template, the arguments
  are read from the tool's declaration: the argument it declares for the
  ``path`` role takes the sample's path, the one for ``hash`` the sample's
  sha256. The platform's own steps compute their own arguments.
* ``formats``: the routed formats the step runs for; empty is every format.
* ``budget_seconds``: the step's wall clock; ``None`` takes the tool's
  declared ``timeout_seconds``, else, for a long step, what is left of the
  pack's budget.
* ``peak_mb``: the memory the step is declared to take at its peak, read
  where a step that measures none is scheduled beside others.
* ``starts_after`` and ``beside``: a step that may run while the pack goes on
  is started, on a thread of its own, right after the step ``starts_after``
  names, when the host has room for it beside the steps ``beside`` names
  (their peaks and its own, against ``triage.memory_floor_mb``); its entry is
  still recorded at its own place in the list. Otherwise it runs in turn, at
  its place, and the pack's facts say why.
* ``renderer``: how the pack's line shows the step's answer (one of
  :data:`PACK_RENDERERS`); empty is the generic line.
* ``kind``: the kind of answer the step records, laid over the tool's
  declared kind on the entry.
* ``display_name``: what the pack's line calls the step; empty is the tool's
  declared display name, else its name.
* ``enabled``: off leaves the step out.
* ``after``: where a step not in the shipped list goes: after the step it
  names, else after every shipped step.

:func:`default_steps` is the shipped list. ``triage.steps`` holds the
operator's declarations (:func:`effective_steps`): one under a shipped step's
id is laid over that step field by field, in its place (``enabled: false``
drops it); one that changes the step's ``tool`` or ``server`` replaces it at
that place, keeping only the id; a new id adds a step. So an operator adds any
tool as a step, drops one, or swaps one for a tool of their own that answers
the same kind.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from maljan.core.tool_declarations import check_tool_name

__all__ = [
    "ARGUMENT_PLACEHOLDERS",
    "default_steps",
    "PACK_RENDERERS",
    "PackStep",
    "check_steps",
    "effective_steps",
    "shipped_step",
]

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_PLACEHOLDER_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

# What a server step's argument template may name, and what each stands for.
ARGUMENT_PLACEHOLDERS: dict[str, str] = {
    "sample_path": "the path the step's server opens the sample at",
    "sha256": "the sample's sha256",
    "file_type": "the format the run routed the sample as",
}

# How a pack line can show an answer: each a shape of answer, never a tool.
PACK_RENDERERS: dict[str, str] = {
    "identity": "a file identification: format, platform, size, mime type, category",
    "digests": "the file's digests, each whole",
    "code_signing": "whether the file carries a code signature, for its format",
    "pe_header": "a PE header: sections, imports, exports, packer signatures, overlay",
    "elf_header": "an ELF header: bitness, interpreter, needed libraries, sections, imports",
    "macho_header": "a Mach-O header: file type, load commands, dylibs, entitlements",
    "apk_manifest": "an APK's manifest facts: package, components, permissions, dex, ABIs",
    "document_facts": "a document's structural facts, as the reader listed them",
    "archive_listing": "an archive's members",
    "string_runs": "a count of the printable runs recorded",
    "file_iocs": "indicators found in the file, counted by kind",
    "signature_rules": "signature rule hits over the bytes",
    "capability_rules": "capability rules, each with the places it matched, and the techniques",
    "event_rules": "event rule hits over a sandbox's events",
    "api_catalogue": "reference associations of API names with behaviours and techniques",
    "command_match": "command lines matching a known proxy-execution shape",
    "sandbox_processes": "a sandbox's process tree",
    "sandbox_network": "a sandbox's network activity, counted by kind",
    "sandbox_signatures": "a sandbox's signatures",
    "sandbox_dropped_files": "a count of the files a sandbox saw dropped",
    "sandbox_channels": "the channels a sandbox reports",
    "sandbox_sections": "a sandbox report's section index",
    "sandbox_status": "the sentence saying what the run's sandbox report is",
    "capture_summary": "a packet capture's counts and external conversations",
    "function_matches": "functions shared with known families",
    "emulated_strings": "strings recovered by emulation, each with its call site",
    "api_hash_resolution": "hash values named as API functions, each where it stands",
    "decoded_blobs": "texts decoded from the data sections, each with who refers to it",
    "crypto_constants": "published constant sets found in the file",
    "anti_analysis_scan": "the exact part of an anti-analysis scan",
    "unpacked_image": "an unpacked program and where it now is",
    "function_table": "a function index, placed in the room the rest of the pack leaves",
}

# The platform's own steps that take a wall clock of their own.
_BUDGETED_BUILTINS = frozenset({"capa", "floss", "yara_scan"})


class PackStep(BaseModel):
    """One step of the triage pack (see the module docstring)."""

    # A key this model does not know is refused: a misspelt ``enabled`` would
    # otherwise save as a step that runs.
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    tool: str = ""
    server: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    formats: tuple[str, ...] = ()
    budget_seconds: float | None = Field(default=None, gt=0)
    peak_mb: int | None = Field(default=None, gt=0)
    starts_after: str = ""
    beside: tuple[str, ...] = ()
    renderer: str = ""
    kind: str = ""
    display_name: str = ""
    enabled: bool = True
    after: str = ""

    @field_validator("id")
    @classmethod
    def _id_is_a_word(cls, value: str) -> str:
        if not _ID_RE.match(value or ""):
            raise ValueError(
                f"step id {value!r} is not a step name: lowercase letters, digits and "
                "underscores, starting with a letter, at most 64 characters"
            )
        return value

    @field_validator("tool")
    @classmethod
    def _tool_is_a_name(cls, value: str) -> str:
        return check_tool_name(value) if value else value

    @field_validator("server")
    @classmethod
    def _server_is_a_key(cls, value: str) -> str:
        if value and value != value.strip():
            raise ValueError(f"server {value!r} must be a server key, not padded")
        return value

    @field_validator("renderer")
    @classmethod
    def _renderer_is_known(cls, value: str) -> str:
        if value and value not in PACK_RENDERERS:
            raise ValueError(
                f"renderer {value!r} is not one of the pack's renderers: "
                + ", ".join(sorted(PACK_RENDERERS))
            )
        return value

    @field_validator("formats")
    @classmethod
    def _formats_are_words(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for name in value:
            if not name or name != name.strip().lower():
                raise ValueError(f"format {name!r} must be a routed format name, lowercase")
        return value

    @field_validator("arguments")
    @classmethod
    def _placeholders_are_known(cls, value: dict[str, Any]) -> dict[str, Any]:
        for name, held in value.items():
            if not isinstance(name, str) or not name:
                raise ValueError("an argument template names each argument")
            for found in _PLACEHOLDER_RE.findall(held if isinstance(held, str) else ""):
                if found not in ARGUMENT_PLACEHOLDERS:
                    raise ValueError(
                        f"argument {name!r} names {{{found}}}, which a template cannot name; "
                        "known: " + ", ".join(f"{{{p}}}" for p in ARGUMENT_PLACEHOLDERS)
                    )
        return value

    @model_validator(mode="after")
    def _a_step_names_what_it_calls(self) -> PackStep:
        if self.server and not self.tool:
            raise ValueError(f"step {self.id!r} names a server and no tool to call on it")
        return self

    @property
    def builtin(self) -> bool:
        """Whether the step is one of the platform's own, run in-process."""
        return not self.server

    @property
    def called(self) -> str:
        """The tool the step calls and is recorded under: its ``tool``, else its id."""
        return self.tool or self.id


def _builtin_problems(step: PackStep) -> list[str]:
    """What a step with no server declares that no in-process step can honour."""
    if step.server:
        return []
    problems: list[str] = []
    shipped = shipped_step(step.id)
    if shipped is None or shipped.server or shipped.called != step.called:
        problems.append(
            f"step {step.id!r} names no server, and is not one of the platform's own "
            "steps: name the server whose tool it is"
        )
    if step.arguments:
        problems.append(
            f"step {step.id!r} is one of the platform's own and computes its own arguments; "
            "to call the tool with arguments of your own, name the server that serves it"
        )
    if step.budget_seconds is not None and step.id not in _BUDGETED_BUILTINS:
        problems.append(
            f"step {step.id!r} runs in-process with no wall clock of its own to set; "
            "budget_seconds applies to " + ", ".join(sorted(_BUDGETED_BUILTINS))
        )
    return problems


def _o(**fields: Any) -> PackStep:
    return PackStep(**fields)


def _shipped() -> tuple[PackStep, ...]:
    from maljan.extractors.sample_identity import ARCHIVE_FILE_TYPES, DOCUMENT_FILE_TYPES
    from maljan.tools.emulated_strings import FLOSS_ADDRESS_SPACE_BYTES

    mib = 1024 * 1024
    sandbox = (
        ("sandbox_status", "sandbox", "sandbox_status"),
        ("sandbox_processes", "sandbox processes", "sandbox_processes"),
        ("sandbox_network", "sandbox network", "sandbox_network"),
        ("sandbox_signatures", "sandbox signatures", "sandbox_signatures"),
        ("sandbox_dropped_files", "sandbox dropped files", "sandbox_dropped_files"),
        ("sandbox_channels", "sandbox channels", "sandbox_channels"),
    )
    return (
        _o(id="identify_file", renderer="identity", display_name="identity"),
        _o(id="hashes", renderer="digests", display_name="hashes"),
        _o(id="signing_info", renderer="code_signing", display_name="signature"),
        _o(id="pe_info", formats=("pe",), renderer="pe_header", display_name="pe"),
        _o(id="elf_info", formats=("elf",), renderer="elf_header", display_name="elf"),
        _o(id="macho_info", formats=("mach-o",), renderer="macho_header", display_name="mach-o"),
        _o(id="apk_info", formats=("apk", "dex"), renderer="apk_manifest", display_name="apk"),
        _o(
            id="document_info",
            formats=tuple(sorted(DOCUMENT_FILE_TYPES)),
            renderer="document_facts",
            display_name="document",
        ),
        _o(
            id="archive_list",
            formats=(*sorted(ARCHIVE_FILE_TYPES), "jar"),
            renderer="archive_listing",
            display_name="archive",
        ),
        _o(id="strings", renderer="string_runs", display_name="strings"),
        _o(id="iocs_from_file", renderer="file_iocs", display_name="iocs"),
        _o(id="yara_scan", renderer="signature_rules", display_name="yara"),
        _o(id="capa", renderer="capability_rules", display_name="capa"),
        _o(id="sigma_match_sandbox", renderer="event_rules", display_name="sigma"),
        _o(id="api_capability", renderer="api_catalogue", display_name="api catalogue"),
        _o(id="lolbin_lookup", renderer="command_match", display_name="lolbin"),
        *(_o(id=key, renderer=renderer, display_name=label) for key, label, renderer in sandbox),
        _o(id="pcap_summary", renderer="capture_summary", display_name="pcap"),
        _o(id="reputation", display_name="reputation"),
        _o(id="function_matches", renderer="function_matches", display_name="function matches"),
        _o(
            id="floss",
            formats=("pe",),
            starts_after="signing_info",
            beside=("capa",),
            peak_mb=FLOSS_ADDRESS_SPACE_BYTES // mib,
            renderer="emulated_strings",
            display_name="decoded strings",
        ),
        _o(
            id="resolve_api_hashes",
            formats=("pe",),
            renderer="api_hash_resolution",
            display_name="resolved hashes",
        ),
        _o(
            id="decode_string_blobs",
            formats=("pe",),
            renderer="decoded_blobs",
            display_name="decoded blobs",
        ),
        _o(
            id="resolved_api_capability",
            tool="api_capability",
            formats=("pe",),
            renderer="api_catalogue",
            display_name="api catalogue",
        ),
        _o(
            id="find_crypto_constants",
            # As shipped: the executable images by the names the scan was
            # first given.
            formats=("pe", "elf", "macho"),
            renderer="crypto_constants",
            display_name="crypto constants",
        ),
        _o(
            id="find_anti_analysis_techniques",
            renderer="anti_analysis_scan",
            display_name="anti-analysis",
        ),
        _o(
            id="function_index",
            formats=("pe",),
            renderer="function_table",
            display_name="function index",
        ),
        _o(
            id="unpack_upx",
            formats=("pe",),
            renderer="unpacked_image",
            display_name="UPX unpacking",
        ),
        _o(id="sandbox_sections", renderer="sandbox_sections", display_name="sandbox sections"),
    )


_DEFAULT: list[tuple[PackStep, ...]] = []


def default_steps() -> tuple[PackStep, ...]:
    """The shipped list built once on first use."""
    if not _DEFAULT:
        _DEFAULT.append(_shipped())
    return _DEFAULT[0]


def shipped_step(step_id: str) -> PackStep | None:
    """The shipped step of ``step_id``, or ``None``."""
    return next((step for step in default_steps() if step.id == step_id), None)


def _by_tool() -> dict[str, PackStep]:
    """The shipped steps by the tool each records under; two steps of one tool share both."""
    return {step.called: step for step in default_steps()}


def shipped_renderer(tool: str) -> str:
    """The renderer of the shipped step that records under ``tool``; ``""`` for none.

    How the pack reads back an entry its own shipped step wrote, which carries
    no step of its own (``LedgerEntry.pack_step``), and every stored entry.
    """
    held = _by_tool().get(str(tool or ""))
    return held.renderer if held is not None else ""


def shipped_label(tool: str) -> str:
    """The label the pack's line gives the shipped step that records under ``tool``.

    ``tool`` itself for a tool no shipped step records under.
    """
    held = _by_tool().get(str(tool or ""))
    return (held.display_name if held is not None else "") or str(tool or "")


def _as_step(value: Any) -> PackStep:
    return value if isinstance(value, PackStep) else PackStep.model_validate(value)


def _laid_over(shipped: PackStep, declared: PackStep) -> PackStep:
    """``declared`` over ``shipped``: each field it set, the shipped value elsewhere.

    A declaration that changes what the step calls is a step of its own at that
    place: of the shipped step it keeps only the id.
    """
    held = declared.model_fields_set
    calls_other = ("server" in held and declared.server != shipped.server) or (
        "tool" in held and declared.tool and declared.tool != shipped.called
    )
    if calls_other:
        return declared
    return shipped.model_copy(update={name: getattr(declared, name) for name in held})


def check_steps(value: Iterable[Any]) -> list[PackStep]:
    """``value`` as declared steps, refusing a step declared twice and a list that cannot run.

    The list is also laid over the shipped one here, so every problem of the
    effective list is refused where it is saved, never found at run time.
    """
    steps = [_as_step(item) for item in value]
    if not steps:
        return []
    seen: set[str] = set()
    for step in steps:
        if step.id in seen:
            raise ValueError(f"step {step.id!r} is declared twice")
        seen.add(step.id)
    _effective(steps)
    return steps


def effective_steps(declared: Iterable[Any] = ()) -> tuple[PackStep, ...]:
    """The steps the pack runs, in order, the disabled ones left out (module docstring)."""
    return tuple(step for step in _effective([_as_step(item) for item in declared]) if step.enabled)


def _effective(declared: list[PackStep]) -> list[PackStep]:
    steps = list(default_steps())
    for step in declared:
        index = next((i for i, held in enumerate(steps) if held.id == step.id), None)
        if index is None:
            placed = step
            at = len(steps)
        else:
            placed = _laid_over(steps[index], step)
            at = index
            del steps[index]
        if step.after:
            anchor = next((i for i, held in enumerate(steps) if held.id == step.after), None)
            if anchor is None:
                raise ValueError(f"step {step.id!r} comes after {step.after!r}, which no step is")
            at = anchor + 1
        steps.insert(at, placed)
    problems: list[str] = []
    ids = {step.id for step in steps}
    for step in steps:
        problems.extend(_builtin_problems(step))
        if step.starts_after and step.starts_after not in ids:
            problems.append(
                f"step {step.id!r} starts after {step.starts_after!r}, which no step is"
            )
        for other in step.beside:
            if other not in ids:
                problems.append(f"step {step.id!r} runs beside {other!r}, which no step is")
    if problems:
        raise ValueError("; ".join(problems))
    return steps


def steps_record(steps: Sequence[PackStep]) -> list[dict[str, Any]]:
    """The steps as stored data, each with only the fields it sets."""
    return [step.model_dump(mode="json", exclude_unset=True) for step in steps]


def placeholder_values(template: Mapping[str, Any], values: Mapping[str, str]) -> dict[str, Any]:
    """``template`` with each ``{placeholder}`` of a string value replaced by its value.

    Values that are not strings are kept as declared.
    """
    out: dict[str, Any] = {}
    for name, held in template.items():
        if not isinstance(held, str):
            out[name] = held
            continue
        out[name] = _PLACEHOLDER_RE.sub(lambda m: str(values.get(m.group(1), m.group(0))), held)
    return out


def step_schedules(facts: Mapping[str, Any] | None) -> dict[str, str]:
    """How each step that may run beside the pack ran, out of the pack's facts.

    The pack writes each such step's schedule under the step's id
    (``triage_pack.PackResult.to_state``): ``beside <steps>``, or ``in turn``
    and why. They are the facts' only text values.
    """
    return {
        str(key): value for key, value in (facts or {}).items() if isinstance(value, str) and value
    }
