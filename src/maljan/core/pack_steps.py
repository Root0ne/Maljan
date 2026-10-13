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
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any, NamedTuple

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from maljan.core.tool_declarations import check_tool_name

__all__ = [
    "ARGUMENT_PLACEHOLDERS",
    "DECLARED_FACT_RENDERERS",
    "answer_field",
    "answer_fields",
    "default_steps",
    "PACK_RENDERERS",
    "PackStep",
    "check_steps",
    "effective_steps",
    "lenient_steps",
    "LeftOutStep",
    "steps_left_out",
    "read_answer_field",
    "runs_shipped",
    "shipped_step",
    "shipped_tools_of",
    "written_for",
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

# The renderers that read an answer through its tool's declared facts (its
# rows, their values and places, its techniques) as well as in the shape of
# the tool they were written for, so any tool of the kind is shown with the
# same facts. Every other renderer reads only the answer of the tool its
# shipped step calls, and is refused on any other step: on another tool's
# answer it would state what that answer does not say.
DECLARED_FACT_RENDERERS = frozenset({"capability_rules"})


class PackStep(BaseModel):
    """One step of the triage pack (see the module docstring).

    A step dumps the fields it was given and no others: a declaration is
    merged over the shipped step field by field, over the fields it sets, so
    a dump that wrote every field would blank the shipped ones when read back.
    """

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
        for name in value:
            if not isinstance(name, str) or not name:
                raise ValueError("an argument template names each argument")
        # Every string of the template is checked, at any depth, as every one
        # is filled (``placeholder_values``).
        for name, text in _template_strings(value):
            for found in _PLACEHOLDER_RE.findall(text):
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

    @model_serializer(mode="wrap")
    def _dump_what_was_set(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        dumped = handler(self)
        held = self.model_fields_set | {"id"}
        return {name: value for name, value in dumped.items() if name in held}

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
            # The executable images, by the names the router gives them.
            formats=("pe", "elf", "mach-o"),
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


_INDEXES: list[tuple[dict[str, PackStep], dict[str, PackStep], dict[str, frozenset[str]]]] = []


def _indexes() -> tuple[dict[str, PackStep], dict[str, PackStep], dict[str, frozenset[str]]]:
    """The shipped steps by id, by the tool each records under, and each renderer's tools.

    Built once.
    """
    if not _INDEXES:
        steps = default_steps()
        tools: dict[str, set[str]] = {}
        for step in steps:
            if step.renderer:
                tools.setdefault(step.renderer, set()).add(step.called)
        _INDEXES.append(
            (
                {s.id: s for s in steps},
                {s.called: s for s in steps},
                {renderer: frozenset(names) for renderer, names in tools.items()},
            )
        )
    return _INDEXES[0]


def shipped_tools_of(renderer: str) -> frozenset[str]:
    """The tools the shipped steps of ``renderer`` call: the answers it was written for."""
    return _indexes()[2].get(renderer, frozenset())


def written_for(renderer: str, tool: Any) -> bool:
    """Whether ``tool`` is one the shipped steps of ``renderer`` call: an answer it reads as is.

    The reading of an entry the pack's own step wrote, as :func:`shipped_renderer` is.
    """
    return str(tool or "") in shipped_tools_of(renderer)


def runs_shipped(renderer: str, steps: Iterable[PackStep] | None = None) -> bool:
    """Whether ``steps`` run one of the tools the shipped steps of ``renderer`` call.

    ``steps`` is the effective list (the shipped one for ``None``), the tool
    as the platform runs it. Where
    no answer of the kind came back, an answer names what it compared with
    by that tool only when the list runs it; else neutrally, so an answer
    never names a tool the operator swapped out.
    """
    held = effective_steps() if steps is None else steps
    tools = shipped_tools_of(renderer)
    return any(step.builtin and step.called in tools for step in held)


def _historic_word(renderer: str) -> str:
    """The one tool the shipped steps of ``renderer`` call; ``""`` for none or several."""
    tools = shipped_tools_of(renderer)
    return next(iter(tools)) if len(tools) == 1 else ""


def answer_field(template: str, renderer: str, neutral: str, *, shipped: bool) -> str:
    """The name an answer gives what the tools behind ``renderer``'s kind contributed.

    ``template`` with the shipped tool's name in it when ``shipped`` (every
    source is the tool the shipped step of ``renderer`` calls, or there is
    none), the name these answers have always used; else with ``neutral``, so
    an answer never names a tool that did not run. ``"also_recovered_by_{}"``
    with the shipped decoder, or ``neutral`` ``"decoder"``.
    """
    word = _historic_word(renderer) if shipped else ""
    return template.format(word or neutral)


def answer_fields(template: str, renderer: str, neutral: str) -> tuple[str, ...]:
    """Both names :func:`answer_field` may give, the shipped one first, each once."""
    return tuple(
        dict.fromkeys(
            answer_field(template, renderer, neutral, shipped=shipped) for shipped in (True, False)
        )
    )


def read_answer_field(
    mapping: Mapping[str, Any], template: str, renderer: str, neutral: str
) -> Any:
    """What ``mapping`` holds under either name :func:`answer_field` gives; ``None`` for neither."""
    for name in answer_fields(template, renderer, neutral):
        if name in mapping:
            return mapping[name]
    return None


def shipped_step(step_id: str) -> PackStep | None:
    """The shipped step of ``step_id``, or ``None``."""
    return _indexes()[0].get(step_id)


def _by_tool() -> dict[str, PackStep]:
    """The shipped steps by the tool each records under; two steps of one tool share both."""
    return _indexes()[1]


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


def _effective(
    declared: list[PackStep], found: dict[str, list[str]] | None = None
) -> list[PackStep]:
    """The shipped list with ``declared`` laid over it, in one pass over each.

    Held as a linked list by id, so placing a step after another, or in its
    own place, costs the same whatever the list's length. Every problem of
    the list is refused with one error naming them all, or, given ``found``,
    recorded there under the id of the step that has it (a step placed after
    no step stays last), for :func:`lenient_steps`.
    """
    held: dict[str, PackStep] = {}
    after: dict[str, str] = {}
    before: dict[str, str] = {}
    head, tail = "", ""

    def link(step_id: str, anchor: str) -> None:
        nonlocal head, tail
        follower = after.get(anchor, "") if anchor else head
        if anchor:
            after[anchor] = step_id
            before[step_id] = anchor
        else:
            head = step_id
        if follower:
            after[step_id] = follower
            before[follower] = step_id
        else:
            tail = step_id

    def unlink(step_id: str) -> str:
        nonlocal head, tail
        previous, following = before.pop(step_id, ""), after.pop(step_id, "")
        if previous:
            if following:
                after[previous] = following
            else:
                after.pop(previous, None)
        else:
            head = following
        if following:
            if previous:
                before[following] = previous
            else:
                before.pop(following, None)
        else:
            tail = previous
        return previous

    for step in default_steps():
        held[step.id] = step
        link(step.id, tail)
    for step in declared:
        if step.id in held:
            held[step.id] = _laid_over(held[step.id], step)
            anchor = unlink(step.id)
        else:
            held[step.id] = step
            anchor = tail
        if step.after:
            if step.after not in held or step.after == step.id:
                said = f"step {step.id!r} comes after {step.after!r}, which no step is"
                if found is None:
                    raise ValueError(said)
                found.setdefault(step.id, []).append(said)
            else:
                anchor = step.after
        link(step.id, anchor)
    steps: list[PackStep] = []
    cursor = head
    while cursor:
        steps.append(held[cursor])
        cursor = after.get(cursor, "")
    problems: list[str] = []
    ids = {step.id for step in steps}
    named_beside = {other for step in steps for other in step.beside}
    set_by = {step.id: step.model_fields_set for step in declared}
    for step in steps:
        own = [
            *_builtin_problems(step),
            *_renderer_problems(step),
            *_schedule_problems(step, set_by.get(step.id, frozenset()), named_beside),
        ]
        if step.starts_after and step.starts_after not in ids:
            own.append(f"step {step.id!r} starts after {step.starts_after!r}, which no step is")
        own.extend(
            f"step {step.id!r} runs beside {other!r}, which no step is"
            for other in step.beside
            if other not in ids
        )
        if own and found is not None:
            found.setdefault(step.id, []).extend(own)
        problems.extend(own)
    if problems and found is None:
        raise ValueError("; ".join(problems))
    return steps


class LeftOutStep(NamedTuple):
    """A stored pack step :func:`steps_left_out` leaves out, and why."""

    # The step's id, else ``#<position>``, else ``triage.steps`` for a stored
    # value that is no list at all.
    name: str
    # Where the stored list holds it; ``None`` for a value that is no list.
    position: int | None
    reason: str


def lenient_steps(
    value: Any, problem: Callable[[PackStep], str] | None = None
) -> tuple[list[PackStep], list[str]]:
    """The stored steps the pack can run, and the names of those left out.

    As :func:`steps_left_out` reads them.
    """
    kept, left = steps_left_out(value, problem)
    return kept, [entry.name for entry in left]


def _validation_said(exc: ValueError) -> str:
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return str(exc)
    said = []
    for error in errors():
        where = ".".join(str(part) for part in error.get("loc", ()))
        message = str(error.get("msg", ""))
        said.append(f"{where}: {message}" if where else message)
    return "; ".join(said) or str(exc)


def steps_left_out(
    value: Any, problem: Callable[[PackStep], str] | None = None
) -> tuple[list[PackStep], list[LeftOutStep]]:
    """The stored steps the pack can run, and each step left out, where it is stored and why.

    How stored settings are read (``core.settings_overrides.build_settings``):
    a stored step this release cannot run, as :func:`check_steps` or
    ``problem`` (the settings' own check of an enabled step, such as the
    server it calls) refuses it, is left out, so the shipped step it changed
    is in force again and every other step still runs, where refusing the
    list would cost the job every setting. A step that names a left-out step
    (``after``, ``starts_after``, ``beside``) is left out with it. A save is
    refused instead (:func:`check_steps`). Each round leaves out every step
    with a problem and the steps naming them, so the rounds stay few
    whatever the list's length.
    """
    if not isinstance(value, list):
        if value in (None, ""):
            return [], []
        return [], [LeftOutStep("triage.steps", None, "the stored steps are not a list")]
    steps: list[PackStep] = []
    left: list[LeftOutStep] = []
    stored_at: dict[str, int] = {}
    for position, item in enumerate(value):
        try:
            step = _as_step(item)
        except ValueError as exc:  # a pydantic ValidationError is one
            named = item.get("id") if isinstance(item, Mapping) else None
            name = named if isinstance(named, str) and named else f"#{position}"
            left.append(LeftOutStep(name, position, _validation_said(exc)))
            continue
        if step.id in stored_at:
            said = f"step {step.id!r} is declared more than once; the first is read"
            left.append(LeftOutStep(step.id, position, said))
            continue
        stored_at[step.id] = position
        steps.append(step)
    shipped = _indexes()[0]
    while steps:
        found: dict[str, list[str]] = {}
        effective = _effective(steps, found)
        if problem is not None:
            for step in effective:
                said = problem(step) if step.enabled else ""
                if said:
                    found.setdefault(step.id, []).append(said)
        if not found:
            break
        out = {step.id: "; ".join(found[step.id]) for step in steps if step.id in found}
        if not out:
            # A problem no declared step holds: the shipped list runs.
            said = "the steps cannot run together: " + "; ".join(
                message for messages in found.values() for message in messages
            )
            left.extend(LeftOutStep(step.id, stored_at[step.id], said) for step in steps)
            return [], left
        naming: dict[str, list[str]] = {}
        for step in steps:
            for other in {step.after, step.starts_after, *step.beside} - {""}:
                naming.setdefault(other, []).append(step.id)
        gone = [step_id for step_id in out if step_id not in shipped]
        while gone:
            cause = gone.pop()
            for step_id in naming.get(cause, ()):
                if step_id not in out:
                    out[step_id] = f"step {step_id!r} names step {cause!r}, which is left out"
                    if step_id not in shipped:
                        gone.append(step_id)
        left.extend(
            LeftOutStep(step.id, stored_at[step.id], out[step.id])
            for step in steps
            if step.id in out
        )
        steps = [step for step in steps if step.id not in out]
    return steps, left


def _starts_early(step: PackStep) -> bool:
    """Whether ``step`` can start beside the pack: any server's tool, or a built-in shipped so."""
    if not step.builtin:
        return True
    shipped = shipped_step(step.id)
    return shipped is not None and bool(shipped.starts_after)


def _early_builtins() -> str:
    return ", ".join(s.id for s in default_steps() if s.builtin and s.starts_after)


def _schedule_problems(
    step: PackStep, declared: frozenset[str] | set[str], named_beside: set[str]
) -> list[str]:
    """The scheduling fields an operator set on ``step`` that the pack could not honour.

    Each would otherwise be saved and ignored at run time: a start beside the
    pack for an in-process step that runs only in turn, steps to run beside
    for a step that starts after none, a peak no schedule reads, a step that
    starts after or beside itself. Only the fields the operator set are
    checked, so a shipped value an operator leaves alone is never refused.
    """
    problems: list[str] = []
    if "starts_after" in declared and step.starts_after == step.id:
        problems.append(f"step {step.id!r} starts after itself")
    if "beside" in declared and step.id in step.beside:
        problems.append(f"step {step.id!r} runs beside itself")
    early = _starts_early(step)
    asked = [
        name for name in ("starts_after", "beside") if name in declared and getattr(step, name)
    ]
    if asked and not early:
        problems.append(
            f"step {step.id!r} runs in-process in turn and cannot start beside the pack, so "
            f"{' and '.join(asked)} would be ignored; of the platform's own steps only "
            f"{_early_builtins()} can, and any server's tool"
        )
    elif "beside" in declared and step.beside and not step.starts_after:
        problems.append(
            f"step {step.id!r} names steps to run beside but starts after none, so it runs "
            "in turn and beside would be ignored; set starts_after"
        )
    if (
        "peak_mb" in declared
        and step.peak_mb is not None
        and not (early and step.starts_after)
        and step.id not in named_beside
    ):
        problems.append(
            f"step {step.id!r} declares peak_mb, which only sizes a step started beside the "
            "pack (starts_after) or one another step runs beside, and this step is neither"
        )
    return problems


def _renderer_problems(step: PackStep) -> list[str]:
    """A renderer that would read ``step``'s answer in another tool's shape.

    A renderer of :data:`DECLARED_FACT_RENDERERS` reads any tool's answer by
    its declared facts; any other only the answer of the tool its shipped step
    calls, on the platform's own step.
    """
    if not step.renderer or step.renderer in DECLARED_FACT_RENDERERS:
        return []
    if step.builtin and step.called in shipped_tools_of(step.renderer):
        return []
    readers = ", ".join(sorted(DECLARED_FACT_RENDERERS))
    return [
        f"step {step.id!r}: renderer {step.renderer!r} reads only the answer of "
        f"{', '.join(sorted(shipped_tools_of(step.renderer)))} as the platform runs it, and "
        f"{step.called!r} is not that; leave renderer empty for the generic line, which reads "
        f"the tool's declared rows, or use a renderer that reads declared facts ({readers})"
    ]


def _template_strings(template: Mapping[str, Any]) -> Iterator[tuple[str, str]]:
    """Every string of ``template`` at any depth, with the top-level argument holding it.

    Walked with a stack of its own, so a deep template costs its size and no
    recursion limit.
    """
    stack: list[tuple[str, Any]] = [(str(name), held) for name, held in template.items()]
    while stack:
        name, held = stack.pop()
        if isinstance(held, str):
            yield name, held
        elif isinstance(held, Mapping):
            stack.extend((name, inner) for inner in held.values())
        elif isinstance(held, list | tuple):
            stack.extend((name, inner) for inner in held)


def placeholder_values(template: Mapping[str, Any], values: Mapping[str, str]) -> dict[str, Any]:
    """``template`` with each ``{placeholder}`` of a string replaced by its value, at any depth.

    Values that are not strings, lists or mappings are kept as declared. A
    filled value is never read for placeholders again.
    """

    def fill(text: str) -> str:
        return _PLACEHOLDER_RE.sub(lambda m: str(values.get(m.group(1), m.group(0))), text)

    def walk(root: Any) -> Any:
        # Built with a stack of its own: each container is copied once and
        # filled in place, so a deep template costs its size.
        def copy(held: Any) -> Any:
            if isinstance(held, str):
                return fill(held)
            if isinstance(held, Mapping):
                made: Any = dict(held)
            elif isinstance(held, list | tuple):
                made = list(held)
            else:
                return held
            pending.append(made)
            return made

        pending: list[Any] = []
        top = copy(root)
        while pending:
            held = pending.pop()
            keys = held.keys() if isinstance(held, dict) else range(len(held))
            for key in list(keys):
                held[key] = copy(held[key])
        return top

    return {name: walk(held) for name, held in template.items()}


def step_schedules(facts: Mapping[str, Any] | None) -> dict[str, str]:
    """How each step that may run beside the pack ran, out of the pack's facts.

    The pack writes each such step's schedule under the step's id
    (``triage_pack.PackResult.to_state``): ``beside <steps>``, or ``in turn``
    and why. They are the facts' only text values.
    """
    return {
        str(key): value for key, value in (facts or {}).items() if isinstance(value, str) and value
    }
