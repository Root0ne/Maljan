"""What a sandbox report format says about itself, as data.

A report format is recognised, read and rated through its declaration, never
through code written against its name. A declaration says:

* ``detect``: how a payload is recognised as this format. It is a list of
  groups; the format matches when every test of any one group holds. A test
  names a field path and what the value there must be: one of ``types``
  (``object``, ``array``, ``string``, ``number``, ``boolean``, ``null``),
  non-empty, or holding ``contains`` in its text (a string, number or boolean,
  compared without regard to case);
* ``task_id_paths``: where the source sandbox's own task id sits; the first
  string or number (not empty text) a path names wins, anything else is absent;
* ``target_sha256_paths``: where the report's claimed target sha256 sits; the
  first non-empty string or number a path names wins;
* ``reader``: the id of the registered report reader
  (``providers.sandbox.readers``) that reads a report of this format into the
  neutral sandbox report (``cape2``, ``cuckoo``, ``triage`` and the JSONPath
  mapping reader ``generic`` ship, and an operator registers more), empty for
  a format no reader reads yet;
* ``mapping``: where each part of a report of this format sits, as JSONPaths
  (``core.report_mapping.RestMappingConfig``), for a reader that reads through
  a mapping; absent, such a reader reads through ``sandbox.rest.mapping``.
  The upload route and the REST provider read it alike, so a sandbox nobody
  wrote a reader for is read per format, each format through its own paths;
* ``signature_scale``: what a signature's severity number means, as the rung
  of the five-word severity ladder each score from 1 up names; absent where the
  format documents no scale;
* ``display_name``: the name published text gives the sandbox whose report
  this is (a sentence that says what the report marks), empty for the
  format's ``name``.

The built-in formats (:data:`BUILTIN_REPORT_FORMATS`) reproduce what the
platform recognised and read before formats were declared. An operator
declares more in ``sandbox.report_formats``, read by every sandbox provider
and by the upload route alike. A new name is tried before the built-ins,
because the operator's format is the more specific knowledge, except a
format read through a mapping (``reader: generic``, an accepted proposal
among them), which is tried after every built-in
(``providers.sandbox.readers.sandbox_formats``); a declaration
under a built-in's name is merged over that built-in field by field, in its
place, so a field it does not set keeps the shipped value
(:func:`effective_formats`).

Field paths are the tool declarations' (``maljan.core.tool_declarations``):
``/``-separated keys and ``*`` for every item, read in time linear in the
payload. ``**`` (any depth) is refused here: recognising a report and finding
its id need only anchored places, and a whole-tree walk per test would make
each upload cost a multiple of the report's size.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from maljan.core.report_mapping import RestMappingConfig, check_mapping_paths
from maljan.core.tool_declarations import parse_path, select

# The name a payload no format recognises is given.
UNKNOWN_FORMAT = "unknown"
# The format an upload no format recognises is accepted as, where the operator
# allows it (``"unread"`` in ``sandbox.upload.allowed_formats``): stored and
# read as raw blocks only, with a proposed declaration beside it
# (``core.report_proposals``). Never a declared format's name.
UNREAD_FORMAT = "unread"
# What a run that read an upload unread records among its degradations.
UNREAD_RUN_REASON = (
    "uploaded sandbox report was read unread: no declared format recognises it, so no "
    "observed fact was drawn from it"
)

# A format's name is stored on the upload row (``sandbox_reports.format``,
# ``String(32)``), so a name is a lowercase word of at most that many characters.
FORMAT_NAME_MAX = 32
FORMAT_NAME_PATTERN = rf"^[a-z][a-z0-9_]{{0,{FORMAT_NAME_MAX - 1}}}$"

# A registered report reader's id, as a declaration names it: a lowercase word,
# or empty for a format no reader reads yet. Whether a reader is registered
# under it is asked where the format is read, so a declaration naming a reader
# an installed package adds is never refused while the settings load.
READER_ID_PATTERN = rf"^(|[a-z][a-z0-9_]{{0,{FORMAT_NAME_MAX - 1}}})$"

ValueType = Literal["object", "array", "string", "number", "boolean", "null"]
SeverityRung = Literal["Critical", "High", "Medium", "Low", "Informational"]


def _type_of(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list | tuple):
        return "array"
    return ""


def _check_anchored(path: str) -> str:
    """``path`` parsed, refusing an empty path and ``**``."""
    if not path:
        raise ValueError("an empty field path names nothing")
    if any(not isinstance(segment, str) for segment in parse_path(path)):
        raise ValueError(f"field path {path!r}: a report-format path may not hold '**'")
    return path


def _scalar(value: Any) -> bool:
    """Whether ``value`` is a string or a number (a boolean is neither)."""
    return isinstance(value, str) or (
        isinstance(value, int | float) and not isinstance(value, bool)
    )


def _text(value: Any) -> str:
    """A scalar's text, empty for a container or an empty value."""
    if not value or isinstance(value, Mapping | list | tuple):
        return ""
    return str(value)


class FieldTest(BaseModel):
    """One test on the value at a field path."""

    model_config = ConfigDict(extra="forbid")

    path: str
    types: list[ValueType] = Field(default_factory=list)
    non_empty: bool = False
    contains: str = ""

    @field_validator("path")
    @classmethod
    def _path_parses(cls, value: str) -> str:
        if not value:
            raise ValueError("a field test needs a path")
        return _check_anchored(value)

    def holds(self, payload: Any) -> bool:
        """Whether some value ``path`` names in ``payload`` passes every part of the test."""
        needle = self.contains.lower()
        for value in select(payload, self.path):
            if self.types and _type_of(value) not in self.types:
                continue
            if self.non_empty and not value:
                continue
            if needle and needle not in _text(value).lower():
                continue
            return True
        return False


class SignatureScale(BaseModel):
    """A signature severity scale: the rung each score from 1 to ``max`` means."""

    model_config = ConfigDict(extra="forbid")

    name: str
    rungs: list[SeverityRung] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def _named(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a signature scale needs a name")
        return value

    @property
    def max(self) -> int:
        return len(self.rungs)

    def record(self) -> dict[str, Any]:
        """The scale as a run records it and the console reads it."""
        return {"name": self.name, "max": self.max, "rungs": list(self.rungs)}


class ReportFormat(BaseModel):
    """One sandbox report format, declared."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=FORMAT_NAME_PATTERN)
    # Empty only on a declaration merged over a built-in that keeps the
    # built-in's detection; a new format must declare it (``check_declared_formats``).
    detect: list[list[FieldTest]] = Field(default_factory=list)
    task_id_paths: list[str] = Field(default_factory=list)
    target_sha256_paths: list[str] = Field(default_factory=list)
    reader: str = Field(default="", pattern=READER_ID_PATTERN)
    signature_scale: SignatureScale | None = None
    display_name: str = Field(default="", max_length=64)
    # Where each part of a report of this format sits, for a reader that reads
    # through a mapping (the module docstring).
    mapping: RestMappingConfig | None = None

    @field_validator("name")
    @classmethod
    def _not_reserved(cls, value: str) -> str:
        if value == UNKNOWN_FORMAT:
            raise ValueError(f"{UNKNOWN_FORMAT!r} names a payload no format recognises")
        if value == UNREAD_FORMAT:
            raise ValueError(f"{UNREAD_FORMAT!r} names an upload accepted unread")
        return value

    @field_validator("detect")
    @classmethod
    def _groups_hold_tests(cls, value: list[list[FieldTest]]) -> list[list[FieldTest]]:
        if any(not group for group in value):
            raise ValueError("every detect group needs at least one test")
        return value

    @model_validator(mode="after")
    def _detect_set_is_not_empty(self) -> ReportFormat:
        if "detect" in self.model_fields_set and not self.detect:
            raise ValueError("detect needs at least one group; leave it out to keep a built-in's")
        return self

    @field_validator("mapping")
    @classmethod
    def _mapping_paths_compile(cls, value: RestMappingConfig | None) -> RestMappingConfig | None:
        if value is not None:
            check_mapping_paths(value)
        return value

    @field_validator("task_id_paths", "target_sha256_paths")
    @classmethod
    def _paths_parse(cls, value: list[str]) -> list[str]:
        for path in value:
            _check_anchored(path)
        return value

    def matches(self, payload: Any) -> bool:
        """Whether every test of some ``detect`` group holds on ``payload``."""
        return any(all(test.holds(payload) for test in group) for group in self.detect)

    def task_id(self, payload: Any) -> str | None:
        """The first string or number a task-id path names, not empty text, as text."""
        for path in self.task_id_paths:
            for value in select(payload, path):
                if _scalar(value) and value != "":
                    return str(value)
        return None

    def target_sha256(self, payload: Any) -> str:
        """The first non-empty string or number a target-hash path names, as text, else empty."""
        for path in self.target_sha256_paths:
            for value in select(payload, path):
                if _scalar(value) and value:
                    return str(value)
        return ""


def _test(path: str, *types: ValueType, non_empty: bool = False, contains: str = "") -> FieldTest:
    return FieldTest(path=path, types=list(types), non_empty=non_empty, contains=contains)


# The CAPE and Cuckoo readers' shared places: CAPE nests the sample's identity
# under ``target.file``; the flat ``target.sha256`` is read where a report
# carries it flat.
_CAPE_TASK_ID = ["/info/id"]
_CAPE_TARGET = ["/target/file/sha256", "/target/sha256"]
_LOW_TO_HIGH: list[SeverityRung] = ["Low", "Medium", "High"]

# Most specific first: the first format that matches names the payload.
BUILTIN_REPORT_FORMATS: tuple[ReportFormat, ...] = (
    # A Triage overview carries ``analysis`` and a non-empty ``tasks``, a list
    # in Triage's documentation and an object keyed by task id from its API.
    ReportFormat(
        name="triage",
        detect=[[_test("/analysis", "object"), _test("/tasks", "object", "array", non_empty=True)]],
        task_id_paths=["/sample/id"],
        target_sha256_paths=["/sample/sha256"],
        reader="triage",
        display_name="Triage",
        # A Triage signature's score is its sample-score scale: 1 no malicious
        # behaviour, 2-5 likely benign, 6-7 suspicious, 8-9 likely malicious,
        # 10 known bad.
        signature_scale=SignatureScale(
            name="Triage 1–10",
            rungs=[
                "Informational",
                "Low",
                "Low",
                "Low",
                "Low",
                "Medium",
                "Medium",
                "High",
                "High",
                "Critical",
            ],
        ),
    ),
    # CAPE: a ``CAPE`` block, or a version string naming it.
    ReportFormat(
        name="cape2",
        detect=[
            [_test("/CAPE", "object", "array")],
            [_test("/info", "object"), _test("/info/version", contains="cape")],
        ],
        task_id_paths=_CAPE_TASK_ID,
        target_sha256_paths=_CAPE_TARGET,
        reader="cape2",
        display_name="CAPE",
        signature_scale=SignatureScale(name="CAPE 1–3", rungs=_LOW_TO_HIGH),
    ),
    # Cuckoo: the generic ``info`` + ``behavior`` shape CAPE inherited, reached
    # only once CAPE has been ruled out.
    ReportFormat(
        name="cuckoo",
        detect=[[_test("/behavior", "object"), _test("/info", "object", non_empty=True)]],
        task_id_paths=_CAPE_TASK_ID,
        target_sha256_paths=_CAPE_TARGET,
        reader="cuckoo",
        display_name="Cuckoo",
        signature_scale=SignatureScale(name="Cuckoo 1–3", rungs=_LOW_TO_HIGH),
    ),
)


def check_declared_formats(value: Sequence[ReportFormat]) -> list[ReportFormat]:
    """``value`` as a list, refusing two declarations under one name and a new
    format that does not say how it is recognised."""
    builtin_names = {fmt.name for fmt in BUILTIN_REPORT_FORMATS}
    seen: set[str] = set()
    for fmt in value:
        if fmt.name in seen:
            raise ValueError(f"report format {fmt.name!r} is declared twice")
        seen.add(fmt.name)
        if fmt.name not in builtin_names and not fmt.detect:
            raise ValueError(f"report format {fmt.name!r} needs detect: how a report is recognised")
    return list(value)


def merged_over(builtin: ReportFormat, declared: ReportFormat) -> ReportFormat:
    """``declared`` over ``builtin``: each field ``declared`` set, the shipped value elsewhere."""
    return builtin.model_copy(
        update={field: getattr(declared, field) for field in declared.model_fields_set}
    )


def effective_formats(declared: Iterable[ReportFormat] = ()) -> tuple[ReportFormat, ...]:
    """The formats tried, in order: new declared names, then the built-ins.

    A declaration under a built-in's name is merged over that built-in, in its
    place (:func:`merged_over`).
    """
    declared = list(declared)
    by_name = {fmt.name: fmt for fmt in declared}
    builtin_names = {fmt.name for fmt in BUILTIN_REPORT_FORMATS}
    new = [fmt for fmt in declared if fmt.name not in builtin_names]
    return (
        *new,
        *(
            merged_over(fmt, by_name[fmt.name]) if fmt.name in by_name else fmt
            for fmt in BUILTIN_REPORT_FORMATS
        ),
    )


def sniff(payload: Any, formats: Iterable[ReportFormat] | None = None) -> ReportFormat | None:
    """The first format that recognises ``payload``, or ``None``."""
    if not isinstance(payload, Mapping) or not payload:
        return None
    for fmt in BUILTIN_REPORT_FORMATS if formats is None else formats:
        if fmt.matches(payload):
            return fmt
    return None


def reader_display_name(reader: str, formats: Iterable[ReportFormat] | None = None) -> str:
    """The name published text gives the sandbox whose reports ``reader`` reads.

    The display name of the first format read by ``reader`` that declares one,
    else that format's name; empty when no format names the reader.
    """
    named = [
        fmt
        for fmt in (BUILTIN_REPORT_FORMATS if formats is None else formats)
        if fmt.reader == reader
    ]
    for fmt in named:
        if fmt.display_name:
            return fmt.display_name
    return named[0].name if named else ""


def format_named(name: str, formats: Iterable[ReportFormat] | None = None) -> ReportFormat | None:
    """The format declared under ``name``, or ``None``."""
    for fmt in BUILTIN_REPORT_FORMATS if formats is None else formats:
        if fmt.name == name:
            return fmt
    return None


def _least_value(test: FieldTest) -> tuple[bool, Any]:
    """``(possible, value)``: the plainest value ``test`` holds on, where one can."""
    allowed = list(test.types) or ["string"]
    if test.contains:
        if "string" in allowed:
            return True, test.contains
        if "number" in allowed and test.contains.isdigit():
            return True, int(test.contains)
        return False, None
    kind = allowed[0]
    least: dict[str, tuple[Any, Any]] = {
        "object": ({}, {"_": 0}),
        "array": ([], [0]),
        "string": ("x", "x"),
        "number": (1, 1),
        "boolean": (True, True),
        "null": (None, None),
    }
    if kind == "null" and test.non_empty:
        return False, None
    empty, filled = least[kind]
    return True, filled if test.non_empty else empty


def least_report(group: Sequence[FieldTest]) -> dict[str, Any] | None:
    """The plainest report every test of ``group`` holds on, or ``None`` where none is built.

    Each test's path is written down with the plainest value it holds on (an
    empty object or list, ``"x"``, the text it must contain); ``*`` is one
    item. The shallowest paths are written first, so a deeper test writes
    into the container a shallower one made. ``None`` where the tests
    contradict each other. Linear in the tests' paths.
    """
    root: dict[str, Any] = {}
    for test in sorted(group, key=lambda t: len(parse_path(t.path))):
        possible, value = _least_value(test)
        segments = parse_path(test.path)
        if not possible or not segments:
            return None
        node: Any = root
        for index, segment in enumerate(segments):
            last = index == len(segments) - 1
            following = None if last else segments[index + 1]
            fresh: Any = value if last else ([] if following == "*" else {})
            if isinstance(node, list):
                if segment != "*":
                    return None
                if not node or node == [0]:
                    node[:] = [fresh]
                child = node[0]
            elif isinstance(node, dict):
                key = "_" if segment == "*" else str(segment)
                if last or not isinstance(node.get(key), dict | list):
                    node[key] = fresh
                child = node[key]
            else:
                return None
            node = child
    return root if all(test.holds(root) for test in group) else None


def builtin_overlapping(
    fmt: ReportFormat, builtins: Iterable[ReportFormat] = BUILTIN_REPORT_FORMATS
) -> str:
    """The first built-in whose detect overlaps ``fmt``'s, by name; empty where none does.

    Two readings, each on the plainest report a detect group describes
    (:func:`least_report`): a built-in recognises the plainest report of one
    of ``fmt``'s groups (the reports ``fmt`` was written for), or ``fmt``
    recognises the plainest report of one of a built-in's groups (``fmt``'s
    tests are among the built-in's). A format read through a mapping is tried
    after every built-in, so a report both recognise is read as the built-in.
    """
    builtins = list(builtins)
    own = [report for group in fmt.detect if (report := least_report(group)) is not None]
    for builtin in builtins:
        if builtin.name == fmt.name:
            continue
        if any(builtin.matches(report) for report in own):
            return builtin.name
        for group in builtin.detect:
            report = least_report(group)
            if report is not None and fmt.matches(report):
                return builtin.name
    return ""


# Where a run summary records the signature scale of the run's sandbox report.
SIGNATURE_SCALE_KEY = "sandbox_signature_scale"


def recorded_signature_scale(container: Any) -> dict[str, Any]:
    """What a run summary records about the signature scale, from the job's container.

    Nothing where no sandbox report was read; otherwise the key, holding the
    scale the provider declared or ``None`` where it declared none. A summary
    without the key (every run recorded before scales were) is read by the
    console's legacy table.
    """
    if getattr(container, "sandbox_normalised", None) is None:
        return {}
    scale = getattr(container, "sandbox_signature_scale", None)
    return {SIGNATURE_SCALE_KEY: dict(scale) if isinstance(scale, Mapping) else None}


def declarations_in_effect(declared: Iterable[ReportFormat]) -> list[dict[str, Any]]:
    """Each declaration as it ran, JSON-ready: a built-in's name merged over the built-in.

    What a run's settings snapshot records for ``sandbox.report_formats``, so a
    redeclared built-in reads as the declaration the run used rather than as
    the fields the operator wrote with empty values elsewhere.
    """
    builtins = {fmt.name: fmt for fmt in BUILTIN_REPORT_FORMATS}
    return [
        (merged_over(builtins[fmt.name], fmt) if fmt.name in builtins else fmt).model_dump(
            mode="json"
        )
        for fmt in declared
    ]
