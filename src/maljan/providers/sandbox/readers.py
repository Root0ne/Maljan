"""The sandbox report readers, registered by id: how a payload becomes a ``SandboxReport``.

A reader declares an ``id``, ``sniff(payload) -> bool`` and
``read(payload) -> SandboxReport``, and what its reports can fill
(``reading``). The CAPE, Cuckoo, Triage and mock readers and the generic
JSONPath mapping (``sandbox.rest.mapping``) are registered here; an operator
registers another one at run time (:func:`register_report_reader`) or by an
installed package's entry point in the ``maljan.sandbox_report_readers``
group, and the upload route, the upload provider and the REST provider read
through it as they read through a built-in one.

The report formats (``core.report_formats``) are the declarations the readers
are found through: a declared format names its reader by id, and a registered
reader no declaration names is a format of its own, recognised by its own
``sniff`` (:func:`sandbox_formats`). Nothing outside a reader branches on a
format's name.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, ClassVar

from maljan.core.logger import logger
from maljan.core.report_formats import (
    BUILTIN_REPORT_FORMATS,
    UNREAD_FORMAT,
    ReportFormat,
    SignatureScale,
    effective_formats,
    format_named,
)
from maljan.schemas.sandbox_report import CAPE_RENAMES

if TYPE_CHECKING:
    from maljan.schemas.sandbox_report import Reading, SandboxReport

# The entry-point group an installed package registers a reader under: each
# entry names a ``ReportReader`` subclass or instance.
ENTRY_POINT_GROUP = "maljan.sandbox_report_readers"


class ReportReader(ABC):
    """One way a sandbox's report payload is read into the neutral form."""

    # The id a report format, ``sandbox.rest.report.format`` and a report's
    # ``source_format`` name the reader by.
    id: ClassVar[str] = ""
    # Whether the reader keeps its source's own arrangement
    # (``schemas.sandbox_document``): the document of its report is the source,
    # each block where the source put it.
    keeps_source_arrangement: ClassVar[bool] = False
    # The source's words for blocks the document names otherwise, and the
    # document's word for each (``schemas.sandbox_document.PLACES``), applied
    # where the reader keeps its source's arrangement (:meth:`keep_source`).
    renames: ClassVar[dict[str, str]] = {}
    # Whether the reader recognises a payload on its own: a reader that reads
    # only what it is told to read (a mapping, a fixture) is never sniffed.
    sniffs: ClassVar[bool] = True
    # Whether an operator may name the reader as the reader of a sandbox's
    # reports (``sandbox.rest.report.format``): not a reader of the platform's
    # own fixtures.
    choosable: ClassVar[bool] = True
    # The name published text gives the sandbox whose reports this reader
    # reads, where no format declaration names one.
    display_name: ClassVar[str] = ""
    # Whether the reader reads a report through a JSONPath mapping (``mapping``
    # in its context): a format declaring a mapping names such a reader.
    reads_mapping: ClassVar[bool] = False

    def builtin_format(self) -> ReportFormat | None:
        """The shipped format declaration under this reader's id, if any."""
        return format_named(self.id)

    def sniff(self, payload: Any) -> bool:
        """Whether ``payload`` is a report this reader reads.

        The shipped declaration of the same id decides where there is one; a
        reader with none recognises nothing unless it says otherwise.
        """
        fmt = self.builtin_format()
        return bool(fmt is not None and fmt.detect and fmt.matches(payload))

    @abstractmethod
    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        """``payload`` read into the neutral form.

        ``fmt`` is the format declaration the payload was recognised as, where
        one was; ``context`` carries what one reader needs beside the payload
        (the task reports a sandbox fetched, a mapping).
        """

    def reading(self, read_from: str = "", provider: str = "") -> Reading:
        """What a report this reader read can fill, by what it read (``read_from``)."""
        from maljan.schemas.sandbox_report import REPORT_LIST_FIELDS, Reading

        return Reading(frozenset(REPORT_LIST_FIELDS))

    def task_id(self, payload: Any) -> str | None:
        """The source sandbox's own task id in ``payload``, where the reader knows where it sits."""
        fmt = self.builtin_format()
        return fmt.task_id(payload) if fmt is not None else None

    def target_sha256(self, payload: Any) -> str:
        """The target hash ``payload`` claims, where the reader knows where it sits."""
        fmt = self.builtin_format()
        return fmt.target_sha256(payload) if fmt is not None else ""

    def signature_scale(self) -> SignatureScale | None:
        """What a signature's severity means in this reader's reports, where it is declared."""
        fmt = self.builtin_format()
        return fmt.signature_scale if fmt is not None else None

    def name_for_text(self, fmt: Any = None) -> str:
        """The name published text gives the sandbox: the format's, else the reader's own."""
        if fmt is not None:
            return str(getattr(fmt, "display_name", "") or getattr(fmt, "name", "") or "")
        declared = self.builtin_format()
        if declared is not None:
            return declared.display_name or declared.name
        return self.display_name or self.id

    def keep_source(self, report: SandboxReport, payload: dict[str, Any]) -> SandboxReport:
        """``report`` keeping ``payload``'s own arrangement, renamed blocks under new words.

        For a reader whose source already uses the document's arrangement: the
        document laid out from ``report`` is then ``payload`` itself
        (``schemas.sandbox_document.decompose``).
        """
        from maljan.schemas.sandbox_document import kept_source

        # Any platform link key in the source's DNS rows is removed here, and
        # again where the document is built.
        report.published, report.extras, report.arrangement = kept_source(payload, self.renames)
        return report

    def _scaled(self, report: SandboxReport, fmt: Any) -> SandboxReport:
        """``report`` carrying the scale its format declares, else the reader's own."""
        scale = getattr(fmt, "signature_scale", None) if fmt is not None else None
        report.signature_scale = scale if scale is not None else self.signature_scale()
        return report


_READERS: dict[str, ReportReader] = {}
_ENTRY_POINTS_READ: list[bool] = []


def register_report_reader(reader: Any) -> Any:
    """Register ``reader`` (a ``ReportReader`` subclass or instance) under its id.

    Usable as a class decorator. A reader registered under an id already taken
    replaces the earlier one, as an operator's reader of a built-in id is
    meant to.
    """
    instance = reader() if isinstance(reader, type) else reader
    if not isinstance(instance, ReportReader) or not instance.id:
        raise TypeError("a sandbox report reader is a ReportReader with an id")
    _READERS[instance.id] = instance
    return reader


def unregister_report_reader(reader_id: str) -> None:
    """Remove the reader registered under ``reader_id``, if any."""
    _READERS.pop(reader_id, None)


def _read_entry_points() -> None:
    if _ENTRY_POINTS_READ:
        return
    _ENTRY_POINTS_READ.append(True)
    from importlib.metadata import entry_points

    try:
        found = entry_points(group=ENTRY_POINT_GROUP)
    except Exception as exc:  # noqa: BLE001 — a broken package never stops the built-ins
        logger.warning("Sandbox report readers: entry points unreadable (%s).", type(exc).__name__)
        return
    for entry in found:
        try:
            register_report_reader(entry.load())
        except Exception as exc:  # noqa: BLE001 — one broken reader never stops the others
            logger.warning(
                "Sandbox report readers: one entry point could not be registered (%s).",
                type(exc).__name__,
            )


def fetches_task_reports(provider: str) -> bool:
    """Whether the registered sandbox provider ``provider`` declares it fetches task reports.

    Read from the provider class's declaration
    (``SandboxProvider.FETCHES_TASK_REPORTS``), never from settings; ``False``
    for a provider that declares nothing and for an id no provider is
    registered under (a stored report of a provider since removed).
    """
    from maljan.providers.errors import ProviderConfigurationError
    from maljan.providers.registry import sandbox_provider_class

    try:
        cls = sandbox_provider_class(str(provider or ""))
    except ProviderConfigurationError:
        return False
    return bool(getattr(cls, "FETCHES_TASK_REPORTS", False))


def report_reader(reader_id: str) -> ReportReader | None:
    """The reader registered under ``reader_id``, or ``None``."""
    _read_entry_points()
    return _READERS.get(str(reader_id or ""))


def required_reader(reader_id: str) -> ReportReader:
    """The reader registered under ``reader_id``, refused in words where there is none."""
    reader = report_reader(reader_id)
    if reader is None:
        from maljan.providers.errors import ProviderConfigurationError

        raise ProviderConfigurationError(
            f"No sandbox report reader is registered under {reader_id!r}; the registered "
            f"readers are {', '.join(report_reader_ids())}."
        )
    return reader


def report_reader_ids() -> list[str]:
    """Every registered reader's id, in registration order."""
    _read_entry_points()
    return list(_READERS)


def choosable_reader_ids() -> list[str]:
    """The readers an operator may name as the reader of a sandbox's reports, in order."""
    return [reader_id for reader_id in report_reader_ids() if _READERS[reader_id].choosable]


@dataclass(frozen=True)
class ReaderFormat:
    """A registered reader no declaration names, as a format: recognised and read by its code.

    It answers what a declared format answers (``core.report_formats.ReportFormat``)
    so the upload route and the providers take it alike.
    """

    reader_impl: ReportReader
    detect: list[Any] = field(default_factory=list)
    task_id_paths: list[str] = field(default_factory=list)
    target_sha256_paths: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.reader_impl.id

    @property
    def reader(self) -> str:
        return self.reader_impl.id

    @property
    def display_name(self) -> str:
        return self.reader_impl.display_name

    @property
    def signature_scale(self) -> SignatureScale | None:
        return self.reader_impl.signature_scale()

    def matches(self, payload: Any) -> bool:
        return isinstance(payload, Mapping) and bool(payload) and self.reader_impl.sniff(payload)

    def task_id(self, payload: Any) -> str | None:
        return self.reader_impl.task_id(payload)

    def target_sha256(self, payload: Any) -> str:
        return self.reader_impl.target_sha256(payload)


def sandbox_formats(declared: Iterable[ReportFormat] = ()) -> tuple[Any, ...]:
    """The formats a payload is tried against, in order: the registry's ids.

    The operator's newly declared formats a reader of its own reads first,
    then each registered reader that recognises payloads on its own and that
    no declaration names, then the shipped declarations (an operator's
    declaration under a shipped name merged over it), and last the newly
    declared formats read through a mapping (an accepted proposal among
    them): ``core.report_formats.effective_formats`` with the registered
    readers in their place. A format read through a mapping is recognised by
    the blocks it reads, which a built-in report may hold too; tried after
    every built-in sniffer, it never takes a report a built-in reader reads.
    """
    formats = effective_formats(declared)
    builtin_names = {fmt.name for fmt in BUILTIN_REPORT_FORMATS}
    named = {fmt.name for fmt in formats}
    new = [fmt for fmt in formats if fmt.name not in builtin_names]
    mapped = [fmt for fmt in new if format_reads_mapping(fmt)]
    own = [fmt for fmt in new if not format_reads_mapping(fmt)]
    shipped = [fmt for fmt in formats if fmt.name in builtin_names]
    reader_only = [
        ReaderFormat(reader)
        for reader_id in report_reader_ids()
        if (reader := _READERS[reader_id]).sniffs and reader_id not in named
    ]
    return (*own, *reader_only, *shipped, *mapped)


def format_reads_mapping(fmt: Any) -> bool:
    """Whether format ``fmt`` is read through a mapping: its reader is the mapping reader."""
    reader = report_reader(getattr(fmt, "reader", ""))
    return bool(reader is not None and reader.reads_mapping)


def format_mapping(fmt: Any, fallback: Any = None) -> Any:
    """The mapping a report of format ``fmt`` is read through: its own, else ``fallback``."""
    own = getattr(fmt, "mapping", None) if fmt is not None else None
    return own if own is not None else fallback


def mapping_refusal(fmt: Any) -> str:
    """Why format ``fmt`` cannot be read as declared, in words; empty where it can.

    A format that declares a mapping must name a registered reader that reads
    through one: otherwise its mapping would be read by nothing.
    """
    if fmt is None or getattr(fmt, "mapping", None) is None:
        return ""
    reader = report_reader(getattr(fmt, "reader", ""))
    if reader is None or reader.reads_mapping:
        return ""
    return (
        f"The report format {fmt.name!r} declares a mapping, but its reader "
        f"{fmt.reader!r} reads no mapping; name a reader that does (the mapping "
        "reader is 'generic') or remove the mapping."
    )


def sandbox_format_named(name: str, formats: Iterable[Any]) -> Any:
    """The format among ``formats`` named ``name``, or ``None``."""
    for fmt in formats:
        if fmt.name == name:
            return fmt
    return None


# -- the built-in readers ---------------------------------------------------


@register_report_reader
class CapeReportReader(ReportReader):
    """A CAPE report: read into the form, keeping the report's own arrangement."""

    id = "cape2"
    keeps_source_arrangement = True
    renames = CAPE_RENAMES

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        from maljan.schemas.sandbox_report import cape_report_to_sandbox_report

        report = cape_report_to_sandbox_report(
            payload,
            provider=provider,
            source_format=self.id,
            task_id=task_id,
            keep_arrangement=self.keeps_source_arrangement,
            renames=self.renames,
        )
        return self._scaled(report, fmt)

    def reading(self, read_from: str = "", provider: str = "") -> Reading:
        from maljan.schemas.sandbox_report import (
            CAPE_NORMALISER_FILLS,
            READ_FROM_MODEL,
            Reading,
        )

        return Reading(CAPE_NORMALISER_FILLS, rendered=read_from == READ_FROM_MODEL)


@register_report_reader
class CuckooReportReader(CapeReportReader):
    """A Cuckoo report: the shape CAPE inherited, read by the same reader."""

    id = "cuckoo"


@register_report_reader
class MockReportReader(CapeReportReader):
    """The mock sandbox's fixture: a recorded report in CAPE's shape, or its empty stand-in."""

    id = "mock"
    sniffs = False
    choosable = False

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        report = super().read(payload, provider=provider, task_id=task_id, fmt=fmt)
        # A fixture is an observation of some earlier detonation, not of this
        # run; the stand-in is marked synthetic instead.
        report.recorded_fixture = not report.synthetic
        return report


@register_report_reader
class TriageReportReader(ReportReader):
    """A Triage overview, with the behavioural task reports a sandbox fetched beside it."""

    id = "triage"
    PARTIAL = "read from its overview alone"

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        from maljan.schemas.sandbox_report import triage_overview_to_sandbox_report

        report = triage_overview_to_sandbox_report(
            payload,
            provider=provider,
            source_format=self.id,
            task_reports=context.get("task_reports"),
            task_id=task_id,
            # A disputed lineage row names its sandbox as the matched format declares it.
            marked_by=self.name_for_text(fmt) if fmt is not None else "",
        )
        return self._scaled(report, fmt)

    def reading(self, read_from: str = "", provider: str = "") -> Reading:
        from maljan.schemas.sandbox_report import (
            READ_FROM_OVERVIEW,
            READ_FROM_TASKS,
            TRIAGE_NORMALISER_FILLS,
            TRIAGE_OVERVIEW_FILLS,
            Reading,
        )

        if not read_from:
            # Not said: a provider that declares it fetches task reports
            # (``SandboxProvider.FETCHES_TASK_REPORTS``) is taken to have.
            read_from = READ_FROM_TASKS if fetches_task_reports(provider) else READ_FROM_OVERVIEW
        if read_from == READ_FROM_OVERVIEW:
            return Reading(TRIAGE_OVERVIEW_FILLS, partial=self.PARTIAL)
        return Reading(TRIAGE_NORMALISER_FILLS)


@register_report_reader
class MappedReportReader(ReportReader):
    """Any sandbox's JSON, read through the operator's JSONPath mapping (``sandbox.rest``)."""

    id = "generic"
    sniffs = False
    reads_mapping = True

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        from maljan.providers.sandbox.rest_mapping import (
            CompiledMapping,
            apply_mapping,
            compile_mapping,
        )

        mapping = context.get("mapping")
        if mapping is None:
            from maljan.core.config import RestMappingConfig

            mapping = RestMappingConfig()
        compiled = mapping if isinstance(mapping, CompiledMapping) else compile_mapping(mapping)
        report = apply_mapping(compiled, payload, provider=provider, task_id=task_id).report
        scale = context.get("signature_scale")
        report.signature_scale = (
            scale if scale is not None else getattr(fmt, "signature_scale", None)
        )
        return report

    def reading(self, read_from: str = "", provider: str = "") -> Reading:
        from maljan.providers.sandbox.rest_mapping import REST_MAPPING_FILLS
        from maljan.schemas.sandbox_report import Reading

        return Reading(REST_MAPPING_FILLS)


@register_report_reader
class UnreadReportReader(ReportReader):
    """A report no format recognises, accepted where the operator allows it: raw blocks only.

    Every top-level block becomes a ``report.<block>`` channel the dynamic
    analyst reads (the mapping reader with no path at all), every section is
    named unavailable, and no observed fact is drawn from it. It is never
    sniffed and never chosen: an upload is read by it only when its row
    recorded it as accepted unread.
    """

    id = UNREAD_FORMAT
    sniffs = False
    choosable = False

    def read(
        self,
        payload: dict[str, Any],
        *,
        provider: str,
        task_id: str = "",
        fmt: Any = None,
        **context: Any,
    ) -> SandboxReport:
        from maljan.core.report_mapping import RestMappingConfig
        from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping

        nothing = compile_mapping(RestMappingConfig(target_sha256=""))
        report = apply_mapping(nothing, payload, provider=provider, task_id=task_id).report
        report.source_format = self.id
        return report

    def reading(self, read_from: str = "", provider: str = "") -> Reading:
        from maljan.schemas.sandbox_report import Reading

        return Reading(frozenset({"channels"}))
