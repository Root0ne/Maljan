"""Operator-uploaded sandbox report behind the provider contract.

Whatever sandbox a shop already runs, this provider is the answer to it:
export the report, attach it to the sample, and the pipeline runs from those
bytes as if they had come from a live detonation. It never submits anything
and never reaches the network — the report is already evidence. It is read as
the format the upload row recorded when the route accepted it, so the format
the console shows for the row is the one the run reads; a blob handed over
with no recorded format is sniffed against the registry's formats
(``providers.sandbox.readers.sandbox_formats``), and read by the registered
reader its format names. A format that declares its own JSONPath mapping
is read through it, else through ``sandbox.rest.mapping``. A row accepted
unread (``core.report_formats.UNREAD_FORMAT``, where the operator allows it) is
read as raw blocks alone until a declaration that recognises it is accepted.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maljan.core.report_formats import UNREAD_FORMAT, ReportFormat, sniff
from maljan.providers.base import SandboxCapabilities, SandboxProvider
from maljan.providers.errors import AttachedReportRefused, ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.providers.sandbox.readers import (
    ReaderFormat,
    format_mapping,
    mapping_refusal,
    report_reader,
    sandbox_format_named,
    sandbox_formats,
)

if TYPE_CHECKING:
    from maljan.core.config import RestMappingConfig, SandboxUploadConfig, Settings
    from maljan.core.report_formats import SignatureScale
    from maljan.schemas.sandbox_report import SandboxRun


@register_sandbox_provider("upload")
class UploadSandboxProvider(SandboxProvider):
    """A sandbox that runs nothing and reads what the operator already has.

    This is the answer to "any sandbox": whatever your shop runs,
    export its report and attach it to the sample. A report attached through
    the upload route is read as the format its row recorded when it was
    accepted (``report_format``), never sniffed again, so the row the console
    shows and the run that reads it always agree; only a blob handed over with
    no recorded format is sniffed.
    """

    # What the console calls this provider and says about it, and its test's label.
    choice_label = "A report you attach"
    guide_leaves = (
        "allowed_formats",
        "max_report_bytes",
    )
    choice_order = 2
    title = "Uploaded report"
    description = "No detonation here: an operator attaches a report from another sandbox."
    settings_intro = "Which report formats an operator may attach, and how large they may be."

    def __init__(
        self,
        cfg: SandboxUploadConfig,
        formats: Iterable[ReportFormat] = (),
        mapping: RestMappingConfig | None = None,
    ) -> None:
        self._cfg = cfg
        # The JSONPath mapping a format read by the mapping reader is read
        # through (``sandbox.rest.mapping``).
        self._mapping = mapping
        self._blob: bytes | None = None
        self._filename = "report.json"
        # M3 (final review): the ledger ruling says report_format is computed
        # per instance from the sniffed format, not hard-coded. Sniffed
        # eagerly in set_pending_blob so it is known by the time anything
        # reads capabilities, without requiring a successful fetch() first;
        # a blob that fails to parse or sniff leaves this None and
        # capabilities falls back to "generic" exactly as before — the real
        # error still surfaces from attach_report()/fetch() when read.
        # The reader of the pending blob's format, which is what report_format names.
        self._sniffed_format: str | None = None
        # The format the pending blob is read as, for its signature scale.
        self._declared: Any = None
        # The format the upload row recorded for the pending blob, if any.
        self._recorded: str | None = None
        self._formats = sandbox_formats(formats)

    @classmethod
    def from_settings(cls, cfg: Settings) -> UploadSandboxProvider:
        return cls(cfg.sandbox.upload, cfg.sandbox.report_formats, cfg.sandbox.rest.mapping)

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            can_submit=False,
            can_poll=False,
            can_fetch_report=True,
            can_fetch_pcap=False,
            accepts_uploaded_report=True,
            provides_tools=False,
            report_format=self._sniffed_format or "generic",
            degrade_on_failure=True,
        )

    def set_pending_blob(
        self, blob: bytes, *, filename: str = "report.json", report_format: str | None = None
    ) -> None:
        """Hand over the bytes the worker just read from storage, and the format its row recorded.

        A recorded format that is no longer declared, or is declared without a
        reader, is refused here in words: the run would otherwise read nothing.
        Idempotent the same way ``open()`` is elsewhere in this layer: a
        second call before the first is ever read simply replaces the pending
        blob rather than layering state on top of it.
        """
        self._blob, self._filename, self._recorded = blob, filename, report_format
        found: Any
        if report_format is not None:
            found = self._recorded_format(report_format)
        else:
            try:
                found = sniff(self._parse(blob), self._formats)
            except ProviderError:
                found = None
        # A blob no format recognises has no report_format; attach_report()
        # and fetch() refuse it with a worded ProviderError, so capabilities
        # just falls back to "generic" for it rather than raising here.
        self._declared = found
        self._sniffed_format = (found.reader or None) if found is not None else None

    def _unread(self) -> Any:
        """The unread format, where the operator allows it; ``None`` otherwise."""
        reader = report_reader(UNREAD_FORMAT)
        if reader is None or UNREAD_FORMAT not in set(self._cfg.allowed_formats):
            return None
        return ReaderFormat(reader)

    def _recorded_format(self, name: str) -> Any:
        """The format an upload row recorded, refused in words where unusable."""
        if name == UNREAD_FORMAT:
            unread = self._unread()
            if unread is None:
                raise AttachedReportRefused(
                    "The attached sandbox report was accepted unread, which "
                    "sandbox.upload.allowed_formats no longer allows; add 'unread' again "
                    "to read it, or accept a declaration that recognises it."
                )
            return unread
        found = sandbox_format_named(name, self._formats)
        if found is None:
            raise AttachedReportRefused(
                f"The attached sandbox report was accepted as format {name!r}, which is no "
                "longer declared in sandbox.report_formats nor registered as a reader; "
                "declare it again to read it."
            )
        if name not in set(self._cfg.allowed_formats):
            raise AttachedReportRefused(
                f"The attached sandbox report was accepted as format {name!r}, which "
                "sandbox.upload.allowed_formats no longer accepts "
                f"({', '.join(sorted(self._cfg.allowed_formats))}); add it again to read it."
            )
        if report_reader(found.reader) is None:
            raise AttachedReportRefused(
                f"The attached sandbox report's format {name!r} names no registered "
                "reader; no analysis can read it yet."
            )
        refusal = mapping_refusal(found)
        if refusal:
            raise AttachedReportRefused(refusal)
        return found

    def submit(self, sample_path: str | Path) -> str:
        raise ProviderError(
            "The upload sandbox does not detonate samples; attach a report to the job instead."
        )

    def submission_address(self) -> str | None:
        """None: this provider submits nothing, and the sample goes nowhere."""
        return None

    def wait_for_completion(
        self,
        task_id: str,
        timeout_seconds: int | None = None,
        poll_interval_seconds: int | None = None,
    ) -> str:
        # Nothing to poll: a report either arrived with the job or it did not.
        return "reported"

    def _parse(self, blob: bytes) -> dict[str, Any]:
        """Decode an untrusted stored blob without ever echoing its content.

        ``utf-8-sig`` matches the upload endpoint's own decode
        (``app.api.v1.sandbox_reports._read_payload``): a report that was
        accepted with a leading BOM at upload time must still parse here.
        """
        from maljan.core.safe_json import loads

        try:
            # Read at any nesting depth (``core.safe_json``).
            payload = loads(blob.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("The attached sandbox report is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ProviderError("The attached sandbox report is not a JSON object.")
        return payload

    def attach_report(
        self, blob: bytes, *, filename: str = "report.json", report_format: str | None = None
    ) -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        payload = self._parse(blob)
        found = (
            self._recorded_format(report_format)
            if report_format is not None
            else sniff(payload, self._formats) or self._unread()
        )
        if found is None:
            # Never a legitimate target regardless of ``allowed_formats``: no
            # reader is registered for a payload nothing recognises, so this
            # is a worded refusal rather than a reader failing on it — even if
            # an operator misconfigured the allow list to include it.
            raise ProviderError(
                "Could not recognise the uploaded report's sandbox format; accepted "
                f"formats are {', '.join(sorted(self._cfg.allowed_formats))}."
            )
        if found.name not in set(self._cfg.allowed_formats):
            raise ProviderError(
                f"Uploaded report sniffed as {found.name!r}; accepted formats are "
                f"{', '.join(sorted(self._cfg.allowed_formats))}."
            )
        refusal = mapping_refusal(found)
        if refusal:
            raise ProviderError(refusal)
        # The format names the registered reader that reads it; the format's
        # own name is never branched on here. An uploaded report is the report
        # alone: whatever a live sandbox fetches beside it (a task report, a
        # capture) did not ride along, and the reader reads what it was given.
        reader = report_reader(found.reader)
        if reader is None:
            raise ProviderError(
                f"Uploaded report sniffed as {found.name!r}, a format that names no "
                "registered reader; no analysis can read it yet."
            )
        report = reader.read(
            payload, provider=self.id, fmt=found, mapping=format_mapping(found, self._mapping)
        )
        return SandboxRun(
            task_id=report.task_id or "uploaded",
            sample_sha256=report.target.sha256,
            sample_name=report.target.name or filename,
            status="reported",
            report=report,
            raw=payload,
        )

    def signature_scale(
        self, run: SandboxRun, formats: Iterable[ReportFormat] | None = None
    ) -> SignatureScale | None:
        """The scale the declared format of the attached report names."""
        return self._declared.signature_scale if self._declared is not None else None

    def fetch(self, task_id: str) -> SandboxRun:
        if self._blob is None:
            raise ProviderError("No sandbox report is attached to this job.")
        return self.attach_report(self._blob, filename=self._filename, report_format=self._recorded)
