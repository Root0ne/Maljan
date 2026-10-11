"""Operator-uploaded sandbox report behind the provider contract.

Whatever sandbox a shop already runs, this provider is the answer to it:
export the report, attach it to the sample, and the pipeline runs from those
bytes as if they had come from a live detonation. It never submits anything
and never reaches the network — the report is already evidence, and the
format is sniffed again from the bytes on every load rather than trusted from
the upload row, because the row is metadata and the bytes are the evidence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from maljan.core.report_formats import ReportFormat, effective_formats, sniff
from maljan.providers.base import SandboxCapabilities, SandboxProvider
from maljan.providers.errors import ProviderError
from maljan.providers.registry import register_sandbox_provider
from maljan.schemas.sandbox_report import (
    cape_report_to_sandbox_report,
    triage_overview_to_sandbox_report,
)

if TYPE_CHECKING:
    from maljan.core.config import SandboxUploadConfig, Settings
    from maljan.core.report_formats import SignatureScale
    from maljan.schemas.sandbox_report import SandboxRun


@register_sandbox_provider("upload")
class UploadSandboxProvider(SandboxProvider):
    """A sandbox that runs nothing and reads what the operator already has.

    This is the answer to "any sandbox": whatever your shop runs,
    export its report and attach it to the sample. The format is sniffed again
    here rather than trusted from the upload row, because the row is metadata
    and the bytes are the evidence.
    """

    def __init__(self, cfg: SandboxUploadConfig) -> None:
        self._cfg = cfg
        self._blob: bytes | None = None
        self._filename = "report.json"
        # M3 (final review): the ledger ruling says report_format is computed
        # per instance from the sniffed format, not hard-coded. Sniffed
        # eagerly in set_pending_blob so it is known by the time anything
        # reads capabilities, without requiring a successful fetch() first;
        # a blob that fails to parse or sniff leaves this None and
        # capabilities falls back to "generic" exactly as before — the real
        # error still surfaces from attach_report()/fetch() when read.
        # The reader of the sniffed format, which is what report_format names.
        self._sniffed_format: Literal["cape2", "cuckoo", "triage"] | None = None
        # The declared format the pending blob sniffed as, for its signature scale.
        self._declared: ReportFormat | None = None
        self._formats = effective_formats(cfg.formats)

    @classmethod
    def from_settings(cls, cfg: Settings) -> UploadSandboxProvider:
        return cls(cfg.sandbox.upload)

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

    def set_pending_blob(self, blob: bytes, *, filename: str = "report.json") -> None:
        """Hand over the bytes the worker just read from storage.

        Idempotent the same way ``open()`` is elsewhere in this layer: a
        second call before the first is ever read simply replaces the pending
        blob rather than layering state on top of it.
        """
        self._blob, self._filename = blob, filename
        try:
            found = sniff(self._parse(blob), self._formats)
        except ProviderError:
            found = None
        # A format no reader reads, or a blob no format recognises, has no
        # report_format; attach_report()/fetch() refuse either with a worded
        # ProviderError, so capabilities just falls back to "generic" for it
        # rather than raising here, ahead of that message.
        self._declared = found
        self._sniffed_format = (found.reader or None) if found is not None else None

    def submit(self, sample_path: str | Path) -> str:
        raise ProviderError(
            "The upload sandbox does not detonate samples; attach a report to the job instead."
        )

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
        try:
            payload = json.loads(blob.decode("utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProviderError("The attached sandbox report is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise ProviderError("The attached sandbox report is not a JSON object.")
        return payload

    def attach_report(self, blob: bytes, *, filename: str = "report.json") -> SandboxRun:
        from maljan.schemas.sandbox_report import SandboxRun

        payload = self._parse(blob)
        found = sniff(payload, self._formats)
        if found is None:
            # Never a legitimate target regardless of ``allowed_formats``:
            # ``SandboxReport.source_format`` has no "unknown" member, so
            # letting this through to ``cape_report_to_sandbox_report`` would
            # surface a raw pydantic ValidationError instead of a clean,
            # worded refusal — even if an operator misconfigured the allow
            # list to include it.
            raise ProviderError(
                "Could not recognise the uploaded report's sandbox format; accepted "
                f"formats are {', '.join(sorted(self._cfg.allowed_formats))}."
            )
        if found.name not in set(self._cfg.allowed_formats):
            raise ProviderError(
                f"Uploaded report sniffed as {found.name!r}; accepted formats are "
                f"{', '.join(sorted(self._cfg.allowed_formats))}."
            )
        # The declared format names the reader; the format's own name is never
        # branched on here.
        fmt = found.reader
        if not fmt:
            raise ProviderError(
                f"Uploaded report sniffed as {found.name!r}, a format declared without a "
                "reader; no analysis can read it yet."
            )
        if fmt == "triage":
            # An uploaded Triage report is an overview.json alone — no
            # per-task behavioural reports rode along with it, so
            # ``task_reports`` stays empty and processes/network are thinner
            # than a fetched run's. Still every key the mapper can fill from
            # the overview itself: target, signatures, cti, unavailable.
            report = triage_overview_to_sandbox_report(payload, provider="upload")
        else:
            report = cape_report_to_sandbox_report(payload, provider="upload", source_format=fmt)
        return SandboxRun(
            task_id=report.task_id or "uploaded",
            sample_sha256=report.target.sha256,
            sample_name=report.target.name or filename,
            status="reported",
            report=report,
            raw=payload,
        )

    def signature_scale(self, run: SandboxRun) -> SignatureScale | None:
        """The scale the declared format of the attached report names."""
        return self._declared.signature_scale if self._declared is not None else None

    def fetch(self, task_id: str) -> SandboxRun:
        if self._blob is None:
            raise ProviderError("No sandbox report is attached to this job.")
        return self.attach_report(self._blob, filename=self._filename)
