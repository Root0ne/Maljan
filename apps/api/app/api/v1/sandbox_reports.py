"""Upload, list and delete the sandbox reports attached to a sample.

The sandbox provider ``upload`` reads these instead of detonating: a shop that
already runs its own sandbox brings the report it has. Validation is layered so
nothing is stored before it is known to be a sandbox report: stream to a size
cap, inflate a gzip under the same cap, parse the JSON, sniff the format, and
only then put the object. The format, its task id and its target hash are read
from the registry's formats (``maljan.providers.sandbox.readers.sandbox_formats``:
the declared report formats, built-ins plus ``sandbox.report_formats``, and the
registered readers no declaration names), never from a format's name in this
route. A
claimed target hash that disagrees with the sample is
a warning carried into the run summary, not a refusal — re-hashing a sample the
sandbox unpacked is a legitimate reason for the two to differ. The comparison
result is stored on the row at upload time rather than recomputed later, so the
listing endpoint reports what was actually observed instead of re-fetching and
re-parsing the blob to ask the same question twice.

Where the operator allows it (``"unread"`` in ``sandbox.upload.allowed_formats``),
a report no format recognises is accepted unread instead of refused: it is
stored, a run reads it as raw blocks alone, and the upload answers with a
proposed format declaration read from its shape
(``maljan.core.report_proposals``). An admin accepts the proposal, as written
or edited (``POST /sandbox-report-formats/accept``): the declaration is saved
with its name allowed, and the upload is read as it from then on. Until then
the report stays unread. Without the opt-in, an unrecognised report is refused
as before.
"""

from __future__ import annotations

import asyncio
import gzip
import hashlib
import inspect
import json
import uuid
import zlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from maljan.core.report_formats import (
    BUILTIN_REPORT_FORMATS,
    UNREAD_FORMAT,
    ReportFormat,
    sniff,
)
from maljan.core.safe_json import loads
from maljan.providers.sandbox.readers import mapping_refusal, report_reader, sandbox_formats
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user, require_active_user, require_admin_session
from app.logging_config import get_logger
from app.models.sample import Sample
from app.models.sandbox_report import SandboxReportRow
from app.models.user import User
from app.schemas.job import (
    AcceptReportFormatRequest,
    SandboxReportFormatListResponse,
    SandboxReportFormatResponse,
    SandboxReportListResponse,
    SandboxReportResponse,
    SignatureScaleResponse,
)
from app.services import audit, object_store
from app.services.report_formats_lock import (
    ALLOWED_FORMATS_KEY,
    REPORT_FORMATS_KEY,
    report_formats_serialised,
)
from app.services.settings_service import effective_core_settings

if TYPE_CHECKING:
    from maljan.core.config import SandboxConfig

logger = get_logger("api.sandbox_reports")

router = APIRouter(prefix="/samples", tags=["Sandbox reports"])
# The declared report formats, served for the console and any client.
formats_router = APIRouter(prefix="/sandbox-report-formats", tags=["Sandbox reports"])

_CHUNK = 64 * 1024
# Matches SandboxReportRow.task_id's column width (String(128)). Truncated, not
# rejected: the id is a correlation key back to the source sandbox's own task,
# not load-bearing for the analysis, and an over-long one is far more likely to
# be a quirky producer than a reason to refuse an otherwise-valid report.
_TASK_ID_MAX_LENGTH = 128


async def _sandbox_settings(db: AsyncSession) -> SandboxConfig:
    core = await effective_core_settings(db)
    return core.sandbox


async def _max_report_bytes(db: AsyncSession) -> int:
    return int((await _sandbox_settings(db)).upload.max_report_bytes)


async def _maybe_await(value: Any) -> Any:
    """Await ``value`` when it is awaitable, otherwise return it unchanged.

    ``_load_sample`` and ``_persist`` are ``async def`` in production, so
    calling them here returns a coroutine that must be awaited. The unit tests
    replace them with a plain ``MagicMock`` so a test never has to build an
    ``AsyncMock`` (or a fake ``AsyncSession``) just to exercise the route —
    calling a ``MagicMock`` returns its value immediately, with nothing to
    await. This lets both shapes flow through the same call site.
    """
    if inspect.isawaitable(value):
        return await value
    return value


def _minio_client() -> Any:
    """The object store's client (``app.services.object_store``)."""
    return object_store.client()


def _put_object_blocking(path: str, blob: bytes, *, content_type: str = "application/json") -> None:
    # The bucket is created the one way every path creates it, with the
    # anonymous-deny policy (``object_store.ensure_bucket``).
    object_store.put_bytes(_minio_client(), path, blob, content_type=content_type)


async def put_object(path: str, blob: bytes, *, content_type: str = "application/json") -> None:
    """Write an uploaded report to the object store, off the event loop.

    The MinIO client is synchronous, and a handler that called it directly held
    the loop for the whole transfer: every other request, every WebSocket frame
    and the health check itself waited on somebody else's upload. A thread
    costs one context switch and gives the loop back.
    """
    await asyncio.to_thread(_put_object_blocking, path, blob, content_type=content_type)


def get_object(path: str) -> bytes:
    """Read an uploaded report back, blocking.

    The worker calls this from its own ``asyncio.to_thread`` — it has the path
    and needs the bytes before the sandbox provider is built — hence the public
    name and the synchronous shape. Inside the API, call ``get_object_async``.
    """
    return object_store.read_bytes(_minio_client(), path)


async def get_object_async(path: str) -> bytes:
    """``get_object`` from a worker thread, for anything on the event loop."""
    return await asyncio.to_thread(get_object, path)


async def _read_payload(file: UploadFile, db: AsyncSession) -> tuple[bytes, dict[str, Any]]:
    """Stream, size-cap, inflate and parse. Returns (canonical json bytes, payload).

    M7 (final review): this used to take a ``filename`` parameter that was
    never read — gzip is detected from the magic bytes at the top of the
    body, never the extension, so there was nothing left for a filename to
    do here. Dropped rather than wired up to avoid a second, redundant way
    to decide the same thing.
    """
    limit = await _max_report_bytes(db)
    raw = bytearray()
    while True:
        chunk = file.file.read(_CHUNK)
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > limit:
            raise HTTPException(
                status.HTTP_413_CONTENT_TOO_LARGE,
                f"Report too large. Maximum: {limit // (1024 * 1024)} MB",
            )
    body = bytes(raw)
    if body[:2] == b"\x1f\x8b":
        try:
            # Inflate incrementally so a zip bomb hits the cap instead of RAM.
            decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
            inflated = bytearray()
            for offset in range(0, len(body), _CHUNK):
                inflated.extend(decompressor.decompress(body[offset : offset + _CHUNK], limit + 1))
                if len(inflated) > limit:
                    raise HTTPException(
                        status.HTTP_413_CONTENT_TOO_LARGE,
                        f"Report too large once decompressed. Maximum: {limit // (1024 * 1024)} MB",
                    )
            inflated.extend(decompressor.flush())
            body = bytes(inflated)
        except (zlib.error, gzip.BadGzipFile) as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "File looks gzipped but could not be decompressed"
            ) from exc
    try:
        # Read at any nesting depth: a report nested past ``json.loads``'s
        # recursion is read again iteratively (``core.safe_json``). Linear in
        # the body, but a large body is still seconds of work, so it is read in
        # a worker thread and never holds the event loop.
        payload = await asyncio.to_thread(_parsed, body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A sandbox report must be a JSON object")
    return body, payload


def _parsed(body: bytes) -> Any:
    """``body`` decoded and read as JSON at any depth (``core.safe_json.loads``)."""
    return loads(body.decode("utf-8-sig"))


def _read_declared(
    payload: dict[str, Any], formats: tuple[Any, ...]
) -> tuple[Any, str | None, str]:
    """The format that recognises ``payload``, its task id and its claimed target hash."""
    fmt = sniff(payload, formats)
    if fmt is None:
        return None, None, ""
    return fmt, _task_id_of(payload, fmt), fmt.target_sha256(payload)


def _task_id_of(payload: dict[str, Any], fmt: Any) -> str | None:
    """The source sandbox's task id, where the format declares it, cut to the column width."""
    raw = fmt.task_id(payload)
    return raw[:_TASK_ID_MAX_LENGTH] if raw is not None else None


def _row_warning(row_format: str, *, matches: bool, sample_sha256: str) -> str | None:
    """The warning shown for a row: an unread report claims no target, so it says that."""
    if row_format == UNREAD_FORMAT:
        return UNREAD_WARNING
    return _match_warning(matches=matches, sample_sha256=sample_sha256)


# What an upload accepted unread says, on the upload and in every listing.
UNREAD_WARNING = (
    "No declared format recognises this report, so it was accepted unread: the analysis "
    "reads its blocks as written and draws no observed fact from them. Accept a format "
    "declaration for it to read it as a known sandbox's report."
)


def _proposal(payload: dict[str, Any]) -> dict[str, Any] | None:
    """The proposed declaration for an unread report, or ``None`` where none could be read."""
    from maljan.core.report_proposals import propose_format

    try:
        return propose_format(payload)
    except Exception as exc:  # noqa: BLE001 — a proposal is advisory, never the upload's failure
        logger.warning("No format declaration could be proposed (%s).", type(exc).__name__)
        return None


def _match_warning(*, matches: bool, sample_sha256: str) -> str | None:
    """The warning shown for a report whose claimed target hash disagrees.

    Built from the *sample's* own hash only, never from the report's payload —
    the payload is untrusted input, and this string is returned to the caller
    on a 201 as well as replayed by every later listing, so it must not carry
    anything the uploader wrote. That also keeps the upload response and the
    listing response saying exactly the same thing for the same row.
    """
    if matches:
        return None
    return (
        f"This report's target hash does not match sample {sample_sha256[:12]}… "
        "The analysis will still run and will say so in its findings."
    )


async def _load_sample(
    db: AsyncSession, sample_id: uuid.UUID, user: User, *, any_for_admin: bool = False
) -> Sample:
    """The sample ``user`` uploaded; any sample for an admin where ``any_for_admin``.

    An unread report's proposal is accepted into the settings, an admin's
    write: an admin reads and accepts the proposal of any stored report, not
    only of the samples they uploaded.
    """
    query = select(Sample).where(Sample.id == sample_id)
    if not (any_for_admin and getattr(user, "role", None) == "admin"):
        query = query.where(Sample.uploaded_by == user.id)
    row = (await db.execute(query)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found")
    return row


async def _persist(db: AsyncSession, row: SandboxReportRow) -> SandboxReportRow:
    db.add(row)
    await db.flush()
    await db.refresh(row)
    return row


@router.post(
    "/{sample_id}/sandbox-reports",
    response_model=SandboxReportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_sandbox_report(
    request: Request,
    sample_id: uuid.UUID,
    file: UploadFile,
    user: User = Depends(require_active_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportResponse:
    sample = await _maybe_await(_load_sample(db, sample_id, user))
    body, payload = await _read_payload(file, db)
    sandbox = await _sandbox_settings(db)
    # The format is named, and its task id and target hash read, from the
    # declared formats alone: a format added as data needs no code here. The
    # walk is linear in the report, and a large report is still a walk, so it
    # runs in a worker thread rather than on the event loop.
    fmt, task_id, target_sha = await asyncio.to_thread(
        _read_declared, payload, sandbox_formats(sandbox.report_formats)
    )
    allowed = set(sandbox.upload.allowed_formats)
    proposal: dict[str, Any] | None = None
    if fmt is None and UNREAD_FORMAT in allowed and report_reader(UNREAD_FORMAT) is not None:
        # The operator's opt-in: kept unread, with a declaration proposed from its shape.
        row_format = UNREAD_FORMAT
        proposal = await asyncio.to_thread(_proposal, payload)
    elif fmt is None or fmt.name not in allowed:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"Unrecognised sandbox report format. Accepted: {', '.join(sorted(allowed))}",
        )
    elif report_reader(fmt.reader) is None:
        # Stored, it would be evidence no run can read: the job would go on
        # without it. Refused here, where the operator is told why.
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"The report is format {fmt.name!r}, which names no registered reader; "
            "no analysis can read it yet.",
        )
    elif mapping_refusal(fmt):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, mapping_refusal(fmt))
    else:
        row_format = fmt.name
    report_id = uuid.uuid4()
    storage_path = f"sandbox-reports/{sample.sha256[:2]}/{sample.sha256}/{report_id}.json"
    matches = bool(target_sha) and target_sha.lower() == sample.sha256.lower()
    now = datetime.now(UTC)
    # Insert before the storage write, not after: a row that fails to persist
    # (a width violation, a constraint, anything) must never leave an object in
    # MinIO that nothing will ever reference. In this order, a storage failure
    # after a successful insert instead leaves an uncommitted row for get_db's
    # own rollback to undo — the same ordering upload_sample uses in
    # samples.py. Mirrored in the tests below via a forced persist failure.
    row = await _maybe_await(
        _persist(
            db,
            SandboxReportRow(
                id=report_id,
                sample_id=sample.id,
                storage_path=storage_path,
                format=row_format,
                task_id=task_id,
                size_bytes=len(body),
                sha256_of_blob=hashlib.sha256(body).hexdigest(),
                sample_sha256_match=matches,
                uploaded_by=user.id,
                created_at=now,
                updated_at=now,
            ),
        )
    )
    await put_object(storage_path, body)
    warning = _row_warning(row_format, matches=matches, sample_sha256=sample.sha256)
    if warning is not None and row_format != UNREAD_FORMAT:
        logger.warning(
            "Uploaded sandbox report sha mismatch for sample %s",
            sample.id,
            extra={"sample_id": str(sample.id), "component": "sandbox-report"},
        )
    await audit.record(
        "sandbox_report.upload",
        resource_type="sandbox_report",
        resource_id=str(row.id),
        user_id=user.id,
        details={
            "sample_id": str(sample.id),
            "format": row.format,
            "size_bytes": row.size_bytes,
            "sample_sha256_match": matches,
        },
        request=request,
    )
    return SandboxReportResponse(
        id=row.id,
        format=row.format,
        task_id=row.task_id,
        size_bytes=row.size_bytes,
        sample_sha256_match=matches,
        warning=warning,
        uploaded_at=row.created_at,
        proposal=proposal,
    )


@router.get("/{sample_id}/sandbox-reports", response_model=SandboxReportListResponse)
async def list_sandbox_reports(
    sample_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportListResponse:
    sample = await _maybe_await(_load_sample(db, sample_id, user))
    rows = (
        (
            await db.execute(
                select(SandboxReportRow)
                .where(SandboxReportRow.sample_id == sample.id)
                .order_by(SandboxReportRow.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    items = [
        SandboxReportResponse(
            id=r.id,
            format=r.format,
            task_id=r.task_id,
            size_bytes=r.size_bytes,
            sample_sha256_match=r.sample_sha256_match,
            warning=_row_warning(
                r.format, matches=r.sample_sha256_match, sample_sha256=sample.sha256
            ),
            uploaded_at=r.created_at,
        )
        for r in rows
    ]
    return SandboxReportListResponse(items=items, total=len(items))


@router.delete("/{sample_id}/sandbox-reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_report(
    request: Request,
    sample_id: uuid.UUID,
    report_id: uuid.UUID,
    user: User = Depends(require_active_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    sample = await _maybe_await(_load_sample(db, sample_id, user))
    row = (
        await db.execute(
            select(SandboxReportRow).where(
                SandboxReportRow.id == report_id, SandboxReportRow.sample_id == sample.id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sandbox report not found")
    try:
        await asyncio.to_thread(object_store.remove, _minio_client(), row.storage_path)
    except Exception as exc:  # noqa: BLE001 — an orphaned object is not a failed delete
        logger.warning("Could not remove %s from storage: %s", row.storage_path, exc)
    await db.execute(delete(SandboxReportRow).where(SandboxReportRow.id == row.id))
    await audit.record(
        "sandbox_report.delete",
        resource_type="sandbox_report",
        resource_id=str(report_id),
        user_id=user.id,
        details={"sample_id": str(sample.id), "format": row.format},
        request=request,
    )


def _format_response(
    fmt: Any, allowed: set[str], declared: ReportFormat | None
) -> SandboxReportFormatResponse:
    scale = fmt.signature_scale
    return SandboxReportFormatResponse(
        name=fmt.name,
        # A declaration merged over a built-in is the operator's, not the shipped one.
        builtin=any(fmt is builtin for builtin in BUILTIN_REPORT_FORMATS),
        allowed=fmt.name in allowed,
        reader=fmt.reader,
        detect=[[test.model_dump(mode="json") for test in group] for group in fmt.detect],
        task_id_paths=list(fmt.task_id_paths),
        target_sha256_paths=list(fmt.target_sha256_paths),
        signature_scale=SignatureScaleResponse(**scale.record()) if scale is not None else None,
        # Only the fields the operator wrote: the value to copy back into
        # sandbox.report_formats without pinning the built-in's other fields.
        declared=declared.model_dump(mode="json", exclude_unset=True) if declared else None,
    )


@formats_router.get("", response_model=SandboxReportFormatListResponse)
async def list_sandbox_report_formats(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportFormatListResponse:
    """Every report format a payload is tried against, in that order, with its declaration.

    The registry's formats: the declared ones and each registered reader no
    declaration names, which recognises a payload by its own code.
    """
    sandbox = await _sandbox_settings(db)
    allowed = set(sandbox.upload.allowed_formats)
    declared = {fmt.name: fmt for fmt in sandbox.report_formats}
    items = [
        _format_response(fmt, allowed, declared.get(fmt.name))
        for fmt in sandbox_formats(sandbox.report_formats)
    ]
    return SandboxReportFormatListResponse(items=items, total=len(items))


async def _owned_row(db: AsyncSession, sample: Sample, report_id: uuid.UUID) -> SandboxReportRow:
    row = (
        await db.execute(
            select(SandboxReportRow).where(
                SandboxReportRow.id == report_id, SandboxReportRow.sample_id == sample.id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sandbox report not found")
    return row


async def _stored_payload(row: SandboxReportRow) -> dict[str, Any]:
    body = await get_object_async(row.storage_path)
    payload = await asyncio.to_thread(loads, body.decode("utf-8-sig"))
    if not isinstance(payload, dict):
        raise HTTPException(status.HTTP_409_CONFLICT, "The stored report is not a JSON object")
    return payload


@router.get(
    "/{sample_id}/sandbox-reports/{report_id}/proposal",
    response_model=SandboxReportResponse,
)
async def sandbox_report_proposal(
    sample_id: uuid.UUID,
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportResponse:
    """An unread upload with its proposed declaration, read again from the stored report.

    The uploader's own reports, and any stored report for an admin, who may
    accept its proposal.
    """
    sample = await _maybe_await(_load_sample(db, sample_id, user, any_for_admin=True))
    row = await _owned_row(db, sample, report_id)
    proposal = None
    if row.format == UNREAD_FORMAT:
        proposal = await asyncio.to_thread(_proposal, await _stored_payload(row))
    return SandboxReportResponse(
        id=row.id,
        format=row.format,
        task_id=row.task_id,
        size_bytes=row.size_bytes,
        sample_sha256_match=row.sample_sha256_match,
        warning=_row_warning(
            row.format, matches=row.sample_sha256_match, sample_sha256=sample.sha256
        ),
        uploaded_at=row.created_at,
        proposal=proposal,
    )


def _accepted_formats(
    sandbox: SandboxConfig, declaration: ReportFormat
) -> tuple[list[dict[str, Any]], list[str]]:
    """``sandbox.report_formats`` and ``sandbox.upload.allowed_formats`` with ``declaration`` in."""
    if any(fmt.name == declaration.name for fmt in sandbox.report_formats):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"A report format named {declaration.name!r} is already declared; "
            "edit it in the settings or accept the proposal under another name.",
        )
    if any(fmt.name == declaration.name for fmt in BUILTIN_REPORT_FORMATS):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{declaration.name!r} is a built-in format's name; accept the proposal "
            "under another name.",
        )
    formats = [
        *(fmt.model_dump(mode="json", exclude_unset=True) for fmt in sandbox.report_formats),
        declaration.model_dump(mode="json", exclude_none=True),
    ]
    allowed = list(sandbox.upload.allowed_formats)
    if declaration.name not in allowed:
        allowed.append(declaration.name)
    return formats, allowed


def _trial_read(payload: dict[str, Any], declaration: ReportFormat, fallback: Any) -> str:
    """Why ``declaration`` reads no fact of ``payload``, in words; empty where it reads one.

    The report is read as an upload of the format would be. A format read
    through a mapping must keep a row with one of its fact paths: a consumer
    channel (processes, calls, signatures, DNS, HTTP, TCP, UDP, hosts,
    domains, dropped files, registry) or a place, or name the target hash.
    Its own ``channels`` are not counted: a kept raw ``report.<block>``
    channel keeps a row from any report, so a mapping whose fact paths all
    miss would pass on it while reading only what the unread read gave. Any
    other reader must read the report without failing.
    """
    from maljan.providers.sandbox.readers import format_mapping
    from maljan.providers.sandbox.rest_mapping import (
        CHANNELS,
        apply_mapping,
        compile_mapping,
    )

    reader = report_reader(declaration.reader)
    if reader is None:
        return f"The declaration names no registered reader ({declaration.reader!r})."
    mapping = format_mapping(declaration, fallback)
    if not reader.reads_mapping or mapping is None:
        try:
            reader.read(payload, provider="upload", fmt=declaration, mapping=mapping)
        except Exception as exc:  # noqa: BLE001 — the reason is the answer
            return f"Its reader cannot read this report ({type(exc).__name__})."
        return ""
    result = apply_mapping(compile_mapping(mapping), payload, provider="upload", task_id="")
    selected = [
        name
        for name, stats in result.stats.items()
        if stats.kept and (name in CHANNELS or name.startswith("places."))
    ]
    if selected or result.report.target.sha256:
        return ""
    return (
        "Read with this report, its mapping reads no fact: no channel or place path keeps a "
        "row and the target hash path names no hash (the kept raw channels are not "
        "counted). Correct the paths before accepting it."
    )


@formats_router.post("/accept", response_model=SandboxReportResponse)
async def accept_report_format(
    body: AcceptReportFormatRequest,
    request: Request,
    user: User = Depends(require_admin_session),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportResponse | Any:
    """Save an operator-accepted format declaration and read the unread upload as it.

    The declaration must be the format that recognises the upload (a format
    read through a mapping is tried after every built-in, so one a built-in
    also recognises is refused, named), and a trial read of the upload with it
    must read a fact (:func:`_trial_read`), or nothing is saved: an accepted
    declaration that reads nothing would leave the report unread with the
    operator told otherwise. An admin accepts for any stored report. Accepts
    and the settings routes' writes of the formats run one at a time
    (``services.report_formats_lock``), each reading the formats as they
    stand, so none drops another. On
    success the declaration is saved through the settings path every
    declaration takes (validated and audited), its name is allowed for
    upload, and the upload's row records the format, its task id and target
    match as an upload of that format records them, in the same commit.
    """
    from fastapi.responses import JSONResponse

    from app.runtime_config import runtime_config
    from app.services.settings_service import (
        SettingsService,
        SettingsValidationError,
        core_settings_cache,
    )

    try:
        declaration = ReportFormat.model_validate(body.declaration)
    except ValidationError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"The declaration does not validate ({exc.error_count()} errors): "
            + "; ".join(str(error.get("msg", "")) for error in exc.errors()[:5]),
        ) from exc
    sample = await _maybe_await(_load_sample(db, body.sample_id, user, any_for_admin=True))
    row = await _owned_row(db, sample, body.report_id)
    if row.format != UNREAD_FORMAT:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"This report is read as {row.format!r} already, not unread.",
        )
    payload = await _stored_payload(row)
    # The settings routes write the formats under the same lock
    # (``services.report_formats_lock``).
    async with report_formats_serialised(db):
        # The formats as they stand now, not as a cache read them a moment ago.
        core_settings_cache.invalidate()
        sandbox = await _sandbox_settings(db)
        formats, allowed = _accepted_formats(sandbox, declaration)
        candidate = sandbox_formats([*sandbox.report_formats, declaration])
        fmt, task_id, target_sha = await asyncio.to_thread(_read_declared, payload, candidate)
        if fmt is None or fmt.name != declaration.name:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                (
                    f"This report is recognised as {fmt.name!r}, which is tried before a "
                    "format read through a mapping: a declaration a built-in or another "
                    "declared format also claims would never read it. Add a detect test "
                    "only this report passes; nothing was saved."
                )
                if fmt is not None
                else "The declaration does not recognise this report; nothing was saved.",
            )
        refusal = mapping_refusal(declaration) or await asyncio.to_thread(
            _trial_read, payload, declaration, sandbox.rest.mapping
        )
        if refusal:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_CONTENT, f"{refusal} Nothing was saved."
            )
        matches = bool(target_sha) and target_sha.lower() == sample.sha256.lower()
        # The row first: the settings save commits, so the two land together.
        row.format = declaration.name
        row.task_id = task_id
        row.sample_sha256_match = matches
        row.updated_at = datetime.now(UTC)
        await db.flush()
        try:
            await SettingsService(db).save(
                {REPORT_FORMATS_KEY: formats, ALLOWED_FORMATS_KEY: allowed},
                user_id=user.id,
                ip=request.client.host if request.client else None,
            )
        except SettingsValidationError as exc:
            await db.rollback()
            return JSONResponse(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"errors": exc.errors}
            )
        runtime_config.invalidate()
        core_settings_cache.invalidate()
    await audit.record(
        "sandbox_report.format_accepted",
        resource_type="sandbox_report",
        resource_id=str(row.id),
        user_id=user.id,
        details={"sample_id": str(sample.id), "format": declaration.name},
        request=request,
    )
    return SandboxReportResponse(
        id=row.id,
        format=row.format,
        task_id=row.task_id,
        size_bytes=row.size_bytes,
        sample_sha256_match=matches,
        warning=_row_warning(row.format, matches=matches, sample_sha256=sample.sha256),
        uploaded_at=row.created_at,
    )
