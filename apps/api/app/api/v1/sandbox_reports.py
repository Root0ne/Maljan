"""Upload, list and delete the sandbox reports attached to a sample.

The sandbox provider ``upload`` reads these instead of detonating: a shop that
already runs its own sandbox brings the report it has. Validation is layered so
nothing is stored before it is known to be a sandbox report: stream to a size
cap, inflate a gzip under the same cap, parse the JSON, sniff the format, and
only then put the object. A ``target.sha256`` that disagrees with the sample is
a warning carried into the run summary, not a refusal — re-hashing a sample the
sandbox unpacked is a legitimate reason for the two to differ. The comparison
result is stored on the row at upload time rather than recomputed later, so the
listing endpoint reports what was actually observed instead of re-fetching and
re-parsing the blob to ask the same question twice.
"""

from __future__ import annotations

import gzip
import hashlib
import inspect
import json
import uuid
import zlib
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from maljan.core.config import get_settings
from maljan.providers.sandbox.formats import sniff_format
from pydantic import SecretStr
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.sample import Sample
from app.models.sandbox_report import SandboxReportRow
from app.models.user import User
from app.schemas.job import SandboxReportListResponse, SandboxReportResponse

logger = get_logger("api.sandbox_reports")

router = APIRouter(prefix="/samples", tags=["Sandbox reports"])

_CHUNK = 64 * 1024


def _max_report_bytes() -> int:
    return int(get_settings().sandbox.upload.max_report_bytes)


def _allowed_formats() -> set[str]:
    return set(get_settings().sandbox.upload.allowed_formats)


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
    from minio import Minio

    raw = settings.minio_secret_key
    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw),
        secure=settings.minio_secure,
    )


def _put_object(path: str, blob: bytes, *, content_type: str = "application/json") -> None:
    import io as _io

    client = _minio_client()
    if not client.bucket_exists(settings.minio_bucket):
        client.make_bucket(settings.minio_bucket)
    client.put_object(
        settings.minio_bucket, path, _io.BytesIO(blob), length=len(blob), content_type=content_type
    )


def get_object(path: str) -> bytes:
    """Read an uploaded report back. The worker calls this, hence the public name."""
    response = _minio_client().get_object(settings.minio_bucket, path)
    try:
        return bytes(response.read())
    finally:
        response.close()
        response.release_conn()


def _read_payload(file: UploadFile, filename: str) -> tuple[bytes, dict[str, Any]]:
    """Stream, size-cap, inflate and parse. Returns (canonical json bytes, payload)."""
    limit = _max_report_bytes()
    raw = bytearray()
    while True:
        chunk = file.file.read(_CHUNK)
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > limit:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
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
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"Report too large once decompressed. Maximum: {limit // (1024 * 1024)} MB",
                    )
            inflated.extend(decompressor.flush())
            body = bytes(inflated)
        except (zlib.error, gzip.BadGzipFile) as exc:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "File looks gzipped but could not be decompressed"
            ) from exc
    try:
        payload = json.loads(body.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "File is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A sandbox report must be a JSON object")
    return body, payload


def _task_id_of(payload: dict[str, Any], fmt: str) -> str | None:
    if fmt == "triage":
        sample = payload.get("sample")
        return str(sample.get("id")) if isinstance(sample, dict) and sample.get("id") else None
    info = payload.get("info")
    return str(info.get("id")) if isinstance(info, dict) and info.get("id") is not None else None


def _target_sha(payload: dict[str, Any], fmt: str) -> str:
    block = payload.get("sample") if fmt == "triage" else payload.get("target")
    return str(block.get("sha256") or "") if isinstance(block, dict) else ""


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


async def _load_sample(db: AsyncSession, sample_id: uuid.UUID, user: User) -> Sample:
    row = (
        await db.execute(
            select(Sample).where(Sample.id == sample_id, Sample.uploaded_by == user.id)
        )
    ).scalar_one_or_none()
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
    sample_id: uuid.UUID,
    file: UploadFile,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SandboxReportResponse:
    sample = await _maybe_await(_load_sample(db, sample_id, user))
    body, payload = _read_payload(file, file.filename or "report.json")
    fmt = sniff_format(payload)
    allowed = _allowed_formats()
    if fmt not in allowed:
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            f"Unrecognised sandbox report format. Accepted: {', '.join(sorted(allowed))}",
        )
    report_id = uuid.uuid4()
    storage_path = f"sandbox-reports/{sample.sha256[:2]}/{sample.sha256}/{report_id}.json"
    _put_object(storage_path, body)
    target_sha = _target_sha(payload, fmt)
    matches = bool(target_sha) and target_sha.lower() == sample.sha256.lower()
    now = datetime.now(UTC)
    row = await _maybe_await(
        _persist(
            db,
            SandboxReportRow(
                id=report_id,
                sample_id=sample.id,
                storage_path=storage_path,
                format=fmt,
                task_id=_task_id_of(payload, fmt),
                size_bytes=len(body),
                sha256_of_blob=hashlib.sha256(body).hexdigest(),
                sample_sha256_match=matches,
                uploaded_by=user.id,
                created_at=now,
                updated_at=now,
            ),
        )
    )
    warning = _match_warning(matches=matches, sample_sha256=sample.sha256)
    if warning is not None:
        logger.warning(
            "Uploaded sandbox report sha mismatch for sample %s",
            sample.id,
            extra={"sample_id": str(sample.id), "component": "sandbox-report"},
        )
    return SandboxReportResponse(
        id=row.id,
        format=row.format,
        task_id=row.task_id,
        size_bytes=row.size_bytes,
        sample_sha256_match=matches,
        warning=warning,
        uploaded_at=row.created_at,
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
            warning=_match_warning(matches=r.sample_sha256_match, sample_sha256=sample.sha256),
            uploaded_at=r.created_at,
        )
        for r in rows
    ]
    return SandboxReportListResponse(items=items, total=len(items))


@router.delete("/{sample_id}/sandbox-reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sandbox_report(
    sample_id: uuid.UUID,
    report_id: uuid.UUID,
    user: User = Depends(get_current_user),
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
        _minio_client().remove_object(settings.minio_bucket, row.storage_path)
    except Exception as exc:  # noqa: BLE001 — an orphaned object is not a failed delete
        logger.warning("Could not remove %s from storage: %s", row.storage_path, exc)
    await db.execute(delete(SandboxReportRow).where(SandboxReportRow.id == row.id))
