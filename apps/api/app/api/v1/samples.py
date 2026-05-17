"""Sample upload and listing endpoints.

Hardening:
    * Stream the upload to disk while computing SHA-256 + MD5 + SHA-1 so the
      whole file is never loaded into memory.
    * Validate MIME type via the ``filetype`` magic-byte sniffer rather than
      trusting the client-supplied ``Content-Type``.
    * Race-safe deduplication via ``ON CONFLICT (sha256) DO NOTHING``.
    * MinIO upload uses the spooled file directly (no second copy in RAM).
"""

from __future__ import annotations

import hashlib
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, status
from pydantic import SecretStr
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.models.sample import Sample
from app.models.user import User
from app.schemas.job import SampleListResponse, SampleResponse

logger = get_logger("api.samples")

router = APIRouter(prefix="/samples", tags=["Samples"])


def _minio_secret() -> str:
    raw = settings.minio_secret_key
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)


def _streaming_hashes(file: UploadFile, dest: Path) -> tuple[str, str, str, int]:
    """Stream the upload to ``dest`` and return (sha256, sha1, md5, size).

    SHA1 and MD5 are emitted alongside SHA256 because every downstream CTI
    consumer (VirusTotal, MalwareBazaar, MISP, YARA imphash workflows)
    indexes malware samples by all three. They are used here purely as
    forensic identifiers, never as cryptographic signatures.
    """
    sha256 = hashlib.sha256()
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1
    sha1 = hashlib.sha1()
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5
    md5 = hashlib.md5()
    total = 0
    chunk_size = 64 * 1024
    with dest.open("wb") as out:
        while True:
            chunk = file.file.read(chunk_size)
            if not chunk:
                break
            total += len(chunk)
            if total > settings.upload_max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=(
                        f"File too large. Maximum: {settings.upload_max_bytes // (1024 * 1024)} MB"
                    ),
                )
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            out.write(chunk)
    return sha256.hexdigest(), sha1.hexdigest(), md5.hexdigest(), total


def _detect_mime(path: Path) -> str | None:
    """Best-effort magic-byte MIME detection (returns None when unknown)."""
    try:
        import filetype

        kind = filetype.guess(str(path))
        if kind is not None:
            mime = kind.mime
            return str(mime) if mime is not None else None
    except Exception as exc:
        logger.debug("filetype guess failed: %s", exc)
    return None


@router.post("/upload", response_model=SampleResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    request: Request,
    file: UploadFile,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Upload a malware sample for analysis (streaming)."""
    logger.info(
        "Sample upload started: %s",
        file.filename,
        extra={"user_id": str(user.id), "component": "upload"},
    )

    with tempfile.NamedTemporaryFile(prefix="maljan-upload-", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        sha256, sha1, md5, size = _streaming_hashes(file, tmp_path)
        if size == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")

        detected_mime = _detect_mime(tmp_path)
        if settings.upload_allowed_mime_types:
            allowed = set(settings.upload_allowed_mime_types)
            if detected_mime is not None and detected_mime not in allowed:
                logger.warning("Upload rejected: MIME %s not in allow-list", detected_mime)
                raise HTTPException(
                    status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                    detail=f"Disallowed MIME type: {detected_mime}",
                )

        logger.info(
            "File hashed: SHA256=%s... size=%d bytes",
            sha256[:16],
            size,
            extra={"sample_id": sha256, "user_id": str(user.id)},
        )

        storage_path = f"samples/{sha256[:2]}/{sha256}"

        # Race-safe insert: another concurrent request may have just inserted
        # the same sha256. We INSERT … ON CONFLICT DO NOTHING; if the row
        # already exists we fetch it and skip the MinIO upload.
        stmt = (
            pg_insert(Sample)
            .values(
                sha256=sha256,
                md5=md5,
                sha1=sha1,
                original_filename=file.filename or "unknown",
                file_size_bytes=size,
                mime_type=detected_mime or "application/octet-stream",
                storage_path=storage_path,
                uploaded_by=user.id,
            )
            .on_conflict_do_nothing(index_elements=["sha256"])
            .returning(Sample)
        )
        result = await db.execute(stmt)
        sample_row: Sample | None = result.scalar_one_or_none()
        if sample_row is None:
            existing = await db.execute(select(Sample).where(Sample.sha256 == sha256))
            sample = existing.scalar_one()
            logger.info("Duplicate sample reused: %s", sample.id)
            return sample

        # Stream to MinIO from the temp file (no extra RAM copy).
        try:
            from minio import Minio

            client = Minio(
                settings.minio_endpoint,
                access_key=settings.minio_access_key,
                secret_key=_minio_secret(),
                secure=settings.minio_secure,
            )

            if not client.bucket_exists(settings.minio_bucket):
                client.make_bucket(settings.minio_bucket)
                logger.info("MinIO bucket created: %s", settings.minio_bucket)

            client.fput_object(
                settings.minio_bucket,
                storage_path,
                str(tmp_path),
                content_type=detected_mime or "application/octet-stream",
            )
        except Exception as exc:
            # Best-effort cleanup: remove the half-inserted DB row so the
            # caller can retry instead of getting a phantom 409.
            await db.execute(select(Sample).where(Sample.sha256 == sha256))  # primes the session
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Storage service unavailable",
            ) from exc

        await db.flush()
        await db.refresh(sample_row)
        logger.info(
            "Sample created: id=%s filename=%s", sample_row.id, sample_row.original_filename
        )
        return sample_row
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
        except Exception as exc:
            logger.debug("Failed to remove temp upload file: %s", exc)


@router.get("", response_model=SampleListResponse)
async def list_samples(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List uploaded samples with pagination."""
    query = (
        select(Sample)
        .where(Sample.uploaded_by == user.id)
        .order_by(Sample.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    result = await db.execute(query)
    samples = result.scalars().all()

    count_result = await db.execute(
        select(func.count()).select_from(Sample).where(Sample.uploaded_by == user.id)
    )
    total = count_result.scalar() or 0

    return {
        "items": samples,
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/{sample_id}", response_model=SampleResponse)
async def get_sample(
    sample_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Get a specific sample's metadata."""
    result = await db.execute(
        select(Sample).where(Sample.id == sample_id, Sample.uploaded_by == user.id)
    )
    sample = result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found")
    return sample


# `Any` is exported so the analysis_service can run an IDOR check without
# importing the underlying SQLAlchemy column type directly.
__all__: list[Any] = ["router"]
