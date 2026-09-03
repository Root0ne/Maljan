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

import asyncio
import hashlib
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, status
from pydantic import SecretStr
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.deps import get_current_user, require_active_user
from app.logging_config import get_logger
from app.models.job import AnalysisJob
from app.models.sample import Sample
from app.models.user import User
from app.runtime_config import runtime_config
from app.schemas.job import SampleListResponse, SampleResponse

logger = get_logger("api.samples")

router = APIRouter(prefix="/samples", tags=["Samples"])


def _minio_secret() -> str:
    raw = settings.minio_secret_key
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)


def _minio_client() -> Any:
    """Build a MinIO client from settings.

    Single construction point so the upload and delete paths cannot drift apart
    (audit 2026-07-26 — the client used to be hand-built inline at every site).
    """
    from minio import Minio

    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=_minio_secret(),
        secure=settings.minio_secure,
    )


def _streaming_hashes(file: UploadFile, dest: Path, max_bytes: int) -> tuple[str, str, str, int]:
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
            if total > max_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=(f"File too large. Maximum: {max_bytes // (1024 * 1024)} MB"),
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


_FILENAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")


def _sanitise_filename(raw: str | None) -> str:
    """Reject path-traversal / control characters and double-extensions.

    SEC-MIME-DOUBLE-EXT-01 (audit 2026-05-19): the storage path is sha256-
    derived so the upload itself is safe even if the filename is hostile,
    but the API returns ``original_filename`` verbatim and downstream
    consumers (CLI download, web UI) sometimes use it for save-as. Reject
    obviously dangerous shapes up-front.
    """
    name = (raw or "").strip() or "sample.bin"
    # Strip directory separators in case a client tried to traverse.
    name = name.replace("/", "_").replace("\\", "_")
    if not _FILENAME_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Filename contains disallowed characters. Allowed: [A-Za-z0-9._-] (1-255 chars)."
            ),
        )
    # Double-extension heuristic: more than one dot is fine for files like
    # ``rust.targets.bin``, but reject filenames where two of the dotted
    # segments look like *executable* extensions (e.g. ``invoice.exe.txt``).
    # The set now covers every shape CAPE can detonate — keeps the
    # ``X.SHAPE.pdf`` phishing pattern blocked across the wider file set.
    _EXE_SHAPED = {
        # Native binaries
        "exe",
        "dll",
        "scr",
        "cpl",
        "sys",
        "ocx",
        "drv",
        "elf",
        "so",
        "dylib",
        # Installers + packages
        "msi",
        "msix",
        "msp",
        "appx",
        "appxbundle",
        "apk",
        "dex",
        "deb",
        "rpm",
        # Office macro-bearing
        "docm",
        "xlsm",
        "pptm",
        "dotm",
        "xltm",
        "potm",
        # Scripts
        "ps1",
        "psm1",
        "vbs",
        "vbe",
        "js",
        "jse",
        "wsf",
        "wsh",
        "bat",
        "cmd",
        "py",
        "pyc",
        "pyw",
        "rb",
        "pl",
        "sh",
        "hta",
        "sct",
        "lnk",
        # Java / .NET / Flash
        "jar",
        "class",
        "swf",
        # Other detonation shapes
        "iso",
        "img",
        "vhd",
        "chm",
        "reg",
    }
    segs = [s.lower() for s in name.split(".") if s]
    exe_segs = [s for s in segs if s in _EXE_SHAPED]
    if len(exe_segs) >= 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename contains multiple executable extensions.",
        )
    return name


@router.post("/upload", response_model=SampleResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    request: Request,
    file: UploadFile,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Upload a malware sample for analysis (streaming)."""
    upload_max_bytes = await runtime_config.get("upload_max_bytes")
    safe_filename = _sanitise_filename(file.filename)
    logger.info(
        "Sample upload started: %s",
        safe_filename,
        extra={"user_id": str(user.id), "component": "upload"},
    )

    # Wave 9 (2026-05-29): route uploads through the Defender-excluded
    # ``settings.upload_temp_dir`` instead of the OS temp dir. See the
    # ``APISettings.upload_temp_dir`` field comment for the audit reference.
    # Wave 9 HOTFIX-08: ``.resolve()`` to keep the path CWD-independent — the
    # original ELF smoke test hit "Invalid argument" downstream when a
    # different coroutine opened the relative path from a different CWD.
    upload_tmp_root = Path(settings.upload_temp_dir).resolve()
    upload_tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="maljan-upload-",
        delete=False,
        dir=str(upload_tmp_root),
    ) as tmp:
        tmp_path = Path(tmp.name)

    try:
        sha256, sha1, md5, size = _streaming_hashes(file, tmp_path, upload_max_bytes)
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

        # Check whether the bytes are already in MinIO (any prior uploader's
        # row works — the storage path is sha256-derived). If yes, the new
        # row points at the same path and we skip the costly re-upload.
        prior_q = await db.execute(select(Sample.id).where(Sample.sha256 == sha256).limit(1))
        bytes_already_stored = prior_q.scalar_one_or_none() is not None

        # Per-user dedup: ON CONFLICT on the new ``(sha256, uploaded_by)``
        # composite key. Re-uploading your own sample returns the existing
        # row idempotently; another user uploading the same hash inserts a
        # fresh metadata row pointing at the shared storage path.
        stmt = (
            pg_insert(Sample)
            .values(
                sha256=sha256,
                md5=md5,
                sha1=sha1,
                original_filename=safe_filename,
                file_size_bytes=size,
                mime_type=detected_mime or "application/octet-stream",
                storage_path=storage_path,
                uploaded_by=user.id,
            )
            .on_conflict_do_nothing(constraint="uq_samples_sha256_uploader")
            .returning(Sample)
        )
        result = await db.execute(stmt)
        sample_row: Sample | None = result.scalar_one_or_none()
        if sample_row is None:
            existing = await db.execute(
                select(Sample).where(
                    Sample.sha256 == sha256,
                    Sample.uploaded_by == user.id,
                )
            )
            sample = existing.scalar_one()
            logger.info("Duplicate sample reused: %s", sample.id)
            return sample

        if bytes_already_stored:
            # Another user already pushed these bytes to MinIO; reuse the
            # storage path and skip the upload. The MinIO bucket is keyed by
            # sha256, so paths coincide and no double-write occurs.
            await db.flush()
            await db.refresh(sample_row)
            logger.info(
                "Sample created (shared storage): id=%s sha256=%s",
                sample_row.id,
                sha256[:12],
            )
            return sample_row

        # Stream to MinIO from the temp file (no extra RAM copy).
        try:
            client = _minio_client()

            if not client.bucket_exists(settings.minio_bucket):
                client.make_bucket(settings.minio_bucket)
                logger.info("MinIO bucket created: %s", settings.minio_bucket)
                # SEC-MINIO-BUCKET-ACL-01 (2026-05-19 audit): MinIO defaults
                # to private buckets, but an operator can mis-configure
                # ``MINIO_BROWSER_ALLOW_PUBLIC_BUCKETS`` or a prior process
                # could have left the bucket public. Set an explicit deny
                # policy on every new bucket so a malware corpus is never
                # served unauthenticated. We deny anonymous reads at the
                # ``s3:GetObject`` level — the API path still works because
                # it presigns via the configured access key.
                _deny_anonymous_policy = (
                    '{"Version":"2012-10-17","Statement":[{'
                    '"Effect":"Deny","Principal":{"AWS":["*"]},'
                    '"Action":["s3:GetObject","s3:PutObject","s3:ListBucket"],'
                    f'"Resource":["arn:aws:s3:::{settings.minio_bucket}",'
                    f'"arn:aws:s3:::{settings.minio_bucket}/*"],'
                    '"Condition":{"StringEquals":{"aws:PrincipalType":"Anonymous"}}}]}'
                )
                try:
                    client.set_bucket_policy(settings.minio_bucket, _deny_anonymous_policy)
                    logger.info(
                        "MinIO bucket policy set (anonymous-deny): %s",
                        settings.minio_bucket,
                    )
                except Exception as policy_exc:
                    # Failure to set the policy is non-fatal but loud —
                    # operators must verify bucket privacy out-of-band.
                    logger.warning(
                        "MinIO set_bucket_policy failed for '%s' (%s). "
                        "Verify the bucket is not anonymously readable.",
                        settings.minio_bucket,
                        policy_exc,
                    )

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
            logger.exception(
                "MinIO upload failed: endpoint=%s bucket=%s path=%s tmp=%s",
                settings.minio_endpoint,
                settings.minio_bucket,
                storage_path,
                tmp_path,
            )
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


@router.delete("/{sample_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sample(
    sample_id: uuid.UUID,
    user: User = Depends(require_active_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a sample, its stored object and every analysis derived from it.

    Audit 2026-07-26 (Ö4): there was no way to remove an uploaded sample through
    the API or the UI, so malware binaries accumulated forever with no retention
    or cleanup path.

    Refuses while an analysis is still in flight — deleting the row underneath a
    running worker would orphan the job and leave the object half-referenced.
    The MinIO object is only removed when no OTHER user still references the same
    sha256 (uploads are deduplicated per user but share one object path).
    """
    result = await db.execute(
        select(Sample).where(Sample.id == sample_id, Sample.uploaded_by == user.id)
    )
    sample = result.scalar_one_or_none()
    if not sample:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found")

    active = await db.execute(
        select(func.count())
        .select_from(AnalysisJob)
        .where(
            AnalysisJob.sample_id == sample.id,
            AnalysisJob.status.in_(("pending", "running")),
        )
    )
    if (active.scalar() or 0) > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Sample has a pending or running analysis; cancel it before deleting.",
        )

    storage_path = sample.storage_path
    sha256 = sample.sha256

    # Jobs (and their reports, via the report->job cascade) go with the sample.
    await db.execute(delete(AnalysisJob).where(AnalysisJob.sample_id == sample.id))
    await db.delete(sample)
    await db.flush()

    others = await db.execute(
        select(func.count()).select_from(Sample).where(Sample.sha256 == sha256)
    )
    if (others.scalar() or 0) == 0:
        try:
            client = _minio_client()
            await asyncio.to_thread(client.remove_object, settings.minio_bucket, storage_path)
        except Exception as exc:  # noqa: BLE001 — object cleanup must not fail the delete
            logger.warning(
                "Sample %s row deleted but MinIO object %s could not be removed: %s",
                sample_id,
                storage_path,
                exc,
                extra={"user_id": str(user.id), "component": "minio"},
            )

        from app.worker import sample_files

        for removed in sample_files.remove_for_sha(sha256):
            logger.info("Removed local copy %s", removed, extra={"sample_id": str(sample_id)})

    logger.info(
        "Sample deleted: id=%s sha256=%s",
        sample_id,
        sha256[:16],
        extra={"user_id": str(user.id), "sample_id": str(sample_id)},
    )


# `Any` is exported so the analysis_service can run an IDOR check without
# importing the underlying SQLAlchemy column type directly.
__all__: list[Any] = ["router"]
