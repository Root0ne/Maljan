"""Sample upload and listing endpoints."""

import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, status
from sqlalchemy import func, select
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

# Maximum upload size: 50 MB
MAX_UPLOAD_SIZE = 50 * 1024 * 1024


@router.post("/upload", response_model=SampleResponse, status_code=status.HTTP_201_CREATED)
async def upload_sample(
    file: UploadFile,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Sample:
    """Upload a malware sample for analysis.

    Computes SHA-256/MD5 hashes, stores the file in MinIO, and creates a
    database record. If a sample with the same SHA-256 already exists,
    returns the existing record.
    """
    logger.info(
        f"Sample upload started: {file.filename} ({file.content_type})",
        extra={"user_id": str(user.id), "component": "upload"},
    )

    # Read file content
    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        logger.warning(
            f"Upload rejected: file too large ({len(content)} bytes)",
            extra={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size: {MAX_UPLOAD_SIZE // (1024 * 1024)} MB",
        )
    if len(content) == 0:
        logger.warning("Upload rejected: empty file", extra={"user_id": str(user.id)})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty file",
        )

    # Compute hashes
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    # SHA-1 is intentionally omitted — SHA-256 is sufficient for identification.
    sha1 = None

    logger.info(
        f"File hashed: SHA256={sha256[:16]}... size={len(content)} bytes",
        extra={"sample_id": sha256, "user_id": str(user.id)},
    )

    # Check if sample already exists
    result = await db.execute(select(Sample).where(Sample.sha256 == sha256))
    existing = result.scalar_one_or_none()
    if existing:
        logger.info(
            f"Duplicate sample detected, returning existing: {sha256[:16]}...",
            extra={"sample_id": str(existing.id)},
        )
        return existing

    # Store in MinIO
    storage_path = f"samples/{sha256[:2]}/{sha256}"
    try:
        from io import BytesIO

        from minio import Minio

        client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )

        # Ensure bucket exists
        if not client.bucket_exists(settings.minio_bucket):
            client.make_bucket(settings.minio_bucket)
            logger.info(f"MinIO bucket created: {settings.minio_bucket}")

        client.put_object(
            settings.minio_bucket,
            storage_path,
            BytesIO(content),
            length=len(content),
            content_type=file.content_type or "application/octet-stream",
        )
        logger.info(
            f"File stored in MinIO: {storage_path}",
            extra={"sample_id": sha256},
        )
    except Exception as e:
        logger.error(
            f"MinIO storage failed: {e}",
            exc_info=True,
            extra={"sample_id": sha256, "component": "minio"},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Storage service unavailable: {e}",
        ) from e

    sample = Sample(
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        original_filename=file.filename or "unknown",
        file_size_bytes=len(content),
        mime_type=file.content_type,
        storage_path=storage_path,
        uploaded_by=user.id,
    )
    db.add(sample)
    await db.flush()
    await db.refresh(sample)

    logger.info(
        f"Sample created: id={sample.id} filename={sample.original_filename}",
        extra={"sample_id": str(sample.id), "user_id": str(user.id)},
    )
    return sample


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

    logger.debug(
        f"Listed samples: page={page} count={len(samples)} total={total}",
        extra={"user_id": str(user.id)},
    )

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
        logger.warning(
            f"Sample not found: {sample_id}",
            extra={"sample_id": str(sample_id), "user_id": str(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sample not found")
    return sample
