"""The object store (MinIO): one client, one bucket, one way to create it.

Every reader and writer of the store — the sample upload and delete, the
sandbox-report upload, read and delete, the health probe, the analysis
worker's sample download and the evidence objects a job's ledger references
(written by the worker, read by the evidence download, removed with the
job) — builds its client here and creates the bucket
here, so none of them can drift from the others. The bucket is
``settings.minio_bucket``, created lazily by the first write that finds it
missing, and every creation path gives a fresh bucket the explicit
anonymous-deny policy.

The MinIO SDK is synchronous. Every function here blocks; a caller on an
event loop runs it in a thread (``asyncio.to_thread``).
"""

from __future__ import annotations

import io
import os
from typing import Any

from pydantic import SecretStr

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("api.object_store")


def _secret() -> str:
    raw = settings.minio_secret_key
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)


def client() -> Any:
    """A MinIO client built from the API's settings."""
    from minio import Minio

    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=_secret(),
        secure=settings.minio_secure,
    )


def deny_anonymous_policy(bucket: str) -> str:
    """The bucket policy that refuses an anonymous principal every read, write and listing."""
    return (
        '{"Version":"2012-10-17","Statement":[{'
        '"Effect":"Deny","Principal":{"AWS":["*"]},'
        '"Action":["s3:GetObject","s3:PutObject","s3:ListBucket"],'
        f'"Resource":["arn:aws:s3:::{bucket}",'
        f'"arn:aws:s3:::{bucket}/*"],'
        '"Condition":{"StringEquals":{"aws:PrincipalType":"Anonymous"}}}]}'
    )


def ensure_bucket(store: Any) -> None:
    """Create the bucket when it is missing, with the anonymous-deny policy.

    MinIO defaults to private buckets, but an operator can mis-configure
    ``MINIO_BROWSER_ALLOW_PUBLIC_BUCKETS`` or a prior process could have left
    the bucket public. An explicit deny policy goes on every new bucket so a
    malware corpus is never served unauthenticated. Anonymous reads are denied
    at the ``s3:GetObject`` level; the API still works because it uses the
    configured access key.
    """
    bucket = settings.minio_bucket
    if store.bucket_exists(bucket):
        return
    store.make_bucket(bucket)
    logger.info("MinIO bucket created: %s", bucket)
    try:
        store.set_bucket_policy(bucket, deny_anonymous_policy(bucket))
        logger.info("MinIO bucket policy set (anonymous-deny): %s", bucket)
    except Exception as policy_exc:
        # Failure to set the policy is non-fatal but loud: operators must
        # verify bucket privacy out-of-band.
        logger.warning(
            "MinIO set_bucket_policy failed for '%s' (%s). "
            "Verify the bucket is not anonymously readable.",
            bucket,
            policy_exc,
        )


def put_file(store: Any, path: str, source: str, *, content_type: str) -> None:
    """Write the file at ``source`` to ``path``, creating the bucket first when missing."""
    ensure_bucket(store)
    store.fput_object(settings.minio_bucket, path, source, content_type=content_type)


def put_bytes(store: Any, path: str, blob: bytes, *, content_type: str) -> None:
    """Write ``blob`` to ``path``, creating the bucket first when missing."""
    ensure_bucket(store)
    store.put_object(
        settings.minio_bucket, path, io.BytesIO(blob), length=len(blob), content_type=content_type
    )


def read_bytes(store: Any, path: str) -> bytes:
    """The object at ``path``, read whole."""
    response = store.get_object(settings.minio_bucket, path)
    try:
        return bytes(response.read())
    finally:
        response.close()
        response.release_conn()


def download(store: Any, path: str, destination: str) -> None:
    """Copy the object at ``path`` to ``destination``, readable by this user only (0600)."""
    store.fget_object(settings.minio_bucket, path, destination)
    os.chmod(destination, 0o600)


def remove(store: Any, path: str) -> None:
    """Delete the object at ``path``."""
    store.remove_object(settings.minio_bucket, path)


# A job's whole answers (``maljan.schemas.evidence_spill``): every object a
# job's ledger references lives under its own prefix, named by the SHA-256 of
# its bytes, so a job's objects are found and removed by the job id alone and
# the same bytes are kept once per job.
EVIDENCE_PREFIX = "evidence"


def evidence_prefix(job_id: object) -> str:
    """The prefix every object of ``job_id``'s ledger is kept under."""
    return f"{EVIDENCE_PREFIX}/{job_id}/"


def evidence_key(job_id: object, sha256: str) -> str:
    """Where the bytes with ``sha256`` that ``job_id``'s ledger references are kept."""
    return f"{evidence_prefix(job_id)}{sha256}"


def evidence_spill(job_id: object) -> Any:
    """The job's store for whole answers, writing into this bucket under the job's prefix.

    The client is built at the first write, on the thread that writes, and
    reused for the job's later writes. A write that fails raises; the caller
    (``spill_part``) states the failure on the entry's reference.
    """
    from maljan.schemas.evidence_spill import EvidenceSpill

    held: list[Any] = []

    def put(sha256: str, blob: bytes, content_type: str) -> str:
        if not held:
            held.append(client())
        key = evidence_key(job_id, sha256)
        put_bytes(held[0], key, blob, content_type=content_type)
        return key

    return EvidenceSpill(put)


def remove_prefix(store: Any, prefix: str) -> int:
    """Delete every object under ``prefix``; returns how many were removed."""
    removed = 0
    for item in store.list_objects(settings.minio_bucket, prefix=prefix, recursive=True):
        store.remove_object(settings.minio_bucket, item.object_name)
        removed += 1
    return removed


def probe() -> None:
    """Raise when the store cannot be reached; the health check's question."""
    client().bucket_exists(settings.minio_bucket)
