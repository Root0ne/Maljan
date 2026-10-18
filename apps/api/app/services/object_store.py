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

from maljan.schemas.evidence_spill import EvidenceSpill, SpillRefused
from pydantic import SecretStr

from app.config import settings
from app.logging_config import get_logger
from app.logsafe import log_safe

logger = get_logger("api.object_store")


def _secret() -> str:
    raw = settings.minio_secret_key
    return raw.get_secret_value() if isinstance(raw, SecretStr) else str(raw)


def client(http_client: Any = None) -> Any:
    """A MinIO client built from the API's settings; ``http_client`` replaces the SDK's pool."""
    from minio import Minio

    return Minio(
        settings.minio_endpoint,
        access_key=settings.minio_access_key,
        secret_key=_secret(),
        secure=settings.minio_secure,
        http_client=http_client,
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


# What one evidence download holds in memory at a time.
EVIDENCE_CHUNK_BYTES = 1024 * 1024


def open_object(store: Any, path: str) -> Any:
    """The object at ``path`` as a response to stream; the caller closes and releases it."""
    return store.get_object(settings.minio_bucket, path)


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


# The operator setting that bounds one kept part: the sample upload limit,
# the largest object the operator already lets one request put in this bucket.
EVIDENCE_BOUND_SETTING = "upload_max_bytes"


# The evidence writers' own client. The SDK's defaults (300 s to connect and
# to read, five retries) let an unreachable store hold a writer for minutes.
# A store on the compose network accepts a connection at once: the health
# probe gives the whole store check 3 s, and a connection is given as long.
EVIDENCE_CONNECT_SECONDS = 3.0
# Between two reads of one answer; a part is written in one request, so this
# is how long the store may go silent mid-write, not how long a write takes.
EVIDENCE_READ_SECONDS = 60.0
# One retry, for a store that dropped one request; a second failure is stated.
EVIDENCE_RETRIES = 1
# How long the worker waits for a job's writes before it stores the ledger.
# They run while the analysts work, so only the last few are in flight then,
# and this is half the shutdown keep's whole grace (``STOP_KEEP_GRACE``, 10 s).
EVIDENCE_DRAIN_SECONDS = 5.0
# Writers per job: parts are written while the analysts work, two at a time,
# so one large part never queues every later one behind it.
EVIDENCE_WRITERS = 2


def _evidence_client() -> Any:
    """A client with the evidence writers' timeouts and one retry."""
    import urllib3

    pool = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=EVIDENCE_CONNECT_SECONDS, read=EVIDENCE_READ_SECONDS),
        retries=urllib3.Retry(
            total=EVIDENCE_RETRIES,
            backoff_factor=0.2,
            status_forcelist=[500, 502, 503, 504],
        ),
    )
    return client(pool)


def _unreachable(exc: BaseException) -> bool:
    """Whether ``exc`` says the store could not be reached at all (not that it refused a write)."""
    import urllib3

    return isinstance(
        exc,
        urllib3.exceptions.MaxRetryError
        | urllib3.exceptions.NewConnectionError
        | urllib3.exceptions.ConnectTimeoutError
        | urllib3.exceptions.ProtocolError
        | ConnectionError
        | TimeoutError,
    )


class JobEvidenceSpill(EvidenceSpill):
    """A job's store writing in the background, on its own writers and its own client.

    ``put`` hands the bytes to a writer and answers with the key at once,
    so no analyst waits on the store. The bucket is made ready once per
    job. The first failure to reach the store marks it down: every later
    part is refused at once (``upload_failed (store unreachable)``), and
    :meth:`drain` reports each write by its digest.
    """

    def __init__(self, job_id: object, max_bytes: int, *, store: Any = None) -> None:
        super().__init__(self._submit, max_bytes=max_bytes, bound_by=EVIDENCE_BOUND_SETTING)
        import threading

        self.job_id = job_id
        self._store = store
        self._lock = threading.Lock()
        self._pool: Any = None
        self._pending: dict[str, Any] = {}
        self._failed: dict[str, str] = {}
        self._bucket_ready = False
        self.down = False

    def _client(self) -> Any:
        with self._lock:
            if self._store is None:
                self._store = _evidence_client()
            return self._store

    def _submit(self, sha256: str, blob: bytes, content_type: str) -> str:
        from concurrent.futures import ThreadPoolExecutor

        key = evidence_key(self.job_id, sha256)
        with self._lock:
            if self.down:
                raise SpillRefused("store unreachable")
            if self._pool is None:
                self._pool = ThreadPoolExecutor(
                    max_workers=EVIDENCE_WRITERS, thread_name_prefix="evidence-writer"
                )
            self._pending[sha256] = self._pool.submit(self._write, key, sha256, blob, content_type)
        return key

    def _write(self, key: str, sha256: str, blob: bytes, content_type: str) -> None:
        if self.down:
            self._failed[sha256] = "store unreachable"
            return
        try:
            store = self._client()
            if not self._bucket_ready:
                ensure_bucket(store)
                self._bucket_ready = True
            store.put_object(
                settings.minio_bucket,
                key,
                io.BytesIO(blob),
                length=len(blob),
                content_type=content_type,
            )
        except Exception as exc:  # noqa: BLE001 — stated on the reference at the drain
            reason = type(exc).__name__
            if _unreachable(exc):
                self.down = True
                reason = "store unreachable"
            self._failed[sha256] = reason
            logger.warning(
                "Evidence object %s was not written: %s",
                log_safe(key),
                log_safe(f"{type(exc).__name__}: {exc}"),
            )

    def drain(self, timeout: float) -> dict[str, str | None]:
        from concurrent.futures import wait

        with self._lock:
            pending = dict(self._pending)
        wait(list(pending.values()), timeout=max(0.0, float(timeout)))
        outcomes: dict[str, str | None] = {}
        for sha256, future in pending.items():
            if not future.done():
                outcomes[sha256] = "not finished"
            else:
                outcomes[sha256] = self._failed.get(sha256)
        return outcomes

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=False)


def evidence_spill(job_id: object, max_bytes: int = 0, *, store: Any = None) -> Any:
    """The job's store for whole answers, writing into this bucket under the job's prefix.

    ``max_bytes`` is the bound on one part, the operator's
    ``upload_max_bytes`` (:func:`job_evidence_spill` reads it): a part above it
    is referenced with that reason and not written. Writes run in the
    background on the job's own writers and client (``EVIDENCE_*`` above); a
    write that fails is logged here, whole and through ``log_safe``, and its
    reference states only a fixed reason once the worker drains the store
    before it stores the ledger. ``store`` replaces the client, for a test.
    """
    return JobEvidenceSpill(job_id, max_bytes, store=store)


async def job_evidence_spill(job_id: object) -> Any:
    """:func:`evidence_spill` bounded by the operator's ``upload_max_bytes``, read now."""
    from maljan.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES

    from app.runtime_config import runtime_config

    try:
        bound = int(await runtime_config.get(EVIDENCE_BOUND_SETTING))
    except Exception as exc:  # noqa: BLE001 — the setting's own default stands
        logger.warning(
            "%s was not read (%s); its default stands.",
            EVIDENCE_BOUND_SETTING,
            type(exc).__name__,
        )
        bound = SAMPLE_UPLOAD_MAX_BYTES
    return evidence_spill(job_id, bound)


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
