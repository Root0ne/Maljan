"""The object store (MinIO): one client, one bucket, one way to create it.

Every reader and writer of the store — the sample upload and delete, the
sandbox-report upload, read and delete, the health probe, the analysis
worker's sample download and the evidence objects a job's ledger references
(written by the worker, read by the evidence download, removed with the
job) and the audit chain's heads (``audit_anchor``) — builds its client here and creates the bucket
here, so none of them can drift from the others. The bucket is
``settings.minio_bucket``, created lazily by the first write that finds it
missing, and every creation path leaves a fresh bucket private: no bucket
policy, which is how MinIO refuses an anonymous caller everything. The health
probe asks the bucket, anonymously, whether it still does.

The MinIO SDK is synchronous. Every function here blocks; a caller on an
event loop runs it in a thread (``asyncio.to_thread``).
"""

from __future__ import annotations

import io
import json
import os
import threading
from typing import Any

from malspark.core.previous_name import PREVIOUS_NAME
from malspark.schemas.evidence_spill import EvidenceSpill, SpillRefused
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


# The bucket a deployment started before the product's rename (T-576) kept
# everything in, and the one this process settled on, by configured name.
PREVIOUS_BUCKET = f"{PREVIOUS_NAME}-samples"
_SETTLED: dict[str, str] = {}


def bucket(store: Any | None = None) -> str:
    """The bucket every read and write uses.

    The configured one, except where nothing configured it (``MINIO_BUCKET``
    unset), the default bucket is missing and the bucket of a deployment
    started before the rename is there: that one is used, and the log names
    ``MINIO_BUCKET``. An empty twin is never created beside it, so the
    samples, the spilled parts and the anchored audit heads (under their object
    lock) stay where they are. Settled once per configured name; a store that
    cannot answer leaves the configured name, asked again next time.
    """
    name: str = settings.minio_bucket
    if name in _SETTLED:
        return _SETTLED[name]
    from app.config import get_settings

    if name == PREVIOUS_BUCKET or "minio_bucket" in get_settings().model_fields_set:
        _SETTLED[name] = name
        return name
    try:
        held = store if store is not None else client()
        if held.bucket_exists(name) or not held.bucket_exists(PREVIOUS_BUCKET):
            _SETTLED[name] = name
            return name
    except Exception:  # noqa: BLE001 — the caller's own call says what is wrong with the store
        return name
    logger.warning(
        "MinIO bucket %s is absent and %s, the bucket before the product's rename, holds the "
        "data; it is used. Set MINIO_BUCKET=%s to keep this.",
        name,
        PREVIOUS_BUCKET,
        PREVIOUS_BUCKET,
    )
    _SETTLED[name] = PREVIOUS_BUCKET
    return PREVIOUS_BUCKET


def ensure_bucket(store: Any) -> None:
    """Create the bucket when it is missing, private.

    MinIO answers an anonymous caller only through a bucket policy that allows
    it; a bucket with no policy refuses every anonymous read, write and
    listing, and the configured access key works as before. So a fresh bucket
    gets no policy. A deny policy is not set either. MinIO refuses the
    ``aws:PrincipalType`` condition that would scope it to anonymous callers;
    a store that accepted the policy but dropped a condition it does not know
    would hold a deny on every principal, the platform's own key among them,
    which no check here could tell from a store that honours it; and any
    policy an operator sets later replaces it whole. Whether the bucket stays
    private is asked of new and old buckets alike (``privacy``): at start, by
    the health probe, and before a sample or a sandbox report is taken or
    served.
    """
    name = bucket(store)
    if store.bucket_exists(name):
        return
    store.make_bucket(name)
    logger.info("MinIO bucket created, private (no bucket policy): %s", name)


def put_file(store: Any, path: str, source: str, *, content_type: str) -> None:
    """Write the file at ``source`` to ``path``, creating the bucket first when missing.

    Not while the bucket lets an anonymous caller in (``require_private``),
    nor any other read or write of a sample, a report or a job's evidence below.
    """
    ensure_bucket(store)
    require_private(store)
    store.fput_object(bucket(store), path, source, content_type=content_type)


def put_bytes(store: Any, path: str, blob: bytes, *, content_type: str) -> None:
    """Write ``blob`` to ``path``, creating the bucket first when missing."""
    ensure_bucket(store)
    require_private(store)
    store.put_object(
        bucket(store), path, io.BytesIO(blob), length=len(blob), content_type=content_type
    )


def read_bytes(store: Any, path: str) -> bytes:
    """The object at ``path``, read whole."""
    require_private(store)
    response = store.get_object(bucket(store), path)
    try:
        return bytes(response.read())
    finally:
        response.close()
        response.release_conn()


# What one evidence download holds in memory at a time.
EVIDENCE_CHUNK_BYTES = 1024 * 1024


def open_object(store: Any, path: str) -> Any:
    """The object at ``path`` as a response to stream; the caller closes and releases it."""
    require_private(store)
    return store.get_object(bucket(store), path)


def download(store: Any, path: str, destination: str) -> None:
    """Copy the object at ``path`` to ``destination``, readable by this user only (0600)."""
    require_private(store)
    store.fget_object(bucket(store), path, destination)
    os.chmod(destination, 0o600)


def remove(store: Any, path: str) -> None:
    """Delete the object at ``path``."""
    store.remove_object(bucket(store), path)


# A job's whole answers (``malspark.schemas.evidence_spill``): every object a
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


def bounded_client(
    *, read_seconds: float = EVIDENCE_READ_SECONDS, retries: int = EVIDENCE_RETRIES
) -> Any:
    """A client with the evidence writers' timeouts and one retry, or the ones given.

    The evidence writers use it, and so does the audit chain's object-store
    anchor (``audit_anchor``, with a shorter read and no retry, so its threads
    end within its own bound): neither may be held for minutes by a store that
    does not answer.
    """
    import urllib3

    pool = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=EVIDENCE_CONNECT_SECONDS, read=read_seconds),
        retries=urllib3.Retry(
            total=retries,
            backoff_factor=0.2,
            status_forcelist=[500, 502, 503, 504],
        ),
    )
    return client(pool)


_evidence_client = bounded_client


def _unreachable(exc: BaseException) -> bool:
    """Whether ``exc`` says the store could not be reached at all (not that it refused a write).

    Retries that ran out are read by their cause: a connection or a timeout
    that failed is a store out of reach; server errors answered every time
    are a store that answered, and only that write failed.
    """
    import urllib3

    causes = (
        urllib3.exceptions.NewConnectionError,
        urllib3.exceptions.TimeoutError,
        urllib3.exceptions.ProtocolError,
        ConnectionError,
        TimeoutError,
    )
    if isinstance(exc, urllib3.exceptions.MaxRetryError):
        return isinstance(exc.reason, causes)
    return isinstance(exc, causes)


class JobEvidenceSpill(EvidenceSpill):
    """A job's store writing in the background, on its own writers and its own client.

    ``put`` hands the bytes to a writer and answers with the key at once,
    so no analyst waits on the store. The bucket is made ready once per
    job. The first failure to reach the store marks it down: every later
    part is refused at once (``upload_failed (store unreachable)``), and
    :meth:`drain` reports each write by its digest.

    The bytes waiting for a writer are bounded by the same setting as one
    part: at most one part per writer (``EVIDENCE_WRITERS`` times
    ``upload_max_bytes``). A part that would pass it is refused at once as
    ``upload_failed (store busy)``; nothing waits and nothing is cut.
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
        # Keys already written or being written: the same bytes go up once per job.
        self._written: set[str] = set()
        # How many times each key was handed to a writer: a write given up on
        # at the drain removes its object only if no later put wrote it again.
        self._generation: dict[str, int] = {}
        self._bucket_ready = False
        self.down = False
        self.closed = False
        # Bytes handed to the writers and not yet written, and their bound.
        self._queued = 0
        self.backlog_bytes = EVIDENCE_WRITERS * self.max_bytes

    def _client(self) -> Any:
        with self._lock:
            if self._store is None:
                self._store = _evidence_client()
            return self._store

    def _submit(self, sha256: str, blob: bytes, content_type: str) -> str:
        from concurrent.futures import ThreadPoolExecutor

        key = evidence_key(self.job_id, sha256)
        with self._lock:
            if self.closed:
                raise SpillRefused("store closed")
            if self.down:
                raise SpillRefused("store unreachable")
            if key in self._written and sha256 not in self._failed:
                return key
            if self.backlog_bytes and self._queued + len(blob) > self.backlog_bytes:
                raise SpillRefused("store busy")
            self._queued += len(blob)
            self._written.add(key)
            self._generation[key] = self._generation.get(key, 0) + 1
            self._failed.pop(sha256, None)
            if self._pool is None:
                self._pool = ThreadPoolExecutor(
                    max_workers=EVIDENCE_WRITERS, thread_name_prefix="evidence-writer"
                )
            future = self._pool.submit(self._write, key, sha256, blob, content_type)
            self._pending[sha256] = future
        # Released when the write ends, and when it is cancelled before it began.
        size = len(blob)
        future.add_done_callback(lambda _done: self._release(size))
        return key

    def read(self, sha256: str, offset: int = 0, length: int | None = None) -> bytes | None:
        """The bytes written under ``sha256``: from ``offset``, ``length`` of them, else to the end.

        Waits for the job's own write of these bytes to end, then reads the
        object through the job's client. ``None`` for bytes this job never
        handed over, a write that failed, or a store that does not answer; the
        reader states which copy it paged.
        """
        key = evidence_key(self.job_id, sha256)
        with self._lock:
            future = self._pending.get(sha256)
            known = key in self._written and sha256 not in self._failed
        if not known or self.down:
            return None
        try:
            require_private(self._client())
        except StoreNotPrivate:
            return None
        if future is not None:
            try:
                future.result(timeout=EVIDENCE_CONNECT_SECONDS + EVIDENCE_READ_SECONDS)
            except Exception:  # noqa: BLE001 — a write that did not end is a copy not kept
                return None
            if sha256 in self._failed:
                return None
        try:
            response = self._client().get_object(
                bucket(self._client()), key, offset=max(0, int(offset)), length=int(length or 0)
            )
            try:
                return bytes(response.read())
            finally:
                response.close()
                response.release_conn()
        except Exception as exc:  # noqa: BLE001 — logged; the reader falls back and says so
            logger.warning(
                "Evidence object %s could not be read: %s",
                log_safe(key),
                log_safe(f"{type(exc).__name__}: {exc}"),
            )
            return None

    def _release(self, size: int) -> None:
        with self._lock:
            self._queued -= size

    def _write(self, key: str, sha256: str, blob: bytes, content_type: str) -> None:
        if self.down:
            self._failed[sha256] = "store unreachable"
            return
        try:
            store = self._client()
            if not self._bucket_ready:
                ensure_bucket(store)
                self._bucket_ready = True
            require_private(store)
            store.put_object(
                bucket(store),
                key,
                io.BytesIO(blob),
                length=len(blob),
                content_type=content_type,
            )
        except StoreNotPrivate:
            self._failed[sha256] = "store not private"
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
        """Wait up to ``timeout`` seconds; then give up on every write still open.

        A write not started by then is cancelled. One already running is
        stated ``not finished``, and when it does finish its object is removed
        again (:meth:`_remove_late`), so no object outlives a reference that
        says it was not kept.
        """
        from concurrent.futures import wait

        with self._lock:
            pending = dict(self._pending)
        wait(list(pending.values()), timeout=max(0.0, float(timeout)))
        # One snapshot decides: a write still open here is stated not finished
        # and its object removed when it ends, even if it ends a moment later.
        late = {sha256: future for sha256, future in pending.items() if not future.done()}
        if late:
            with self._lock:
                pool, self._pool = self._pool, None
            if pool is not None:
                pool.shutdown(wait=False, cancel_futures=True)
        outcomes: dict[str, str | None] = {
            sha256: "not finished" if sha256 in late else self._failed.get(sha256)
            for sha256 in pending
        }
        for sha256, future in late.items():
            key = evidence_key(self.job_id, sha256)
            with self._lock:
                self._written.discard(key)
                generation = self._generation.get(key, 0)
            future.add_done_callback(
                lambda done, key=key, generation=generation: self._remove_late(
                    done, key, generation
                )
            )
        return outcomes

    def _remove_late(self, future: Any, key: str, generation: int) -> None:
        """Remove the object a write left after its reference was stated not finished.

        Not when a later put handed the same key to a writer again: that
        object is the later write's.
        """
        with self._lock:
            rewritten = self._generation.get(key, 0) != generation
        if future.cancelled() or rewritten:
            return
        if self._failed.get(key.rsplit("/", 1)[-1]) is not None:
            return
        logger.info("Evidence object %s was written after its drain; removing it", log_safe(key))
        try:
            remove(self._client(), key)
        except Exception as exc:  # noqa: BLE001 — logged; the row already says not kept
            logger.warning(
                "Evidence object %s written after its drain could not be removed: %s",
                log_safe(key),
                log_safe(f"{type(exc).__name__}: {exc}"),
            )

    def close(self) -> None:
        """No part is taken after this; writes already handed over still finish."""
        with self._lock:
            self.closed = True
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
    return evidence_spill(job_id, await evidence_bound())


async def evidence_bound() -> int:
    """The bound on one kept part: the operator's ``upload_max_bytes``, read now.

    The setting's own default stands when it cannot be read, and that is logged.
    """
    from malspark.core.delivery_limits import SAMPLE_UPLOAD_MAX_BYTES

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
    return bound


def remove_prefix(store: Any, prefix: str) -> int:
    """Delete every object under ``prefix``; returns how many were removed."""
    removed = 0
    name = bucket(store)
    for item in store.list_objects(name, prefix=prefix, recursive=True):
        store.remove_object(name, item.object_name)
        removed += 1
    return removed


# How long an anonymous request of the privacy check may take, and how long
# its verdict is kept before the store is asked again: a store that is fixed
# is served again within that time, without a restart.
ANONYMOUS_SECONDS = 2.0
PRIVACY_TTL_SECONDS = 60.0


def anonymous_client(store: Any | None = None, name: str | None = None) -> Any:
    """A client with no credentials: every request it sends is an anonymous one.

    Each request is bounded (``ANONYMOUS_SECONDS`` to connect and to read) and
    never retried. Its region is the one ``store``'s key resolves for the
    bucket, so an unsigned request reaches a bucket outside the default region.
    """
    import urllib3
    from minio import Minio

    region = None
    if store is not None and name is not None:
        try:
            region = store._get_region(name) or None
        except Exception:  # noqa: BLE001 — the client then resolves no region, as before
            region = None
    pool = urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=ANONYMOUS_SECONDS, read=ANONYMOUS_SECONDS),
        retries=False,
    )
    return Minio(
        settings.minio_endpoint, secure=settings.minio_secure, region=region, http_client=pool
    )


# The key an anonymous read is asked for. It is never written: a private
# bucket refuses the read (AccessDenied), one that lets anyone read answers
# that the key is missing.
ANONYMOUS_PROBE_KEY = "anonymous-access-probe"
# The buckets whose policy this process's key could not read, said once each.
_POLICY_UNREAD: set[str] = set()


def _code(exc: Exception) -> str | None:
    return getattr(exc, "code", None)


def _names_anyone(principal: Any) -> bool:
    """Whether ``*`` is among the principals, however the statement spells them."""
    if principal == "*":
        return True
    if isinstance(principal, list):
        return any(_names_anyone(item) for item in principal)
    if isinstance(principal, dict):
        return any(_names_anyone(item) for item in principal.values())
    return False


def _as_list(value: Any) -> list[Any]:
    return [value] if isinstance(value, str) else list(value or [])


def policy_grants(policy: str) -> list[str]:
    """What a bucket policy allows an anonymous caller, statement by statement.

    A statement is open to anyone when its principal names ``*`` anywhere (a
    string, in a list, under any key) or when it allows by ``NotPrincipal``,
    which allows everyone it does not name. ``NotAction`` allows every action
    but the ones it names, and is reported so.
    """
    statements = json.loads(policy).get("Statement", [])
    found: list[str] = []
    for statement in statements if isinstance(statements, list) else [statements]:
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if "NotPrincipal" not in statement and not _names_anyone(statement.get("Principal")):
            continue
        if "NotAction" in statement:
            grants = ["all but " + ", ".join(map(str, _as_list(statement["NotAction"])))]
        else:
            grants = [str(action) for action in _as_list(statement.get("Action"))]
        for grant in grants:
            if f"policy allows {grant}" not in found:
                found.append(f"policy allows {grant}")
    return found


def anonymous_access(store: Any, anonymous: Any) -> list[str]:
    """What the bucket lets an anonymous caller do; empty when it is private.

    Asked twice over. ``anonymous`` (a client with no credentials) lists the
    bucket and reads a key that is never written, so a refusal is the server's
    own answer, whatever the policy says; and the bucket's policy, read with
    ``store``'s key, names what it allows anyone, a write among it, which is
    not tried. A key not let read the policy leaves the write unchecked, said
    once, and the anonymous answers stand. A failure other than a refusal is
    raised, so the caller reports a store it could not ask rather than a
    private one.

    The probe reads the bucket, not each object: a store that grants
    per-object access (an object ACL on AWS S3) is not seen by it.
    """
    from minio.error import S3Error

    name = bucket(store)
    found: list[str] = []
    try:
        if anonymous.bucket_exists(name):
            found.append("list")
    except S3Error as exc:
        if _code(exc) != "AccessDenied":
            raise
    try:
        anonymous.stat_object(name, ANONYMOUS_PROBE_KEY)
        found.append("read")
    except S3Error as exc:
        if _code(exc) == "NoSuchKey":
            found.append("read")
        elif _code(exc) != "AccessDenied":
            raise
    try:
        policy = store.get_bucket_policy(name)
    except S3Error as exc:
        if _code(exc) == "AccessDenied":
            if name not in _POLICY_UNREAD:
                _POLICY_UNREAD.add(name)
                logger.warning(
                    "MinIO bucket %s: the configured key may not read the bucket policy, so "
                    "whether an anonymous caller may write is not checked; the anonymous "
                    "read and listing are.",
                    log_safe(name),
                )
            return found
        if _code(exc) != "NoSuchBucketPolicy":
            raise
        return found
    if policy:
        found.extend(grant for grant in policy_grants(policy) if grant not in found)
    return found


class StoreNotPrivate(RuntimeError):
    """The bucket lets an anonymous caller in: samples are neither taken nor served."""

    detail = "object store is not private; see the API log"

    def __init__(self) -> None:
        super().__init__(self.detail)


# The privacy verdict per bucket: when it was asked, and what an anonymous
# caller is let do (``None``: the store could not be asked). An unanswered ask
# is kept only ``UNCHECKED_TTL_SECONDS``, and never replaces a verdict that
# found the bucket open: that one stands until the store answers private.
_PRIVACY: dict[str, tuple[float, tuple[str, ...] | None]] = {}
UNCHECKED_TTL_SECONDS = 5.0
# Held while ``_PRIVACY`` is read or written, never while the store is asked:
# the API's threads and the health probe ask at once.
_PRIVACY_LOCK = threading.Lock()


def privacy(store: Any, *, fresh: bool = False) -> tuple[str, ...] | None:
    """What the bucket lets an anonymous caller do, asked at most once a ``PRIVACY_TTL_SECONDS``.

    Empty when it is private or does not exist yet (nothing in it to expose,
    and not kept, so the bucket is asked once it is made); ``None`` when the
    store could not be asked. A failed ask after the bucket was found open
    keeps that verdict, so a passing error never opens the gate. A bucket
    that lets anyone in is logged at ERROR each time it is asked again; one
    that is fixed is logged once when it is found private.
    """
    import time

    name = bucket(store)
    now = time.monotonic()
    with _PRIVACY_LOCK:
        held = _PRIVACY.get(name)
    if held is not None and not fresh:
        ttl = PRIVACY_TTL_SECONDS if held[1] is not None else UNCHECKED_TTL_SECONDS
        if now - held[0] < ttl:
            return held[1]
    try:
        if not store.bucket_exists(name):
            return ()
        verdict = tuple(anonymous_access(store, anonymous_client(store, name)))
    except Exception as exc:  # noqa: BLE001 — an unanswered check is no verdict
        logger.warning(
            "MinIO bucket %s: whether it is private could not be checked: %s",
            log_safe(name),
            log_safe(type(exc).__name__),
        )
        # Read again: another caller may have found the bucket open meanwhile.
        with _PRIVACY_LOCK:
            current = _PRIVACY.get(name)
            if current is not None and current[1]:
                return current[1]
            _PRIVACY[name] = (now, None)
        return None
    if verdict:
        logger.error(
            "MinIO bucket %s is not private; an anonymous caller is let through: %s. "
            "Samples are neither taken nor served until it is. Remove the bucket "
            "policy that allows it (mc anonymous set none).",
            log_safe(name),
            log_safe(", ".join(verdict)),
        )
    with _PRIVACY_LOCK:
        current = _PRIVACY.get(name)
        _PRIVACY[name] = (now, verdict)
    if not verdict and current is not None and current[1]:
        logger.info("MinIO bucket %s is private again.", log_safe(name))
    return verdict


def require_private(store: Any) -> None:
    """Raise ``StoreNotPrivate`` while the bucket lets an anonymous caller in (fail closed)."""
    if privacy(store):
        raise StoreNotPrivate()


def check_privacy_at_start() -> None:
    """Ask the bucket once at start, after its name settles; the verdict is logged."""
    store = client()
    if store.bucket_exists(bucket(store)):
        privacy(store, fresh=True)


def probe() -> dict[str, Any] | None:
    """The health check's question: raise when the store cannot be reached.

    A bucket that lets an anonymous caller in fails the check, as a required
    component; one whose privacy could not be asked fails it as an optional
    one. The endpoint is unauthenticated, so the answer says only which check
    failed; the log says the rest.
    """
    store = client()
    if not store.bucket_exists(bucket(store)):
        return None
    verdict = privacy(store)
    if verdict is None:
        return {"ok": False, "error": "object store privacy not checked; see the API log"}
    if verdict:
        return {
            "ok": False,
            "error": "object store policy check failed; see the API log",
            "required": True,
        }
    return None
