"""The audit chain's head kept outside the database: the anchor.

The head record (``AuditChainHead``) lives in the same database as the chain it
closes, so a writer who holds the settings key can rewrite both, and one who
kept an earlier head record can put it back after cutting the rows that followed
it (``audit_chain``). An anchor keeps each committed head where that writer
cannot reach it, and verification compares the chain with the latest anchored
head: a chain rewritten, or cut back below it, no longer verifies.

The anchor is chosen by the bootstrap variable ``AUDIT_ANCHOR``, never by the
settings store, so a database writer cannot switch it off:

- ``database``: rows of ``audit_chain_anchor`` written through
  ``AUDIT_ANCHOR_DATABASE_URL``, a role meant to hold only INSERT and SELECT
  there; on PostgreSQL a trigger refuses UPDATE, DELETE and TRUNCATE. The
  default when that URL is set.
- ``object_store``: one object per head in the platform's bucket
  (``OBJECT_PREFIX``), written under the bucket's object lock when it has one,
  under a legal hold when the lock has no default retention, and plainly when
  the bucket has no lock.
- ``none`` (or nothing configured): today's behaviour, and every verification
  says so (:data:`NOT_CONFIGURED`); nothing claims more than the database head.

What protects the anchor is read from the store itself (the roles' privileges,
the bucket's lock) and stated with every verification, never assumed.

A head is anchored after the transaction that wrote it commits (the hook
:func:`anchor_after_commit` puts on the session): the head the append computed
is written once the committed database agrees with it (its MAC verifies under a
key the platform holds, the chain holds its value at its seq, and it does not
contradict the anchor), so a head rolled back is never anchored. Anchoring is
best effort: a store that is down, slow or refuses is logged at ERROR and
counted in ``audit_anchor_failures``, and the job goes on; the rows written
meanwhile read as past the last anchored head, which verification states. An
empty anchor is given the current head once at startup
(:func:`start_anchoring`).

Once an anchor is configured, a verification that could not read it, or found
it empty beside a head, or holding a head under a key the platform cannot
derive, is ``unverifiable``, never ``verified``.

The limit, stated: rows past the last anchored head are checked against the
database head only, and the anchor protects as much as its own store's
credentials allow; the protection sentence says which holds.
"""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app import observability
from app.logging_config import get_logger
from app.logsafe import log_safe

logger = get_logger("api.audit_anchor")

NONE = "none"
DATABASE = "database"
OBJECT_STORE = "object_store"
KINDS: tuple[str, ...] = (NONE, DATABASE, OBJECT_STORE)

ANCHOR_TABLE = "audit_chain_anchor"
# Where the object-store anchor keeps its heads: one object per head, named by
# its ``chain_seq`` zero-padded, so the names sort in chain order.
OBJECT_PREFIX = "audit-chain/head/"
_SEQ_WIDTH = 12
# How long one anchor read or write may take before it is given up on: the
# anchor is best effort and never holds a job or a verification for long.
ANCHOR_SECONDS = 10.0
# How long a connection to the anchor database may take.
CONNECT_SECONDS = 3.0

NOT_CONFIGURED = (
    "No anchor outside the database is configured (AUDIT_ANCHOR): the audit chain is "
    "checked against the head record in the same database only, so a writer who holds the "
    "settings key can rewrite the chain and its head, and one who kept an earlier head "
    "record can put it back after cutting the rows that followed, unseen."
)


@dataclass(frozen=True)
class AnchoredHead:
    """One head of the audit chain as it was committed, as the anchor keeps it."""

    chain_seq: int
    chain: str
    key_id: str | None
    rotated_at_seq: int
    mac: str
    anchored_at: str | None = None

    def record(self) -> dict[str, Any]:
        return {
            "chain_seq": int(self.chain_seq),
            "chain": self.chain,
            "key_id": self.key_id,
            "rotated_at_seq": int(self.rotated_at_seq),
            "mac": self.mac,
            "anchored_at": self.anchored_at,
        }

    @classmethod
    def read(cls, row: Any) -> AnchoredHead:
        def _get(name: str) -> Any:
            return row.get(name) if isinstance(row, Mapping) else getattr(row, name, None)

        anchored_at = _get("anchored_at")
        if isinstance(anchored_at, datetime):
            anchored_at = anchored_at.isoformat()
        return cls(
            chain_seq=int(_get("chain_seq")),
            chain=str(_get("chain")),
            key_id=_get("key_id") or None,
            rotated_at_seq=int(_get("rotated_at_seq")),
            mac=str(_get("mac")),
            anchored_at=anchored_at,
        )


class AnchorConflict(RuntimeError):
    """The anchor already holds another head at the same ``chain_seq``."""


class AnchorTampered(RuntimeError):
    """A head the anchor kept is hidden or gone: the anchor itself was written over."""


class ChainAnchor:
    """Where heads are kept outside the database; each kind answers these three."""

    kind: str = NONE

    async def latest(self) -> AnchoredHead | None:
        """The head with the highest ``chain_seq`` the anchor holds; ``None`` when it holds none."""
        raise NotImplementedError

    async def put(self, head: AnchoredHead) -> None:
        """Keep ``head``: nothing when it is kept already, :class:`AnchorConflict` for another."""
        raise NotImplementedError

    async def protection(self) -> str:
        """What keeps an anchored head from being changed, read from the store, in a sentence."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# The database anchor: a role that only appends
# ---------------------------------------------------------------------------


def _role_of(url: str) -> str | None:
    """The user name in a database URL, never its password; ``None`` when there is none."""
    try:
        from sqlalchemy.engine import make_url

        return make_url(url).username or None
    except Exception:  # noqa: BLE001 — an unreadable URL names no role
        return None


class DatabaseAnchor(ChainAnchor):
    """Heads kept as rows of ``audit_chain_anchor``, reached through their own role.

    ``engine`` replaces the engine built from ``url``, for a test. The engine
    holds no pooled connection: each read or write connects and disconnects.
    """

    kind = DATABASE

    def __init__(self, url: str = "", *, engine: Any = None, app_role: str | None = None) -> None:
        self._url = url
        self._engine = engine
        self._app_role = app_role

    def _get_engine(self) -> Any:
        if self._engine is None:
            from sqlalchemy.ext.asyncio import create_async_engine
            from sqlalchemy.pool import NullPool

            connect_args: dict[str, Any] = {}
            if self._url.startswith("postgresql+asyncpg"):
                connect_args["timeout"] = CONNECT_SECONDS
            self._engine = create_async_engine(
                self._url, poolclass=NullPool, connect_args=connect_args
            )
        return self._engine

    async def latest(self) -> AnchoredHead | None:
        from sqlalchemy import select

        from app.models.audit import AuditChainAnchor

        table = AuditChainAnchor.__table__
        async with self._get_engine().connect() as conn:
            row = (
                (await conn.execute(select(table).order_by(table.c.chain_seq.desc()).limit(1)))
                .mappings()
                .first()
            )
        return AnchoredHead.read(row) if row is not None else None

    async def put(self, head: AnchoredHead) -> None:
        from sqlalchemy import insert, select
        from sqlalchemy.exc import IntegrityError

        from app.models.audit import AuditChainAnchor

        table = AuditChainAnchor.__table__
        values = {k: v for k, v in head.record().items() if k != "anchored_at"}
        engine = self._get_engine()
        try:
            async with engine.begin() as conn:
                await conn.execute(insert(AuditChainAnchor).values(**values))
        except IntegrityError:
            # Another writer kept a head at this seq first: the same head is
            # nothing to do; another one is a fork the operator must see.
            async with engine.connect() as conn:
                held = (
                    (
                        await conn.execute(
                            select(table).where(table.c.chain_seq == int(head.chain_seq))
                        )
                    )
                    .mappings()
                    .first()
                )
            if held is None or str(held["chain"]) != head.chain:
                raise AnchorConflict("the anchor holds another head at this seq") from None

    async def protection(self) -> str:
        from sqlalchemy import text

        async with self._get_engine().connect() as conn:
            if conn.dialect.name != "postgresql":
                return (
                    f"The anchor database is {conn.dialect.name}, not PostgreSQL: who may change "
                    "its rows was not checked."
                )
            mine = (
                (
                    await conn.execute(
                        text(
                            "SELECT current_user AS role, "
                            "(SELECT rolsuper FROM pg_roles WHERE rolname = current_user) "
                            "AS superuser, "
                            "has_table_privilege('audit_chain_anchor', 'INSERT') AS can_insert, "
                            "has_table_privilege('audit_chain_anchor', 'SELECT') AS can_select, "
                            "has_table_privilege('audit_chain_anchor', 'UPDATE') AS can_update, "
                            "has_table_privilege('audit_chain_anchor', 'DELETE') AS can_delete, "
                            "has_table_privilege('audit_chain_anchor', 'TRUNCATE') "
                            "AS can_truncate, "
                            "(SELECT pg_get_userbyid(relowner) FROM pg_class "
                            "WHERE oid = 'audit_chain_anchor'::regclass) AS owner, "
                            "EXISTS (SELECT 1 FROM pg_trigger "
                            "WHERE tgrelid = 'audit_chain_anchor'::regclass "
                            "AND tgname = 'audit_chain_anchor_append_only' "
                            "AND tgenabled <> 'D') AS append_only"
                        )
                    )
                )
                .mappings()
                .one()
            )
            app_role = self._app_role
            if app_role is None:
                from app.config import settings

                app_role = _role_of(settings.database_url)
            theirs = None
            if app_role:
                theirs = (
                    (
                        await conn.execute(
                            text(
                                "SELECT rolsuper AS superuser, "
                                "has_table_privilege(rolname, 'audit_chain_anchor', 'INSERT') "
                                "AS can_insert, "
                                "has_table_privilege(rolname, 'audit_chain_anchor', 'UPDATE') "
                                "AS can_update, "
                                "has_table_privilege(rolname, 'audit_chain_anchor', 'DELETE') "
                                "AS can_delete, "
                                "has_table_privilege(rolname, 'audit_chain_anchor', 'TRUNCATE') "
                                "AS can_truncate "
                                "FROM pg_roles WHERE rolname = :role"
                            ),
                            {"role": app_role},
                        )
                    )
                    .mappings()
                    .first()
                )
        return database_protection(dict(mine), app_role, dict(theirs) if theirs else None)


_WRITES = (("UPDATE", "can_update"), ("DELETE", "can_delete"), ("TRUNCATE", "can_truncate"))


def _changes(row: Mapping[str, Any], *, inserts: bool = False) -> list[str]:
    """The writes ``row`` says a role may make beyond reading; INSERT only when asked."""
    verbs = ((("INSERT", "can_insert"),) if inserts else ()) + _WRITES
    return [verb for verb, column in verbs if row.get(column)]


def database_protection(
    mine: Mapping[str, Any], app_role: str | None, theirs: Mapping[str, Any] | None
) -> str:
    """The sentence that says what keeps the anchor table's rows, from the roles' privileges.

    ``mine`` is what the anchor's own role holds, ``theirs`` what the
    application's database role holds on the same table (``None`` when that
    role does not exist in the anchor's database).
    """
    role = str(mine.get("role") or "")
    owner = str(mine.get("owner") or "")
    weak: list[str] = []
    if app_role and role == app_role:
        weak.append(
            f"the anchor connects as the application's own database role ({role}), so a "
            "writer holding the application's credentials can change it"
        )
    if mine.get("superuser"):
        weak.append(f"the anchor role {role} is a superuser")
    elif owner == role:
        weak.append(f"the anchor role {role} owns the anchor table")
    elif _changes(mine):
        weak.append(f"the anchor role {role} may also {', '.join(_changes(mine))} it")
    if theirs is not None and app_role and app_role != role:
        if theirs.get("superuser"):
            weak.append(f"the application's role {app_role} is a superuser")
        elif owner == app_role:
            weak.append(f"the application's role {app_role} owns the anchor table")
        elif _changes(theirs, inserts=True):
            # INSERT counts here: a writer with the application's credentials
            # could add a head of its own choosing above the true one.
            changes = ", ".join(_changes(theirs, inserts=True))
            weak.append(f"the application's role {app_role} may {changes} it")
    if not (mine.get("can_insert") and mine.get("can_select")):
        weak.append(f"the anchor role {role} lacks INSERT or SELECT on it, so heads cannot be kept")
    trigger = (
        "an append-only trigger refuses UPDATE, DELETE and TRUNCATE (its owner can drop it)"
        if mine.get("append_only")
        else "no append-only trigger is in place"
    )
    if weak:
        return (
            "The anchor table is not protected from the database's own writers: "
            + "; ".join(weak)
            + f"; {trigger}."
        )
    return (
        f"The anchor role {role} may only INSERT and SELECT the anchor table, and the "
        f"application's role {app_role or '(unnamed)'} can neither change nor remove its rows: "
        f"a writer holding only the application's credentials cannot move an anchored head; "
        f"{trigger}."
    )


# ---------------------------------------------------------------------------
# The object-store anchor: one object per head, under object lock when it can
# ---------------------------------------------------------------------------


def _object_name(seq: int) -> str:
    return f"{OBJECT_PREFIX}{int(seq):0{_SEQ_WIDTH}d}.json"


@dataclass(frozen=True)
class BucketLock:
    """The bucket's object lock as the store answers it: off, on with no default, or a rule."""

    enabled: bool
    mode: str | None = None
    duration: int | None = None
    unit: str | None = None


def bucket_lock_sentence(lock: BucketLock) -> str:
    """What the bucket's object lock does for an anchored head, in a sentence."""
    if not lock.enabled:
        return (
            "The bucket has no object lock: a holder of the object store's keys (the "
            "platform's own) can overwrite or delete an anchored head. The anchor still rules "
            "out a writer who holds only the database, and a head this process saw that is "
            "gone is detected."
        )
    if lock.mode is None:
        return (
            "The bucket has object lock enabled with no default retention: each anchored head "
            "is written under a legal hold, which a user granted s3:PutObjectLegalHold can lift; "
            "a delete marker hides a head, and is detected."
        )
    period = f"{lock.duration} {str(lock.unit or '').lower()}"
    if str(lock.mode).upper() == "COMPLIANCE":
        return (
            f"The bucket keeps every object version under object lock in COMPLIANCE mode for "
            f"{period}: versions cannot be removed, by the object store's root user either, "
            "before that ends; a delete marker hides a head, and is detected."
        )
    return (
        f"The bucket keeps every object version under object lock in {lock.mode} mode for "
        f"{period}: a user granted s3:BypassGovernanceRetention can still remove a version; a "
        "delete marker hides a head, and is detected."
    )


def _seq_of(name: str) -> int:
    return int(name[len(OBJECT_PREFIX) :].split(".", 1)[0])


class ObjectStoreAnchor(ChainAnchor):
    """Heads kept as objects in the platform's bucket, one per ``chain_seq``.

    ``store`` replaces the client, for a test. The MinIO SDK blocks, so every
    call runs in a thread, on a client whose timeouts end it within
    :data:`ANCHOR_SECONDS`. With the bucket's object lock on, every version is
    listed: a head is read from the first version written under its name, so a
    later version put over it is not taken for it, and a name whose latest
    version is a delete marker is a hidden head (:class:`AnchorTampered`). The
    highest name seen is kept for the process: later listings start just below
    it, and a head seen once that is gone is :class:`AnchorTampered` too.
    """

    kind = OBJECT_STORE

    def __init__(self, *, store: Any = None) -> None:
        self._store = store
        self._lock: BucketLock | None = None
        self._highest: str | None = None

    def _client(self) -> Any:
        if self._store is None:
            from app.services import object_store

            self._store = object_store.bounded_client(read_seconds=ANCHOR_SECONDS, retries=0)
        return self._store

    def _bucket_lock(self) -> BucketLock:
        if self._lock is not None:
            return self._lock
        from app.config import settings

        try:
            config = self._client().get_object_lock_config(settings.minio_bucket)
        except Exception as exc:  # noqa: BLE001 — sorted below: no lock, or the store is down
            code = getattr(exc, "code", "")
            if code in ("ObjectLockConfigurationNotFoundError", "InvalidRequest"):
                self._lock = BucketLock(enabled=False)
                return self._lock
            raise
        self._lock = BucketLock(
            enabled=True,
            mode=getattr(config, "mode", None),
            duration=getattr(config, "duration", None),
            unit=getattr(config, "duration_unit", None),
        )
        return self._lock

    def _read(self, name: str, version_id: str | None = None) -> AnchoredHead:
        from app.config import settings

        kwargs = {"version_id": version_id} if version_id else {}
        response = self._client().get_object(settings.minio_bucket, name, **kwargs)
        try:
            body = bytes(response.read())
        finally:
            response.close()
            response.release_conn()
        return AnchoredHead.read(json.loads(body.decode("utf-8")))

    def _listing(self, *, prefix: str = OBJECT_PREFIX, start_after: str | None = None) -> dict:
        """Every head object under ``prefix`` after ``start_after``, by name, with its versions."""
        from app.config import settings

        kwargs: dict[str, Any] = {"prefix": prefix, "recursive": True}
        if self._bucket_lock().enabled:
            kwargs["include_version"] = True
        if start_after:
            kwargs["start_after"] = start_after
        found: dict[str, list[Any]] = {}
        for item in self._client().list_objects(settings.minio_bucket, **kwargs):
            name = str(item.object_name)
            if name.startswith(OBJECT_PREFIX) and name.endswith(".json"):
                found.setdefault(name, []).append(item)
        return found

    @staticmethod
    def _hidden(versions: list[Any]) -> bool:
        """Whether the latest version under a name is a delete marker."""
        latest = [v for v in versions if getattr(v, "is_latest", False)]
        if not latest:
            latest = [max(versions, key=lambda v: getattr(v, "last_modified", None) or 0)]
        return bool(getattr(latest[0], "is_delete_marker", False))

    @staticmethod
    def _first(versions: list[Any]) -> str | None:
        """The version id of the first object written under a name; ``None`` unversioned."""
        live = [
            v
            for v in versions
            if getattr(v, "version_id", None) and not getattr(v, "is_delete_marker", False)
        ]
        if not live:
            return None
        return str(min(live, key=lambda v: v.last_modified).version_id)

    def _latest(self) -> AnchoredHead | None:
        cached = self._highest
        # Just below the highest name seen, so that name is listed again.
        start = _object_name(_seq_of(cached) - 1) if cached and _seq_of(cached) > 0 else None
        listing = self._listing(start_after=start)
        hidden = sorted(n for n, versions in listing.items() if self._hidden(versions))
        if hidden:
            raise AnchorTampered("a head the anchor kept is hidden behind a delete marker")
        live = sorted(listing)
        if cached is not None and (not live or live[-1] < cached):
            raise AnchorTampered("a head the anchor kept earlier is gone from it")
        if not live:
            return None
        name = live[-1]
        self._highest = name
        return self._read(name, self._first(listing[name]))

    def _held(self, name: str) -> AnchoredHead | None:
        versions = self._listing(prefix=name).get(name)
        if not versions:
            return None
        if self._hidden(versions):
            raise AnchorTampered("a head the anchor kept is hidden behind a delete marker")
        return self._read(name, self._first(versions))

    def _put(self, head: AnchoredHead) -> None:
        from app.config import settings
        from app.services import object_store

        store = self._client()
        object_store.ensure_bucket(store)
        name = _object_name(head.chain_seq)
        held = self._held(name)
        if held is not None:
            if held.chain != head.chain:
                raise AnchorConflict("the anchor holds another head at this seq")
            return
        lock = self._bucket_lock()
        record = dict(head.record(), anchored_at=datetime.now(UTC).isoformat())
        blob = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        store.put_object(
            settings.minio_bucket,
            name,
            io.BytesIO(blob),
            length=len(blob),
            content_type="application/json",
            # A lock with no default retention keeps nothing by itself: the
            # head is held until someone with the right lifts the hold.
            legal_hold=lock.enabled and lock.mode is None,
        )
        if self._highest is None or name > self._highest:
            self._highest = name

    async def latest(self) -> AnchoredHead | None:
        return await asyncio.to_thread(self._latest)

    async def put(self, head: AnchoredHead) -> None:
        await asyncio.to_thread(self._put, head)

    async def protection(self) -> str:
        return bucket_lock_sentence(await asyncio.to_thread(self._bucket_lock))


# ---------------------------------------------------------------------------
# The configured anchor
# ---------------------------------------------------------------------------


def configured_kind(s: Any = None) -> str:
    """The anchor kind the bootstrap settings name; an empty value is resolved, never guessed."""
    if s is None:
        from app.config import settings as s
    raw = str(getattr(s, "audit_anchor", "") or "").strip().lower()
    if raw:
        return raw
    return DATABASE if str(getattr(s, "audit_anchor_database_url", "") or "").strip() else NONE


def bootstrap_findings(s: Any) -> tuple[list[str], list[str]]:
    """The startup problems and warnings of the anchor settings; never a value of theirs."""
    problems: list[str] = []
    warnings: list[str] = []
    kind = configured_kind(s)
    url = str(getattr(s, "audit_anchor_database_url", "") or "").strip()
    if kind not in KINDS:
        problems.append(f"AUDIT_ANCHOR must be one of {', '.join(KINDS)}, or empty")
    elif kind == DATABASE and not url:
        problems.append("AUDIT_ANCHOR is database but AUDIT_ANCHOR_DATABASE_URL is not set")
    elif kind == DATABASE and _role_of(url) == _role_of(str(getattr(s, "database_url", ""))):
        warnings.append(
            "AUDIT_ANCHOR_DATABASE_URL connects as the application's own database role: the "
            "anchor then guards nothing a writer with the application's credentials cannot "
            "change. Give it a role that may only INSERT and SELECT audit_chain_anchor."
        )
    return problems, warnings


_ANCHOR: ChainAnchor | None = None
_ANCHOR_FOR: tuple[str, str] | None = None


def configured() -> ChainAnchor | None:
    """The anchor the bootstrap settings name, built once per process; ``None`` for none."""
    global _ANCHOR, _ANCHOR_FOR
    from app.config import settings

    kind = configured_kind(settings)
    url = str(settings.audit_anchor_database_url or "").strip()
    if _ANCHOR_FOR == (kind, url):
        return _ANCHOR
    anchor: ChainAnchor | None
    if kind == DATABASE and url:
        anchor = DatabaseAnchor(url)
    elif kind == OBJECT_STORE:
        anchor = ObjectStoreAnchor()
    else:
        anchor = None
    _ANCHOR, _ANCHOR_FOR = anchor, (kind, url)
    return anchor


def reset() -> None:
    """Forget the anchor built for this process (tests, and a changed environment)."""
    global _ANCHOR, _ANCHOR_FOR
    _ANCHOR, _ANCHOR_FOR = None, None


# ---------------------------------------------------------------------------
# Anchoring the committed head
# ---------------------------------------------------------------------------

ANCHORED = "anchored"
CURRENT = "current"
NOTHING = "nothing"
REFUSED = "refused"
FAILED = "failed"


async def _db_head(db: Any) -> Any:
    from sqlalchemy import select

    from app.models.audit import AuditChainHead
    from app.services import audit_chain

    heads = AuditChainHead.__table__
    return (
        (await db.execute(select(heads).where(heads.c.name == audit_chain.HEAD_NAME)))
        .mappings()
        .first()
    )


async def _chain_at(db: Any, seq: int) -> str | None:
    from sqlalchemy import select

    from app.models.audit import AuditLog

    log = AuditLog.__table__
    value = (await db.execute(select(log.c.chain).where(log.c.chain_seq == int(seq)))).scalar()
    return str(value) if value is not None else None


def _mac_holds(head: Any, keys: Mapping[str, Any]) -> bool | None:
    """Whether the head's MAC verifies under the key it names; ``None`` without that key."""
    from app.services import audit_chain

    key = keys.get(_get(head, "key_id") or "")
    if key is None:
        return None
    return bool(
        audit_chain.head_mac(
            int(_get(head, "chain_seq")),
            str(_get(head, "chain")),
            _get(head, "rotated_at_seq"),
            key,
        )
        == _get(head, "mac")
    )


def _get(row: Any, name: str) -> Any:
    return row.get(name) if isinstance(row, Mapping) else getattr(row, name, None)


async def _refusal(db: Any, last: AnchoredHead | None, head: Any, candidate: Any) -> str | None:
    """Why ``candidate`` may not be anchored over ``last``, or ``None`` when it may."""
    from app.services import ledger_chain

    if _mac_holds(candidate, ledger_chain.known_keys()) is not True:
        return "the head does not verify under a key the platform holds"
    seq = int(_get(candidate, "chain_seq"))
    if int(head["chain_seq"]) < seq:
        return "the database's audit head is behind the head to anchor"
    if await _chain_at(db, seq) != str(_get(candidate, "chain")):
        return "the chained row the head names is missing or differs from it"
    if last is not None:
        if int(head["chain_seq"]) < last.chain_seq:
            return "the database's audit head is behind the head anchored outside it"
        if await _chain_at(db, last.chain_seq) != last.chain:
            return "the chained row the anchored head names is missing or differs from it"
    return None


def _failed(anchor: ChainAnchor, why: str) -> None:
    observability.counters.audit_anchor_failures += 1
    logger.error("The audit head was not anchored (%s): %s.", anchor.kind, why)


async def anchor_committed_head(
    db: Any, anchor: ChainAnchor | None = None, expected: Any = None
) -> str:
    """Anchor a committed head through ``db``; what happened, as one of the outcomes above.

    ``db`` reads the platform's database (an ``AsyncConnection`` or session).
    ``expected`` is the head the append computed, the value anchored; without
    it the head ``db`` reads is. The anchor is read first, then the database.
    The value is anchored only when its MAC verifies under a key the platform
    holds, the database's head is not behind it, the chain holds its value at
    its seq, and the database agrees with the latest anchored head (not behind
    it, the same chain value at its seq). Anything else is refused and logged;
    a store that fails is logged and counted. Never raises but on cancellation.
    """
    anchor = anchor if anchor is not None else configured()
    if anchor is None:
        return NOTHING
    try:
        async with asyncio.timeout(ANCHOR_SECONDS):
            last = await anchor.latest()
            head = await _db_head(db)
            if head is None:
                return NOTHING
            candidate = expected if expected is not None else head
            refusal = await _refusal(db, last, head, candidate)
            if refusal is not None:
                _failed(anchor, refusal)
                return REFUSED
            if last is not None and int(_get(candidate, "chain_seq")) <= last.chain_seq:
                return CURRENT
            await anchor.put(AnchoredHead.read(candidate))
            return ANCHORED
    except (AnchorConflict, AnchorTampered) as exc:
        _failed(anchor, str(exc))
        return REFUSED
    except Exception as exc:  # noqa: BLE001 — the anchor is best effort, but never silent
        _failed(anchor, f"the anchor failed ({type(exc).__name__})")
        return FAILED


# The anchor writes scheduled and not yet finished; held so a task is not
# collected mid-write, and so a test or a shutdown can wait (:func:`drain`).
_PENDING: set[asyncio.Task[Any]] = set()
_HOOKED = "audit_anchor_after_commit"
_HEAD = "audit_anchor_head"


async def _anchor_through(engine: Any, expected: Any = None, *, only_if_empty: bool = False) -> str:
    try:
        if only_if_empty:
            anchor = configured()
            if anchor is None or await anchor.latest() is not None:
                return NOTHING
        async with engine.connect() as conn:
            return await anchor_committed_head(conn, expected=expected)
    except asyncio.CancelledError:
        observability.counters.audit_anchor_failures += 1
        logger.error("The audit head was not anchored: the anchor write was cancelled.")
        raise
    except Exception as exc:  # noqa: BLE001 — the connection or the anchor itself failed
        observability.counters.audit_anchor_failures += 1
        logger.error(
            "The audit head was not anchored: the database or the anchor could not be read (%s).",
            type(exc).__name__,
        )
        return FAILED


def _schedule(work: Any) -> asyncio.Task[Any]:
    task = asyncio.get_running_loop().create_task(work)
    _PENDING.add(task)
    task.add_done_callback(_PENDING.discard)
    return task


def anchor_after_commit(db: Any, head: Any = None) -> None:
    """Anchor ``head`` once ``db``'s transaction commits; nothing without an anchor.

    Called by every chained append with the head it computed. The session
    keeps the highest such head of its open transaction; a rollback, a
    savepoint's included, forgets it, and a commit runs the anchor write in a
    task of its own through the session's engine (:func:`anchor_committed_head`),
    so the caller never waits on the anchor and a store that is down never
    fails the job. A head with no key id (a platform without a settings key)
    is not anchored and nothing is said: no head under no key could verify.
    """
    if configured() is None:
        return
    if isinstance(head, Mapping) and not _get(head, "key_id"):
        return
    sync = getattr(db, "sync_session", None)
    engine = getattr(db, "bind", None)
    if sync is None or engine is None or not hasattr(engine, "connect"):
        return
    held = sync.info.get(_HEAD)
    if head is None:
        head = held if held is not None else True
    elif isinstance(held, Mapping) and int(_get(held, "chain_seq")) > int(_get(head, "chain_seq")):
        head = held
    sync.info[_HEAD] = head
    if sync.info.get(_HOOKED):
        return
    from sqlalchemy import event

    sync.info[_HOOKED] = True

    def _after_commit(session: Any) -> None:
        pending = session.info.pop(_HEAD, None)
        if pending is None:
            return
        try:
            _schedule(_anchor_through(engine, pending if pending is not True else None))
        except RuntimeError:
            observability.counters.audit_anchor_failures += 1
            logger.error("The audit head was not anchored: no event loop after the commit.")

    def _after_rollback(session: Any) -> None:
        # Fires for a rolled-back savepoint as for the whole transaction: the
        # savepoint may have held the append, so its head is forgotten rather
        # than anchored, and the next append catches the anchor up.
        if session.info.pop(_HEAD, None) is not None:
            logger.debug("A rollback dropped the audit head waiting to be anchored.")

    event.listen(sync, "after_commit", _after_commit)
    event.listen(sync, "after_rollback", _after_rollback)


def start_anchoring(engine: Any) -> None:
    """Give an empty anchor the current head, in a task of its own; called at startup.

    After it, an anchor found empty beside a head makes a verification
    ``unverifiable``. Nothing without an anchor or outside an event loop.
    """
    if configured() is None:
        return
    try:
        _schedule(_anchor_through(engine, only_if_empty=True))
    except RuntimeError:
        logger.error("The audit head was not anchored at startup: no event loop.")


async def drain(timeout: float = ANCHOR_SECONDS) -> None:
    """Wait up to ``timeout`` seconds for the anchor writes already scheduled."""
    if _PENDING:
        await asyncio.wait(list(_PENDING), timeout=timeout)


# ---------------------------------------------------------------------------
# Verification against the anchor
# ---------------------------------------------------------------------------

MATCHES = "matches"
LAGS = "lags"
EMPTY = "empty"
UNREADABLE = "unreadable"
UNVERIFIABLE = "unverifiable"
BROKEN = "broken"

BEHIND = (
    "the database's audit head is behind the head anchored outside the database: chained rows "
    "were cut off and an earlier head put back"
)
MISSING = "the chained row the anchored head names is missing from the database"
EMPTY_BESIDE_A_HEAD = (
    "The audit chain's anchor outside the database holds no head although the chain has one: "
    "the chain could be checked against the database head only."
)
UNKNOWN_KEY = (
    "The head anchored outside the database is under a key the platform's settings cannot "
    "derive: it can be neither verified nor compared."
)


@dataclass
class AnchorVerdict:
    """What comparing the audit chain with the head anchored outside the database found.

    ``broken`` is set only when the chain contradicts the anchor;
    ``unverifiable`` when an anchor is configured and the chain could not be
    held to it (unreadable, empty beside a head, an anchored head under an
    unknown key). ``state`` is one of ``none``, ``empty``, ``matches``,
    ``lags``, ``unreadable``, ``unverifiable`` and ``broken``. A job's answer
    carries the kind and the state only; ``protection``, ``anchored_seq`` and
    ``head_seq`` are for the operator.
    """

    kind: str
    state: str
    protection: str | None = None
    broken: str | None = None
    unverifiable: str | None = None
    anchored_seq: int | None = None
    head_seq: int | None = None
    checks: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self, *, full: bool = False, positions: bool = False) -> dict[str, Any]:
        body: dict[str, Any] = {"kind": self.kind, "state": self.state}
        if full:
            body["protection"] = self.protection
        if positions:
            body["anchored_seq"] = self.anchored_seq
            body["head_seq"] = self.head_seq
        return body

    def operator_notes(self) -> list[str]:
        """The notes, with what protects the anchor first: the operator's text."""
        said = [f"Audit chain anchor ({self.kind}): {self.protection}"] if self.protection else []
        return said + list(self.notes)


def compare(
    kind: str,
    anchored: AnchoredHead | None,
    head: Any,
    chain_at_anchored: str | None,
    keys: Mapping[str, Any],
    *,
    protection: str | None = None,
) -> AnchorVerdict:
    """Compare the database's chain and head with the latest anchored head.

    ``head`` is the database's head record (``None`` when it has none) and
    ``chain_at_anchored`` the chain value the database stores at the anchored
    head's seq (``None`` when no row is there). Reasons never name a seq.
    """
    verdict = AnchorVerdict(kind=kind, state=MATCHES, protection=protection)
    if anchored is None:
        verdict.state = EMPTY
        if head is not None:
            verdict.unverifiable = EMPTY_BESIDE_A_HEAD
            verdict.notes.append(EMPTY_BESIDE_A_HEAD)
        return verdict
    verdict.anchored_seq = anchored.chain_seq
    head_seq = int(_get(head, "chain_seq")) if head is not None else 0
    verdict.head_seq = head_seq if head is not None else None

    def _broken(reason: str) -> AnchorVerdict:
        verdict.state = BROKEN
        verdict.broken = reason
        return verdict

    holds = _mac_holds(anchored, keys)
    if holds is None:
        verdict.state = UNVERIFIABLE
        verdict.unverifiable = UNKNOWN_KEY
        verdict.notes.append(UNKNOWN_KEY)
        return verdict
    if holds is False:
        return _broken("the head anchored outside the database does not verify under its key")
    if head_seq < anchored.chain_seq:
        return _broken(BEHIND)
    if chain_at_anchored is None:
        return _broken(MISSING)
    if chain_at_anchored != anchored.chain:
        return _broken(
            "the chained row the anchored head names differs from it: the chain was rewritten"
        )
    verdict.checks.append(f"the audit chain holds the head anchored outside the database ({kind})")
    if head_seq > anchored.chain_seq:
        verdict.state = LAGS
        verdict.notes.append(
            "The audit chain's newest rows lie past the last head anchored outside the database "
            "(an anchor write has not landed yet): they are checked against the database head "
            "only."
        )
    return verdict


@dataclass
class AnchorReading:
    """The anchor as read once: its latest head and protection, or why it could not be read."""

    kind: str
    anchored: AnchoredHead | None = None
    protection: str | None = None
    error: str | None = None
    tampered: str | None = None


async def read(anchor: ChainAnchor) -> AnchorReading:
    """Read ``anchor``'s latest head and what protects it, bounded; never raises."""
    try:
        async with asyncio.timeout(ANCHOR_SECONDS):
            anchored = await anchor.latest()
            try:
                protection: str | None = await anchor.protection()
            except Exception as exc:  # noqa: BLE001 — stated, the comparison still runs
                protection = f"what protects the anchor could not be read ({type(exc).__name__})"
    except AnchorTampered as exc:
        return AnchorReading(kind=anchor.kind, tampered=str(exc))
    except Exception as exc:  # noqa: BLE001 — stated; the database checks still stand
        logger.warning(
            "The audit chain's anchor (%s) could not be read: %s",
            anchor.kind,
            log_safe(type(exc).__name__),
        )
        return AnchorReading(kind=anchor.kind, error=type(exc).__name__)
    return AnchorReading(kind=anchor.kind, anchored=anchored, protection=protection)


def _fresh_engine(db: Any) -> Any:
    """The engine ``db`` was opened on, for a read outside its snapshot; ``None`` if unknown."""
    for name in ("bind", "engine"):
        engine = getattr(db, name, None)
        if engine is not None and hasattr(engine, "connect"):
            return engine
    return None


async def verification(
    db: Any,
    head: Any,
    anchor: ChainAnchor | None = None,
    *,
    reading: AnchorReading | None = None,
    operator: bool = False,
) -> AnchorVerdict:
    """Compare ``db``'s audit chain with the configured anchor; never raises.

    ``head`` is the database's head record as already read, and ``reading``
    the anchor as read before it, where the caller could read it first (so a
    head anchored after the database was read is not taken for a cut chain).
    Without an anchor the verdict says so in a note (:data:`NOT_CONFIGURED`).
    An anchor that cannot be read is ``unverifiable``, stated. A database head
    behind the anchored one, or the anchored row missing, is read again on a
    connection of its own outside ``db``'s snapshot, and is a break only when
    that read still says so.
    """
    from app.services import ledger_chain

    anchor = anchor if anchor is not None else configured()
    if anchor is None:
        return AnchorVerdict(kind=NONE, state=NONE, notes=[NOT_CONFIGURED])
    reading = reading if reading is not None else await read(anchor)
    if reading.tampered is not None:
        return AnchorVerdict(
            kind=anchor.kind,
            state=BROKEN,
            protection=reading.protection,
            broken=reading.tampered,
        )
    if reading.error is not None:
        # The error's class goes to the log (``read``) and to the operator,
        # never into a job's answer.
        why = f" ({reading.error})" if operator else ""
        said = (
            f"The audit chain's anchor outside the database ({anchor.kind}) could not be "
            f"read{why}: the chain could be checked against the database head "
            "only, which a writer holding an earlier head record can put back."
        )
        return AnchorVerdict(kind=anchor.kind, state=UNREADABLE, unverifiable=said, notes=[said])
    anchored = reading.anchored
    keys = ledger_chain.known_keys()
    chain_at = await _chain_at(db, anchored.chain_seq) if anchored is not None else None
    verdict = compare(anchor.kind, anchored, head, chain_at, keys, protection=reading.protection)
    engine = _fresh_engine(db)
    if anchored is not None and verdict.broken in (BEHIND, MISSING) and engine is not None:
        try:
            async with engine.connect() as fresh:
                again = await _db_head(fresh)
                chain_again = await _chain_at(fresh, anchored.chain_seq)
        except Exception as exc:  # noqa: BLE001 — the first read stands, and is said
            logger.warning(
                "The audit chain could not be read again for its anchor: %s",
                log_safe(type(exc).__name__),
            )
            return verdict
        verdict = compare(
            anchor.kind, anchored, again, chain_again, keys, protection=reading.protection
        )
    return verdict
