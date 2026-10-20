"""The one-time repair of long-term memory written before AUD-65.

Two kinds of entry a store kept before that change cannot be read as they are:

- **Case vectors with no backend label.** A case point stored before the
  backend was recorded may hold a bag-of-words vector beside the model's, and
  a search ranks it by that vector. The repair embeds each such point's text
  again with the model, in batches, and labels it.
- **Function hashes filed name-first, and ungated.** The corpus writer handed
  the index the provider's ``(func_name, func_hash)`` pairs where it reads
  ``(func_hash, func_name)``, so every point it wrote holds the name where the
  hash belongs and no later sample could match it; and it filed them under
  the judge's family beside any verdict. Every such point lacks the
  ``family_key`` this change records, and the corpus has no other writer: the
  repair deletes them. Nothing is lost (they never matched), and nothing
  filed before the Malware and published-family gate is re-filed.

One pass over each collection, a page at a time. It runs once per store: a
marker point in a small collection of its own (``REPAIR_COLLECTION``) records
it, and a later start finds the marker and skips. Without the embedding model
nothing is repaired and no marker is written, so the next start tries again.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from maljan.core.logger import logger

# Where the marker of a finished repair is kept, and which repair it is.
REPAIR_COLLECTION = "maljan_memory_repairs"
REPAIR_ID = "aud65-labels-and-hash-order-v1"
# The scroll page the stores already read with.
_PAGE = 256
# Marks a point adoption filed under its owner: not the owner's own copy of a sample, so a
# rerun after a failure keeps adopting that sample. A later store by the owner
# writes a payload without it.
ADOPTED_KEY = "adopted"

SKIPPED_NO_MODEL = "skipped: the embedding model is not available"
ALREADY_DONE = "already repaired"


def _marker_id(*names: str) -> int:
    digest = hashlib.sha256("|".join((REPAIR_ID, *names)).encode()).digest()
    return int.from_bytes(digest[:8], "little")


def _collections(client: Any) -> set[str]:
    return {c.name for c in client.get_collections().collections}


def _pages(client: Any, collection: str) -> Any:
    """Every point of ``collection``, one page at a time, with its payload and no vector."""
    offset: Any = None
    while True:
        points, offset = client.scroll(
            collection_name=collection,
            limit=_PAGE,
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )
        if points:
            yield points
        if offset is None:
            return


def _still_unlabelled(client: Any, collection: str, ids: list[Any]) -> list[Any]:
    """Those of ``ids`` that still exist and still carry no backend label."""
    from maljan.memory.qdrant_store import BACKEND_KEY

    found = client.retrieve(
        collection_name=collection, ids=ids, with_payload=True, with_vectors=False
    )
    return [pt.id for pt in found if not (pt.payload or {}).get(BACKEND_KEY)]


def _relabel_cases(client: Any, collection: str) -> int | None:
    """Embed every unlabelled case point's text again and label it; ``None`` without the model.

    Only the vector and the label are written, and only to points that are
    still unlabelled when they are written: a case stored again meanwhile
    keeps its own vector, and one purged meanwhile is not brought back.
    """
    from qdrant_client.models import (
        Filter,
        HasIdCondition,
        IsEmptyCondition,
        PayloadField,
        PointVectors,
    )

    from maljan.memory.embeddings import encode_batch_with_backend, model_backend_id
    from maljan.memory.qdrant_store import BACKEND_KEY

    model = model_backend_id()
    repaired = 0
    for page in _pages(client, collection):
        unlabelled = [pt for pt in page if not (pt.payload or {}).get(BACKEND_KEY)]
        if not unlabelled:
            continue
        texts = [str((pt.payload or {}).get("summary_text") or "") for pt in unlabelled]
        vectors, backend = encode_batch_with_backend(texts)
        if backend != model:
            return None
        still = set(_still_unlabelled(client, collection, [pt.id for pt in unlabelled]))
        if not still:
            continue
        client.update_vectors(
            collection_name=collection,
            points=[
                PointVectors(id=pt.id, vector=vec)
                for pt, vec in zip(unlabelled, vectors, strict=True)
                if pt.id in still
            ],
            wait=True,
        )
        client.set_payload(
            collection_name=collection,
            payload={BACKEND_KEY: model},
            points=Filter(
                must=[
                    HasIdCondition(has_id=list(still)),
                    IsEmptyCondition(is_empty=PayloadField(key=BACKEND_KEY)),
                ]
            ),
            wait=True,
        )
        repaired += len(still)
    return repaired


def _drop_ungated_function_hashes(client: Any, collection: str) -> int:
    """Delete every function-hash point filed before the gate (no ``family_key``); how many.

    They were filed name-first under whatever family the judge wrote beside
    any verdict, so none of them ever matched a later sample and none of them
    passed the Malware and published-family gate: deleted, never re-filed.
    A point filed since keeps its ``family_key`` and is not touched.
    """
    from qdrant_client.models import PointIdsList

    deleted = 0
    for page in _pages(client, collection):
        stale = [pt.id for pt in page if not (pt.payload or {}).get("family_key")]
        if stale:
            client.delete(
                collection_name=collection, points_selector=PointIdsList(points=stale), wait=True
            )
            deleted += len(stale)
    return deleted


def repair_once(client: Any, cases: str, function_hashes: str | None) -> str:
    """Repair ``cases`` and ``function_hashes`` once, recording it; what was done, in words.

    Never raises: a repair that fails leaves no marker and is tried again at
    the next start.
    """
    try:
        from maljan.memory.embeddings import active_backend, model_backend_id

        if active_backend() != model_backend_id():
            return SKIPPED_NO_MODEL
        from qdrant_client.models import Distance, PointStruct, VectorParams

        marker = _marker_id(cases, function_hashes or "")
        existing = _collections(client)
        if REPAIR_COLLECTION in existing and client.retrieve(
            collection_name=REPAIR_COLLECTION, ids=[marker]
        ):
            return ALREADY_DONE
        relabelled = 0
        if cases in existing:
            done = _relabel_cases(client, cases)
            if done is None:
                return SKIPPED_NO_MODEL
            relabelled = done
        deleted = 0
        if function_hashes and function_hashes in existing:
            deleted = _drop_ungated_function_hashes(client, function_hashes)
        if REPAIR_COLLECTION not in existing:
            client.create_collection(
                collection_name=REPAIR_COLLECTION,
                vectors_config=VectorParams(size=1, distance=Distance.DOT),
            )
        client.upsert(
            collection_name=REPAIR_COLLECTION,
            points=[
                PointStruct(
                    id=marker,
                    vector=[1.0],
                    payload={
                        "repair": REPAIR_ID,
                        "cases": cases,
                        "function_hashes": function_hashes,
                    },
                )
            ],
            wait=True,
        )
    except Exception as exc:  # noqa: BLE001 — a repair never costs a start
        logger.warning("Long-term memory repair failed (%s); tried again at the next start.", exc)
        return f"failed: {type(exc).__name__}"
    said = (
        f"repaired: {relabelled} case vector(s) labelled, {deleted} function hash(es) "
        "filed before the gate deleted"
    )
    logger.info("Long-term memory %s.", said)
    return said


def repair_memory(store: Any) -> str:
    """The one-time repair of ``store``, for a backend that has one; what was done."""
    repair = getattr(store, "repair_once", None)
    if not callable(repair):
        return "nothing to repair: the backend keeps nothing durable"
    return str(repair())


def _ownerless_pages(client: Any, collection: str) -> Any:
    """Every ownerless point of ``collection`` with payload and vector, a page at a time."""
    from qdrant_client.models import Filter, IsEmptyCondition, PayloadField

    from maljan.memory.qdrant_store import OWNER_KEY

    ownerless = Filter(must=[IsEmptyCondition(is_empty=PayloadField(key=OWNER_KEY))])
    offset: Any = None
    while True:
        points, offset = client.scroll(
            collection_name=collection,
            scroll_filter=ownerless,
            limit=_PAGE,
            offset=offset,
            with_payload=True,
            with_vectors=True,
        )
        if points:
            yield points
        if offset is None:
            return


class AdoptionFailed(Exception):  # noqa: N818 - carries the partial counts of a failed run
    """An adoption that stopped part way: ``counts`` is what it had done, the cause is chained."""

    def __init__(self, counts: dict[str, int]) -> None:
        super().__init__("adoption stopped part way")
        self.counts = dict(counts)


def _created_at(payload: dict[str, Any] | None) -> datetime:
    """A point's ``created_at``; a point with none (or an unreadable one) counts as oldest."""
    oldest = datetime.min.replace(tzinfo=UTC)
    raw = (payload or {}).get("created_at")
    if not isinstance(raw, str):
        return oldest
    try:
        when = datetime.fromisoformat(raw)
    except ValueError:
        return oldest
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _adopt_cases(
    client: Any, collection: str, owner: str, counts: dict[str, int], replaced: set[str]
) -> None:
    """Re-file every ownerless case under ``owner``, keeping the newer copy of a shared sample.

    A case is keyed by its owner (``qdrant_store._case_id``), so setting the
    label alone would leave two points for one sample once the owner stores it
    again. An ownerless case is written under the owner's id with its vector
    and the owner in its payload, then its old id deleted. When the owner
    already holds the sample, the copy with the later ``created_at`` is kept
    (the owner's on a tie; a point with none is older): the ownerless one is
    only deleted, or, when it is newer, replaces the owner's point and its
    sample is recorded in ``replaced``. The owner's point is read again right
    before the write, so one filed meanwhile is never overwritten by an older
    copy. A case with no ``sample_id`` cannot be keyed and is left as it is
    (counted as skipped). The owned point is written before the old one is
    deleted, so a failure leaves a duplicate, never a loss.
    """
    from qdrant_client.models import PointIdsList, PointStruct

    from maljan.memory.qdrant_store import OWNER_KEY, _case_id

    for page in _ownerless_pages(client, collection):
        keyed = [pt for pt in page if (pt.payload or {}).get("sample_id")]
        counts["skipped_cases"] += len(page) - len(keyed)
        if not keyed:
            continue
        new_ids = {pt.id: _case_id(str((pt.payload or {})["sample_id"]), owner) for pt in keyed}
        # Read right before the writes below.
        held = {
            pt.id: pt.payload
            for pt in client.retrieve(
                collection_name=collection,
                ids=list(set(new_ids.values())),
                with_payload=True,
                with_vectors=False,
            )
        }
        write, drop = [], []
        for pt in keyed:
            owned = held.get(new_ids[pt.id])
            if owned is not None and _created_at(pt.payload) <= _created_at(owned):
                drop.append(pt)
                continue
            write.append(pt)
            if owned is not None:
                replaced.add(str((pt.payload or {})["sample_id"]))
        if write:
            client.upsert(
                collection_name=collection,
                points=[
                    PointStruct(
                        id=new_ids[pt.id],
                        vector=pt.vector,
                        payload={**(pt.payload or {}), OWNER_KEY: owner, ADOPTED_KEY: True},
                    )
                    for pt in write
                ],
                wait=True,
            )
        client.delete(
            collection_name=collection,
            points_selector=PointIdsList(points=[pt.id for pt in keyed]),
            wait=True,
        )
        counts["cases"] += len(write)
        counts["dropped_cases"] += len(drop)


def _owner_holds_sample(owner: str, sample_id: str) -> Any:
    """The filter naming ``owner``'s own points of ``sample_id`` (adopted ones excluded)."""
    from qdrant_client.models import FieldCondition, Filter, MatchValue

    from maljan.memory.qdrant_store import OWNER_KEY

    return Filter(
        must=[
            FieldCondition(key=OWNER_KEY, match=MatchValue(value=owner)),
            FieldCondition(key="sample_id", match=MatchValue(value=sample_id)),
        ],
        # Points this adoption filed are not the owner's own copy.
        must_not=[FieldCondition(key=ADOPTED_KEY, match=MatchValue(value=True))],
    )


def _adopt_hashes(
    client: Any, collection: str, owner: str, counts: dict[str, int], replaced: set[str]
) -> None:
    """Re-file every ownerless function hash under ``owner``, deciding per sample.

    A sample's hashes are kept from one side only, so it never straddles two
    families. If the owner holds any hash point for the sample, every
    ownerless point of it is deleted, unless the ownerless case of that sample
    was newer and replaced the owner's (``replaced``): then the owner's stale
    hash points of the sample are removed and the ownerless ones adopted. A
    point with no ``sample_id`` or ``func_hash`` is left as it is (skipped).
    """
    from qdrant_client.models import FilterSelector, PointIdsList, PointStruct

    from maljan.memory.function_hash_store import _point_id
    from maljan.memory.qdrant_store import OWNER_KEY

    verdict: dict[str, bool] = {}  # sample_id -> adopt its ownerless points
    for page in _ownerless_pages(client, collection):
        keyed = [
            pt
            for pt in page
            if (pt.payload or {}).get("sample_id") and (pt.payload or {}).get("func_hash")
        ]
        counts["skipped_function_hashes"] += len(page) - len(keyed)
        if not keyed:
            continue
        for pt in keyed:
            sid = str((pt.payload or {})["sample_id"])
            if sid in verdict:
                continue
            mine = _owner_holds_sample(owner, sid)
            held = client.count(collection_name=collection, count_filter=mine, exact=True).count
            if sid in replaced:
                if held:
                    client.delete(
                        collection_name=collection,
                        points_selector=FilterSelector(filter=mine),
                        wait=True,
                    )
                verdict[sid] = True
            else:
                verdict[sid] = not held
        adopt = [pt for pt in keyed if verdict[str((pt.payload or {})["sample_id"])]]
        ids = {
            pt.id: _point_id(
                str((pt.payload or {})["sample_id"]), str((pt.payload or {})["func_hash"]), owner
            )
            for pt in adopt
        }
        # Read right before the writes below: a point the owner filed meanwhile stands.
        have = (
            {
                pt.id
                for pt in client.retrieve(
                    collection_name=collection,
                    ids=list(set(ids.values())),
                    with_payload=False,
                    with_vectors=False,
                )
            }
            if adopt
            else set()
        )
        write = [pt for pt in adopt if ids[pt.id] not in have]
        if write:
            client.upsert(
                collection_name=collection,
                points=[
                    PointStruct(
                        id=ids[pt.id],
                        vector=pt.vector,
                        payload={**(pt.payload or {}), OWNER_KEY: owner, ADOPTED_KEY: True},
                    )
                    for pt in write
                ],
                wait=True,
            )
        client.delete(
            collection_name=collection,
            points_selector=PointIdsList(points=[pt.id for pt in keyed]),
            wait=True,
        )
        counts["function_hashes"] += len(write)
        counts["dropped_function_hashes"] += len(keyed) - len(write)


def adopt_unowned(
    client: Any, cases: str, function_hashes: str | None, owner: str
) -> dict[str, int]:
    """Adopt the memory written before owners existed under ``owner``; counts per kind.

    An explicit operator action (``POST /system/ltm/adopt``): nothing adopts
    it automatically. Run it while no job is running: a job storing for the
    owner meanwhile is read again before each write, but not locked out.
    Idempotent: a second run finds only what was skipped. ``cases`` and
    ``function_hashes`` count points re-filed under the owner, ``dropped_*``
    those deleted because the owner held a newer copy (or, for hashes, held the
    sample), ``skipped_*`` those left ownerless for want of a sample id. A
    failure raises :class:`AdoptionFailed` carrying the counts so far, with the
    cause chained.
    """
    if not owner:
        raise ValueError("an owner is required to adopt ownerless memory")
    counts = {
        "cases": 0,
        "function_hashes": 0,
        "dropped_cases": 0,
        "dropped_function_hashes": 0,
        "skipped_cases": 0,
        "skipped_function_hashes": 0,
    }
    replaced: set[str] = set()
    try:
        if cases in _collections(client):
            _adopt_cases(client, cases, owner, counts, replaced)
        if function_hashes and function_hashes in _collections(client):
            _adopt_hashes(client, function_hashes, owner, counts, replaced)
    except Exception as exc:
        raise AdoptionFailed(counts) from exc
    logger.info("Long-term memory adoption under one owner: %s.", counts)
    return counts
