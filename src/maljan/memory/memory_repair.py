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
from typing import Any

from maljan.core.logger import logger

# Where the marker of a finished repair is kept, and which repair it is.
REPAIR_COLLECTION = "maljan_memory_repairs"
REPAIR_ID = "aud65-labels-and-hash-order-v1"
# The scroll page the stores already read with.
_PAGE = 256

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
