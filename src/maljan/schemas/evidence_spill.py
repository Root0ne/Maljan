"""Where an answer the ledger does not keep whole is kept whole.

A ledger entry keeps what the model was handed, and the run can take more
away afterwards: the tool-output guardrail shortens, summarises or cuts an
answer before the model reads it, the per-agent byte budget blanks a stored
output and its structure, and the structure eviction drops a structure the
server returned beside a prose answer. Each of those decisions stays exactly
as it is. What this module adds is a copy of what was lost: the bytes are
handed to a store the job owns, and the entry gains a reference to them
(``LedgerEntry.spilled``) — the part that was lost, the object key, the byte
length and the SHA-256 of the bytes.

The store is the caller's: the analysis worker hands the job's container a
sink that writes into object storage, and a run without one (the CLI, the
rehearsal, a test) spills nothing and its entries carry no reference. An
upload that fails is stated on the reference with its reason and the run goes
on. The size of one kept part is bounded only by the operator setting the
caller names (the API bounds it by ``upload_max_bytes``, the sample upload
limit); a part above it is referenced with that reason and not kept.

Nothing a model reads changes: the reference lives on the entry beside what
it already kept, and no prompt or tool result renders it.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, MutableMapping
from typing import Any

logger = logging.getLogger(__name__)

# The parts of an answer a reference can name, in the order the run loses them.
#
# ``answer``: the tool's answer before the output guardrail shortened,
# summarised or cut it, or before the conversation had no room for it.
# ``structured_content``: the structured answer the tool's server returned
# beside its text, which the entry does not keep.
# ``output``: the stored output the byte budget blanked.
# ``structured``: the stored structure the byte budget blanked or the
# structure eviction dropped.
ANSWER = "answer"
STRUCTURED_CONTENT = "structured_content"
OUTPUT = "output"
STRUCTURED = "structured"
PARTS = (ANSWER, STRUCTURED_CONTENT, OUTPUT, STRUCTURED)

TEXT = "text/plain; charset=utf-8"
JSON = "application/json"

# What a part is written as, so a reader of the object knows how to open it.
CONTENT_TYPES = {ANSWER: TEXT, STRUCTURED_CONTENT: JSON, OUTPUT: TEXT, STRUCTURED: JSON}


class EvidenceSpill:
    """A job's store for whole answers: ``put(sha256, blob, content_type)`` returns the key.

    One per job, shared by every recorder of the job's agents. Copying it
    returns the same object, so an entry copied with its private attributes
    never copies a storage client.
    """

    def __init__(
        self,
        put: Callable[[str, bytes, str], str],
        *,
        max_bytes: int = 0,
        bound_by: str = "",
    ) -> None:
        self._put = put
        # The largest object one part may be kept as, read by the caller from
        # an operator setting it names (``bound_by``); 0 when the caller bounds
        # nothing. A part above it is referenced with the reason and not kept.
        self.max_bytes = max(0, int(max_bytes or 0))
        self.bound_by = bound_by

    def put(self, sha256: str, blob: bytes, content_type: str) -> str:
        return str(self._put(sha256, blob, content_type))

    def __copy__(self) -> EvidenceSpill:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> EvidenceSpill:
        return self


def part_bytes(part: str, value: Any) -> bytes:
    """``value`` as the bytes a part is kept as: text as UTF-8, a structure as its JSON."""
    if CONTENT_TYPES.get(part) == JSON:
        return json.dumps(value, ensure_ascii=False).encode("utf-8")
    return str(value).encode("utf-8", errors="surrogatepass")


def spill_part(
    sink: EvidenceSpill, part: str, value: Any, held: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    """Keep ``value`` whole in ``sink`` and return its reference; never raises.

    ``held`` is the entry's references so far: bytes already kept under one of
    them are referenced again rather than uploaded twice. A failed upload is
    returned as a reference with no key and a fixed reason naming only the
    failure's class (``upload_failed (<class>)``): the failure's own text can
    name the store's host or its credentials, and a reference is served. A
    part larger than the sink's bound is referenced with the reason
    (``exceeds <setting> (<n> bytes)``) and not uploaded.
    """
    try:
        blob = part_bytes(part, value)
    except (TypeError, ValueError) as exc:
        return {"part": part, "error": f"not_serialisable ({type(exc).__name__})"}
    digest = hashlib.sha256(blob).hexdigest()
    ref: dict[str, Any] = {"part": part, "bytes": len(blob), "sha256": digest}
    for earlier in held or ():
        if earlier.get("sha256") == digest and earlier.get("key"):
            return {**ref, "key": earlier["key"]}
    bound = getattr(sink, "max_bytes", 0)
    if bound and len(blob) > bound:
        ref["error"] = f"exceeds {getattr(sink, 'bound_by', '') or 'the bound'} ({bound} bytes)"
        return ref
    try:
        ref["key"] = sink.put(digest, blob, CONTENT_TYPES.get(part, TEXT))
    except Exception as exc:  # noqa: BLE001 — a failed upload is stated, never fatal
        ref["error"] = f"upload_failed ({type(exc).__name__})"
        logger.warning("evidence: the %s part was not kept (%s)", part, type(exc).__name__)
    return ref


def add_ref(held: list[dict[str, Any]] | None, ref: dict[str, Any]) -> list[dict[str, Any]]:
    """``held`` with ``ref`` added, unless a reference to the same part is already there."""
    refs = list(held or [])
    if any(earlier.get("part") == ref.get("part") for earlier in refs):
        return refs
    refs.append(ref)
    return refs


def spill_into(entry: Any, sink: EvidenceSpill | None, part: str, value: Any) -> None:
    """Keep ``value`` for ``entry`` (an entry or its dump) under ``part``; no-op without a sink.

    Nothing is kept for an empty value or for a part the entry already
    references.
    """
    if sink is None or value is None or value == "":
        return
    held = entry.get("spilled") if isinstance(entry, MutableMapping) else entry.spilled
    if any(earlier.get("part") == part for earlier in held or ()):
        return
    refs = add_ref(held, spill_part(sink, part, value, held))
    if isinstance(entry, MutableMapping):
        entry["spilled"] = refs
    else:
        entry.spilled = refs


__all__ = [
    "ANSWER",
    "CONTENT_TYPES",
    "OUTPUT",
    "PARTS",
    "STRUCTURED",
    "STRUCTURED_CONTENT",
    "EvidenceSpill",
    "add_ref",
    "part_bytes",
    "spill_into",
    "spill_part",
]
