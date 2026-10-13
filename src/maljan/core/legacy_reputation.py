"""LEGACY READERS: how reputation answers were read before one declared path read them.

LEGACY MODULE. Nothing new reads an answer here: a reputation answer is read
once, through its tool's declared paths, into the record of
``core.reputation`` when its entry is written, and every consumer reads that
record. Three things written before then are read here, and only they:

* a facts record stored on an entry while the built-in lookups declared the
  kinds ``file_reputation`` and ``hash_reputation`` (one kind, ``reputation``,
  since): those kinds still read as a reputation lookup;
* a report stored before reports carried the reputation records
  (``MalwareReport.reputation`` absent): its reputation line is read from the
  rows of the section its lookups were drawn in, as the Markdown renderer
  always read it, so a stored run re-renders byte for byte;
* a stored report whose network rows the network extractor seeded with a
  reputation permalink under the one lookup service's own key: post-verdict
  enrichment still keeps that key when it replaces the record
  (``enrichment.orchestrator``), as it always did.

The console keeps its own legacy reader for the same stored reports
(``apps/web/src/components/analysis/reputationLegacy.ts``).
"""

from __future__ import annotations

import re
from collections.abc import Mapping

# The kinds the built-in reputation lookups declared before ``reputation``.
STORED_REPUTATION_KINDS: tuple[str, ...] = ("file_reputation", "hash_reputation")

# The permalink key the network extractor seeded a stored row's reputation
# with, before a record's link was the neutral ``link`` field.
STORED_REPUTATION_LINK_KEYS: tuple[str, ...] = ("virustotal_url",)


def _first_match(pattern: str, text: str) -> str:
    match = re.search(pattern, text)
    return match.group(1) if match else ""


def stored_report_counts(rows: Mapping[str, str]) -> tuple[str, str, str]:
    """``(flagged, engines, source)`` of a stored report's reputation section rows.

    ``rows`` are the section's key/value rows, keys lowercased, first value
    of each kept. The engine counts are the section's own rows where the
    lookup was lifted into them, and otherwise the flattened answer the
    stored section carries (a VirusTotal file report's ``last_analysis_stats``
    and ``coverage``); the source is the answer's ``source`` field up to the
    word "via", or "Reputation lookup".
    """
    blob = " ".join(rows.values())
    flagged = rows.get("engines malicious") or _first_match(
        r"last_analysis_stats=malicious=(\d+)", blob
    )
    engines = rows.get("engines") or _first_match(r"engines=(\d+)", blob)
    source = rows.get("source", "").split(" via ")[0].strip() or "Reputation lookup"
    return flagged, engines, source
