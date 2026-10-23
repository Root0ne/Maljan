"""An answer's ``(claims begun, distinct claims)``, read from ``claim_headings.claim_blocks``.

Each claim is keyed by its block, as ``claim_blocks`` keys it. The module is read
by attribute so a test that patches ``claim_headings`` reads its patched rules.
"""

from __future__ import annotations

from maljan.agents import claim_headings


def begun_and_distinct(text: str) -> tuple[int, int]:
    blocks = claim_headings.claim_blocks(text)
    return len(blocks), len({key for _start, key in blocks})
