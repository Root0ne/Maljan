"""One counter every evaluation harness reports its population with.

A harness that skips a sample it cannot parse must say so: the artefact then
carries attempted / parsed / scored and the reasons, and ``paper_facts``
refuses an artefact whose denominator shrank without explanation.

The reason strings are not a closed set — a producer names its own drop
causes, one string per distinct cause, so two different reasons never get
collapsed into one label. Reasons in use across the evaluation harnesses as
of this writing: ``unparseable`` (an exception while parsing a sample),
``no_static`` (static analysis produced no result), ``no_isrs`` (no ISR
reports were collected at all, a distinct precondition from ``no_static``),
``no_profile_text`` (a rendered profile was empty), ``torn_line`` (a
checkpoint/JSONL line could not be decoded).
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class Tally:
    attempted: int = 0
    parsed: int = 0
    scored: int = 0
    dropped: Counter[str] = field(default_factory=Counter)

    def attempt(self) -> None:
        self.attempted += 1

    def parse_ok(self) -> None:
        self.parsed += 1

    def score_ok(self) -> None:
        self.scored += 1

    def drop(self, reason: str, *, detail: str | None = None) -> None:
        self.dropped[reason] += 1
        print(f"  drop [{reason}]{': ' + detail if detail else ''}", file=sys.stderr)

    def as_dict(self) -> dict[str, object]:
        return {
            "attempted": self.attempted,
            "parsed": self.parsed,
            "scored": self.scored,
            "dropped": dict(sorted(self.dropped.items())),
        }
