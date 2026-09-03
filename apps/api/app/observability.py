"""Process-local state operators must be able to see.

Two things live here because two routes read them: the auth throttle's
availability (Task H1) and the count of audit rows that could not be written
(M6). Both are per process; a multi-process deployment reports each worker's
own view, which is what a health probe wants.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ThrottleState:
    available: bool = True
    degraded_since: float | None = None
    last_error: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "available": self.available,
            "degraded_since": self.degraded_since,
            "last_error": self.last_error,
        }


@dataclass
class Counters:
    audit_write_failures: int = 0


throttle = ThrottleState()
counters = Counters()
