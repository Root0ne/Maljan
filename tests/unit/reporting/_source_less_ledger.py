"""A ledger written before entries recorded their source, for the section rebuild check.

One entry per stored tool answer fixture (``tests/fixtures/ledger``), and the
empty answers a built-in tool gives when it finds nothing: those draw no
section, before and after tools declared their kind.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from maljan.schemas.evidence import build_entry

LEDGER = Path(__file__).resolve().parents[2] / "fixtures" / "ledger"

# Built-in tools answering with nothing in them.
EMPTY_ANSWERS: list[tuple[str, dict[str, Any]]] = [
    ("yara_scan", {"matches": [], "filtered": 0, "rule_count": 31}),
    ("iocs_from_file", {"iocs": []}),
    ("capa", {"capabilities": [], "meta": {"rule_count": 10}}),
    ("sandbox_mutexes", {"mutexes": [], "total": 0}),
    ("sandbox_registry_ops", {"operations": [], "total": 0}),
    ("sandbox_services_and_tasks", {"services": [], "total": 0}),
    ("sandbox_api_calls", {"calls": [], "total": 0}),
    ("sandbox_dropped_files", {"files": [], "total": 0}),
    ("sandbox_items", {"items": [], "total": 0}),
]


def source_less_ledger() -> list[Any]:
    answers = [(path.stem, json.loads(path.read_text())) for path in sorted(LEDGER.glob("*.json"))]
    answers += EMPTY_ANSWERS
    return [
        build_entry(
            entry_id=f"ev_{n:04d}",
            seq=n,
            agent="pipeline",
            tool=tool,
            args={},
            server=None,
            output=json.dumps(answer),
        )
        for n, (tool, answer) in enumerate(answers, start=1)
    ]
