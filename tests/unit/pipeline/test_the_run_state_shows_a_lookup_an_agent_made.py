"""The run-state block shows a lookup of the sample an agent made itself.

The pack asks only a declared reputation lookup; where none is declared it
records that no lookup was made. An agent that then called an operator's
lookup itself — a tool nobody declared, given the sample's own SHA-256 — left
the block saying "not done" for a lookup the run had made. The block now shows
that call; a tool declared of any other kind, a call without the sample's hash,
and a pack that holds an answered lookup read as before.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.pipeline.run_state import render_run_state
from maljan.pipeline.triage_pack import NOT_RUN_PREFIX, PIPELINE
from maljan.schemas.evidence import build_entry, format_entry_id

SHA = "ab" * 32
NOT_ASKED = f"{NOT_RUN_PREFIX} no server declares a reputation lookup; no lookup was made"
RECORD = {"data": {"attributes": {"stats": {"malicious": 3, "total": 60}}}}


def _not_asked(seq: int) -> dict[str, Any]:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=PIPELINE,
        tool="reputation",
        args={"sha256": SHA},
        server=PIPELINE,
        source="pack",
        output=NOT_ASKED,
        ok=False,
        error=NOT_ASKED,
    ).model_dump(mode="json")


def _agent_call(
    seq: int, *, tool: str = "lookup_hash", source: str = "mcp:repstub", args: Any = None
) -> dict[str, Any]:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent="judge",
        tool=tool,
        args={"sha256": SHA} if args is None else args,
        server=source.partition(":")[2],
        source=source,
        output=json.dumps(RECORD),
    ).model_dump(mode="json")


def _block(rows: list[dict[str, Any]]) -> str:
    return render_run_state({"file_hash": SHA, "evidence_ledger": rows})


def test_an_agents_own_lookup_replaces_the_not_done_line() -> None:
    body = _block([_not_asked(1), _agent_call(2)])
    assert "[ev_0002]" in body
    assert "not done" not in body


def test_without_the_agents_call_the_not_done_line_stays() -> None:
    body = _block([_not_asked(1)])
    assert "[ev_0001] reputation: not done" in body


def test_a_call_without_the_sample_s_hash_is_not_a_lookup_of_it() -> None:
    body = _block([_not_asked(1), _agent_call(2, args={"sha256": "cd" * 32})])
    assert "[ev_0002]" not in body
    assert "not done" in body


def test_a_tool_declared_of_another_kind_is_never_one() -> None:
    body = _block([_not_asked(1), _agent_call(2, tool="pe_info", source="mcp:analysis")])
    assert "[ev_0002]" not in body


def test_many_rows_are_read_in_one_pass() -> None:
    import time

    def _timed(n: int) -> float:
        rows = [
            _not_asked(1),
            *(_agent_call(i, args={"query": f"q{i}"}) for i in range(2, n)),
            _agent_call(n),
        ]
        start = time.perf_counter()
        assert f"[{format_entry_id(n)}]" in _block(rows)
        return time.perf_counter() - start

    small, large = _timed(200), _timed(2_000)
    assert large < max(small * 30, 1.0)
