"""A job on the shipped Ghidra declaration closes the program it opened when the job ends."""

from __future__ import annotations

from typing import Any

import pytest

from maljan.core.config import GHIDRA_SAMPLE_OPEN
from tests.unit.providers.test_a_job_reads_its_own_program import (
    A,
    B,
    _cfg,
    _Job,
    _rest,
    _SharedGhidra,
)


def test_the_shipped_declaration_names_ghidras_close_tool() -> None:
    assert GHIDRA_SAMPLE_OPEN.close_tool == "close_program"
    assert GHIDRA_SAMPLE_OPEN.close_argument == "name"


def test_a_shared_server_gets_a_close_of_the_name_the_load_answered(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ghidra = _SharedGhidra()
    _rest(monkeypatch, ghidra)
    job_a, job_b = _Job(ghidra, A), _Job(ghidra, B)
    job_a.call("load_program", file=A)
    job_b.call("load_program", file=B)

    job_a.provider.close()

    # The name is the one the load answered under ``name_field``, and only this job's.
    assert ghidra.sent("/close_program", "name") == ["a.exe"]
    assert job_a.provider.sample_notes.take_owned(_key(job_a)) == []
    assert job_b.provider.sample_notes.owns(_key(job_b), "b.exe")


def _key(job: Any) -> str:
    from maljan.providers.sample_open import server_note_key

    return server_note_key(job.provider._cfg, str(getattr(job.provider, "note_instance", "") or ""))


def test_a_server_no_other_job_shares_is_not_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    ghidra = _SharedGhidra()
    _rest(monkeypatch, ghidra)
    job = _Job(ghidra, A)
    job.call("load_program", file=A)
    job.provider._cfg = _cfg().model_copy(update={"transport": "stdio"})

    job.provider.close()

    assert ghidra.sent("/close_program", "name") == []
