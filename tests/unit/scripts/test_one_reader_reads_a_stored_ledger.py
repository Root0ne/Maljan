"""One reader takes a stored run's ledger rows for the replay, the scorer and the verifier.

``evidence.json`` is written with its rows under ``items`` (the API's page)
or ``entries``, or as a bare list. Every offline reader takes them through
:func:`scripts.replay.stored.evidence_rows`, which also says why it read no
row, so a reader never scores or checks an empty ledger without saying so.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from scripts.replay.stored import evidence_rows, read_run

ROWS = [{"entry_id": "ev_0001"}, {"entry_id": "ev_0002"}]


@pytest.mark.parametrize("document", [{"items": ROWS}, {"entries": ROWS}, ROWS])
def test_every_written_form_yields_its_rows(document: Any) -> None:
    assert evidence_rows(document) == (ROWS, "")


@pytest.mark.parametrize(
    ("document", "said"),
    [
        ({"items": []}, "holds no entries"),
        ({"total": 3}, "holds no entry list"),
        (7, "holds no entry list"),
    ],  # fmt: skip
)
def test_no_row_read_is_said(document: Any, said: str) -> None:
    rows, why = evidence_rows(document)
    assert rows == [] and said in why


def test_the_replay_and_the_verifier_read_the_same_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "evidence.json").write_text(json.dumps({"entries": ROWS}), encoding="utf-8")
    assert read_run(tmp_path).evidence == ROWS

    from scripts.ledger import verify

    from app.services import ledger_verify

    seen: list[Any] = []
    monkeypatch.setattr(
        ledger_verify, "verify_ledger", lambda _job, rows, report=None: seen.append(rows) or {}
    )
    verify.verify_run(tmp_path)
    assert seen == [ROWS]


def test_the_replay_names_a_ledger_it_read_no_row_from(tmp_path: Path) -> None:
    (tmp_path / "evidence.json").write_text(json.dumps({"total": 2}), encoding="utf-8")
    run = read_run(tmp_path)
    assert run.evidence == []
    assert "holds no entry list" in run.evidence_unread

    from scripts.replay.rules import replay_run

    record = replay_run(run)
    assert {"part": "stored run", "why": run.evidence_unread} in record["not_replayed"]


def test_the_verifier_sees_a_malformed_row_and_says_why_it_read_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.ledger import verify

    from app.services import ledger_verify

    seen: list[Any] = []
    monkeypatch.setattr(
        ledger_verify, "verify_ledger", lambda _job, rows, report=None: seen.append(rows) or {}
    )
    (tmp_path / "evidence.json").write_text(json.dumps({"items": [*ROWS, "junk"]}))
    assert "evidence_not_read" not in verify.verify_run(tmp_path)
    assert seen[-1] == [*ROWS, "junk"]
    (tmp_path / "evidence.json").write_text(json.dumps({"items": []}))
    assert "holds no entries" in verify.verify_run(tmp_path)["evidence_not_read"]
    (tmp_path / "evidence.json").unlink()
    assert "absent" in verify.verify_run(tmp_path)["evidence_not_read"]
