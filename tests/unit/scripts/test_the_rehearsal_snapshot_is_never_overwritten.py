"""A snapshot an earlier run left holds the operator's real settings; no later run overwrites it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts.rehearsal.run import SettingsGuard, gate_changes

from tests.unit.scripts.test_the_rehearsal_runner_reads_a_job_back_from_the_api import (
    STUB,
    _Api,
    _client,
    _values,
)


def test_a_second_keep_refuses_names_the_file_and_leaves_it_whole(tmp_path: Path) -> None:
    values = _values()
    client = _client(_Api(json.loads(json.dumps(values))))
    path = tmp_path / "settings-snapshot.json"
    SettingsGuard(client, path).keep(values, list(gate_changes(values, STUB)))
    before = path.read_text()
    second = SettingsGuard(client, path)
    with pytest.raises(SystemExit) as refused:
        second.keep(values, ["core.llm.openai.base_url"])
    assert str(path) in str(refused.value)
    assert f"--restore {path}" in str(refused.value)
    assert path.read_text() == before
    assert second.saved == {}
    client.close()


def test_a_restored_run_leaves_room_for_the_next(tmp_path: Path) -> None:
    values = _values()
    client = _client(_Api(json.loads(json.dumps(values))))
    path = tmp_path / "settings-snapshot.json"
    guard = SettingsGuard(client, path)
    guard.keep(values, list(gate_changes(values, STUB)))
    assert guard.restore() == []
    assert not path.exists()
    SettingsGuard(client, path).keep(values, list(gate_changes(values, STUB)))
    client.close()
