"""The console's test fixture is exactly the schema the API serves a fresh deployment.

The guides' unit tests and the Playwright mocks read
``apps/web/src/test-fixtures/settings-schema.json``; a hand-set flag there
once hid a fussier setup step. Regenerate it with
``scripts/dev/write_console_schema.py`` when the catalogue changes.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def _writer():
    spec = importlib.util.spec_from_file_location(
        "write_console_schema", ROOT / "scripts" / "dev" / "write_console_schema.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_fixture_is_the_served_schema():
    writer = _writer()
    fixture = ROOT / writer.FIXTURE
    assert fixture.read_text(encoding="utf-8") == writer.rendered(), (
        "the console fixture is stale: run scripts/dev/write_console_schema.py"
    )
