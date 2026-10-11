"""Write the settings schema a fresh deployment is served, for the console's tests.

The console's unit tests and the Playwright mocks read this file
(``apps/web/src/test-fixtures/settings-schema.json``) instead of a hand-made
catalogue, and ``tests/unit/api/test_the_console_fixture_is_the_served_schema.py``
fails when it no longer matches what the API serves. Run from the repository
root with the API on the path:

    PYTHONPATH=src:apps/api python scripts/dev/write_console_schema.py
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURE = Path("apps/web/src/test-fixtures/settings-schema.json")


# Left out of the fixture: the long texts no console decision reads. Every
# field the console decides on (keys, types, choices, flags, applies_when,
# probes, editors and each provider's declarations) is kept as served.
_OMITTED = ("default", "description")


def rendered() -> str:
    """The served default schema as the fixture holds it."""
    from app.api.v1.settings import default_served_schema

    schema = default_served_schema().model_dump(mode="json")
    for group in schema["groups"]:
        group.pop("description", None)
        for entry in group["entries"]:
            for field in _OMITTED:
                entry.pop(field, None)
    return json.dumps(schema, indent=1, sort_keys=True) + "\n"


if __name__ == "__main__":
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(rendered(), encoding="utf-8")
    print(f"wrote {FIXTURE}")
