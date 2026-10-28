"""Write the settings schema a deployment is served, for the console's tests.

The console's unit tests and the Playwright mocks read this file
(``apps/web/src/test-fixtures/settings-schema.json``) instead of a hand-made
catalogue, and ``tests/unit/api/test_the_console_fixture_is_the_served_schema.py``
fails when it no longer matches what the API serves. The deployment is one
whose built-in reputation service was listed once, as every test starts
(``tests/conftest.py``): what is read of its listing
(``tests/fixtures/virustotal_listing.json``, ``core.derived_declarations``)
is what binds it to the agents' reputation capability. Run from the
repository root with the API on the path:

    PYTHONPATH=src:apps/api python scripts/dev/write_console_schema.py
"""

from __future__ import annotations

import json
from pathlib import Path

# Anchored on this file, not on the working directory the script is run from.
FIXTURE = Path(__file__).resolve().parents[2] / "apps/web/src/test-fixtures/settings-schema.json"


# Left out of the fixture: the long texts no console decision reads. Every
# field the console decides on (keys, types, choices, flags, applies_when,
# probes, editors and each provider's declarations) is kept as served.
_OMITTED = ("default", "description")


_LISTING = Path(__file__).resolve().parents[2] / "tests/fixtures/virustotal_listing.json"


def _listed_once() -> None:
    """Keep what is read of the built-in reputation service's listing, unless something is."""
    from maljan.core.config import _builtin_servers
    from maljan.core.derived_declarations import derived_tool_facts
    from maljan.core.served_declarations import derived, register_served
    from maljan.core.tool_declarations import launch_identity

    launch = launch_identity(_builtin_servers()["virustotal"])
    if derived("mcp:virustotal", launch):
        return
    listing = json.loads(_LISTING.read_text(encoding="utf-8"))
    register_served("mcp:virustotal", {}, launch, derived_tool_facts(listing["tools"]))


def rendered() -> str:
    """The served default schema as the fixture holds it."""
    from app.api.v1.settings import default_served_schema

    _listed_once()
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
