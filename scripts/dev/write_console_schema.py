"""Write the settings schema a deployment is served, for the console's tests.

The console's unit tests and the Playwright mocks read this file
(``apps/web/src/test-fixtures/settings-schema.json``) instead of a hand-made
catalogue, and ``tests/unit/api/test_the_console_fixture_is_the_served_schema.py``
fails when it no longer matches what the API serves. The deployment is one
whose built-in reputation service, Ghidra and radare2 were listed once, as
every test starts (``tests/conftest.py``): what is read of the reputation
service's listing (``tests/fixtures/virustotal_listing.json``,
``core.derived_declarations``) is what binds it to the agents' reputation
capability, and what is read of Ghidra's and radare2's vendored listings
(``core.program_reading``) is their tools. Run from the
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
    if not derived("mcp:virustotal", launch):
        listing = json.loads(_LISTING.read_text(encoding="utf-8"))
        register_served("mcp:virustotal", {}, launch, derived_tool_facts(listing["tools"]))
    _reversers_listed_once()


_TOOLS = Path(__file__).resolve().parents[2] / "tests/fixtures/tools"


def _reversers_listed_once() -> None:
    """Keep what is read of Ghidra's and radare2's vendored listings, unless something is.

    As every test starts (``tests/conftest.py``): Ghidra's ``/mcp/schema`` as
    its HTTP client lists it, and r2mcp's listing (``core.program_reading``).
    """
    from maljan.core.config import ghidra_block, r2_block
    from maljan.core.derived_declarations import derived_readings, program_readings_of
    from maljan.core.served_declarations import program_read, register_served
    from maljan.core.tool_declarations import launch_identity
    from maljan.providers.static.ghidra.http_client import GhidraHTTPClient

    client = GhidraHTTPClient(base_url="http://ghidra.invalid")
    client._schema = list(
        json.loads((_TOOLS / "ghidra_mcp_schema.json").read_text(encoding="utf-8"))["tools"]
    )
    r2 = [
        {"name": t["name"], "description": t["description"], "inputSchema": t["input_schema"]}
        for t in json.loads((_TOOLS / "r2mcp_tool_definitions.json").read_text(encoding="utf-8"))
    ]
    # And ``run_command``, which r2mcp lists when started with ``-r``.
    r2.append(
        {
            "name": "run_command",
            "description": "Run a radare2 command and get the output",
            "inputSchema": {
                "type": "object",
                "properties": {"command": {"type": "string", "description": "Command to execute"}},
                "required": ["command"],
            },
        }
    )
    for source, block, listing in (
        ("provider:ghidra", ghidra_block(), client.tool_definitions()),
        ("provider:r2", r2_block(), r2),
    ):
        launch = launch_identity(block)
        if program_read(source, launch):
            continue
        read, closed = derived_readings(listing)
        register_served(source, {}, launch, read, closed, program_readings_of(listing))


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
