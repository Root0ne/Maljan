"""List the tools an installed r2mcp offers, and pin them for the r2 provider.

    uv run python scripts/probe_r2_tools.py            # uses `r2mcp` on PATH
    uv run python scripts/probe_r2_tools.py /path/r2mcp

Writes tests/fixtures/golden/r2_tools.json. The provider's allow-list constant
is filled from that file; running this again on a newer r2mcp shows, as a diff,
exactly which names moved.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "golden" / "r2_tools.json"


def main() -> None:
    from maljan.providers.static.r2 import enumerate_r2_tools

    command = sys.argv[1] if len(sys.argv) > 1 else "r2mcp"
    names = asyncio.run(enumerate_r2_tools(command))
    payload = [{"name": n} for n in names]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(
            {
                # Recorded as the bare executable name, never the machine-local
                # absolute path the caller may have passed on argv: the fixture
                # is committed and must stay portable across machines.
                "command": Path(command).name,
                "source": "live handshake",
                "tools": sorted(payload, key=lambda t: t["name"]),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"{len(names)} tools -> {OUT}")


if __name__ == "__main__":
    main()
