#!/usr/bin/env python3
"""Refresh the vendored top-level-domain list from the IANA root zone.

Offline for the pipeline: operator-run, never imported by it and never run by a
test. It downloads IANA's ``tlds-alpha-by-domain.txt``, checks it with the same
reader the string sweep loads it with (``maljan.tools.strings.read_tld_list``:
a ``# Version`` line first, then one TLD per line) and writes it, unchanged and
with its version line, to ``data/tlds-alpha-by-domain.txt``.

Usage::

    uv run python scripts/knowledge/refresh_iana_tlds.py
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from maljan.tools.strings import TLD_LIST_PATH, read_tld_list  # noqa: E402


def main() -> int:
    # The root zone list, at the one fixed https address IANA publishes it.
    response = httpx.get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", timeout=60)
    response.raise_for_status()
    text = response.content.decode("ascii")
    version, tlds = read_tld_list(text)
    previous = TLD_LIST_PATH.read_text(encoding="ascii") if TLD_LIST_PATH.is_file() else ""
    TLD_LIST_PATH.write_text(text if text.endswith("\n") else text + "\n", encoding="ascii")
    old = read_tld_list(previous)[1] if previous else frozenset()
    print(f"{version}: {len(tlds)} TLDs, {len(tlds - old)} added, {len(old - tlds)} removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
