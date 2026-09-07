"""Every scripts/... path the Makefile names must exist.

Task 4 regroups twenty scripts into five directories. A target that still names
the old path fails only when somebody runs that target, which for ``paper-check``
and ``cohort-complete`` can be weeks later. Reading the Makefile and stat-ing
what it names turns that into a test failure in the same commit as the move.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
MAKEFILE = ROOT / "Makefile"

# A path token starting with "scripts/". Stops at whitespace, a quote, a comma or
# a closing paren, so `$(PY_SOURCES)` expansions and shell quoting do not bleed in.
_SCRIPT_TOKEN = re.compile(r"scripts/[A-Za-z0-9_./-]+")


def makefile_script_tokens() -> set[str]:
    """Every distinct scripts/... token in the Makefile, comments included."""
    return {
        token.rstrip("/")
        for token in _SCRIPT_TOKEN.findall(MAKEFILE.read_text(encoding="utf-8"))
        if token != "scripts/"
    }


def test_the_makefile_names_scripts_at_all() -> None:
    assert len(makefile_script_tokens()) >= 7


def test_every_script_the_makefile_names_exists() -> None:
    missing = sorted(t for t in makefile_script_tokens() if not (ROOT / t).exists())
    assert missing == [], f"the Makefile names paths that are not there: {missing}"
