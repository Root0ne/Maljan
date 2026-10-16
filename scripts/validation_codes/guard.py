"""What the register holds the tree to: the page is current, and every code is raised and tested.

Three findings, each named so a test can show it failing on its own:

* ``stale``: the committed page is not what the source gives;
* ``dead``: a code nothing raises. A code kept because stored runs carry it is
  bound under a ``LEGACY_`` name whose comment says so; that is the only way
  out, and it is in the code, not in a list here. A kept code that is still
  raised, or kept with no comment saying why, is dead too;
* ``untested``: a code no test names. A code the platform raises needs a
  Python test, since that is where it is raised; a console test naming it
  checks only how the console words it. A code kept for stored runs may be
  named by a test of whatever reads it, the console's included.
"""

from __future__ import annotations

from dataclasses import dataclass

from scripts.validation_codes.page import COMMAND
from scripts.validation_codes.register import KEPT_PREFIX, PAGE, Register


@dataclass(frozen=True)
class Findings:
    stale: tuple[str, ...]
    dead: tuple[str, ...]
    untested: tuple[str, ...]

    def all(self) -> list[str]:
        return [*self.stale, *self.dead, *self.untested]


def check(register: Register, rendered: str, committed: str | None) -> Findings:
    """``rendered`` is the page this tree gives; ``committed`` the file on disk (None: absent)."""
    stale: list[str] = []
    if committed is None:
        stale.append(f"{PAGE} is missing: run `{COMMAND}` and commit the page")
    elif committed != rendered:
        stale.append(f"{PAGE} is not what the source gives: run `{COMMAND}` and commit the page")
    dead: list[str] = []
    untested: list[str] = []
    for code in register.codes:
        if code.kept_by:
            holders = ", ".join(code.kept_by)
            if code.raised_at:
                dead.append(
                    f"`{code.code}` is kept for stored runs by {holders} but is raised at "
                    f"{', '.join(code.raised_at)}: take it out of the {KEPT_PREFIX} binding"
                )
            elif not code.kept_reason:
                dead.append(
                    f"`{code.code}` is kept for stored runs by {holders}, which has no comment "
                    "saying which stored runs carry it and what reads it"
                )
        elif not code.raised_at:
            named = ", ".join(code.constants or code.collections)
            dead.append(
                f"`{code.code}` ({named}): nothing raises it. Remove it, or bind it under a "
                f"{KEPT_PREFIX} name whose comment says which stored runs carry it and what "
                "reads it"
            )
        if code.tests or (code.kept_by and code.console_tests):
            continue
        if code.console_tests:
            untested.append(
                f"`{code.code}`: only the console's tests name it "
                f"({', '.join(code.console_tests)}). Add a test that makes the platform raise "
                "it, beside its family's tests"
            )
        else:
            untested.append(
                f"`{code.code}`: no test names it. Add a test that makes the platform raise it, "
                "beside its family's tests"
            )
    return Findings(tuple(stale), tuple(dead), tuple(untested))
