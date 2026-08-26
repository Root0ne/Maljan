"""Making a loaded program the *current* one — the step Ghidra does not take.

`load_program` imports a binary into the Ghidra project and answers
``{"success": true, "program": "<name>"}``. That response is what every caller
in this repository treated as "Ghidra is now looking at this binary". It is not.
The server keeps a separate notion of the **current program**, and `load_program`
only sets it when nothing is current yet — the very first load after a restart.
Every later load reports success and leaves the current program where it was.

The consequence, measured 2026-08-10 against the live container:

    load A        -> {"success": true, "program": "A"}   current: A
    load B        -> {"success": true, "program": "B"}   current: A   <-- still A
    run_analysis  -> {"program": "A", "new_functions": 0}
    call graph    -> A's graph, byte-identical, for every sample

The failure mode is the dangerous kind: no error, no warning, a plausible
answer. Two binaries of 241 KB and 139 KB produced call graphs identical to the
character, and the only reason it surfaced at all is that a hint length repeated
across samples that had nothing in common.

The fix is one extra call — ``POST /switch_program?program=<name>`` — issued
after a successful load. It is genuinely a *query* parameter; a JSON body is
answered with "Program name is required", which reads like a missing argument
and is really a misplaced one.

This module holds the pure part: reading the program name out of a load
response, and deciding whether a switch is warranted. The HTTP is left to the
three callers, which speak to Ghidra in three different ways (async client,
sync pre-pass, sync attribution pass).
"""

from __future__ import annotations

import json
from typing import Any

#: The endpoint that actually moves Ghidra's attention, and the parameter name
#: it insists on. Both are query-encoded — see the module docstring.
SWITCH_PATH = "/switch_program"
SWITCH_PARAM = "program"


def program_name_from_load(response_text: str) -> str | None:
    """The program name a ``/load_program`` response reports, if it succeeded.

    Returns ``None`` for anything that is not a successful load — a failure, a
    tool-error envelope, or a body that is not JSON at all. A caller that gets
    ``None`` has nothing to switch to and must not guess: switching to a name
    derived from the *requested* path would paper over a load that did not
    happen, which is the same silent-wrong-answer this module exists to stop.
    """
    try:
        payload: Any = json.loads(response_text)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("success") is not True:
        return None
    name = payload.get("program")
    if not isinstance(name, str) or not name.strip():
        return None
    return name


def switch_is_confirmed(response_text: str, expected: str) -> bool:
    """Whether a ``/switch_program`` response confirms the expected program.

    Used to decide what to log, not what to raise: a failed switch leaves the
    caller reading the previous program's data, which is worth a loud warning,
    but it must not turn a working analysis into a crashed one.
    """
    try:
        payload = json.loads(response_text)
    except (TypeError, ValueError):
        return False
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return False
    return payload.get("switched_to") == expected
