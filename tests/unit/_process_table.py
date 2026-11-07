"""Whether a process is running, asked of ``ps`` rather than of ``/proc``.

``ps -o stat= -p PID`` reads the same on every Unix the suite runs on, where
``/proc`` is only on some: an empty answer is no such process, and a state
starting with ``Z`` is a zombie waiting to be reaped, which has run its course.
"""

from __future__ import annotations

import subprocess


def running(pid: int) -> bool:
    """Whether ``pid`` is a live process: present, and not a zombie waiting to be reaped."""
    shown = subprocess.run(  # noqa: S603 — fixed argv, no shell
        ["ps", "-o", "stat=", "-p", str(pid)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return bool(shown) and not shown.startswith("Z")
