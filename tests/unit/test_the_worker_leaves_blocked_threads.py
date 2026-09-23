"""At its own exit the worker leaves threads blocked in calls that cannot be cancelled.

The guard used to be started by the worker's shutdown hook and ended the
process ten seconds later whatever was running, with status 0: a test that
called the hook took the rest of the suite with it, green. It is now armed by
the hook and started only by the interpreter's own exit, and it ends the
process only when a non-daemon thread is still blocked after the grace.

Each case runs in a child interpreter, because what is under test is how a
process exits.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time


def _run(script: str) -> tuple[subprocess.CompletedProcess[str], float]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    started = time.monotonic()
    done = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        env=env,
        timeout=60,
    )
    return done, time.monotonic() - started


def test_calling_the_shutdown_hook_leaves_the_calling_process_alive() -> None:
    done, _took = _run(
        """
        import asyncio, time
        from app.worker import analysis_worker as worker
        worker.EXIT_GRACE = 0.2
        asyncio.run(worker.shutdown({}))
        time.sleep(1.0)
        print("still here")
        """
    )

    assert done.returncode == 0, done.stderr[-2000:]
    assert "still here" in done.stdout


def test_the_guard_does_nothing_when_no_thread_is_blocked() -> None:
    done, _took = _run(
        """
        import threading
        from app.worker import analysis_worker as worker
        worker.arm_the_exit_guard(0.2)
        finished = threading.Thread(target=lambda: None)
        finished.start()
        finished.join()
        print("done")
        """
    )

    assert done.returncode == 0, done.stderr[-2000:]
    assert "leaving them" not in done.stdout + done.stderr


def test_a_thread_still_blocked_at_exit_is_left_after_the_grace() -> None:
    done, took = _run(
        """
        import threading, time
        from app.worker import analysis_worker as worker
        worker.arm_the_exit_guard(0.2)
        threading.Thread(target=time.sleep, args=(30,), name="model-call").start()
        """
    )

    assert done.returncode == 1
    assert took < 20, "the blocked thread's 30 s were not waited out"
    assert "model-call" in done.stdout + done.stderr
