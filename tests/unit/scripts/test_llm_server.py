"""The model server's launcher, tested on the way it lied.

``pid_of`` decides whether the server is running. On 2026-08-15 it was
``pgrep -f "llama-server .*--port $PORT"``, which matches any process whose
command line merely contains that text — and a monitor started to report a
run's progress greps for exactly that string. Its own shell matched, ``start``
printed "already running", skipped the launch, and an eval spent a cycle
talking to a server that was not there.

Nothing failed loudly. The supervisor's log said "stopping pid 3491804" and
then "already running (pid 3500402)" — two pids for one server, one line apart,
and it read as noise.

The test below is the decoy: a process whose command line contains the pattern
and which is emphatically not a model server. Matching on the process *name*
survives it, because a bash script cannot claim to be called ``llama-server``.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _ROOT / "scripts" / "llm_server.sh"

pytestmark = pytest.mark.skipif(
    not Path("/proc/self/cmdline").exists(), reason="pid_of reads /proc"
)


def _pid_of(port: str = "8080") -> subprocess.CompletedProcess[str]:
    """Call the script's own pid_of, with nothing else from the script running."""
    body = _SCRIPT.read_text()
    start = body.index("pid_of() {")
    end = body.index("\n}", start) + 2
    harness = f'PORT="{port}"\n{body[start:end]}\npid_of\n'
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=30)


def test_a_process_that_merely_mentions_the_server_is_not_the_server() -> None:
    decoy = subprocess.Popen(
        [
            "bash",
            "-c",
            # The monitor that caused this: it greps for the server by pattern,
            # so the pattern is in its own argv.
            "while true; do pgrep -f 'llama-server .*--port 8080' >/dev/null; sleep 5; done",
        ]
    )
    try:
        time.sleep(1)
        # The decoy is findable the old way, which is the whole point.
        old = subprocess.run(
            ["pgrep", "-f", "llama-server .*--port 8080"],
            capture_output=True,
            text=True,
        )
        assert str(decoy.pid) in old.stdout.split(), (
            "the decoy does not reproduce the condition — pgrep -f no longer matches it, "
            "so this test is not testing anything"
        )

        result = _pid_of()
        assert str(decoy.pid) not in result.stdout.split(), (
            "pid_of matched a process that only mentions the server in its command line. "
            "That is how a dead server was reported as running.\n"
            f"pid_of said: {result.stdout!r}"
        )
    finally:
        decoy.kill()
        decoy.wait(timeout=10)


def test_pid_of_finds_nothing_rather_than_guessing_when_the_server_is_absent() -> None:
    """An absent server must be absent, not the nearest lookalike.

    Reported through the exit status, because every caller branches on it:
    ``start`` skips the launch, ``stop`` says "not running", ``status`` exits 3.
    """
    result = _pid_of(port="59999")  # a port nothing here serves
    assert result.returncode != 0, (
        f"pid_of claimed to find a server on an unused port: {result.stdout!r}"
    )
    assert not result.stdout.strip(), f"and printed a pid for it: {result.stdout!r}"


def test_the_tuned_flags_are_in_the_script_rather_than_in_a_running_process() -> None:
    """The reason this file exists at all.

    Before it, the offload regex that fits a 35B MoE on an 8 GB card lived in
    exactly one place: the argv of a process. If the server died the tuning died
    with it, and the reproducibility appendix could not name the settings that
    produced the measurements.
    """
    text = _SCRIPT.read_text()
    for flag in ("ffn_(up|gate|down)_exps=CPU", "-ctk", "-ctv", "--context-shift", "-ngl"):
        assert flag in text, f"{flag!r} is not recorded in the launcher"


def test_a_model_load_is_declared_to_the_memory_guard() -> None:
    """Loading 14 GB is declared work, not runaway work.

    The guard kills the registered job when memory goes critical. A model load
    looks exactly like that from outside, and on 2026-08-11 the strike counter
    expired mid-load three times and ended a run for pressure that had already
    passed.
    """
    text = _SCRIPT.read_text()
    assert "night-job.grace" in text, (
        "the launcher does not lay the grace marker, so a load can be mistaken "
        "for a runaway job by the guard that is watching it"
    )


def test_the_scripts_parse() -> None:
    for script in ("llm_server.sh", "run_with_restarts.sh"):
        path = _ROOT / "scripts" / script
        result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
        assert result.returncode == 0, f"{script} does not parse:\n{result.stderr}"
        assert os.access(path, os.X_OK), f"{script} is not executable"
