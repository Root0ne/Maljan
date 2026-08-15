"""The memory guard, tested on the two ways it has actually failed.

The guard kills a registered job when the machine runs out of memory. Both of
its defects were the same shape: it acted on a signal it had not attributed, and
the log said it was working the whole time.

* **It killed a job that was not holding the memory.** On 2026-08-15 it stopped
  a model run at 3921 MB available; MemAvailable then read 3912, 3928 and 3920
  over the next ninety seconds, because every page the job returned was taken
  straight back by a swap-in. The floor was the model server's 18 GB of dirty
  anonymous memory, which the guard neither manages nor can free. It then fired
  every ninety seconds for an hour with nothing left to kill. Cost: 34 minutes
  of GPU work and no memory recovered.

* **It could not see its own job.** ``read -r pid < file || pid=""`` returns
  non-zero at EOF without a trailing newline — *after* assigning what it read —
  so the fallback wiped a perfectly good pid. A pid file written with
  ``write(str(os.getpid()))`` therefore disarmed both the kill path and the
  oom_score_adj path, the second of which is what keeps the kernel's OOM killer
  off the user's editor.

These tests drive the real script against a real machine state, because both
defects survived reading and only measurement found them.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_GUARD = _ROOT / "scripts" / "night_guard.sh"

pytestmark = pytest.mark.skipif(
    not Path("/proc/meminfo").exists(), reason="guard reads /proc directly"
)


def _available_mb() -> int:
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) // 1024
    raise AssertionError("no MemAvailable in /proc/meminfo")


def _run_guard(log_dir: Path, *, kill_mb: int, pid_file: Path, seconds: int = 20) -> str:
    env = {
        **os.environ,
        "LOG_DIR": str(log_dir),
        "JOB_PID_FILE": str(pid_file),
        "INTERVAL": "2",
        "KILL_STRIKES": "2",
        "KILL_MB": str(kill_mb),
        # Heat is a separate branch and would pre-empt the one under test.
        "THERMAL_MAX": "200",
    }
    subprocess.run(
        ["timeout", str(seconds), str(_GUARD)],
        env=env,
        capture_output=True,
        timeout=seconds + 15,
    )
    return (log_dir / "night-guard.log").read_text()


@pytest.fixture
def holder(tmp_path: Path):
    """A process holding 300 MB, registering itself the way that broke the guard.

    ``write(str(pid))`` and no newline — not a contrived input, it is what a
    one-line Python registration produces.
    """
    pid_file = tmp_path / "job.pid"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            textwrap.dedent(f"""
                import os, time
                blob = bytearray(300 * 1024 * 1024)
                open({str(pid_file)!r}, "w").write(str(os.getpid()))
                time.sleep(120)
            """),
        ]
    )
    for _ in range(100):
        if pid_file.exists() and pid_file.read_text().strip():
            break
        time.sleep(0.1)
    else:
        proc.kill()
        pytest.fail("the holder never registered itself")
    assert not pid_file.read_bytes().endswith(b"\n"), "fixture must omit the newline"
    yield proc, pid_file
    if proc.poll() is None:
        proc.kill()
    proc.wait(timeout=10)


def test_a_job_holding_the_memory_is_still_killed(tmp_path: Path, holder) -> None:
    """The guard's whole purpose, and the pid file has no trailing newline."""
    proc, pid_file = holder
    # A floor 150 MB above the current reading: less than the job holds, so
    # killing it clears the floor and the guard should judge it worthwhile.
    log = _run_guard(tmp_path, kill_mb=_available_mb() + 150, pid_file=pid_file)

    assert f"SIGTERM -> {proc.pid}" in log, (
        f"the guard did not stop a job that was holding more than the shortfall. Log:\n{log}"
    )
    assert re.search(r"the registered job holds \d+MB", log), (
        "the guard killed without saying what the job held, so the log cannot "
        f"distinguish a justified kill from the 2026-08-15 one. Log:\n{log}"
    )
    # The pid file had no trailing newline: if `slurp` regressed to plain `read`,
    # the guard would have reported the job as absent instead.
    assert "no live job registered" not in log, (
        f"the guard could not see a live job — the trailing-newline read bug is back. Log:\n{log}"
    )


def test_a_shortfall_the_job_does_not_own_is_not_charged_to_the_job(
    tmp_path: Path,
) -> None:
    """The 2026-08-15 failure: killing what is not holding the memory.

    Nothing is registered here, so killing the job could not possibly recover
    anything — the limiting case of the same misattribution, and the one that
    produced an hour of kill attempts against an empty pid file.
    """
    empty = tmp_path / "nobody.pid"
    empty.write_text("")
    # A floor above whatever the machine currently has, so the branch is entered.
    log = _run_guard(tmp_path, kill_mb=_available_mb() + 500, pid_file=empty)

    assert "SIGTERM" not in log, f"the guard killed something it should not have:\n{log}"
    assert "is not what is holding the memory" in log, (
        f"the guard did not attribute the shortage before acting. Log:\n{log}"
    )
    # It must name the actual holder, or whoever reads the log looks in the
    # wrong place — which is how the original hour was spent.
    assert re.search(r"\w+ \(pid \d+, \d+MB\) is", log), (
        f"the guard reported a shortage without naming its owner. Log:\n{log}"
    )
    # And it says it once, not on every pass.
    assert log.count("is not what is holding the memory") == 1, (
        f"the guard repeated its explanation instead of holding quietly:\n{log}"
    )


def test_the_stop_sentinel_is_still_laid_when_the_guard_holds(tmp_path: Path) -> None:
    """Holding is not standing down: no new heavy step may start."""
    empty = tmp_path / "nobody.pid"
    empty.write_text("")
    _run_guard(tmp_path, kill_mb=_available_mb() + 500, pid_file=empty)
    assert (tmp_path / "overnight-watch.STOP").exists(), (
        "the guard declined to kill and also forgot to gate new work, which "
        "would let a fresh heavy step start into the same shortage"
    )


@pytest.mark.parametrize("trailing", ["", "\n"])
def test_slurp_reads_a_value_whether_or_not_the_writer_added_a_newline(
    tmp_path: Path, trailing: str
) -> None:
    """The read bug, pinned at the unit it lives in.

    Every caller in the guard asks "did I get a value", and `read`'s exit status
    answers "did I find a newline". Those differ on exactly the files other
    programs write.
    """
    target = tmp_path / "value"
    target.write_text(f"31337{trailing}")
    script = f"""
        source /dev/stdin <<'EOF'
{_slurp_source()}
EOF
        v=""
        slurp v {target} || echo "SLURP-FAILED"
        echo "got=$v"
    """
    out = subprocess.run(
        ["bash", "-c", textwrap.dedent(script)], capture_output=True, text=True
    ).stdout
    assert "SLURP-FAILED" not in out, f"slurp rejected a readable value: {out!r}"
    assert "got=31337" in out, out


def _slurp_source() -> str:
    """The guard's own definition, so this test cannot drift from it."""
    text = _GUARD.read_text()
    match = re.search(r"^slurp\(\) \{.*?^\}", text, re.M | re.S)
    assert match, "slurp() is gone from the guard"
    return match.group(0)
