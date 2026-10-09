"""A whole analysis against the rehearsal's stub model passes the written checklist.

The real pipeline — the default profile, the triage pack, the repository's own
tool sidecars over stdio, the mock sandbox, every model call through the
settings a deployment sets — runs in this process against the loopback stub
(``scripts/rehearsal``), once per scenario: a normal run, each fault the live
runs met (a call cut at its cap with only thinking, an empty answer, a schema
break, a long tool loop, a slow model inside a job deadline, one server error
before success) and the report stage's calls after the analysts' on the
Anthropic wire. Each run must pass every check of
``scripts/rehearsal/checklist.py`` but the ones ``KNOWN_DEFECTS`` names, and
fail exactly those: a defect fixed is a test that says to strike it from the
list. Two normal runs must be identical.

Skipped where what an in-process run needs is absent: the web server packages
the stub is served with (``starlette``, ``uvicorn``), the ``mcp`` package the
tool sidecars speak, or a loopback port to bind. No Docker, no network beyond
127.0.0.1, no model cost.
"""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

import pytest

pytest.importorskip("starlette", reason="the stub model is served with starlette")
pytest.importorskip("uvicorn", reason="the stub model is served with uvicorn")
pytest.importorskip("mcp", reason="the tool sidecars speak the mcp package's protocol")

from scripts.rehearsal.checklist import check_run, compare, signature  # noqa: E402
from scripts.rehearsal.inprocess import Rehearsal, rehearse  # noqa: E402


def _loopback_binds() -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False


pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not _loopback_binds(), reason="no loopback port to bind the stub on"),
]

# A deadline every rehearsal finishes far inside: the stand-in for the
# worker's job timeout the slow-model scenario runs near.
JOB_DEADLINE_S = 600.0

# The checks a scenario fails today because of a defect in the product, each
# with where it is. The rehearsal found them; the fixes are not this change's.
KNOWN_DEFECTS: dict[tuple[str, str], dict[str, str]] = {
    ("server_error_once", "openai"): {
        "every analyst answered": (
            "one HTTP 500 on an analyst's first call fails its whole tool loop: the ReAct "
            "call and the revision call are not retried, only the mediator retries"
        ),
    },
    ("cross_loop", "anthropic"): {
        "verdict stated by the judge": (
            "the judge reads a ChatAnthropic answer as str(content), so an answer with a "
            "thinking block before its JSON is never read as the bundle "
            "(judge_agent._answer_text, _bundle_from_response)"
        ),
    },
}


@pytest.mark.parametrize(
    ("scenario", "provider", "kwargs"),
    [
        ("normal", "openai", {}),
        ("cut_at_cap", "openai", {}),
        ("empty_answer", "openai", {}),
        ("schema_break", "openai", {}),
        ("long_loop", "openai", {"loop_steps": 8}),
        ("slow_model", "openai", {"slow_seconds": 0.1}),
        ("server_error_once", "openai", {}),
        ("cross_loop", "anthropic", {}),
    ],
)
def test_every_check_passes_but_a_known_defect(
    tmp_path: Path, scenario: str, provider: str, kwargs: dict
) -> None:
    rehearsal = Rehearsal(
        scenario=scenario,
        provider=provider,
        work_dir=tmp_path / scenario,
        job_timeout_s=JOB_DEADLINE_S,
        **kwargs,
    )
    checks = check_run(asyncio.run(rehearse(rehearsal)))
    failed = {c.name: c.detail for c in checks if not c.ok}
    assert sorted(failed) == sorted(KNOWN_DEFECTS.get((scenario, provider), {})), failed


def test_two_normal_runs_are_identical(tmp_path: Path) -> None:
    signatures = []
    for index in range(2):
        rehearsal = Rehearsal(scenario="normal", work_dir=tmp_path / f"run{index}")
        record = asyncio.run(rehearse(rehearsal))
        signatures.append(signature(record, check_run(record)))
    assert compare(signatures) == []
