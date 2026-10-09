"""A whole analysis against the rehearsal's stub model passes the written checklist.

The real pipeline — the default profile, the triage pack, the repository's own
tool sidecars over stdio, the mock sandbox, every model call through the
settings a deployment sets — runs in this process against the loopback stub
(``scripts/rehearsal``), once per scenario: a normal run, each fault the live
runs met (a call cut at its cap with only thinking, an empty answer, a schema
break, a long tool loop, a slow model inside a job deadline, one server error
before success) and the report stage's calls after the analysts' on the
Anthropic wire. Each run must pass every check of
``scripts/rehearsal/checklist.py``; two normal runs must be identical.

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

from scripts.rehearsal.checklist import Check, check_run, compare, signature  # noqa: E402
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
VERDICT_CHECK = "verdict stated by the judge"


def _run(tmp_path: Path, scenario: str, provider: str = "openai", **kwargs: object) -> list[Check]:
    rehearsal = Rehearsal(
        scenario=scenario,
        provider=provider,
        work_dir=tmp_path / scenario,
        job_timeout_s=JOB_DEADLINE_S,
        **kwargs,  # type: ignore[arg-type]
    )
    return check_run(asyncio.run(rehearse(rehearsal)))


def _failures(checks: list[Check]) -> list[str]:
    return [f"{c.name}: {c.detail}" for c in checks if not c.ok]


@pytest.mark.parametrize(
    ("scenario", "kwargs"),
    [
        ("normal", {}),
        ("cut_at_cap", {}),
        ("empty_answer", {}),
        ("schema_break", {}),
        ("long_loop", {"loop_steps": 8}),
        ("slow_model", {"slow_seconds": 0.1}),
        ("server_error_once", {}),
    ],
)
def test_every_check_passes(tmp_path: Path, scenario: str, kwargs: dict) -> None:
    assert _failures(_run(tmp_path, scenario, **kwargs)) == []


def test_two_normal_runs_are_identical(tmp_path: Path) -> None:
    signatures = []
    for index in range(2):
        rehearsal = Rehearsal(scenario="normal", work_dir=tmp_path / f"run{index}")
        record = asyncio.run(rehearse(rehearsal))
        signatures.append(signature(record, check_run(record)))
    assert compare(signatures) == []


@pytest.fixture(scope="module")
def anthropic_checks(tmp_path_factory: pytest.TempPathFactory) -> list[Check]:
    return _run(tmp_path_factory.mktemp("anthropic"), "cross_loop", provider="anthropic")


def test_the_anthropic_wire_passes_every_other_check(anthropic_checks: list[Check]) -> None:
    others = [c for c in anthropic_checks if c.name != VERDICT_CHECK]
    assert _failures(others) == []


@pytest.mark.xfail(
    strict=True,
    reason=(
        "the judge reads a ChatAnthropic answer as str(content): an answer with a thinking "
        "block before its JSON is not read as the bundle, and the verdict falls back to text "
        "extraction (judge_agent._answer_text and _bundle_from_response)"
    ),
)
def test_the_anthropic_judge_states_its_verdict(anthropic_checks: list[Check]) -> None:
    (verdict,) = [c for c in anthropic_checks if c.name == VERDICT_CHECK]
    assert verdict.ok, verdict.detail
