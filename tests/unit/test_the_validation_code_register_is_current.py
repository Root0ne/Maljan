"""The validation-code register is the source's, and every code in it is raised and tested.

``apps/docs/content/docs/validation-codes.mdx`` is written by
``scripts/validation_codes/run.py`` from the source alone: it is parsed with
``ast``, never imported. This regenerates the page in memory and fails when the
committed page is not what the source gives, when a code has no place that
raises it (a code kept because stored runs carry it is bound under a
``LEGACY_`` name whose comment says why, and nowhere else), and when no test
names a code. Each failure names what to do. Another process, under another
hash seed, writes the same page.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from scripts.validation_codes.guard import Findings, check
from scripts.validation_codes.page import render
from scripts.validation_codes.register import PAGE, Register, build

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def register() -> Register:
    return build(ROOT)


@pytest.fixture(scope="module")
def findings(register: Register) -> Findings:
    page = ROOT / PAGE
    committed = page.read_text(encoding="utf-8") if page.is_file() else None
    return check(register, render(register), committed)


def test_the_validators_families_are_read(register: Register) -> None:
    raised = {code.family for code in register.codes if code.raised_at}

    assert {"attck", "isr", "report", "stix", "verdict"} <= raised


def test_the_committed_page_is_what_the_source_gives(findings: Findings) -> None:
    assert findings.stale == (), "\n".join(findings.stale)


def test_every_code_has_a_place_that_raises_it(findings: Findings) -> None:
    assert findings.dead == (), "\n".join(findings.dead)


def test_every_code_is_named_by_a_test(findings: Findings) -> None:
    assert findings.untested == (), "\n".join(findings.untested)


def test_another_process_under_another_hash_seed_writes_the_same_page(
    register: Register,
) -> None:
    command = [sys.executable, str(ROOT / "scripts" / "validation_codes" / "run.py"), "--stdout"]
    env = {**os.environ, "PYTHONHASHSEED": "4242"}

    written = subprocess.run(command, env=env, capture_output=True, check=True, timeout=600)

    assert written.stdout.decode("utf-8") == render(register)
