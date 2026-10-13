"""The rehearsal's sample is answered by the mock sandbox's recorded fixture, wherever it is staged.

The worker stages an uploaded sample under its sha256, the in-process run
under ``sample_1.exe``; the mock sandbox looks a fixture up by either. A
change to the synthetic image moves its hash, and the fixture filed under the
old one would stop answering, leaving the dynamic and network analysts with no
sandbox data in a stack rehearsal.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.rehearsal.sample import SAMPLE_NAME, sample_bytes

FIXTURES = Path(__file__).resolve().parents[3] / "data" / "samples" / "dynamic"


def test_the_sample_s_hash_names_a_fixture() -> None:
    digest = hashlib.sha256(sample_bytes()).hexdigest()
    fixture = FIXTURES / f"{digest}.json"
    assert fixture.is_file()
    assert json.loads(fixture.read_text())["behavior"]["generic"]


def test_the_sample_s_name_names_the_same_fixture() -> None:
    digest = hashlib.sha256(sample_bytes()).hexdigest()
    by_name = (FIXTURES / f"{Path(SAMPLE_NAME).stem}.json").read_text()
    assert (FIXTURES / f"{digest}.json").read_text() == by_name
