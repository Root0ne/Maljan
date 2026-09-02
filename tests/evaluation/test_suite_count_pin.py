"""The manuscript's passing-test count is a recorded fact, not a live one.

Any test added to this tree used to move the number in a paper under
submission (2,716 -> 2,719 on 2026-09-02). The count now describes the suite
at study time and lives in an artefact next to the other paper inputs.
"""

import json
from pathlib import Path

from tests.evaluation import paper_facts

_ART = Path(__file__).with_name("test_suite_count.json")


def test_artifact_exists_and_is_well_formed():
    data = json.loads(_ART.read_text())
    assert data["count"] == 2716
    assert len(data["measured_at_commit"]) >= 7
    assert data["measured_on"] == "2026-09-02"


def test_recorded_count_is_what_the_paper_prints():
    assert paper_facts.recorded_suite_count() == 2716
    assert paper_facts._format_count(2716) == "2,716"
