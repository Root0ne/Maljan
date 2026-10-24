"""The checker's tables point at code that exists and at surfaces it knows.

The web field map names a source file for each tab and each field, under
``apps/web/src``; the mapping table and the filter table name only surfaces
the inventory defines. A rename in the console or the API that leaves the map
behind fails here rather than silently checking nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.audit import surfaces

ROOT = Path(__file__).resolve().parents[3]
SPEC = json.loads(surfaces.WEB_FIELDS.read_text(encoding="utf-8"))
ROOTS = {"report", "job", "stix", "evidence", "events", "follow_ups"}


def _file(ref: str) -> Path:
    return ROOT / SPEC["base"] / ref.split(":", 1)[0]


def test_every_tab_and_field_names_a_console_file() -> None:
    missing = []
    for name, tab in SPEC["tabs"].items():
        if not _file(tab["route"]).is_file():
            missing.append((name, tab["route"]))
        for item in tab["fields"]:
            if not _file(item["ref"]).is_file():
                missing.append((name, item["ref"]))
            assert item["path"].partition(":")[0] in ROOTS, item["path"]
    assert missing == []


def test_the_section_rules_name_console_files() -> None:
    routing = SPEC["section_routing"]
    for ref in (
        routing["ref"],
        routing["detection_draws_only"]["ref"],
        SPEC["section_body"]["ref"],
    ):
        assert _file(ref).is_file(), ref


def test_the_mapping_and_filters_name_known_surfaces() -> None:
    known = set(surfaces.SURFACES) | {
        "capability_matrix",
        "report_row.mitre_techniques",
    }
    for row in surfaces.MAPPING:
        assert row["surface"] in known, row
        assert row["rule"] in {"all", "published", "same", "declined"}, row
    for row in surfaces.FILTERS:
        assert row["surface"] in surfaces.SURFACES, row


def test_every_surface_names_a_file_that_exists() -> None:
    for name, where in surfaces.SURFACES.items():
        ref = where["ref"].split(":", 1)[0]
        assert (ROOT / ref).exists(), (name, ref)
