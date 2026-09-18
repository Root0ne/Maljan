"""The two tables a reader meets first, checked against the code they describe.

Both had drifted. ``docs/configuration.md`` enumerated sixteen setting groups
when the catalogue held seventeen, so the one place that lists them all omitted
the group two documented settings live in. ``README.md`` listed every seeded
team without its ``triage_pack`` stage, and named the stage after it ``triage``
— which is a different thing, the triage *agent* — so the first table a reader
meets both dropped a stage and reused its name for another.

Neither drift is catchable by reading the docs, because both files are
internally consistent. They are only catchable against the code, which is what
this does: the group list against ``GROUP_ORDER`` and the teams table against
``_builtin_profiles()``.
"""

from __future__ import annotations

import re
from pathlib import Path

from maljan.core.config import _builtin_profiles
from maljan.core.settings_annotations import GROUP_ORDER

ROOT = Path(__file__).resolve().parents[2]
CONFIGURATION = ROOT / "docs" / "configuration.md"
README = ROOT / "README.md"

# Only as far as the catalogue can grow before someone has to write the word
# out; the point is the count in the sentence, not a general numeral parser.
NUMBER_WORDS = {
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}


def _group_table() -> list[str]:
    """The ``| Group | Covers |`` table's first column, in file order."""
    text = CONFIGURATION.read_text(encoding="utf-8")
    start = text.index("| Group | Covers |")
    rows: list[str] = []
    for line in text[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        rows.append(line.split("|")[1].strip())
    return rows


def test_the_documented_group_list_is_the_catalogue_in_its_own_order() -> None:
    assert _group_table() == [label for _, label in GROUP_ORDER]


def test_the_sentence_over_the_table_counts_the_same_groups() -> None:
    text = CONFIGURATION.read_text(encoding="utf-8")
    match = re.search(r"The backend exposes (\w+) groups", text)
    assert match, "the sentence that counts the groups is gone; the table needs one"
    assert NUMBER_WORDS[match.group(1)] == len(GROUP_ORDER)


def _teams_table() -> dict[str, str]:
    """Each seeded team's row in the README, by team name."""
    text = README.read_text(encoding="utf-8")
    start = text.index("| Team | Stages | For |")
    rows: dict[str, str] = {}
    for line in text[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = line.split("|")
        rows[cells[1].strip().strip("`")] = cells[2].strip()
    return rows


def test_every_seeded_team_is_in_the_readme() -> None:
    assert set(_teams_table()) == set(_builtin_profiles())


def test_a_team_that_opens_on_the_pack_says_so() -> None:
    """The stage that was missing from four rows, and only from those four."""
    rows = _teams_table()
    for name, profile in _builtin_profiles().items():
        has_pack = any(stage.key == "triage_pack" for stage in profile.stages)
        mentions_pack = "triage_pack" in rows[name]
        assert mentions_pack is has_pack, name


def test_no_row_names_the_triage_agent_where_it_means_the_pack() -> None:
    """``triage`` and ``triage_pack`` are two stages, and one is not the other."""
    rows = _teams_table()
    for name, profile in _builtin_profiles().items():
        keys = [stage.key for stage in profile.stages]
        bare = re.findall(r"`triage`", rows[name])
        assert bool(bare) is ("triage" in keys), name
