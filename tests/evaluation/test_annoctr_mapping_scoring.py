"""The AnnoCTR replication decides whether C5a holds on a second corpus, so its
extraction is pinned here.

The metrics are deliberately not re-implemented — `eval_annoctr_mapping` imports
`eval_technique_mapping._evaluate`, because a replication that quietly redefines its
measure is not a replication. What *is* new, and therefore what can silently be wrong,
is how AnnoCTR's annotations become (evidence, technique) pairs:

  * ``_technique_id`` must turn ``…/techniques/T1574/002`` into ``T1574.002``. Collapsing
    sub-techniques to their parent would inflate top-1 for every backend equally and make
    the corpus look easier than it is.
  * ``_iter_json_objects`` must read AnnoCTR's pretty-printed ``.jsonl``, which is not one
    object per line. A line-by-line reader throws on the second line — the first thing
    that happened when this corpus was opened.
  * ``restrict_to_index`` must drop labels our ATT&CK bundle does not contain, because
    they are unreachable for every backend and would depress all three identically while
    hiding the coverage loss. The count it returns is published for that reason.

Network-free, corpus-free, model-free.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_EVAL_DIR = Path(__file__).resolve().parent
if str(_EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(_EVAL_DIR))

from eval_annoctr_mapping import (  # noqa: E402
    _iter_json_objects,
    _technique_id,
    load_pairs,
    restrict_to_index,
)


class TestTechniqueIdExtraction:
    def test_a_top_level_technique(self) -> None:
        assert _technique_id("https://attack.mitre.org/techniques/T1486") == "T1486"

    def test_a_sub_technique_keeps_its_suffix(self) -> None:
        """T1574/002 is Hijack Execution Flow: DLL Side-Loading — not plain T1574."""
        assert _technique_id("https://attack.mitre.org/techniques/T1574/002") == "T1574.002"

    def test_a_group_link_is_not_a_technique(self) -> None:
        assert _technique_id("https://attack.mitre.org/groups/G0129") is None

    def test_a_tactic_link_is_not_a_technique(self) -> None:
        assert _technique_id("https://attack.mitre.org/tactics/TA0002") is None

    def test_a_missing_link_is_handled(self) -> None:
        assert _technique_id(None) is None
        assert _technique_id("") is None

    def test_a_trailing_slash_does_not_produce_a_bogus_subtechnique(self) -> None:
        assert _technique_id("https://attack.mitre.org/techniques/T1486/") == "T1486"


class TestPrettyPrintedJsonlIsReadable:
    def test_objects_spanning_multiple_lines_are_parsed(self) -> None:
        """AnnoCTR ships this shape; a line-oriented reader fails on line 2."""
        raw = '{\n  "a": 1\n}\n{\n  "a": 2\n}\n'
        assert [o["a"] for o in _iter_json_objects(raw)] == [1, 2]

    def test_true_json_lines_still_work(self) -> None:
        """So a future release switching format does not break the harness."""
        raw = '{"a": 1}\n{"a": 2}\n'
        assert [o["a"] for o in _iter_json_objects(raw)] == [1, 2]

    def test_an_empty_file_yields_nothing(self) -> None:
        assert list(_iter_json_objects("   \n\n")) == []


class TestPairConstruction:
    @staticmethod
    def _write(tmp_path: Path, objs: str) -> Path:
        (tmp_path / "test.jsonl").write_text(objs, encoding="utf-8")
        return tmp_path

    def test_the_mention_is_scored_in_its_written_context(self, tmp_path: Path) -> None:
        """Scoring the mention alone would measure an easier task than production's."""
        d = self._write(
            tmp_path,
            '{"mention": "Dll-Sideloading trojans", "context_left": "Mustang Panda used ",'
            ' "context_right": " with temporal C2",'
            ' "label_link": "https://attack.mitre.org/techniques/T1574/002"}',
        )
        pairs = load_pairs(d, ("test",))
        assert len(pairs) == 1
        text, label = pairs[0]
        assert label == "T1574.002"
        assert "Mustang Panda used" in text and "temporal C2" in text
        assert "Dll-Sideloading trojans" in text

    def test_non_technique_entities_are_skipped(self, tmp_path: Path) -> None:
        d = self._write(
            tmp_path,
            '{"mention": "Mustang Panda", "label_link": "https://attack.mitre.org/groups/G0129"}'
            '\n{"mention": "ransomware",'
            ' "label_link": "https://attack.mitre.org/techniques/T1486"}',
        )
        assert [lab for _, lab in load_pairs(d, ("test",))] == ["T1486"]

    def test_a_missing_split_is_not_an_error(self, tmp_path: Path) -> None:
        """Splits are a CLI argument; a typo should yield no pairs, not a crash."""
        assert load_pairs(tmp_path, ("nonexistent",)) == []

    def test_a_blank_mention_with_no_context_is_dropped(self, tmp_path: Path) -> None:
        d = self._write(
            tmp_path,
            '{"mention": "  ", "context_left": "", "context_right": "",'
            ' "label_link": "https://attack.mitre.org/techniques/T1486"}',
        )
        assert load_pairs(d, ("test",)) == []


class _Index:
    def __init__(self, ids: list[str]) -> None:
        self.techniques = dict.fromkeys(ids)


class TestRestrictToIndex:
    def test_labels_our_bundle_lacks_are_dropped_and_counted(self) -> None:
        pairs = [("a", "T1486"), ("b", "T9999"), ("c", "T1055")]
        kept, dropped = restrict_to_index(pairs, _Index(["T1486", "T1055"]))
        assert [lab for _, lab in kept] == ["T1486", "T1055"]
        assert dropped == 1

    def test_the_comparison_is_case_insensitive(self) -> None:
        kept, dropped = restrict_to_index([("a", "t1486")], _Index(["T1486"]))
        assert dropped == 0 and len(kept) == 1

    def test_nothing_reachable_is_reported_rather_than_hidden(self) -> None:
        kept, dropped = restrict_to_index([("a", "T9999")], _Index(["T1486"]))
        assert kept == [] and dropped == 1


@pytest.mark.parametrize(
    ("link", "expected"),
    [
        ("https://attack.mitre.org/techniques/T1027", "T1027"),
        ("https://attack.mitre.org/techniques/T1027/002", "T1027.002"),
        ("http://attack.mitre.org/techniques/T1055/012", "T1055.012"),
        ("https://attack.mitre.org/software/S0002", None),
    ],
)
def test_technique_id_table(link: str, expected: str | None) -> None:
    assert _technique_id(link) == expected
