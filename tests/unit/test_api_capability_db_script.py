"""The API capability builder regenerates the files it owns.

Its source was curated against an older ATT&CK release, and its own check
refuses an id the vendored catalogue no longer carries — so the two retired
ids in it left the shipped data file with no working generator. The retarget
is mechanical now: the vendored set's ``revoked_by`` decides, and an id it
names no successor for is dropped and said so.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _ROOT / "scripts" / "knowledge" / "build_api_capability_db.py"


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("build_api_capability_db", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _rule(tid: str, name: str = "A rule") -> dict[str, Any]:
    return {
        "technique_id": tid,
        "name": name,
        "min_apis": 2,
        "confidence_base": 0.4,
        "confidence_max": 0.6,
        "apis": ["OpenProcess", "VirtualAllocEx"],
    }


class TestTheSourceIsSoundAgainstTheShippedCatalogue:
    def test_the_builder_accepts_its_own_tables(self) -> None:
        script = _script()
        techniques, _moved, dropped = script._retargeted(script.ATTCK_TECHNIQUES)
        assert dropped == []
        assert script._validate(techniques) == []

    def test_the_retired_ids_are_followed_to_the_id_that_replaced_them(self) -> None:
        script = _script()
        _techniques, moved, _dropped = script._retargeted(script.ATTCK_TECHNIQUES)
        assert moved == [("T1562.001", "T1685"), ("T1562.006", "T1685")]

    def test_every_id_the_builder_emits_is_in_the_vendored_catalogue(self) -> None:
        script = _script()
        techniques, _moved, _dropped = script._retargeted(script.ATTCK_TECHNIQUES)
        valid = script._vendored_ids()
        assert valid
        assert {t["technique_id"] for t in techniques} <= valid

    def test_the_shipped_file_is_what_the_builder_writes(self, tmp_path: Path) -> None:
        """No hand edits: the data file and its generator agree byte for byte."""
        script = _script()
        behaviour, attck = tmp_path / "behaviour.json", tmp_path / "attck.json"
        script._BEHAVIOUR_OUT = behaviour
        script._ATTCK_OUT = attck
        script._ROOT = tmp_path  # only the summary line reads it
        assert script.main() == 0
        for written, shipped in (
            (behaviour, _ROOT / "data" / "api_behaviour_map_v1.json"),
            (attck, _ROOT / "data" / "api_attck_map_v1.json"),
        ):
            assert written.read_text(encoding="utf-8") == shipped.read_text(encoding="utf-8")


class TestTheRetarget:
    def test_an_id_the_release_kept_is_left_alone(self) -> None:
        script = _script()
        kept, moved, dropped = script._retargeted([_rule("T1055")])
        assert [t["technique_id"] for t in kept] == ["T1055"]
        assert (moved, dropped) == ([], [])

    def test_an_id_with_no_named_successor_is_dropped_rather_than_guessed_at(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _script()
        monkeypatch.setattr(script, "_vendored_replacements", dict)
        kept, moved, dropped = script._retargeted([_rule("T1562.001"), _rule("T1055")])
        assert [t["technique_id"] for t in kept] == ["T1055"]
        assert (moved, dropped) == ([], ["T1562.001"])

    def test_a_successor_the_release_does_not_carry_is_no_successor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        script = _script()
        monkeypatch.setattr(script, "_vendored_replacements", lambda: {"T1562.001": "T9999"})
        _kept, moved, dropped = script._retargeted([_rule("T1562.001")])
        assert (moved, dropped) == ([], ["T1562.001"])

    def test_the_rule_keeps_everything_but_its_id(self) -> None:
        script = _script()
        kept, _moved, _dropped = script._retargeted([_rule("T1562.001", "Disable or Modify Tools")])
        assert kept == [{**_rule("T1685", "Disable or Modify Tools")}]


class TestTheDuplicateCheck:
    def test_two_rules_on_one_id_are_allowed_when_they_are_different_rules(self) -> None:
        """A release that folds two sub-techniques into one leaves two rules
        pointing at it, and each keeps its own evidence."""
        script = _script()
        problems = script._validate([_rule("T1685", "One"), _rule("T1685", "Another")])
        assert problems == []

    def test_the_same_rule_twice_is_still_a_problem(self) -> None:
        script = _script()
        problems = script._validate([_rule("T1685", "One"), _rule("T1685", "One")])
        assert problems == ["duplicate technique T1685 'One'"]

    def test_an_id_outside_the_catalogue_is_a_problem(self) -> None:
        script = _script()
        assert script._validate([_rule("T9999")]) == ["T9999 is not in attck_valid_ids.json"]


class TestWhatTheVendoredSetSays:
    def test_the_replacements_come_from_the_revoked_by_rows_alone(self) -> None:
        script = _script()
        replacements = script._vendored_replacements()
        assert replacements["T1562.001"] == "T1685"
        assert "_meta" not in replacements
        retired = json.loads((_ROOT / "data" / "attck_retired_ids.json").read_text())
        for tid, row in retired.items():
            if tid.startswith("_") or "revoked_by" not in row:
                assert tid not in replacements
