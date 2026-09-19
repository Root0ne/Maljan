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
        assert problems == ["duplicate windows technique T1685 'One'"]

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


class TestTheLinuxBlock:
    """The ELF vocabulary mirrors the Windows one's structure and its
    discipline: an association, never a verdict, and only names whose presence
    says something a reader could not have assumed."""

    def test_every_linux_rule_names_a_technique_the_catalogue_allows_on_linux(self) -> None:
        from maljan.memory.attck_loader import technique_entry

        script = _script()
        linux = [t for t in script.ATTCK_TECHNIQUES if "linux" in (t.get("platforms") or [])]
        assert linux, "the catalogue ships no Linux technique rules"
        for rule in linux:
            entry = technique_entry(rule["technique_id"])
            assert entry is not None, rule["technique_id"]
            assert "Linux" in entry.platforms, rule["technique_id"]

    def test_every_api_a_linux_rule_names_is_in_a_linux_category(self) -> None:
        script = _script()
        known = {api for _tier, apis in script.LINUX_CATEGORIES.values() for api in apis}
        for rule in script.ATTCK_TECHNIQUES:
            if "linux" not in (rule.get("platforms") or []):
                continue
            assert set(rule["apis"]) <= known, rule["technique_id"]

    def test_no_libc_name_is_claimed_by_two_categories(self) -> None:
        script = _script()
        owners: dict[str, list[str]] = {}
        for category, (_tier, apis) in script.LINUX_CATEGORIES.items():
            for api in apis:
                owners.setdefault(api, []).append(category)
        assert [api for api, cats in owners.items() if len(cats) > 1] == []

    def test_the_groups_that_would_be_a_guess_are_absent(self) -> None:
        """Linux persistence is a path, not a call; the registry has no
        counterpart. A category that cannot be evidenced by a symbol name is
        not authored at all."""
        script = _script()
        assert not {"registry", "persistence", "keylogging", "credential"} & set(
            script.LINUX_CATEGORIES
        )

    def test_the_symbols_that_ordinary_software_lives_on_are_never_a_rule(self) -> None:
        """Measured, then written down: no Linux technique rule may rest on
        privilege dropping, on ordinary networking or on ordinary process
        control, because every daemon on a system does all three."""
        script = _script()
        ordinary = (
            set(script.LINUX_CATEGORIES["privilege"][1])
            | set(script.LINUX_CATEGORIES["network"][1])
            | set(script.LINUX_CATEGORIES["process"][1])
            | set(script.LINUX_CATEGORIES["discovery"][1])
        )
        checked = 0
        for rule in script.ATTCK_TECHNIQUES:
            if "linux" not in (rule.get("platforms") or []):
                continue
            assert not (set(rule["apis"]) & ordinary), rule["technique_id"]
            checked += 1
        assert checked >= 3

    def test_only_a_measured_minority_of_the_block_is_ever_labelled(self) -> None:
        """A group whose bare presence labels more than one ordinary binary in
        a hundred is an association with corroborators, not a tier."""
        script = _script()
        labelled = {
            group
            for group, (tier, _apis) in script.LINUX_CATEGORIES.items()
            if tier in {script.HIGH, script.MEDIUM}
        }
        assert labelled == {"process_injection"}
        # And even that one waits for a name that reaches into another process.
        assert set(script.LINUX_FLAG_GATES) == labelled

    def test_a_group_that_means_little_alone_names_what_would_give_it_weight(self) -> None:
        script = _script()
        for group in ("privilege", "network", "execution", "anti_debug", "crypto", "process"):
            assert script.LINUX_CORROBORATORS.get(group), group

    def test_a_corroborator_and_a_gate_name_a_symbol_the_block_actually_has(self) -> None:
        script = _script()
        known = {api for _tier, apis in script.LINUX_CATEGORIES.values() for api in apis}
        for named in (script.LINUX_CORROBORATORS, script.LINUX_FLAG_GATES):
            for group, names in named.items():
                assert set(names) <= known, group

    def test_the_windows_block_carries_no_gate(self) -> None:
        """The label there is the tier alone, as it has always been."""
        assert _script().FLAG_GATES_BY_PLATFORM["windows"] == {}
