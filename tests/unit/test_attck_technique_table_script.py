"""The autoupdate script vendors the technique table beside the id catalogue."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "knowledge"
    / "prepare_attck_malware_fixtures.py"
)


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("prepare_attck_malware_fixtures", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _technique(tid: str, platforms: list[str], **extra: Any) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
        "x_mitre_platforms": platforms,
        **extra,
    }


def _tactic(tactic_id: str, slug: str, name: str, **extra: Any) -> dict[str, Any]:
    return {
        "type": "x-mitre-tactic",
        "external_references": [{"source_name": "mitre-attack", "external_id": tactic_id}],
        "x_mitre_shortname": slug,
        "name": name,
        **extra,
    }


class TestTheTechniqueTable:
    def test_each_active_technique_gets_its_name_tactics_domain_and_sorted_platforms(self) -> None:
        script = _script()
        objects = [
            _technique(
                "T1055",
                ["Windows", "Linux", "macOS"],
                name="Process Injection",
                kill_chain_phases=[
                    {"kill_chain_name": "mitre-attack", "phase_name": "stealth"},
                    {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
                    {"kill_chain_name": "other", "phase_name": "ignored"},
                ],
            ),
            _technique("T1583", ["PRE"], name="Acquire Infrastructure"),
            _technique("T1000", ["Windows"], revoked=True),
            _technique("T1001", ["Windows"], x_mitre_deprecated=True),
            {"type": "relationship"},
        ]
        assert script._extract_technique_table(objects, "enterprise") == {
            "T1055": {
                "domain": "enterprise",
                "name": "Process Injection",
                "tactics": ["stealth", "privilege-escalation"],
                "platforms": ["Linux", "Windows", "macOS"],
            },
            "T1583": {
                "domain": "enterprise",
                "name": "Acquire Infrastructure",
                "tactics": [],
                "platforms": ["PRE"],
            },
        }

    def test_an_id_in_two_domains_keeps_the_first_in_domain_order(self) -> None:
        script = _script()
        merged = script.merge_technique_tables(
            {
                "mobile": {"T1000": {"domain": "mobile", "platforms": ["Android"]}},
                "enterprise": {"T1000": {"domain": "enterprise", "platforms": ["Windows"]}},
                "ics": {"T0800": {"domain": "ics", "platforms": []}},
            }
        )
        assert list(merged) == ["T0800", "T1000"]
        assert merged["T1000"]["domain"] == "enterprise"

    def test_the_file_is_written_sorted_with_the_tactic_catalogue_and_read_back(
        self, tmp_path: Path
    ) -> None:
        script = _script()
        out = tmp_path / "attck_techniques.json"
        script.write_technique_table(
            {
                "T1055": {
                    "domain": "enterprise",
                    "name": "Process Injection",
                    "tactics": ["stealth"],
                    "platforms": ["Windows"],
                }
            },
            {"enterprise": {"stealth": {"id": "TA0005", "name": "Stealth"}}},
            out,
            "19.2",
        )
        assert json.loads(out.read_text(encoding="utf-8")) == {
            "_meta": {"attck_version": "19.2"},
            "_tactics": {
                "enterprise": {"stealth": {"id": "TA0005", "name": "Stealth"}},
                "mobile": {},
                "ics": {},
            },
            "T1055": {
                "domain": "enterprise",
                "name": "Process Injection",
                "tactics": ["stealth"],
                "platforms": ["Windows"],
            },
        }


class TestTheTacticCatalogue:
    def test_every_active_matrix_column_is_keyed_by_its_kill_chain_slug(self) -> None:
        script = _script()
        objects = [
            _tactic("TA0005", "stealth", "Stealth"),
            _tactic("TA0003", "persistence", "Persistence"),
            _tactic("TA0099", "gone", "Gone", x_mitre_deprecated=True),
            {"type": "x-mitre-tactic", "x_mitre_shortname": "nameless"},
        ]
        assert script._extract_tactics(objects) == {
            "persistence": {"id": "TA0003", "name": "Persistence"},
            "stealth": {"id": "TA0005", "name": "Stealth"},
        }


class TestTheRetiredSet:
    def test_ids_the_previous_catalogue_had_are_kept_with_their_release(self) -> None:
        script = _script()
        retired = script.retired_ids(
            {"enterprise": {"T1055", "T1562.001"}, "mobile": {"T1400"}},
            {"enterprise": ["T1055"], "mobile": ["T1400"], "ics": []},
            "19.2",
        )
        assert retired == {"T1562.001": {"domain": "enterprise", "retired_in": "19.2"}}

    def test_an_earlier_retirement_keeps_its_release_and_a_comeback_leaves(self) -> None:
        script = _script()
        existing = {
            "T1500": {"domain": "enterprise", "retired_in": "18.0"},
            "T1055": {"domain": "enterprise", "retired_in": "18.0"},
        }
        retired = script.retired_ids(
            {"enterprise": {"T1055", "T1562.001"}},
            {"enterprise": ["T1055"], "mobile": [], "ics": []},
            "19.2",
            existing,
        )
        assert retired == {
            "T1500": {"domain": "enterprise", "retired_in": "18.0"},
            "T1562.001": {"domain": "enterprise", "retired_in": "19.2"},
        }

    def test_the_release_is_read_from_the_bundle(self) -> None:
        script = _script()
        bundle = {"objects": [{"type": "x-mitre-collection", "x_mitre_version": "19.2"}]}
        assert script.bundle_version(bundle) == "19.2"
        assert script.bundle_version({"objects": []}) == "unknown"


class TestWhatRevokedAnId:
    def test_the_bundle_s_own_relationship_is_the_only_source(self) -> None:
        script = _script()
        old = {**_technique("T1562.001", ["Windows"]), "id": "attack-pattern--old", "revoked": True}
        new = {**_technique("T1685", ["Windows"]), "id": "attack-pattern--new"}
        objects = [
            old,
            new,
            {
                "type": "relationship",
                "relationship_type": "revoked-by",
                "source_ref": "attack-pattern--old",
                "target_ref": "attack-pattern--new",
            },
            {
                "type": "relationship",
                "relationship_type": "subtechnique-of",
                "source_ref": "attack-pattern--old",
                "target_ref": "attack-pattern--new",
            },
        ]
        assert script.revoked_by(objects, script._build_index(objects)) == {"T1562.001": "T1685"}

    def test_a_retired_row_carries_its_replacement_and_a_row_without_one_does_not(self) -> None:
        script = _script()
        retired = script.retired_ids(
            {"enterprise": {"T1055", "T1562.001", "T1499"}},
            {"enterprise": ["T1055", "T1685"], "mobile": [], "ics": []},
            "19.2",
            None,
            {"T1562.001": "T1685", "T1499": "T9999"},
        )
        # T9999 is not in this release, so the row states the retirement alone.
        assert retired == {
            "T1499": {"domain": "enterprise", "retired_in": "19.2"},
            "T1562.001": {
                "domain": "enterprise",
                "retired_in": "19.2",
                "revoked_by": "T1685",
            },
        }


class TestTheTwoDomainTuplesAgree:
    def test_the_script_and_the_loader_spell_the_domains_the_same(self) -> None:
        from maljan.memory import attck_loader

        assert _script().DOMAINS == attck_loader.DOMAINS


class TestIcsPlatformsAreNotTheStringNone:
    def test_the_literal_none_is_dropped(self) -> None:
        script = _script()
        rows = script._extract_technique_table(
            [_technique("T0800", ["None"], name="Activate")], "ics"
        )
        assert rows == {
            "T0800": {"domain": "ics", "name": "Activate", "tactics": [], "platforms": []}
        }
