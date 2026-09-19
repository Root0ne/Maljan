"""The technique universe spans Enterprise, Mobile and ICS.

An Android sample's techniques are Mobile ids. While the catalog was Enterprise
only, the validator called every one of them a hallucination and the cascade
dropped the claims that carried them, so a mobile analysis could not produce a
mapped technique at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from maljan.memory import attck_loader


@pytest.fixture(autouse=True)
def _clean_caches():
    attck_loader.reset_caches()
    yield
    attck_loader.reset_caches()


def _write_catalog(tmp_path: Path, payload: object) -> Path:
    path = tmp_path / "attck_valid_ids.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _point_at(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setattr(attck_loader, "VALID_IDS_FILE", path)
    attck_loader.reset_caches()


class TestTheVendoredCatalog:
    def test_the_shipped_catalog_has_one_list_per_domain(self) -> None:
        raw = json.loads(attck_loader.VALID_IDS_FILE.read_text(encoding="utf-8"))
        assert {k for k in raw if not k.startswith("_")} == set(attck_loader.DOMAINS)
        assert raw["enterprise"], "the Enterprise list is the one that cannot be empty"

    def test_a_mobile_technique_is_valid(self) -> None:
        # T1626 (Abuse Elevation Control Mechanism) exists only in Mobile.
        assert "T1626" in attck_loader.valid_ids()
        assert attck_loader.domain_of("T1626") == "mobile"

    def test_an_enterprise_technique_keeps_its_domain(self) -> None:
        assert "T1055" in attck_loader.valid_ids("enterprise")
        assert attck_loader.domain_of("T1055") == "enterprise"

    def test_an_invented_id_belongs_to_no_domain(self) -> None:
        assert attck_loader.domain_of("T9999") is None
        assert "T9999" not in attck_loader.valid_ids()


class TestTheCatalogShapesItAccepts:
    def test_the_old_flat_list_reads_as_enterprise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _point_at(monkeypatch, _write_catalog(tmp_path, ["T1055", "T1059"]))
        assert attck_loader.valid_ids() == {"T1055", "T1059"}
        assert attck_loader.domain_of("T1055") == "enterprise"
        assert attck_loader.valid_ids("mobile") == set()

    def test_the_counted_wrapper_reads_as_enterprise(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _point_at(monkeypatch, _write_catalog(tmp_path, {"count": 1, "technique_ids": ["T1055"]}))
        assert attck_loader.valid_ids("enterprise") == {"T1055"}

    def test_empty_domain_lists_are_tolerated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _point_at(monkeypatch, _write_catalog(tmp_path, {"enterprise": ["T1055"]}))
        assert attck_loader.valid_ids() == {"T1055"}
        assert attck_loader.valid_ids("ics") == set()
        assert attck_loader.domain_of("T0800") is None

    def test_an_unreadable_catalog_is_empty_rather_than_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _point_at(monkeypatch, tmp_path / "absent.json")
        assert attck_loader.valid_ids() == set()


class TestThePlatformMap:
    @pytest.mark.parametrize(
        ("platform", "expected"),
        [
            ("windows", ("Windows",)),
            ("linux", ("Linux",)),
            ("macos", ("macOS",)),
            ("android", ("Android",)),
            ("ios", ("iOS",)),
            ("MacOS", ("macOS",)),
            # A cross-platform or undetermined sample must not filter at all.
            ("multi", ()),
            ("unknown", ()),
            ("", ()),
            (None, ()),
        ],
    )
    def test_each_platform_maps_to_mitre_strings(
        self, platform: str | None, expected: tuple[str, ...]
    ) -> None:
        assert attck_loader.mitre_platforms(platform) == expected

    def test_an_uncatalogued_technique_reports_no_platforms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # With no vendored row, a real id is answered from the bundle cache and
        # an invented one from nowhere.
        monkeypatch.setattr(attck_loader, "_technique_table_cache", ({}, {}))
        monkeypatch.setattr(attck_loader, "_platform_cache", {"T1055": ("Windows",)})
        assert attck_loader.platforms_for("T1055") == ("Windows",)
        assert attck_loader.platforms_for("T9999") == ()


class TestOptionalDomains:
    def test_a_missing_optional_bundle_is_skipped_not_raised(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _boom(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("no network")

        monkeypatch.setattr(attck_loader, "load_attck_data", _boom)
        assert attck_loader.load_domain_data("mobile") is None
        with pytest.raises(RuntimeError):
            attck_loader.load_domain_data("enterprise")

    def test_an_unknown_domain_is_a_programming_error(self) -> None:
        with pytest.raises(ValueError, match="Unknown ATT&CK domain"):
            attck_loader.load_domain_data("cloud")


class TestTheVendoredTechniqueTable:
    """Every dictionary question about a technique answers from data/, not from
    a bundle load: the table ships beside the id catalogue, from the same
    script and the same bundles."""

    def test_the_shipped_table_carries_name_tactics_domain_and_platforms_per_id(self) -> None:
        raw = json.loads(attck_loader.TECHNIQUES_FILE.read_text(encoding="utf-8"))
        assert raw["T1055"]["domain"] == "enterprise"
        assert raw["T1055"]["name"] == "Process Injection"
        assert "privilege-escalation" in raw["T1055"]["tactics"]
        assert "Windows" in raw["T1055"]["platforms"]
        assert raw["T1633"]["domain"] == "mobile"
        assert set(raw["T1633"]["platforms"]) == {"Android", "iOS"}
        # Every id in the table is in the id catalogue, and in the same domain.
        ids = json.loads(attck_loader.VALID_IDS_FILE.read_text(encoding="utf-8"))
        rows = [(t, r) for t, r in raw.items() if not t.startswith("_")]
        assert len(rows) == sum(len(v) for v in ids.values() if isinstance(v, list))
        for tid, row in rows[:200]:
            assert tid in ids[row["domain"]], tid

    def test_every_tactic_a_technique_names_is_in_the_vendored_catalogue(self) -> None:
        raw = json.loads(attck_loader.TECHNIQUES_FILE.read_text(encoding="utf-8"))
        for tid, row in raw.items():
            if tid.startswith("_"):
                continue
            for slug in row["tactics"]:
                assert raw["_tactics"][row["domain"]].get(slug), f"{tid} names {slug}"

    def test_the_entry_answers_the_name_and_the_tactics(self) -> None:
        attck_loader.reset_caches()
        entry = attck_loader.technique_entry("t1055")
        assert entry is not None
        assert (entry.technique_id, entry.name, entry.domain) == (
            "T1055",
            "Process Injection",
            "enterprise",
        )
        assert "privilege-escalation" in entry.tactics
        assert attck_loader.technique_entry("T9999") is None
        assert attck_loader.technique_entry("") is None

    def test_a_kill_chain_slug_resolves_in_its_own_domain_and_falls_back_to_enterprise(
        self,
    ) -> None:
        attck_loader.reset_caches()
        enterprise = attck_loader.tactic_entry("enterprise", "persistence")
        mobile = attck_loader.tactic_entry("mobile", "persistence")
        assert enterprise is not None and mobile is not None
        assert enterprise.tactic_id != mobile.tactic_id
        # A caller with no domain gets the matrix the capabilities view draws.
        assert attck_loader.tactic_entry(None, "persistence") == enterprise
        # A slug a domain does not have falls back rather than answering nothing.
        assert attck_loader.tactic_entry("ics", "resource-development") is not None
        assert attck_loader.tactic_entry("enterprise", "not-a-tactic") is None
        assert attck_loader.tactic_entry("enterprise", "") is None

    def test_the_three_vendored_files_say_which_release_they_came_from(self) -> None:
        versions = set()
        for path in (
            attck_loader.VALID_IDS_FILE,
            attck_loader.TECHNIQUES_FILE,
            attck_loader.RETIRED_IDS_FILE,
        ):
            raw = json.loads(path.read_text(encoding="utf-8"))
            versions.add(raw["_meta"]["attck_version"])
        assert versions == {"19.2"}
        # The metadata keys are not techniques.
        assert attck_loader.platforms_for("_META") == ()
        assert attck_loader.technique_entry("_TACTICS") is None
        assert "_META" not in attck_loader.retired_ids()

    def test_platforms_come_from_the_table_and_nothing_is_loaded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _no_load(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("the bundle catalogue was loaded")

        attck_loader.reset_caches()
        monkeypatch.setattr(attck_loader, "load_all_domains", _no_load)
        assert "Windows" in attck_loader.platforms_for("T1055")
        assert attck_loader.platforms_for("T1633") == ("Android", "iOS")
        assert attck_loader.domain_of("T1633") == "mobile"

    def test_an_invented_id_loads_nothing_and_has_no_platforms(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _no_load(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("the bundle catalogue was loaded")

        attck_loader.reset_caches()
        monkeypatch.setattr(attck_loader, "load_all_domains", _no_load)
        assert attck_loader.platforms_for("T9999") == ()

    def test_a_real_id_the_table_lacks_falls_back_to_the_bundles(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        short_map = tmp_path / "attck_techniques.json"
        short_map.write_text(
            json.dumps({"T1055": {"domain": "enterprise", "platforms": ["Windows"]}}),
            encoding="utf-8",
        )
        monkeypatch.setattr(attck_loader, "TECHNIQUES_FILE", short_map)
        attck_loader.reset_caches()
        loads: list[int] = []

        class _Technique:
            technique_id = "T1059"
            platforms = ["Linux", "Windows"]

        class _Domain:
            techniques = [_Technique()]

        def _load(*_args: object, **_kwargs: object) -> dict[str, _Domain]:
            loads.append(1)
            return {"enterprise": _Domain()}

        monkeypatch.setattr(attck_loader, "load_all_domains", _load)
        assert attck_loader.platforms_for("T1055") == ("Windows",)
        assert loads == []
        assert attck_loader.platforms_for("T1059") == ("Linux", "Windows")
        assert loads == [1]

    def test_an_unreadable_table_is_empty_rather_than_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(attck_loader, "TECHNIQUES_FILE", tmp_path / "absent.json")
        monkeypatch.setattr(attck_loader, "_platform_cache", {})
        attck_loader.reset_caches()
        monkeypatch.setattr(attck_loader, "_platform_cache", {})
        assert attck_loader.platforms_for("T1055") == ()


class TestRetiredIds:
    def test_an_id_the_previous_catalogue_had_names_the_release_that_retired_it(self) -> None:
        attck_loader.reset_caches()
        assert attck_loader.retired_in("T1562.001") == "19.2"
        assert attck_loader.retired_in("t1070.001") == "19.2"
        assert "T1562.001" not in attck_loader.valid_ids()

    def test_an_id_no_catalogue_had_is_not_retired(self) -> None:
        assert attck_loader.retired_in("T9999") is None
        assert attck_loader.retired_in("T1055") is None

    def test_the_replacement_is_the_one_the_bundle_named(self) -> None:
        attck_loader.reset_caches()
        assert attck_loader.revoked_by("T1562.001") == "T1685"
        assert attck_loader.revoked_by("t1070.001") == "T1685.005"
        # A live id was never revoked, and an invented one names no successor.
        assert attck_loader.revoked_by("T1055") is None
        assert attck_loader.revoked_by("T9999") is None

    def test_a_missing_file_is_an_empty_set(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(attck_loader, "RETIRED_IDS_FILE", tmp_path / "absent.json")
        attck_loader.reset_caches()
        assert attck_loader.retired_ids() == {}
        attck_loader.reset_caches()
