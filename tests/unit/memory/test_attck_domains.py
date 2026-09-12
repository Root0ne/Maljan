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
        assert set(raw) == set(attck_loader.DOMAINS)
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
