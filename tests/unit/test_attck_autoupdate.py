"""Unit tests for the MITRE ATT&CK auto-update path.

Covers tactic-catalogue parsing (incl. the v19 Stealth / Defense Impairment
split), the cache TTL + offline fallback, the index tactic accessors, and the
dynamic tactic resolution (catalogue-first, hardcoded-fallback) used by the
capability matrix. All tests use fixtures — no network calls.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from maljan.extractors.capability_matrix import _TACTIC_BY_SLUG, _resolve_tactic
from maljan.memory.attck_index import ATTCKIndex
from maljan.memory.attck_loader import _load_raw_bundle, _parse_tactics

# ---------------------------------------------------------------------------
# Fixture bundle: a v19-shaped slice (Stealth TA0005 + Defense Impairment TA0112)
# ---------------------------------------------------------------------------


def _tactic_obj(
    stix_id: str,
    ta_id: str,
    shortname: str,
    name: str,
    deprecated: bool = False,
) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": stix_id,
        "name": name,
        "x_mitre_shortname": shortname,
        "x_mitre_deprecated": deprecated,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": ta_id,
                "url": f"https://attack.mitre.org/tactics/{ta_id}/",
            }
        ],
    }


V19_BUNDLE = {
    "objects": [
        # Matrix object defines the canonical left-to-right column order.
        {
            "type": "x-mitre-matrix",
            "tactic_refs": [
                "x-mitre-tactic--exec",
                "x-mitre-tactic--stealth",
                "x-mitre-tactic--impair",
            ],
        },
        _tactic_obj("x-mitre-tactic--stealth", "TA0005", "stealth", "Stealth"),
        _tactic_obj("x-mitre-tactic--impair", "TA0112", "defense-impairment", "Defense Impairment"),
        _tactic_obj("x-mitre-tactic--exec", "TA0002", "execution", "Execution"),
        # Deprecated tactic must be skipped.
        _tactic_obj("x-mitre-tactic--old", "TA0099", "legacy", "Legacy", deprecated=True),
        {"type": "x-mitre-collection", "x_mitre_version": "19.1"},
    ]
}


class TestParseTactics:
    def test_extracts_v19_tactics(self) -> None:
        by_id = {t.tactic_id: t for t in _parse_tactics(V19_BUNDLE)}
        assert by_id["TA0005"].name == "Stealth"
        assert by_id["TA0005"].shortname == "stealth"
        assert by_id["TA0112"].name == "Defense Impairment"
        assert by_id["TA0112"].shortname == "defense-impairment"

    def test_matrix_column_order(self) -> None:
        # tactic_refs order is exec, stealth, impair.
        ids = [t.tactic_id for t in _parse_tactics(V19_BUNDLE)]
        assert ids == ["TA0002", "TA0005", "TA0112"]

    def test_skips_deprecated(self) -> None:
        ids = {t.tactic_id for t in _parse_tactics(V19_BUNDLE)}
        assert "TA0099" not in ids

    def test_empty_bundle(self) -> None:
        assert _parse_tactics({"objects": []}) == []


class TestIndexTacticCatalogue:
    def test_get_tactic_by_slug(self) -> None:
        idx = ATTCKIndex.from_techniques([], tactics=_parse_tactics(V19_BUNDLE))
        t = idx.get_tactic_by_slug("stealth")
        assert t is not None
        assert t.tactic_id == "TA0005"
        assert t.name == "Stealth"

    def test_get_tactic_by_id(self) -> None:
        idx = ATTCKIndex.from_techniques([], tactics=_parse_tactics(V19_BUNDLE))
        t = idx.get_tactic_by_id("TA0112")
        assert t is not None
        assert t.name == "Defense Impairment"

    def test_tactics_in_matrix_order(self) -> None:
        idx = ATTCKIndex.from_techniques([], tactics=_parse_tactics(V19_BUNDLE))
        assert [t.tactic_id for t in idx.tactics] == ["TA0002", "TA0005", "TA0112"]

    def test_unknown_slug_returns_none(self) -> None:
        idx = ATTCKIndex.from_techniques([], tactics=[])
        assert idx.get_tactic_by_slug("nope") is None


def _write_bundle(path: Path, version: str) -> None:
    path.write_text(
        json.dumps({"objects": [{"type": "x-mitre-collection", "x_mitre_version": version}]}),
        encoding="utf-8",
    )


def _age(path: Path, days: float) -> None:
    old = time.time() - days * 86400
    os.utime(path, (old, old))


class TestCacheTTL:
    def test_fresh_cache_is_used_without_fetch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = tmp_path / "b.json"
        _write_bundle(cache, "fresh")

        def boom(url: str) -> dict:
            raise AssertionError("fresh cache must not trigger a fetch")

        monkeypatch.setattr("maljan.memory.attck_loader._fetch_bundle", boom)
        raw = _load_raw_bundle("http://x", cache, force_refresh=False, max_age_days=30)
        assert raw["objects"][0]["x_mitre_version"] == "fresh"

    def test_stale_cache_refreshes(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache = tmp_path / "b.json"
        _write_bundle(cache, "old")
        _age(cache, 60)
        monkeypatch.setattr(
            "maljan.memory.attck_loader._fetch_bundle",
            lambda url: {"objects": [{"type": "x-mitre-collection", "x_mitre_version": "new"}]},
        )
        raw = _load_raw_bundle("http://x", cache, force_refresh=False, max_age_days=30)
        assert raw["objects"][0]["x_mitre_version"] == "new"

    def test_offline_refresh_falls_back_to_stale(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = tmp_path / "b.json"
        _write_bundle(cache, "stale")
        _age(cache, 60)

        def fail(url: str) -> dict:
            raise RuntimeError("network down")

        monkeypatch.setattr("maljan.memory.attck_loader._fetch_bundle", fail)
        raw = _load_raw_bundle("http://x", cache, force_refresh=False, max_age_days=30)
        # A failed refresh must not break the run — the stale cache is reused.
        assert raw["objects"][0]["x_mitre_version"] == "stale"

    def test_max_age_zero_disables_refresh(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = tmp_path / "b.json"
        _write_bundle(cache, "ancient")
        _age(cache, 9999)

        def boom(url: str) -> dict:
            raise AssertionError("max_age<=0 must not refresh")

        monkeypatch.setattr("maljan.memory.attck_loader._fetch_bundle", boom)
        raw = _load_raw_bundle("http://x", cache, force_refresh=False, max_age_days=0)
        assert raw["objects"][0]["x_mitre_version"] == "ancient"

    def test_missing_cache_offline_raises(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cache = tmp_path / "missing.json"

        def fail(url: str) -> dict:
            raise RuntimeError("network down")

        monkeypatch.setattr("maljan.memory.attck_loader._fetch_bundle", fail)
        with pytest.raises(RuntimeError):
            _load_raw_bundle("http://x", cache, force_refresh=False, max_age_days=30)


class _FakeIndex:
    """Minimal stand-in exposing get_tactic_by_slug for _resolve_tactic."""

    def __init__(self, tactics: list) -> None:
        self._by_slug = {t.shortname: t for t in tactics}

    def get_tactic_by_slug(self, slug: str):
        return self._by_slug.get(slug)


class TestResolveTactic:
    def test_dynamic_resolution_wins(self) -> None:
        idx = _FakeIndex(_parse_tactics(V19_BUNDLE))
        # A NEW v19 tactic not in the canonical table resolves straight from the
        # bundle (tid + live name both come from the catalogue).
        assert _resolve_tactic(idx, "defense-impairment") == ("TA0112", "Defense Impairment")
        # 2026-07 audit (Bulgu #5): for a KNOWN Enterprise tactic the canonical
        # display name is pinned, so a v19+ bundle relabelling TA0005 to
        # "Stealth" no longer leaks into exports — it stays "Defense Evasion".
        assert _resolve_tactic(idx, "stealth") == ("TA0005", "Defense Evasion")

    def test_fallback_to_hardcoded_without_index(self) -> None:
        assert _resolve_tactic(None, "defense-evasion") == _TACTIC_BY_SLUG["defense-evasion"]

    def test_unknown_slug_without_index(self) -> None:
        # Unknown slug with no catalogue echoes the slug back with an empty id.
        assert _resolve_tactic(None, "made-up") == ("", "made-up")

    def test_empty_slug(self) -> None:
        assert _resolve_tactic(None, "") == ("", "")
