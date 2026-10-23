"""Every in-process YARA pass states an engine whose case folding is broken."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from maljan.core import ctype_locale
from maljan.providers.static.capa_yara import CapaYaraStaticProvider
from maljan.tools import rules

PROBLEM = "the YARA engine's case folding is broken in this process's locale (test)"


class _Compiled:
    def match(self, data: bytes, timeout: int) -> list[object]:
        return []


class _Layer:
    _rules = [object()]
    _yara_rules = _Compiled()
    _yara_id_map: dict[str, str] = {}


def test_the_yara_scan_tool_carries_the_engine_note(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(rules, "_yara_layer", lambda _ruleset: _Layer())
    target = tmp_path / "s.bin"
    target.write_bytes(b"x")

    monkeypatch.setattr(ctype_locale, "yara_case_folding_problem", lambda: PROBLEM)
    assert rules.yara_scan(path=str(target))["engine_note"] == PROBLEM

    monkeypatch.setattr(ctype_locale, "yara_case_folding_problem", lambda: None)
    assert "engine_note" not in rules.yara_scan(path=str(target))


class _Stub:
    """A YaraLayer whose engine is compiled (``native``) or the regex fallback."""

    def __init__(self, native: bool) -> None:
        self._yara_rules = object() if native else None

    def scan(self, _data: bytes) -> list[object]:
        return []


def _provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, native: bool) -> Any:
    from maljan.analysis.yara_layer import YaraLayer

    (tmp_path / "rules.yml").write_text("rules: []\n")
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ")
    provider = CapaYaraStaticProvider.__new__(CapaYaraStaticProvider)
    provider._yara = SimpleNamespace(rules_dir=str(tmp_path))  # type: ignore[attr-defined]
    monkeypatch.setattr(provider, "_run_capa", lambda _path: None, raising=False)
    monkeypatch.setattr(YaraLayer, "from_yaml", classmethod(lambda cls, _p: _Stub(native)))
    return provider, str(sample)


def test_a_scan_with_no_hit_still_states_a_broken_engine(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    provider, sample = _provider(tmp_path, monkeypatch, native=True)
    monkeypatch.setattr(ctype_locale, "yara_case_folding_problem", lambda: PROBLEM)

    bundle = provider.collect_evidence(sample)

    assert bundle is not None
    assert PROBLEM in bundle.technical_evidence["yara"]
    (entry,) = bundle.entries
    assert entry.payload["engine_note"] == PROBLEM
    assert entry.payload["matches"] == []


def test_a_scan_with_hits_states_it_beside_them(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    provider, sample = _provider(tmp_path, monkeypatch, native=True)
    hits = [{"rule": "r", "strings": ["s"], "technique": "T1055"}]
    monkeypatch.setattr(provider, "_run_yara", lambda _path: hits, raising=False)
    provider._native_yara_ran = True
    monkeypatch.setattr(ctype_locale, "yara_case_folding_problem", lambda: PROBLEM)

    bundle = provider.collect_evidence(sample)

    assert bundle is not None
    assert PROBLEM in bundle.technical_evidence["yara"]
    assert bundle.entries[0].payload["engine_note"] == PROBLEM


def test_the_regex_fallback_is_given_no_note(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    provider, sample = _provider(tmp_path, monkeypatch, native=False)
    monkeypatch.setattr(ctype_locale, "yara_case_folding_problem", lambda: PROBLEM)

    assert provider.collect_evidence(sample) is None
