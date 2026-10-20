"""A bundle that cannot be fetched stops the run; it is never read as a domain with no ids."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = (
    Path(__file__).resolve().parents[3]
    / "scripts"
    / "knowledge"
    / "prepare_attck_malware_fixtures.py"
)
_SHA = "a" * 40


def _script() -> Any:
    spec = importlib.util.spec_from_file_location("prepare_attck_fixtures_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bundle(*ids: str) -> dict[str, Any]:
    objects: list[dict[str, Any]] = [
        {"type": "x-mitre-collection", "x_mitre_version": "1.0", "id": "x-mitre-collection--1"}
    ]
    for i, tid in enumerate(ids):
        objects.append(
            {
                "type": "attack-pattern",
                "id": f"attack-pattern--{tid}-{i}",
                "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            }
        )
    return {"objects": objects}


class _Fetcher:
    def __init__(self, bundles: dict[str, dict[str, Any] | None]) -> None:
        self.bundles = bundles
        self.calls: list[tuple[str, str]] = []

    def __call__(
        self, url: str, cache_dir: Path | None, domain: str = "enterprise"
    ) -> dict[str, Any]:
        self.calls.append((domain, url))
        bundle = self.bundles[domain]
        if bundle is None:
            raise SystemExit(1)
        return bundle


def _paths(tmp_path: Path) -> dict[str, Any]:
    return {
        "valid_ids_out": tmp_path / "valid.json",
        "retired_out": tmp_path / "retired.json",
        "techniques_out": tmp_path / "tech.json",
        "labeled_out": None,
        "cache_dir": None,
    }


def _previous(path: Path) -> str:
    path.write_text(
        json.dumps({"enterprise": ["T1001"], "mobile": ["T1400"], "ics": ["T0800"]}),
        encoding="utf-8",
    )
    return path.read_text(encoding="utf-8")


def test_a_failed_optional_bundle_exits_non_zero_and_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    before = _previous(paths["valid_ids_out"])
    fetcher = _Fetcher({"enterprise": _bundle("T1001"), "mobile": None, "ics": _bundle("T0800")})
    with pytest.raises(SystemExit) as stopped:
        mod.prepare(fetcher=fetcher, **paths)
    assert stopped.value.code == 1
    assert "mobile bundle unavailable" in capsys.readouterr().err
    assert paths["valid_ids_out"].read_text(encoding="utf-8") == before
    assert not paths["retired_out"].exists()
    assert not paths["techniques_out"].exists()


def test_every_domain_fetched_retires_only_what_left_a_fetched_domain(tmp_path: Path) -> None:
    mod = _script()
    paths = _paths(tmp_path)
    _previous(paths["valid_ids_out"])
    fetcher = _Fetcher(
        {"enterprise": _bundle("T1001"), "mobile": _bundle("T1400"), "ics": _bundle()}
    )
    mod.prepare(fetcher=fetcher, **paths)
    retired = json.loads(paths["retired_out"].read_text(encoding="utf-8"))
    assert set(retired) - {"_meta"} == {"T0800"}


def test_the_ref_is_in_every_url_and_a_moving_ref_is_said(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    mod = _script()
    fetcher = _Fetcher({"enterprise": _bundle("T1001"), "mobile": _bundle(), "ics": _bundle()})
    mod.prepare(
        fetcher=fetcher, ref=_SHA, url=mod.bundle_url("enterprise", _SHA), **_paths(tmp_path)
    )
    assert all(f"/{_SHA}/" in url for _, url in fetcher.calls)
    assert "not a commit sha" not in capsys.readouterr().out
    # The default is a commit sha: nothing is said, and every URL carries it.
    fetcher.calls.clear()
    mod.prepare(fetcher=fetcher, **_paths(tmp_path))
    assert "not a commit sha" not in capsys.readouterr().out
    assert mod.DEFAULT_ATTACK_REF in mod.ENTERPRISE_ATTACK_URL
    assert all(f"/{mod.DEFAULT_ATTACK_REF}/" in url for _, url in fetcher.calls)
    mod.prepare(fetcher=fetcher, ref="master", **_paths(tmp_path))
    assert "not a commit sha" in capsys.readouterr().out


class _Response:
    def __init__(self, raw: str) -> None:
        self.raw = raw

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self) -> bytes:
        return self.raw.encode()


def test_the_cache_is_refreshed_when_the_ref_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _script()
    served = {"body": json.dumps(_bundle("T1001"))}
    opened: list[str] = []

    def fake_urlopen(url: str, timeout: int) -> _Response:
        opened.append(url)
        return _Response(served["body"])

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)
    cache = tmp_path / "cache"
    old_url, new_url = mod.bundle_url("enterprise", "master"), mod.bundle_url("enterprise", _SHA)
    mod._fetch_bundle(old_url, cache)
    mod._fetch_bundle(old_url, cache)
    assert opened == [old_url]
    served["body"] = json.dumps(_bundle("T1002"))
    refreshed = mod._fetch_bundle(new_url, cache)
    assert opened == [old_url, new_url]
    assert json.loads((cache / "enterprise-attack.json").read_text()) == refreshed
    assert sorted(p.name for p in cache.iterdir()) == [
        "enterprise-attack.json",
        "enterprise-attack.json.source",
    ]


def test_a_failed_cache_write_leaves_the_earlier_cache_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mod = _script()
    target = tmp_path / "enterprise-attack.json"
    target.write_text("old", encoding="utf-8")

    def boom(src: object, dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(mod.os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        mod._atomic_write_text(target, "new")
    assert target.read_text(encoding="utf-8") == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["enterprise-attack.json"]
