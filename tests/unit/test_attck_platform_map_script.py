"""The autoupdate script vendors the platform map beside the id catalogue."""

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


class TestThePlatformMap:
    def test_each_active_technique_gets_its_domain_and_sorted_platforms(self) -> None:
        script = _script()
        objects = [
            _technique("T1055", ["Windows", "Linux", "macOS"]),
            _technique("T1583", ["PRE"]),
            _technique("T1000", ["Windows"], revoked=True),
            _technique("T1001", ["Windows"], x_mitre_deprecated=True),
            {"type": "relationship"},
        ]
        assert script._extract_platform_map(objects, "enterprise") == {
            "T1055": {"domain": "enterprise", "platforms": ["Linux", "Windows", "macOS"]},
            "T1583": {"domain": "enterprise", "platforms": ["PRE"]},
        }

    def test_an_id_in_two_domains_keeps_the_first_in_domain_order(self) -> None:
        script = _script()
        merged = script.merge_platform_maps(
            {
                "mobile": {"T1000": {"domain": "mobile", "platforms": ["Android"]}},
                "enterprise": {"T1000": {"domain": "enterprise", "platforms": ["Windows"]}},
                "ics": {"T0800": {"domain": "ics", "platforms": ["None"]}},
            }
        )
        assert list(merged) == ["T0800", "T1000"]
        assert merged["T1000"]["domain"] == "enterprise"

    def test_the_file_is_written_sorted_and_read_back(self, tmp_path: Path) -> None:
        script = _script()
        out = tmp_path / "attck_platforms.json"
        script.write_platform_map(
            {"T1055": {"domain": "enterprise", "platforms": ["Windows"]}}, out
        )
        assert json.loads(out.read_text(encoding="utf-8")) == {
            "T1055": {"domain": "enterprise", "platforms": ["Windows"]}
        }
