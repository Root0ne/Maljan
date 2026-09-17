"""Every technique id our own rule files assert is in the catalogue we ship.

The catalogue moves with ATT&CK releases; a rule that kept asserting an id
the move retired would make the pack contradict the run's own validity
check, which is the one shape of fact a reader cannot check.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from maljan.memory import attck_loader

ROOT = Path(__file__).resolve().parents[2]


def _api_rule_ids() -> set[str]:
    data = json.loads((ROOT / "data" / "api_attck_map_v1.json").read_text(encoding="utf-8"))
    rules = data.get("techniques") or data.get("rules") or data
    if isinstance(rules, dict):
        rules = [row for value in rules.values() if isinstance(value, list) for row in value]
    return {str(r["technique_id"]) for r in rules if isinstance(r, dict) and r.get("technique_id")}


def _yara_rule_ids() -> set[str]:
    data = yaml.safe_load((ROOT / "data" / "yara_ttp_rules.yaml").read_text(encoding="utf-8"))
    out: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            if node.get("technique_id"):
                out.add(str(node["technique_id"]))
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return out


class TestTheVendoredRulesAssertOnlyLiveIds:
    def test_the_api_rules(self) -> None:
        ids = _api_rule_ids()
        assert ids, "no rules read"
        assert ids <= attck_loader.valid_ids(), sorted(ids - attck_loader.valid_ids())
        assert not ids & set(attck_loader.retired_ids())

    def test_the_yara_rules(self) -> None:
        ids = _yara_rule_ids()
        assert ids, "no rules read"
        assert ids <= attck_loader.valid_ids(), sorted(ids - attck_loader.valid_ids())
        assert not ids & set(attck_loader.retired_ids())
