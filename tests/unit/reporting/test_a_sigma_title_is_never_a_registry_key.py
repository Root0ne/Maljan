"""A Sigma rule that fired is a detection-rule match, and a Run key only when its event names one.

A rule's title is what the rule is called. One live report filed the title of
a rule naming no technique at all as a ``registry_run`` key, printed it in the
host-indicator table as a registry key and handed it to the drafts.
"""

from __future__ import annotations

from typing import Any

from maljan.reporting.ledger_projection import persistence_from_ledger
from maljan.schemas.evidence import EvidenceCounter
from tests.unit._ledger_helpers import entry


def _sigma(*matches: dict[str, Any]) -> list[Any]:
    return [
        entry(
            "sigma_match_sandbox",
            {"matches": list(matches), "rule_count": 10, "event_count": 2},
            EvidenceCounter(),
            agent="pipeline",
        )
    ]


def test_a_rule_naming_no_technique_is_no_persistence_row() -> None:
    ledger = _sigma(
        {
            "rule": "r1",
            "title": "Utility Run From An Unusual Drive",
            "tags": ["attack.stealth"],
            "matched_fields": {"Image": "C:\\Windows\\system32\\rundll32.exe"},
        }
    )

    assert persistence_from_ledger(ledger) == []


def test_a_rule_naming_an_autostart_technique_without_a_key_stays_a_rule_match() -> None:
    ledger = _sigma(
        {
            "rule": "r2",
            "title": "Autostart Entry Written",
            "tags": ["attack.persistence", "attack.t1547.001"],
            "matched_fields": {"Image": "C:\\Users\\a\\x.exe"},
        }
    )

    assert persistence_from_ledger(ledger) == []


def test_a_rule_with_a_key_is_filed_under_the_key_and_never_under_its_title() -> None:
    key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"
    ledger = _sigma(
        {
            "rule": "r3",
            "title": "Autostart Entry Written",
            "tags": ["attack.persistence", "attack.t1547.001"],
            "matched_fields": {"TargetObject": key, "Details": "C:\\Users\\a\\x.exe"},
        }
    )

    [row] = persistence_from_ledger(ledger)

    assert row.kind == "registry_run"
    assert row.target == key
    assert row.payload == "C:\\Users\\a\\x.exe"
    assert row.technique_id == "T1547.001"
    assert "Autostart Entry Written" not in row.target


def test_the_kind_follows_the_sub_technique_when_the_key_does_not_say() -> None:
    key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages"
    ledger = _sigma(
        {
            "rule": "r4",
            "title": "Security Package Registered",
            "tags": ["attack.t1547.005"],
            "matched_fields": {"TargetObject": key},
        }
    )

    [row] = persistence_from_ledger(ledger)

    assert row.kind == "lsa_provider"
    assert row.target == key


def test_a_rule_for_another_technique_is_no_persistence_row() -> None:
    ledger = _sigma(
        {
            "rule": "r5",
            "title": "Call By Ordinal",
            "tags": ["attack.t1218.011"],
            "matched_fields": {"TargetObject": "HKCU\\Software\\x"},
        }
    )

    assert persistence_from_ledger(ledger) == []
