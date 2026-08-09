"""``enforce_bundle_integrity`` must report what it removed, and to whom.

C7 claims that repairing a malformed bundle beats rejecting it. That is a design
claim until someone counts how often the pass fires and what it takes out, which
is queue item B4 — and B4 can only run if the pass reports. These tests pin the
reporting, not the repair (the repair itself is covered by
``test_judge_postprocess.py``).

The one that matters most is ``test_the_default_call_still_works``: the ledger is
optional, every existing call site passes nothing, and instrumentation that
changed behaviour would be a worse bug than no instrumentation.
"""

from __future__ import annotations

from typing import Any

from maljan.agents.judge_postprocess import enforce_bundle_integrity
from maljan.core.truncation_ledger import TruncationLedger

_GOOD_PATTERN = "[file:hashes.'SHA-256' = '" + "a" * 64 + "']"


def _indicator(oid: str, pattern: str = _GOOD_PATTERN) -> dict[str, Any]:
    return {"type": "indicator", "id": oid, "pattern": pattern, "pattern_type": "stix"}


def _attack_pattern(oid: str, tid: str) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": oid,
        "name": f"Technique {tid}",
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _relationship(oid: str, src: str, tgt: str) -> dict[str, Any]:
    return {
        "type": "relationship",
        "id": oid,
        "relationship_type": "indicates",
        "source_ref": src,
        "target_ref": tgt,
    }


class TestTheLedgerIsOptional:
    def test_the_default_call_still_works(self) -> None:
        """Every pre-existing call site omits the ledger; none may change."""
        objects = [_indicator("indicator--1"), _attack_pattern("attack-pattern--1", "T1055")]
        assert len(enforce_bundle_integrity(list(objects))) == 2

    def test_a_broken_ledger_cannot_damage_the_bundle(self) -> None:
        class Exploding:
            def record_integrity_pass(self, **_: object) -> None:
                raise RuntimeError("ledger is broken")

        objects = [_indicator("indicator--1")]
        out = enforce_bundle_integrity(objects, ledger=Exploding())
        assert len(out) == 1


class TestWhatGetsReported:
    def test_a_clean_bundle_reports_a_firing_with_no_removals(self) -> None:
        """The denominator again: C7 needs how often the pass runs, not only
        when it finds something."""
        ledger = TruncationLedger()
        objects = [_indicator("indicator--1"), _attack_pattern("attack-pattern--1", "T1055")]

        enforce_bundle_integrity(objects, ledger=ledger)

        snap = ledger.snapshot()
        assert snap["integrity_invocations"] == 1
        assert snap["integrity_objects_in"] == 2
        assert snap["integrity_objects_out"] == 2
        assert snap["integrity_objects_removed"] == 0

    def test_an_empty_pattern_is_attributed_to_empty_pattern(self) -> None:
        ledger = TruncationLedger()
        objects = [_indicator("indicator--1", pattern="   "), _indicator("indicator--2")]

        enforce_bundle_integrity(objects, ledger=ledger)

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["empty_pattern"] == 1

    def test_a_truncated_pattern_is_attributed_to_empty_pattern(self) -> None:
        """The real LLM failure mode: generation stopped mid-pattern. It is the
        same category as empty because the shape check is what rejects both."""
        ledger = TruncationLedger()
        objects = [_indicator("indicator--1", pattern="[file:name = 'x")]

        enforce_bundle_integrity(objects, ledger=ledger)

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["empty_pattern"] == 1

    def test_duplicate_attack_patterns_are_attributed_separately(self) -> None:
        ledger = TruncationLedger()
        objects = [
            _attack_pattern("attack-pattern--1", "T1055"),
            _attack_pattern("attack-pattern--2", "T1055"),
            _attack_pattern("attack-pattern--3", "T1027"),
        ]

        enforce_bundle_integrity(objects, ledger=ledger)

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["duplicate_attack_pattern"] == 1
        assert dropped["duplicate_indicator"] == 0

    def test_a_dangling_relationship_is_attributed_to_dangling(self) -> None:
        ledger = TruncationLedger()
        objects = [
            _indicator("indicator--1"),
            _relationship("relationship--1", "indicator--1", "attack-pattern--missing"),
        ]

        enforce_bundle_integrity(objects, ledger=ledger)

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["dangling_relationship"] == 1
        assert dropped["duplicate_relationship"] == 0

    def test_two_passes_accumulate(self) -> None:
        """The pass runs twice per analysis — once in the judge post-process and
        once in the extended renderer — so both must land on one ledger."""
        ledger = TruncationLedger()
        enforce_bundle_integrity([_indicator("indicator--1", pattern="")], ledger=ledger)
        enforce_bundle_integrity([_indicator("indicator--2", pattern="")], ledger=ledger)

        snap = ledger.snapshot()
        assert snap["integrity_invocations"] == 2
        dropped = snap["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["empty_pattern"] == 2
