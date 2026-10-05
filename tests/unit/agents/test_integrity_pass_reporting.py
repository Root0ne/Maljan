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

    def test_a_truncated_pattern_is_kept_for_the_judge_to_be_asked_about(self) -> None:
        """Generation stopped mid-pattern: the judge is asked (``stix.pattern_refused``)
        and the export declines one it keeps. Only an empty pattern is dropped here."""
        ledger = TruncationLedger()
        objects = [_indicator("indicator--1", pattern="[file:name = 'x")]

        kept = enforce_bundle_integrity(objects, ledger=ledger)

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["empty_pattern"] == 0
        assert len(kept) == 1

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


class TestWhatTheIndicatorCapOrphans:
    """The pass runs a third time, after the cap, and used to report nothing.

    A relationship the cap leaves pointing at an indicator that is no longer in
    the bundle is swept there. Nothing counted it, so the aggregate's
    "objects removed" did not reconcile with the bundle a reader holds.
    """

    def test_it_is_counted_under_its_own_reason(self) -> None:
        ledger = TruncationLedger()
        objects = [
            _indicator("indicator--1"),
            _relationship("relationship--1", "indicator--1", "indicator--capped"),
        ]

        enforce_bundle_integrity(objects, ledger=ledger, dropped_as="cap_orphan")

        dropped = ledger.snapshot()["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["cap_orphan"] == 1
        assert dropped["dangling_relationship"] == 0

    def test_the_renderer_carries_every_indicator_and_orphans_nothing(self) -> None:
        """The export has no total cap, so nothing is left for it to orphan."""
        from maljan.core.truncation_ledger import TruncationLedger as Ledger
        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.models import NetworkIOCs
        from maljan.reporting.renderers.stix_renderer import ExtendedSTIXRenderer
        from maljan.schemas.stix_models import Bundle

        report = MalwareReportBuilder(
            file_hash="d" * 64,
            file_name="sample.exe",
            sample_path=None,
            sandbox_report={},
            reports={},
            isr_reports={},
            stix_output={"objects": []},
            run_summary={},
            discussion_history=[],
            final_decision="Malware",
            overall_confidence=0.6,
            judge_assessment=None,
            malware_category="loader",
            sample_platform="windows",
            sample_file_type="pe",
            evidence_ledger=[],
        ).build_deterministic()
        report.network = NetworkIOCs()
        # A sandbox saw every file written: the second source the one publish
        # rule asks of the judge's values. A file name is a value the export
        # mints no row of its own for, so the indicators that reach the cap are
        # the judge's.
        from maljan.reporting.models import DynamicBehavior

        report.dynamic = DynamicBehavior(
            file_operations=[{"operation": "write", "path": f"h{n}.exe"} for n in range(40)]
        )
        # Forty indicators, more than the fifteen a cap used to keep, each with
        # a relationship of its own.
        objects: list[dict[str, Any]] = []
        for index in range(40):
            oid = f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{index:02d}"
            objects.append(_indicator(oid, pattern=f"[file:name = 'h{index}.exe']"))
            objects.append(
                _relationship(
                    f"relationship--0f1e2d3c-4b5a-4968-8776-6554433322{index:02d}",
                    oid,
                    "indicator--0f1e2d3c-4b5a-4968-8776-655443332200",
                )
            )
        ledger = Ledger()

        bundle = ExtendedSTIXRenderer().render(
            report, Bundle.model_validate({"objects": objects}), ledger=ledger
        )

        patterns = {str(getattr(o, "pattern", "")) for o in bundle.objects}
        assert all(f"[file:name = 'h{index}.exe']" in patterns for index in range(40))
        snapshot = ledger.snapshot()
        dropped = snapshot["integrity_dropped"]
        assert isinstance(dropped, dict)
        assert dropped["cap_orphan"] == 0
        assert snapshot["indicator_cap_removed"] == 0


class TestEverythingThatLeavesTheBundleIsCounted:
    """The aggregate reconciles with the bundle a reader holds.

    Three things take objects or references out between the assembled list and
    the exported bundle: the integrity pass's own repairs, the total indicator
    cap, and step 5's trim of a report's or a note's ``object_refs``. The first
    was counted, the other two were not, so the difference between what went in
    and what came out was a number nobody could total.
    """

    def _note(self, oid: str, refs: list[str]) -> dict[str, Any]:
        return {"type": "note", "id": oid, "content": "about these", "object_refs": list(refs)}

    def test_a_trimmed_note_reports_the_references_it_lost(self) -> None:
        ledger = TruncationLedger()
        objects = [
            _indicator("indicator--1"),
            self._note("note--1", ["indicator--1", "indicator--gone", "indicator--also-gone"]),
        ]

        enforce_bundle_integrity(objects, ledger=ledger)

        snapshot = ledger.snapshot()
        assert snapshot["integrity_refs_trimmed"] == 2
        assert snapshot["integrity_objects_removed"] == 0

    def test_a_reader_can_total_what_left_a_large_bundle(self) -> None:
        ledger = TruncationLedger()
        # Twenty indicators, more than the fifteen a cap used to keep, each
        # with a relationship, plus a note referencing every one of them.
        ids = [f"indicator--{index:02d}" for index in range(20)]
        objects: list[Any] = [
            _indicator(oid, pattern=f"[domain-name:value = 'h{index}.example.org']")
            for index, oid in enumerate(ids)
        ]
        objects += [
            _relationship(f"relationship--{index:02d}", oid, "indicator--00")
            for index, oid in enumerate(ids)
        ]
        objects.append(self._note("note--1", ids))
        assembled = len(objects)

        # The sequence the renderer runs: the repair, and nothing after it.
        final = enforce_bundle_integrity(objects, ledger=ledger)

        snapshot = ledger.snapshot()
        assert snapshot["indicator_cap_removed"] == 0
        assert assembled - len(final) == int(snapshot["integrity_objects_removed"]) == 0
        note = next(o for o in final if o["type"] == "note")
        assert len(note["object_refs"]) == 20
        assert snapshot["integrity_refs_trimmed"] == 0


class TestWhoseRemovalsTheyAre:
    """The judge path's passes are not the export's, and are not summed in.

    ``postprocess_judge_bundle`` runs the same pass on the judge's own bundle,
    on the run's one ledger, **once per verdict attempt** — a discarded retry
    included — and over objects the export may never carry. Counted together
    with the export's, the total reconciled with nothing a reader holds.
    """

    def test_a_judge_pass_is_counted_apart(self) -> None:
        ledger = TruncationLedger()
        objects = [
            _indicator("indicator--1"),
            _relationship("relationship--1", "indicator--1", "indicator--gone"),
        ]

        enforce_bundle_integrity(objects, ledger=ledger, whose="judge")

        snapshot = ledger.snapshot()
        assert snapshot["judge_integrity_invocations"] == 1
        assert snapshot["judge_integrity_objects_removed"] == 1
        assert snapshot["integrity_invocations"] == 0
        assert snapshot["integrity_objects_removed"] == 0

    def test_a_discarded_retry_does_not_move_what_the_export_reconciles(self) -> None:
        """Two judge attempts, one export: the export's figures are the export's."""

        ledger = TruncationLedger()
        # Two verdict attempts, the first of them thrown away and retried.
        for _attempt in range(2):
            enforce_bundle_integrity(
                [
                    _indicator("indicator--1"),
                    _indicator("indicator--2", pattern="   "),
                    _relationship("relationship--1", "indicator--1", "indicator--gone"),
                ],
                ledger=ledger,
                whose="judge",
            )

        # And the export, once, over the bundle that is published.
        ids = [f"indicator--{index:02d}" for index in range(20)]
        objects: list[Any] = [
            _indicator(oid, pattern=f"[domain-name:value = 'h{index}.example.org']")
            for index, oid in enumerate(ids)
        ]
        assembled = len(objects)
        final = enforce_bundle_integrity(objects, ledger=ledger)

        snapshot = ledger.snapshot()
        assert snapshot["judge_integrity_invocations"] == 2
        assert snapshot["judge_integrity_objects_removed"] == 4
        # The invariant a reader uses, unmoved by either judge attempt.
        assert assembled - len(final) == int(snapshot["integrity_objects_removed"])

    def test_the_reasons_are_kept_apart_too(self) -> None:
        ledger = TruncationLedger()
        enforce_bundle_integrity(
            [_indicator("indicator--1", pattern="  ")], ledger=ledger, whose="judge"
        )

        snapshot = ledger.snapshot()
        judge_dropped = snapshot["judge_integrity_dropped"]
        export_dropped = snapshot["integrity_dropped"]
        assert isinstance(judge_dropped, dict) and isinstance(export_dropped, dict)
        assert judge_dropped["empty_pattern"] == 1
        assert export_dropped["empty_pattern"] == 0
