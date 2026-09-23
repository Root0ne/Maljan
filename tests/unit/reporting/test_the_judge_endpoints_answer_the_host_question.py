"""The judge writes indicator objects, and an endpoint is an endpoint.

The host question — could anything outside the analysed network ever answer
for this name or address — is about the endpoint, not about who wrote the row
down. It was asked of the judge's URL objects and of nothing else, so a judge
bundle carrying ``[domain-name:value = 'localhost']`` or
``[ipv4-addr:value = '127.0.0.1']`` exported both, and told a consumer's
blocklist that loopback is malicious infrastructure with nothing in the run
summary saying it had happened. Every other path in the tree refuses the same
two values.

What is still not asked of the judge's objects is the corroboration half. The
judge's own assertion is the source, so that half would answer trivially, and
letting "the judge said so" count as a second source is a claim this code
should not make on the judge's behalf. A syntactically public address the
judge invented therefore passes this question — and is caught by the grounding
check instead, which is the check that asks whether any evidence holds it up.
The last class below pins that, because it is the half of the answer this file
is not responsible for.
"""

from __future__ import annotations

import ast
import pathlib
import re
from typing import Any

from maljan.pipeline.validation import validate_verdict_bundle
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport, NetworkIOCs
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_ENDPOINT_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.stix_models import Bundle

# The reviewer's four-value bundle: a private-use name, a reserved name, a
# loopback address and a version number out of a strings table.
INTERNAL = "fileserver.corp.internal"
RESERVED = "localhost"
LOOPBACK = "127.0.0.1"
VERSION_SHAPED = "6.0.0.0"

# Real infrastructure, for the rows that must survive.
C2_DOMAIN = "gate.example.org"
C2_ADDRESS = "185.220.101.1"

_ID = "indicator--0f1e2d3c-4b5a-4968-8776-6554433322{:02d}"


def export_codes_in(tree: ast.AST) -> set[str]:
    """Every ``stix.`` export code a module mints, wherever it mints it.

    The whole tree, not its top level: a code is as much a code for being a
    class attribute or a constant a function keeps, and a scan that read only
    the top level would not have followed one there — which is an ordinary
    refactor, and would have taken the code off the console's list with the
    suite green.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Constant):
            continue
        value = node.value.value
        if not isinstance(value, str) or not value.startswith("stix."):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id.endswith("_CODE"):
                found.add(value)
    return found


def _judge_bundle(*patterns: str) -> Bundle:
    return Bundle.model_validate(
        {
            "objects": [
                {
                    "type": "indicator",
                    "id": _ID.format(index + 1),
                    "pattern": pattern,
                    "pattern_type": "stix",
                }
                for index, pattern in enumerate(patterns)
            ]
        }
    )


def _report() -> MalwareReport:
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
    return report


def _patterns(bundle: Any) -> list[str]:
    return [
        str(getattr(obj, "pattern", ""))
        for obj in bundle.objects
        if getattr(obj, "type", "") == "indicator"
    ]


def _render(*patterns: str) -> tuple[list[str], list[tuple[str, str]]]:
    """What the export carries of the judge's own indicators, and what it declined.

    The sample's own hash indicator is in every bundle and is not the judge's,
    so it is left out of the answer.
    """
    renderer = ExtendedSTIXRenderer()
    bundle = renderer.render(_report(), base_bundle=_judge_bundle(*patterns))
    return [p for p in _patterns(bundle) if "d" * 64 not in p], renderer.declined


class TestTheFourValuesEveryOtherPathRefuses:
    def test_none_of_them_reaches_the_exported_bundle(self) -> None:
        exported, _declined = _render(
            f"[domain-name:value = '{INTERNAL}']",
            f"[domain-name:value = '{RESERVED}']",
            f"[ipv4-addr:value = '{LOOPBACK}']",
            f"[url:value = 'http://{RESERVED}/gate']",
        )

        assert exported == []

    def test_each_one_is_recorded_with_a_true_reason(self) -> None:
        _exported, declined = _render(
            f"[domain-name:value = '{INTERNAL}']",
            f"[domain-name:value = '{RESERVED}']",
            f"[ipv4-addr:value = '{LOOPBACK}']",
            f"[url:value = 'http://{RESERVED}/gate']",
        )

        assert [code for code, _why in declined] == [
            UNPUBLISHABLE_ENDPOINT_CODE,
            UNPUBLISHABLE_ENDPOINT_CODE,
            UNPUBLISHABLE_ENDPOINT_CODE,
            UNPUBLISHABLE_ENDPOINT_CODE,
        ]
        for (_code, why), value in zip(
            declined, (INTERNAL, RESERVED, LOOPBACK, RESERVED), strict=True
        ):
            assert value in why
            assert "the judge's own bundle" in why

    def test_an_address_is_named_as_one(self) -> None:
        _exported, declined = _render(f"[ipv4-addr:value = '{LOOPBACK}']")

        assert declined[0][1].startswith("the address indicator for")

    def test_a_name_is_named_as_one(self) -> None:
        _exported, declined = _render(f"[domain-name:value = '{RESERVED}']")

        assert declined[0][1].startswith("the domain indicator for")

    def test_the_judge_bundle_itself_is_not_edited(self) -> None:
        base = _judge_bundle(f"[domain-name:value = '{RESERVED}']")

        ExtendedSTIXRenderer().render(_report(), base_bundle=base)

        assert _patterns(base) == [f"[domain-name:value = '{RESERVED}']"]


class TestWhatTheJudgeMayStillPublish:
    def test_real_infrastructure_survives(self) -> None:
        exported, declined = _render(
            f"[domain-name:value = '{C2_DOMAIN}']",
            f"[ipv4-addr:value = '{C2_ADDRESS}']",
        )

        assert exported == [
            f"[domain-name:value = '{C2_DOMAIN}']",
            f"[ipv4-addr:value = '{C2_ADDRESS}']",
        ]
        assert declined == []

    def test_a_private_address_the_judge_cites_is_lateral_movement(self) -> None:
        """The judge asserting an address is somebody observing it.

        A private address in a judge's bundle came out of the sandbox evidence
        it was shown, which is the case an analyst most needs to see. A string
        sweep's identical run of digits has no such origin and is refused on
        the other paths.
        """
        exported, declined = _render("[ipv4-addr:value = '10.0.0.5']")

        assert exported == ["[ipv4-addr:value = '10.0.0.5']"]
        assert declined == []

    def test_a_version_number_the_judge_wrote_is_a_public_address_and_passes(self) -> None:
        """Stated rather than hidden: the host question alone lets this through.

        ``6.0.0.0`` is syntactically routable, so nothing about the endpoint
        refuses it, and the corroboration half is deliberately not asked of the
        judge. Whether any evidence holds it up is the grounding check's
        question, and the class below shows that check firing on exactly this.
        """
        exported, declined = _render(f"[ipv4-addr:value = '{VERSION_SHAPED}']")

        assert exported == [f"[ipv4-addr:value = '{VERSION_SHAPED}']"]
        assert declined == []

    def test_an_ipv6_address_is_asked_the_same_question(self) -> None:
        exported, declined = _render("[ipv6-addr:value = '::1']")

        assert exported == []
        assert [code for code, _why in declined] == [UNPUBLISHABLE_ENDPOINT_CODE]

    def test_a_hash_indicator_is_not_an_endpoint_and_is_not_asked(self) -> None:
        pattern = "[file:hashes.'SHA-256' = '" + "e" * 64 + "']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []


class TestAPatternIsNotOneComparison:
    def test_an_or_of_two_endpoints_is_refused_when_either_fails(self) -> None:
        pattern = f"[domain-name:value = '{C2_DOMAIN}'] OR [domain-name:value = '{RESERVED}']"

        exported, declined = _render(pattern)

        assert exported == []
        assert [code for code, _why in declined] == [UNPUBLISHABLE_ENDPOINT_CODE]

    def test_an_or_of_two_endpoints_that_both_pass_is_published(self) -> None:
        pattern = f"[domain-name:value = '{C2_DOMAIN}'] OR [ipv4-addr:value = '{C2_ADDRESS}']"

        exported, _declined = _render(pattern)

        assert exported == [pattern]

    def test_a_list_of_values_is_asked_of_every_value(self) -> None:
        pattern = f"[ipv4-addr:value IN ('{C2_ADDRESS}', '{LOOPBACK}')]"

        exported, declined = _render(pattern)

        assert exported == []
        assert LOOPBACK in declined[0][1]

    def test_a_kind_this_question_is_not_about_does_not_carry_over(self) -> None:
        """A second object path in one pattern is read as itself."""
        pattern = f"[domain-name:value = '{C2_DOMAIN}' AND file:name = '{RESERVED}']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []

    def test_the_object_type_is_read_whatever_case_it_is_written_in(self) -> None:
        """Case carries no meaning in a STIX object path, and a judge shouts."""
        exported, declined = _render(f"[DOMAIN-NAME:value = '{RESERVED}']")

        assert exported == []
        assert [code for code, _why in declined] == [UNPUBLISHABLE_ENDPOINT_CODE]

    def test_a_comparison_with_no_endpoint_in_it_says_that_is_why(self) -> None:
        """A regular expression is not an endpoint, and saying it is not a name
        or address that could exist would be a sentence about something else."""
        exported, declined = _render(r"[url:value MATCHES '^https?://.*\\.evil\\.example/']")

        assert exported == []
        assert declined[0][0] == UNPUBLISHABLE_ENDPOINT_CODE
        assert "could not read the pattern's endpoint" in declined[0][1]

    def test_the_same_holds_for_a_wildcard_and_for_a_subnet(self) -> None:
        for pattern in (
            "[domain-name:value LIKE '%.evil.example']",
            f"[ipv4-addr:value ISSUBSET '{C2_ADDRESS}/24']",
        ):
            exported, declined = _render(pattern)

            assert exported == [], pattern
            assert "could not read the pattern's endpoint" in declined[0][1], pattern

    def test_an_endpoint_reached_through_a_reference_is_asked_the_same_question(self) -> None:
        """``network-traffic:dst_ref.value`` carries an endpoint like any other.

        The checked set was a list of object types, so this shape reached no
        question at all and a judge-written loopback address in it exported
        unasked and unrecorded.
        """
        for prop in ("dst_ref.value", "src_ref.value"):
            exported, declined = _render(f"[network-traffic:{prop} = '{LOOPBACK}']")

            assert exported == [], prop
            assert [code for code, _why in declined] == [UNPUBLISHABLE_ENDPOINT_CODE], prop

    def test_a_reference_to_real_infrastructure_survives(self) -> None:
        pattern = f"[network-traffic:dst_ref.value = '{C2_ADDRESS}']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []

    def test_a_reference_carrying_a_name_is_asked_the_host_question(self) -> None:
        """A ``*_ref.value`` is whichever of the two the judge wrote there."""
        refused, declined = _render(f"[network-traffic:dst_ref.value = '{RESERVED}']")
        kept, _ = _render(f"[domain-name:resolves_to_refs[*].value = '{C2_ADDRESS}']")

        assert refused == []
        assert declined[0][1].startswith("the endpoint indicator for")
        assert kept == [f"[domain-name:resolves_to_refs[*].value = '{C2_ADDRESS}']"]

    def test_a_reference_that_is_not_a_network_endpoint_is_carried_as_written(self) -> None:
        """``email-message:from_ref.value`` is a mailbox, not a host.

        The reference rule is scoped to the two object types whose references
        carry an endpoint; asking a mailbox the host question would decline an
        object for a reason that is not so.
        """
        pattern = "[email-message:from_ref.value = 'operator@example.org']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []

    def test_a_reference_at_something_that_is_not_an_endpoint_is_carried(self) -> None:
        """``src_payload_ref`` points at an artefact, which has no host to ask about."""
        pattern = "[network-traffic:src_payload_ref.value = 'localhost']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []

    def test_a_hardware_address_is_not_told_it_could_not_exist(self) -> None:
        """A MAC is a legal ``dst_ref`` target and is not a host."""
        pattern = "[network-traffic:dst_ref.value = '00:11:22:33:44:55']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []

    def test_a_hash_under_a_quoted_algorithm_is_not_read_as_a_file_name(self) -> None:
        """The key inside the object path is the reader's business, not a heuristic."""
        pattern = "[file:extensions['pe'].pe_imphash = '" + "f" * 32 + "']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []

    def test_a_pattern_whose_quote_never_closes_is_declined_rather_than_read(self) -> None:
        exported, declined = _render(f"[domain-name:value = '{C2_DOMAIN}")

        assert exported == []
        assert "could not read the pattern's endpoint" in declined[0][1]

    def test_a_qualifier_timestamp_is_not_read_as_an_endpoint(self) -> None:
        """Asked of the question itself: a qualified pattern does not reach the
        bundle at all, because the integrity pass wants a bracketed expression
        and records that drop under its own reason."""
        from maljan.reporting.renderers.stix_renderer import _judge_indicator_problem

        indicator = _judge_bundle(
            f"[ipv4-addr:value = '{C2_ADDRESS}'] "
            "START '2026-01-01T00:00:00Z' STOP '2026-01-02T00:00:00Z'"
        ).objects[0]

        assert _judge_indicator_problem(indicator) is None

    def test_an_object_path_written_inside_a_url_is_not_one(self) -> None:
        """A URL's own text can look like a comparison, and is not."""
        url = f"https://{C2_DOMAIN}/x?next=domain-name:value"
        pattern = f"[url:value = '{url}']"

        exported, declined = _render(pattern)

        assert exported == [pattern]
        assert declined == []


class TestTheOtherHalfOfTheAnswer:
    """The grounding check is what asks whether evidence holds an endpoint up."""

    def test_an_address_no_ledger_entry_contains_is_ungrounded(self) -> None:
        bundle = _judge_bundle(f"[ipv4-addr:value = '{VERSION_SHAPED}']")

        violations = validate_verdict_bundle(bundle, evidence_corpus=set())

        assert "stix.ungrounded_indicator" in [v.code for v in violations]

    def test_an_address_the_evidence_contains_is_not(self) -> None:
        bundle = _judge_bundle(f"[ipv4-addr:value = '{C2_ADDRESS}']")

        violations = validate_verdict_bundle(
            bundle, evidence_corpus={f"the sandbox reached {C2_ADDRESS} on port 443"}
        )

        assert "stix.ungrounded_indicator" not in [v.code for v in violations]


class TestTheConsoleReadsTheseCodesAsTheExportsOwn:
    """A row under one of these was the export's call, not a producer's.

    The console draws an unresolved row as "{agent} left {code} unfixed" unless
    the code is on its own list, and the list is the one place that knows which
    codes those are. A code minted here and missing there reads as the judge's
    failure to fix a decision this pipeline made about the judge's work.
    """

    SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "maljan"
    ROWS = pathlib.Path(__file__).resolve().parents[3] / "apps/web/src/lib/validationRows.ts"

    # A ``stix.`` code a producer really can fix, and that the console is right
    # to draw as the producer's own unresolved finding: the judge was asked
    # about the object and kept it.
    # ``stix.indicator_type_contradicts_verdict`` is one of these too: the
    # judge can retype the indicator or restate the verdict, and a row that
    # survives is a type it was asked about and kept.
    PRODUCER_FIXABLE = frozenset(
        {
            "stix.ungrounded_indicator",
            "stix.unknown_object",
            "stix.indicator_type_contradicts_verdict",
            "stix.unknown_observable_type",
            "stix.indicator_type_vocabulary",
            "stix.credit_without_claim",
            "stix.is_family_missing",
        }
    )

    @classmethod
    def _listed(cls) -> set[str]:
        """The codes inside the console's own set, read as a set and not as text.

        Parsed out of the literal rather than found anywhere in the file: a
        mention in a comment satisfied the file-wide search while the set that
        decides the wording had lost the code.
        """
        text = cls.ROWS.read_text(encoding="utf-8")
        opened = text.index("EXPORT_DECIDED")
        body = text[text.index("[", opened) : text.index("]", opened)]
        return set(re.findall(r'"([^"]+)"', body))

    @classmethod
    def _minted(cls) -> dict[str, str]:
        """Every ``stix.`` code this tree mints, and the module that mints it."""
        found: dict[str, str] = {}
        for path in sorted(cls.SRC.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for code in export_codes_in(tree):
                found[code] = str(path.relative_to(cls.SRC))
        return found

    def test_the_scan_reads_more_than_one_module(self) -> None:
        """The renderer is not the only place a run's export codes come from."""
        minted = self._minted()

        assert len(set(minted.values())) >= 2, minted
        assert minted.get("stix.unlinked_technique") == "pipeline/nodes.py"

    def test_every_code_the_export_declines_under_is_on_the_consoles_list(self) -> None:
        listed = self._listed()
        minted = {
            code: module
            for code, module in self._minted().items()
            if code not in self.PRODUCER_FIXABLE
        }

        assert minted, "the scan found no decline code to check"
        missing = {code: module for code, module in minted.items() if code not in listed}
        assert not missing, missing

    def test_a_code_a_producer_can_fix_is_not_drawn_as_the_exports_own(self) -> None:
        listed = self._listed()

        assert not (self.PRODUCER_FIXABLE & listed), sorted(self.PRODUCER_FIXABLE & listed)

    def test_the_codes_a_stored_run_carries_are_still_read(self) -> None:
        from maljan.reporting.renderers.stix_renderer import LEGACY_UNPUBLISHABLE_CODES

        assert set(LEGACY_UNPUBLISHABLE_CODES) <= self._listed()

    def test_a_mention_outside_the_set_does_not_satisfy_it(self) -> None:
        """The scan passes trivially if it reads the whole file, so prove it does not."""
        text = self.ROWS.read_text(encoding="utf-8")
        opened = text.index("EXPORT_DECIDED")
        body = text[text.index("[", opened) : text.index("]", opened)]

        assert "stix.unpublishable_endpoint" in body
        assert "EXPORT_DECIDED" not in body


class TestTheDriftScanReadsAWholeModule:
    """A code defined inside a class or a function used to be invisible.

    ``_minted`` read a module's top level alone, so moving a constant onto the
    class that mints it would have taken it out of the scan with the suite
    green.
    """

    def test_a_code_on_a_class_is_found(self) -> None:
        source = 'class Renderer:\n    SOME_CODE = "stix.a_new_decline"\n'

        assert export_codes_in(ast.parse(source)) == {"stix.a_new_decline"}

    def test_a_code_inside_a_function_is_found(self) -> None:
        source = 'def mint():\n    SOME_CODE = "stix.another_decline"\n    return SOME_CODE\n'

        assert export_codes_in(ast.parse(source)) == {"stix.another_decline"}

    def test_a_name_that_is_not_a_code_is_not_found(self) -> None:
        source = 'PREFIX = "stix.not_a_code"\nclass R:\n    OTHER = "stix.nor_this"\n'

        assert export_codes_in(ast.parse(source)) == set()
