"""What makes two indicators one, and what a fold is allowed to touch.

The fingerprint is the whole risk here: too shy and a report repeats itself,
too eager and it loses a fact with nothing saying so. So both directions are
asserted — the spellings that must fold together, and the pairs that must not.
"""

from __future__ import annotations

import pytest

from maljan.agents.judge_postprocess import enforce_bundle_integrity
from maljan.reporting.dedupe import (
    MergeTally,
    canonical_value,
    finding_fingerprint,
    indicator_fingerprint,
    merge_cell,
    normalised_title,
)


class TestTheIndicatorFingerprint:
    @pytest.mark.parametrize(
        "written",
        [
            "http://c2.evil.tld/gate.php",
            "HTTP://C2.EVIL.TLD/gate.php",
            "  http://c2.evil.tld/gate.php  ",
            "hxxp://c2[.]evil[.]tld/gate.php",
            "hxxp://c2(.)evil(.)tld/gate.php",
        ],
    )
    def test_the_spellings_of_one_endpoint_fold_together(self, written: str) -> None:
        assert indicator_fingerprint("url", written) == indicator_fingerprint(
            "url", "http://c2.evil.tld/gate.php"
        )

    def test_a_defanged_mail_address_folds_onto_the_plain_one(self) -> None:
        assert indicator_fingerprint("email", "drop[at]evil.tld") == indicator_fingerprint(
            "email", "drop@evil.tld"
        )

    @pytest.mark.parametrize(
        ("left", "right"),
        [
            (("url", "http://a.tld/one"), ("url", "http://a.tld/two")),
            (("domain", "a.tld"), ("url", "a.tld")),
            (("ip", "10.0.0.1"), ("ip", "10.0.0.10")),
            (("sha256", "ab" * 32), ("sha256", "ac" * 32)),
        ],
    )
    def test_two_different_indicators_stay_two(self, left: tuple, right: tuple) -> None:
        assert indicator_fingerprint(*left) != indicator_fingerprint(*right)

    def test_hxxps_is_read_before_hxxp(self) -> None:
        assert canonical_value("hxxps://a.tld") == "https://a.tld"


class TestTheFindingFingerprint:
    def test_the_same_conclusion_written_twice_folds(self) -> None:
        assert finding_fingerprint(["T1055"], "Injects into explorer.exe") == finding_fingerprint(
            ["t1055"], "  injects  into explorer.exe. "
        )

    def test_a_different_technique_is_a_different_finding(self) -> None:
        assert finding_fingerprint(["T1055"], "same words") != finding_fingerprint(
            ["T1027"], "same words"
        )

    def test_a_finding_with_no_technique_is_filed_on_its_title(self) -> None:
        assert finding_fingerprint([], "Packed with UPX") == ("", "packed with upx")

    def test_the_first_technique_is_the_one_it_is_filed_under(self) -> None:
        assert finding_fingerprint(["T1055", "T1027"], "x")[0] == "T1055"

    def test_an_empty_title_normalises_to_nothing(self) -> None:
        assert normalised_title(None) == ""


class TestMergingACell:
    def test_it_is_a_union_in_the_order_first_seen(self) -> None:
        assert merge_cell("ev_0002, ev_0001", "ev_0003, ev_0001") == "ev_0002, ev_0001, ev_0003"

    def test_an_empty_side_changes_nothing(self) -> None:
        assert merge_cell("static", "") == "static"
        assert merge_cell("", "reverser") == "reverser"


class TestTheBundleFoldsTheSameIndicatorsTheReportDoes:
    def _indicator(self, stix_id: str, pattern: str, label: str) -> dict:
        return {
            "type": "indicator",
            "id": stix_id,
            "pattern_type": "stix",
            "pattern": pattern,
            "labels": [label],
        }

    def test_two_spellings_of_one_endpoint_become_one_object(self) -> None:
        objects = [
            self._indicator("indicator--1", "[url:value = 'http://C2.Evil.tld/a']", "malicious"),
            self._indicator("indicator--2", "[url:value = 'hxxp://c2[.]evil[.]tld/a']", "c2"),
        ]

        kept = enforce_bundle_integrity(objects)

        assert [o["id"] for o in kept] == ["indicator--1"]
        assert kept[0]["pattern"] == "[url:value = 'http://C2.Evil.tld/a']", "as written"
        assert kept[0]["labels"] == ["malicious", "c2"], "only the set grows"

    def test_a_reference_to_the_folded_object_follows_the_kept_one(self) -> None:
        objects = [
            self._indicator("indicator--1", "[url:value = 'http://a.tld/x']", "malicious"),
            self._indicator("indicator--2", "[url:value = 'HTTP://A.TLD/x']", "malicious"),
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "indicates",
                "source_ref": "indicator--2",
                "target_ref": "indicator--1",
            },
        ]

        kept = enforce_bundle_integrity(objects)

        assert [o["id"] for o in kept] == ["indicator--1", "relationship--1"]
        relationship = kept[1]
        assert relationship["source_ref"] == "indicator--1", "it points at the kept object"

    def test_two_different_endpoints_stay_two_objects(self) -> None:
        objects = [
            self._indicator("indicator--1", "[url:value = 'http://a.tld/one']", "malicious"),
            self._indicator("indicator--2", "[url:value = 'http://a.tld/two']", "malicious"),
        ]

        assert len(enforce_bundle_integrity(objects)) == 2


class TestTheTally:
    def test_it_states_both_numbers_and_adds_the_bundle_s_own(self) -> None:
        tally = MergeTally()
        tally.indicator()
        tally.finding()
        tally.finding()

        assert tally.as_dict() == {"indicators_merged": 1, "findings_merged": 2}
        assert tally.as_dict(extra_indicators=3)["indicators_merged"] == 4
