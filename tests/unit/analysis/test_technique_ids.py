"""The technique ids are read in the shapes the tools write them."""

from __future__ import annotations

from maljan.analysis.technique_ids import (
    api_capability_hits,
    sigma_technique_ids,
    technique_ids_in,
)


class TestTechniqueIdsIn:
    def test_capa_s_decorated_strings(self) -> None:
        attck = [
            "Defense Evasion::Obfuscated Files or Information::Software Packing [T1027.002]",
            "Defense Evasion::Process Injection [T1055]",
        ]
        assert technique_ids_in(attck) == ["T1027.002", "T1055"]

    def test_a_bare_id_and_a_lower_case_one(self) -> None:
        assert technique_ids_in("T1218.011") == ["T1218.011"]
        assert technique_ids_in("t1218.011") == ["T1218.011"]

    def test_duplicates_collapse_and_order_is_kept(self) -> None:
        assert technique_ids_in(["x [T1055]", "T1027", "T1055"]) == ["T1055", "T1027"]

    def test_nothing_else_names_a_technique(self) -> None:
        assert technique_ids_in(None) == []
        assert technique_ids_in(42) == []
        assert technique_ids_in({"technique_id": "T1055"}) == []
        assert technique_ids_in("TA0005 is a tactic, T105 is not an id") == []


class TestSigmaTechniqueIds:
    def test_the_tags_sigma_match_emits(self) -> None:
        row = {"tags": ["attack.persistence", "attack.t1547.001", "attack.T1055.012"]}
        assert sigma_technique_ids(row) == ["T1547.001", "T1055.012"]

    def test_a_tactic_tag_is_not_a_technique(self) -> None:
        assert sigma_technique_ids({"tags": ["attack.defense-evasion", "cve.2021.1234"]}) == []

    def test_a_hand_written_row_is_read_too(self) -> None:
        assert sigma_technique_ids({"meta": {"technique_ids": ["T1547.001"]}}) == ["T1547.001"]
        assert sigma_technique_ids({"technique_ids": ["T1053.005"]}) == ["T1053.005"]

    def test_not_a_row(self) -> None:
        assert sigma_technique_ids(None) == []


class TestApiCapabilityHits:
    def _payload(self, matched: list[str], min_apis: int = 2) -> dict:
        rule = {
            "technique_id": "T1055",
            "name": "Process Injection",
            "matched": matched,
            "min_apis": min_apis,
        }
        return {"capabilities": [{"api": api, "techniques": [rule]} for api in matched]}

    def test_a_rule_the_set_cleared_is_one_row_with_the_pooled_apis(self) -> None:
        hits = api_capability_hits(self._payload(["WriteProcessMemory", "CreateRemoteThread"]))
        assert hits == [
            {
                "technique_id": "T1055",
                "name": "Process Injection",
                "matched_apis": ["WriteProcessMemory", "CreateRemoteThread"],
            }
        ]

    def test_a_rule_under_its_floor_is_not_a_hit(self) -> None:
        assert api_capability_hits(self._payload(["WriteProcessMemory"], min_apis=2)) == []

    def test_not_a_payload(self) -> None:
        assert api_capability_hits(None) == []
        assert api_capability_hits({"capabilities": "nope"}) == []
