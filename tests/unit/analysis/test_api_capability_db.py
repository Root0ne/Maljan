"""The import table stops being a 51-name lookup and starts being evidence.

Two data assets, one resolved-import set, two projections: behaviour categories
and ATT&CK techniques. This file pins the properties that make the enlargement
safe, because every one of them is a way the change could quietly make the
analysis *worse* rather than better.

The four that matter:

* **Nothing the curated table flagged may stop being flagged.** Growing 51 names
  to ~680 is only an improvement if the original 51 — names a human picked
  because they matter — survive the move.
* **Categorising is not the same as accusing.** ``RegOpenKeyExA`` belongs to
  ``registry``; it is not suspicious. If tiering fails and everything becomes
  suspicious, four consumers degrade to noise at once and none of them raise.
* **A claim must describe a capability, not a coincidence.** ``min_apis`` is the
  only thing standing between "this binary imports GetUserNameA" and "this
  binary performs Account Discovery".
* **A rule match may not outrank a signature match.** Every confidence stays
  under the YARA floor of 0.70, enforced in the loader as well as the builder
  because the JSON is hand-editable.
"""

from __future__ import annotations

import json
from pathlib import Path

from maljan.analysis.api_capability_db import (
    load_api_attck_map,
    load_api_behaviour_db,
    reset_cache,
)
from maljan.core.paths import resolve_data

_BEHAVIOUR = str(resolve_data("data/api_behaviour_map_v1.json"))
_ATTCK = str(resolve_data("data/api_attck_map_v1.json"))


def _classify(api: str) -> tuple[str | None, bool]:
    """What the shipped catalogue says about one API: (category, catalogue flag)."""
    db = load_api_behaviour_db(_BEHAVIOUR)
    assert db is not None
    return db.classify(api)


# The eight names that existed before the enlargement. Frozen on purpose: they
# are consumed by capability_matrix, the import layer and
# — invisibly — by the vendored family fingerprints, whose description text
# embeds this exact vocabulary. Renaming one desynchronises the family-RAG query
# from its catalog inside a single embedding space, with no exception and no
# test failure anywhere. This assertion is the only thing that would notice.
_FROZEN_CATEGORIES = frozenset(
    {
        "process_injection",
        "anti_debug",
        "network",
        "crypto",
        "filesystem",
        "registry",
        "privilege",
        "execution",
    }
)


class TestCategorisingIsNotAccusing:
    def setup_method(self) -> None:
        reset_cache()

    def test_registry_reads_are_categorised_but_not_suspicious(self) -> None:
        """Every Windows program opens registry keys. A catalogue that flagged
        all of them would tell a reader nothing.
        """
        category, suspicious = _classify("RegQueryValueExA")
        assert category == "registry"
        assert suspicious is False

    def test_injection_apis_are_categorised_and_no_longer_labelled_either(self) -> None:
        """Measured, the category appeared on 65.6% of ordinary Windows
        software and 70.7% of malware — a label carried by two benign binaries
        in three says nothing about the third. The categorisation is right and
        stays; the label went."""
        category, suspicious = _classify("WriteProcessMemory")
        assert category == "process_injection"
        assert suspicious is False

    def test_the_new_names_did_not_arrive_pre_flagged(self) -> None:
        """The load-bearing property of the whole enlargement.

        Six hundred new names may be *categorised* freely; if they arrive
        flagged, the ``api_capability`` tool's ``catalog_flags`` stops saying
        anything and every import in a benign PE reads as suspicious.
        """
        newly_added = [
            "ReadFile",
            "CloseHandle",
            "RegQueryValueExA",
            "GetModuleFileNameA",
            "FindFirstFileA",
            "FindNextFileA",
            "GetTempPathA",
            "GetFileSize",
            "SetFilePointer",
            "CreateDirectoryA",
            "GetSystemDirectoryA",
            "RegCloseKey",
            "RegEnumKeyExA",
            "GetFullPathNameA",
        ]
        flagged = [fn for fn in newly_added if _classify(fn)[1]]
        assert not flagged, f"newly-catalogued Win32 calls arrived flagged: {flagged}"

    def test_none_is_cached_so_a_missing_file_is_read_once(self, tmp_path: Path) -> None:
        missing = str(tmp_path / "nope.json")
        assert load_api_behaviour_db(missing) is None
        assert load_api_behaviour_db(missing) is None


class TestReadingPermissionsIsNotModifyingThem:
    """The asymmetry added on 2026-07-28, and the reason it is an asymmetry.

    A real sample — a signed security product — imported fourteen ACL/SID
    functions and Maljan categorised none of them. Wiring them all in at one
    tier would have been the easy fix and the wrong one: ``GetFileSecurityW``
    is what every security-aware program calls, while ``SetFileSecurityW`` is
    someone rewriting a DACL. Filed apart on purpose, and this class is what
    stops a later edit from quietly collapsing them back together.
    """

    def setup_method(self) -> None:
        reset_cache()

    def test_writing_a_dacl_is_filed_apart_from_reading_one(self) -> None:
        for api in ("SetFileSecurityW", "SetEntriesInAclW", "SetSecurityInfo"):
            category, _suspicious = _classify(api)
            assert category == "privilege", api

    def test_reading_a_dacl_is_categorised_but_not_suspicious(self) -> None:
        for api in ("GetFileSecurityW", "GetAclInformation", "GetAce", "GetSidSubAuthority"):
            category, suspicious = _classify(api)
            assert category == "discovery", api
            assert suspicious is False, api

    def test_the_permissions_rule_claims_neither_now(self) -> None:
        """The asymmetry was right and the rule on top of it was not.

        Measured over both corpora, T1222 appeared on 1.8% of ordinary Windows
        software and 0.8% of malware profiles — it labelled software that is
        not a sample twice as often as software that is. The category split
        survives because it describes what the calls do; the technique claim
        does not, because it discriminated in the wrong direction.
        """
        table = load_api_attck_map(_ATTCK)
        assert table is not None
        for imports in (
            {"SetFileSecurityW", "SetEntriesInAclW"},
            {"GetFileSecurityW", "GetAclInformation", "GetAce"},
        ):
            assert "T1222" not in {rule.technique_id for rule, _ in table.match(imports)}


class TestSearchPathControlIsCategorisedButNeverClaimed:
    """``SetDllDirectoryW`` is the DLL search-order hijacking primitive and it
    is also how hardened software removes the CWD from its own search path.
    An import table cannot tell the two apart, so the API is categorised — it
    belongs in the histogram and the analyst prompt — but no ATT&CK rule may
    name it. This is the same discipline that got T1129 and T1218 dropped.
    """

    def setup_method(self) -> None:
        reset_cache()

    def test_the_apis_are_categorised(self) -> None:
        for api in ("SetDllDirectoryW", "AddDllDirectory", "SetDefaultDllDirectories"):
            category, _suspicious = _classify(api)
            assert category == "execution", api

    def test_no_technique_claims_them(self) -> None:
        table = load_api_attck_map(_ATTCK)
        assert table is not None
        named = {api.lower() for rule in table.techniques for api in rule.apis}
        for api in ("setdlldirectorya", "setdlldirectoryw", "adddlldirectory"):
            assert api not in named, api
        assert "T1574.001" not in {rule.technique_id for rule in table.techniques}


class TestTheOneLetterAndOneSuffixBlindSpots:
    """Both gaps were found by diffing against another analyser on a real
    sample, and both looked like depth problems until read closely: the table
    simply did not carry the spelling the binary happened to import.
    """

    def setup_method(self) -> None:
        reset_cache()

    def test_the_ex_spelling_of_a_covered_call_is_covered(self) -> None:
        assert _classify("FindFirstFileW")[0] == "filesystem"
        assert _classify("FindFirstFileExW")[0] == "filesystem"

    def test_authenticode_verification_is_recognised(self) -> None:
        for api in ("WinVerifyTrust", "CryptCATAdminAcquireContext", "CryptQueryObject"):
            assert _classify(api)[0] == "crypto", api


class TestEveryApiHasExactlyOneOwner:
    """The consumer is a reverse index — one dict, one entry per name — so an
    API listed under two categories has no defined tier: whichever category is
    built last wins.

    This was not hypothetical. ``CheckTokenMembership`` was added to
    ``discovery`` on 2026-07-28 while already sitting in ``privilege``, and the
    two disagree about tier: high means the import is flagged suspicious,
    informational means it is not. The flag therefore depended on dict ordering
    rather than on anything about the import. The builder rejects this now; this
    test is the same guard on the shipped artifact, because the JSON is
    hand-editable and the builder is not in the run path.
    """

    def setup_method(self) -> None:
        reset_cache()

    def test_no_api_is_claimed_by_two_categories(self) -> None:
        raw = json.loads(Path(_BEHAVIOUR).read_text(encoding="utf-8"))
        windows = raw["platforms"]["windows"]

        owners: dict[str, list[str]] = {}
        for category, block in windows.items():
            for api in block["apis"]:
                owners.setdefault(api.lower(), []).append(category)

        ambiguous = {api: cats for api, cats in owners.items() if len(cats) > 1}
        assert not ambiguous, f"APIs with no defined tier: {ambiguous}"

    def test_the_shipped_artifact_matches_the_builders_own_count(self) -> None:
        """A guard against editing the JSON and forgetting the builder, which
        would make the reviewable Python source a lie."""
        raw = json.loads(Path(_BEHAVIOUR).read_text(encoding="utf-8"))
        windows = raw["platforms"]["windows"]
        total = sum(len(block["apis"]) for block in windows.values())
        assert total > 700, f"catalog shrank unexpectedly to {total}"
        assert len(windows) == 15


class TestACategoryThatMeansNothingAloneSaysWhatWouldChangeThat:
    """The GDI blit calls were `keylogging` at tier high, so a program that
    drew a window read as suspicious. They are their own category now, and the
    catalogue names the company they would need."""

    def setup_method(self) -> None:
        reset_cache()

    def _windows(self) -> dict:
        return json.loads(Path(_BEHAVIOUR).read_text(encoding="utf-8"))["platforms"]["windows"]

    def test_the_informational_groups_carry_their_corroborators(self) -> None:
        windows = self._windows()
        for name in ("screen_capture", "message_loop"):
            assert windows[name]["tier"] == "informational"
            assert windows[name]["corroborated_by"]

    def test_a_group_that_stands_on_its_own_names_none(self) -> None:
        assert "corroborated_by" not in self._windows()["registry"]

    def test_the_corroborators_are_apis_the_catalogue_knows(self) -> None:
        """A name with a typo in it is advice nobody can act on."""
        windows = self._windows()
        known = {api.lower() for block in windows.values() for api in block["apis"]}
        for name in ("screen_capture", "message_loop"):
            named = {api.lower() for api in windows[name]["corroborated_by"]}
            assert named <= known, sorted(named - known)


class TestAnAssociationCarriesWhatItWasMeasuredAt:
    """The Windows block labelled 97.73% of ordinary software and 93.50% of
    malware, which is not a weak signal but no signal stated as a fact.

    What replaced the label is the measurement itself: every surviving
    association says what share of a named corpus of software that is not a
    sample it fires on, so a reader weighs the row instead of reading it as a
    finding.
    """

    def setup_method(self) -> None:
        reset_cache()

    def test_every_surviving_rule_says_what_it_fires_on_and_what_that_is_a_share_of(self) -> None:
        table = load_api_attck_map(_ATTCK)
        assert table is not None
        for rule in table.techniques:
            assert rule.measured is not None, rule.technique_id
            assert rule.measured.benign_corpus, rule.technique_id
            assert rule.measured.seen_on_benign_files >= 0, rule.technique_id

    def test_every_category_says_the_same(self) -> None:
        for platform in ("windows", "linux"):
            db = load_api_behaviour_db(_BEHAVIOUR, platform)
            assert db is not None
            for category in db.tiers:
                rate = db.measured_for(category)
                assert rate is not None, f"{platform} {category}"
                assert rate.benign_corpus, f"{platform} {category}"

    def test_the_numbers_travel_without_the_corpus_sentence_under_every_name(self) -> None:
        """One answer can carry three hundred import rows. The sentence naming
        the corpus is said once; the row carries the share."""
        table = load_api_attck_map(_ATTCK)
        assert table is not None
        rule = next(r for r in table.techniques if r.technique_id == "T1113")
        assert rule.measured is not None
        assert not [key for key in rule.measured.rates() if "corpus" in key]
        assert rule.measured.corpora()["benign"]

    def test_an_association_that_was_not_measured_says_nothing_rather_than_zero(self) -> None:
        from maljan.analysis.api_capability_db import _measured

        assert _measured(None) is None
        assert _measured({"seen_on_benign_percent": 0.4}) is None
        assert _measured({"seen_on_benign_files": 4}) is None
        assert _measured({"seen_on_benign_percent": 0.0, "seen_on_benign_files": 0}) is not None


class TestTheFloorIsReadStrictlyRatherThanCoerced:
    """``min_apis`` is what stands between an import and a claim.

    The data file is hand-editable and the loader used to run it through
    ``max(1, int(...))``, which turned a ``0``, a negative, ``true`` or ``1.4``
    into 1 — and a floor of one on a sixteen-name rule makes it fire on any
    single one of them. A floor of one is allowed only where the rule names one
    API, which is the shape the tool's own documentation promises.
    """

    def setup_method(self) -> None:
        reset_cache()

    @staticmethod
    def _row(**over: object) -> dict:
        row = {
            "technique_id": "T1055",
            "name": "Process Injection",
            "apis": ["WriteProcessMemory", "CreateRemoteThread"],
            "min_apis": 2,
        }
        row.update(over)
        return row

    def test_a_floor_that_is_not_a_whole_number_of_names_drops_the_rule(self) -> None:
        from maljan.analysis.api_capability_db import _parse_rule

        assert _parse_rule(self._row()) is not None
        for bad in (0, -1, True, 1.4, "2", None):
            assert _parse_rule(self._row(min_apis=bad)) is None, bad

    def test_one_name_is_a_floor_only_for_a_rule_that_names_one(self) -> None:
        from maljan.analysis.api_capability_db import _parse_rule

        assert _parse_rule(self._row(min_apis=1)) is None
        alone = _parse_rule(self._row(min_apis=1, apis=["IcmpSendEcho"]))
        assert alone is not None and alone.min_apis == 1

    def test_the_shipped_catalogue_has_exactly_one_such_rule(self) -> None:
        table = load_api_attck_map(_ATTCK)
        assert table is not None
        single = [r for r in table.techniques if r.min_apis == 1]
        assert [r.technique_id for r in single] == ["T1095"]
        assert len(single[0].apis) == 1


class TestALabelWaitsForTheCombinationThatEarnsIt:
    """One labelled category per platform, and each waits for a second name.

    Every Windows category that carried a bare tier is informational now, and
    the one that keeps a label carries the input hook or raw-input device that
    is the capture rather than the key-state read a game does every frame.
    """

    def setup_method(self) -> None:
        reset_cache()

    def test_only_a_gated_category_is_ever_labelled(self) -> None:
        for platform in ("windows", "linux"):
            db = load_api_behaviour_db(_BEHAVIOUR, platform)
            assert db is not None
            for category, tier in db.tiers.items():
                if tier == "informational":
                    continue
                assert db.flags_with(category), f"{platform} {category}"

    def test_the_windows_key_read_alone_is_not_a_label(self) -> None:
        db = load_api_behaviour_db(_BEHAVIOUR, "windows")
        assert db is not None
        category, labelled = db.classify("GetKeyState", ["GetKeyState"])
        assert (category, labelled) == ("keylogging", False)
        _category, labelled = db.classify("GetKeyState", ["GetKeyState", "SetWindowsHookExW"])
        assert labelled is True
