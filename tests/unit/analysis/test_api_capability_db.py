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

    def test_injection_apis_are_both(self) -> None:
        category, suspicious = _classify("WriteProcessMemory")
        assert category == "process_injection"
        assert suspicious is True

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

    def test_writing_a_dacl_is_high_tier_and_suspicious(self) -> None:
        for api in ("SetFileSecurityW", "SetEntriesInAclW", "SetSecurityInfo"):
            category, suspicious = _classify(api)
            assert category == "privilege", api
            assert suspicious is True, api

    def test_reading_a_dacl_is_categorised_but_not_suspicious(self) -> None:
        for api in ("GetFileSecurityW", "GetAclInformation", "GetAce", "GetSidSubAuthority"):
            category, suspicious = _classify(api)
            assert category == "discovery", api
            assert suspicious is False, api

    def test_t1222_fires_on_writes_only(self) -> None:
        table = load_api_attck_map(_ATTCK)
        assert table is not None

        writes = {
            rule.technique_id for rule, _ in table.match({"SetFileSecurityW", "SetEntriesInAclW"})
        }
        assert "T1222" in writes

        reads = {
            rule.technique_id
            for rule, _ in table.match({"GetFileSecurityW", "GetAclInformation", "GetAce"})
        }
        assert "T1222" not in reads


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
        assert len(windows) == 13
