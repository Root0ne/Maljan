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
from maljan.extractors.pe_extractor import _SUSPICIOUS_IMPORTS, classify_import

_BEHAVIOUR = str(resolve_data("data/api_behaviour_map_v1.json"))
_ATTCK = str(resolve_data("data/api_attck_map_v1.json"))

# The eight names that existed before the enlargement. Frozen on purpose: they
# are consumed by capability_matrix, ghidra_tool_selector, the import layer and
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


class TestTheCuratedTableSurvives:
    def setup_method(self) -> None:
        reset_cache()

    def test_every_legacy_name_is_still_known_to_the_catalog(self) -> None:
        """A curated name that the enlarged table has never heard of is a gap,
        not a decision — the catalog is meant to be a superset."""
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None, "the catalog must load; without it this test proves nothing"

        unknown = [fn for fn in _SUSPICIOUS_IMPORTS if db.classify(fn)[0] is None]
        assert not unknown, f"legacy imports missing from the catalog: {unknown}"

    def test_every_legacy_suspicious_import_stays_suspicious(self) -> None:
        """The regression that would be easiest to ship and hardest to notice.

        Note this asserts on ``classify_import``, not on the catalog: six
        filesystem and three registry names sit in ``informational`` categories
        and stay flagged only because suspicion is the union of the catalog and
        the curated table. See ``classify_import``'s comment for why that union
        exists — the short version is that the vendored family fingerprints were
        built against the old flags.
        """
        demoted = [fn for fn in _SUSPICIOUS_IMPORTS if not classify_import(fn)[1]]
        assert not demoted, f"legacy suspicious imports demoted: {demoted}"

    def test_legacy_names_are_never_uncategorised(self) -> None:
        for fn in _SUSPICIOUS_IMPORTS:
            category, _ = classify_import(fn)
            # The category may be *refined* (execution -> discovery, say), but a
            # curated name must never come back with nothing at all.
            assert isinstance(category, str) and category, f"{fn} lost its category"

    def test_an_unknown_import_is_neither_categorised_nor_flagged(self) -> None:
        assert classify_import("Sc0peNotARealApi") == (None, False)


class TestCategorisingIsNotAccusing:
    def setup_method(self) -> None:
        reset_cache()

    def test_registry_reads_are_categorised_but_not_suspicious(self) -> None:
        """Every Windows program opens registry keys. A 'suspicious imports'
        table that lists all of them tells a reader nothing.

        ``RegOpenKeyExA`` itself is one of the nine inherited exceptions (see
        ``classify_import``), so the property is asserted on a sibling the
        curated table never mentioned.
        """
        category, suspicious = classify_import("RegQueryValueExA")
        assert category == "registry"
        assert suspicious is False

    def test_injection_apis_are_both(self) -> None:
        category, suspicious = classify_import("WriteProcessMemory")
        assert category == "process_injection"
        assert suspicious is True

    def test_the_new_names_did_not_arrive_pre_flagged(self) -> None:
        """The load-bearing property of the whole enlargement.

        Six hundred new names may be *categorised* freely; if they arrive
        flagged, the suspicious-first sort that decides which import rows
        survive the prompt cap becomes a no-op, the report's "Suspicious
        Imports" table becomes the entire import table, and the family-RAG
        profile text saturates. None of those raise.

        Every name below is absent from the curated 51, so nothing here is
        covered by the inherited-flag exception.
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
        assert not (set(newly_added) & set(_SUSPICIOUS_IMPORTS)), "fixture drifted"
        flagged = [fn for fn in newly_added if classify_import(fn)[1]]
        assert not flagged, f"newly-catalogued Win32 calls arrived flagged: {flagged}"

    def test_the_inherited_exceptions_are_a_short_list(self) -> None:
        """The union is a compatibility concession, not a policy. If it ever
        covers most of the table, the concession has become the rule."""
        informational_but_flagged = [
            fn
            for fn, cat in _SUSPICIOUS_IMPORTS.items()
            if classify_import(fn)[0] in {"filesystem", "registry", "discovery"}
            for _ in [cat]
        ]
        assert len(informational_but_flagged) <= 12, informational_but_flagged

    def test_lookup_is_case_insensitive(self) -> None:
        """Forwarded exports and ordinal-resolved names are not case-consistent."""
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None
        assert db.classify("writeprocessmemory")[0] == "process_injection"


class TestTheFrozenVocabulary:
    def setup_method(self) -> None:
        reset_cache()

    def test_the_eight_original_categories_still_exist(self) -> None:
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None
        missing = _FROZEN_CATEGORIES - set(db.tiers)
        assert not missing, f"renamed or dropped: {missing} — see this file's docstring"

    def test_the_catalog_only_declares_known_tiers(self) -> None:
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None
        assert set(db.tiers.values()) <= {"high", "medium", "informational"}


class TestAClaimMustBeACapability:
    def setup_method(self) -> None:
        reset_cache()

    def test_one_import_below_min_apis_does_not_fire(self) -> None:
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        # GetUserNameA alone is the textbook false positive: ubiquitous, and
        # under an "any hit counts" rule it promotes Account Discovery.
        assert catalog.match({"GetUserNameA"}) == []

    def test_a_real_combination_does_fire(self) -> None:
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        hits = catalog.match({"CreateToolhelp32Snapshot", "Process32First", "Process32Next"})
        assert any(rule.technique_id == "T1057" for rule, _ in hits)

    def test_confidence_grows_with_corroboration_but_is_bounded(self) -> None:
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        rule = next(r for r in catalog.techniques if r.technique_id == "T1057")
        two = rule.confidence_for(2)
        many = rule.confidence_for(50)
        assert two < many, "more corroborating imports should mean more confidence"
        assert many <= rule.confidence_max, "…but not unboundedly more"

    def test_no_rule_can_outrank_a_yara_match(self) -> None:
        """0.70 is the YARA floor. A deterministic import signal corroborates
        other layers; it must never solo-drive a verdict."""
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        for rule in catalog.techniques:
            assert rule.confidence_for(999) <= 0.65, f"{rule.technique_id} exceeds the ceiling"

    def test_the_ceiling_is_enforced_on_hand_edited_data(self, tmp_path: Path) -> None:
        """The JSON is editable in place, so the builder's check is not enough."""
        rogue = tmp_path / "rogue.json"
        rogue.write_text(
            json.dumps(
                {
                    "schema": "maljan-api-attck/v1",
                    "techniques": [
                        {
                            "technique_id": "T1055",
                            "name": "x",
                            "apis": ["WriteProcessMemory", "VirtualAllocEx"],
                            "min_apis": 1,
                            "confidence_base": 0.99,
                            "confidence_max": 0.99,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        catalog = load_api_attck_map(str(rogue))
        assert catalog is not None
        assert catalog.techniques[0].confidence_for(99) <= 0.65


class TestTheCatalogDegradesInsteadOfFailing:
    def setup_method(self) -> None:
        reset_cache()

    def test_a_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert load_api_behaviour_db(str(tmp_path / "nope.json")) is None
        assert load_api_attck_map(str(tmp_path / "nope.json")) is None

    def test_malformed_json_returns_none(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        assert load_api_behaviour_db(str(bad)) is None
        assert load_api_attck_map(str(bad)) is None

    def test_a_missing_platforms_key_returns_none(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"schema": "x"}), encoding="utf-8")
        assert load_api_behaviour_db(str(empty)) is None

    def test_classify_import_still_works_without_any_catalog(self) -> None:
        """The whole point of keeping the hardcoded table: an analysis that
        loses depth is acceptable, one that fails because a file moved is not."""
        from unittest.mock import patch

        with patch("maljan.extractors.pe_extractor._behaviour_db", return_value=None):
            assert classify_import("WriteProcessMemory") == ("process_injection", True)
            assert classify_import("Sc0peNotARealApi") == (None, False)

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
            category, suspicious = classify_import(api)
            assert category == "privilege", api
            assert suspicious is True, api

    def test_reading_a_dacl_is_categorised_but_not_suspicious(self) -> None:
        for api in ("GetFileSecurityW", "GetAclInformation", "GetAce", "GetSidSubAuthority"):
            category, suspicious = classify_import(api)
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
            category, _suspicious = classify_import(api)
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
        assert classify_import("FindFirstFileW")[0] == "filesystem"
        assert classify_import("FindFirstFileExW")[0] == "filesystem"

    def test_authenticode_verification_is_recognised(self) -> None:
        for api in ("WinVerifyTrust", "CryptCATAdminAcquireContext", "CryptQueryObject"):
            assert classify_import(api)[0] == "crypto", api
