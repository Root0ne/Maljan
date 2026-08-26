"""Half the import table was invisible because of one letter.

Found by running Qu1cksc0pe against the same sample and diffing. It categorised
140 of 218 imports; Maljan categorised 81 of 217. The difference was not depth
of research — it was that Win32 ships most string-taking APIs twice,
``GetSystemDirectoryA`` and ``GetSystemDirectoryW``, and a hand-curated table
naturally lists one of each pair. Thirteen imports on that sample were nothing
but the other spelling of a name already in the catalog.

Resolving it in the lookup rather than by writing both spellings into the JSON
keeps the asset half the size and removes the failure mode entirely — the next
contributor cannot forget a suffix.

The second half of this file is the bug that fix introduced, and the reason
counting is done the way it is. A rule listing both ``GetUserNameA`` and
``GetUserNameW`` is satisfied by *one* import under normalisation, and the first
implementation counted rule entries rather than imports — so a lone
``GetUserNameA`` cleared ``min_apis=2`` by itself. That is exactly the
"coincidence promoted to capability" the threshold exists to prevent, and it was
caught by the pre-existing test asserting a lone GetUserNameA maps to nothing.
"""

from __future__ import annotations

from maljan.analysis.api_capability_db import (
    load_api_attck_map,
    load_api_behaviour_db,
    reset_cache,
)
from maljan.core.paths import resolve_data

_BEHAVIOUR = str(resolve_data("data/api_behaviour_map_v1.json"))
_ATTCK = str(resolve_data("data/api_attck_map_v1.json"))


class TestBothSpellingsClassify:
    def setup_method(self) -> None:
        reset_cache()

    def test_the_wide_sibling_of_a_catalogued_ansi_name(self) -> None:
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None
        # These are the exact names the live diff surfaced.
        for wide in [
            "GetWindowsDirectoryW",
            "GetSystemDirectoryW",
            "LookupAccountSidW",
            "RegGetValueW",
            "SetEnvironmentVariableW",
            "GetLongPathNameW",
        ]:
            category, _ = db.classify(wide)
            assert category is not None, f"{wide} still uncategorised"

    def test_the_ansi_sibling_of_a_catalogued_wide_name(self) -> None:
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None
        assert db.classify("Process32FirstW")[0] is not None
        assert db.classify("Process32First")[0] is not None

    def test_an_unrelated_name_is_still_unknown(self) -> None:
        """Normalisation must not become a wildcard."""
        db = load_api_behaviour_db(_BEHAVIOUR)
        assert db is not None
        assert db.classify("Sc0peNotARealApiW")[0] is None
        assert db.classify("Sc0peNotARealApiA")[0] is None


class TestCountingImportsNotRuleEntries:
    def setup_method(self) -> None:
        reset_cache()

    def test_one_import_cannot_satisfy_min_apis_by_matching_both_variants(self) -> None:
        """The regression the A/W fix introduced, and the reason for `_canonical`."""
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        assert catalog.match({"GetUserNameA"}) == []
        assert catalog.match({"GetUserNameW"}) == []

    def test_importing_both_spellings_is_still_one_capability(self) -> None:
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        assert catalog.match({"GetUserNameA", "GetUserNameW"}) == []

    def test_two_genuinely_distinct_imports_do_fire(self) -> None:
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        hits = catalog.match({"GetUserNameW", "LookupAccountSidW"})
        assert any(rule.technique_id == "T1033" for rule, _ in hits)

    def test_the_evidence_cites_the_spelling_the_binary_uses(self) -> None:
        """A report that says GetSystemDirectoryA when the binary imports the W
        form sends a reader looking for something that is not there.

        (``GetWindowsDirectoryW``/``GetSystemDirectoryW`` are deliberately not
        used here: they are catalogued under the ``filesystem`` behaviour
        category but map to no ATT&CK technique, because path resolution is
        something nearly every installer does. Qu1cksc0pe maps them to File and
        Directory Discovery; that is a firehose we are declining.)
        """
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        hits = catalog.match({"FindFirstFileW", "FindNextFileW", "GetFileAttributesW"})
        assert hits
        for _rule, matched in hits:
            assert all(m.endswith("W") for m in matched), matched


class TestTheMeasuredEffect:
    def setup_method(self) -> None:
        reset_cache()

    def test_a_wide_only_discovery_set_now_maps(self) -> None:
        """T1083 was missing from Maljan's output for the audited sample and
        present in Qu1cksc0pe's, for exactly this reason."""
        catalog = load_api_attck_map(_ATTCK)
        assert catalog is not None
        hits = catalog.match(
            {"FindFirstFileW", "FindNextFileW", "GetFileAttributesW", "GetLogicalDriveStringsA"}
        )
        assert any(rule.technique_id == "T1083" for rule, _ in hits)
