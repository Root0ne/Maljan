"""Unit tests for ATTCKIndex, ATTCKLoader utilities, and ATTCKValidator.

All tests use fixture data to avoid network calls to the MITRE CTI repository.
"""

from __future__ import annotations

import pytest

from maljan.memory.attck_index import ATTCKIndex, SearchResult, _cosine_similarity
from maljan.memory.attck_loader import ATTCKTechnique, _parse_bundle
from maljan.memory.attck_validator import ATTCKValidator
from maljan.memory.semantic_attck_index import SemanticATTCKIndex
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_technique(
    technique_id: str,
    name: str,
    description: str,
    tactic_phases: list[str] | None = None,
    is_subtechnique: bool = False,
) -> ATTCKTechnique:
    return ATTCKTechnique(
        technique_id=technique_id,
        name=name,
        description=description,
        tactic_phases=tactic_phases or [],
        is_subtechnique=is_subtechnique,
        url=f"https://attack.mitre.org/techniques/{technique_id}/",
    )


FIXTURE_TECHNIQUES = [
    _make_technique(
        "T1055",
        "Process Injection",
        "Adversaries may inject code into processes in order to evade process-based "
        "defenses as well as possibly elevate privileges. Process injection is a method "
        "of executing arbitrary code in the address space of a separate live process. "
        "Running code in the context of another process may allow access to memory, "
        "resources, or privileges. Using VirtualAllocEx WriteProcessMemory CreateRemoteThread.",
        tactic_phases=["defense-evasion", "privilege-escalation"],
    ),
    _make_technique(
        "T1055.001",
        "Dynamic-link Library Injection",
        "Adversaries may inject dynamic link libraries DLL into processes via LoadLibrary "
        "to evade process-based defenses as well as possibly elevate privileges.",
        tactic_phases=["defense-evasion", "privilege-escalation"],
        is_subtechnique=True,
    ),
    _make_technique(
        "T1071",
        "Application Layer Protocol",
        "Adversaries may communicate using application layer protocols to avoid detection "
        "or network filtering. Commands or C2 traffic to remote systems over HTTP HTTPS DNS.",
        tactic_phases=["command-and-control"],
    ),
    _make_technique(
        "T1547",
        "Boot or Logon Autostart Execution",
        "Adversaries may configure system settings to automatically execute a program "
        "during system boot or logon to maintain persistence or gain higher privileges. "
        "Registry run keys startup folder scheduled tasks.",
        tactic_phases=["persistence", "privilege-escalation"],
    ),
    _make_technique(
        "T1486",
        "Data Encrypted for Impact",
        "Adversaries may encrypt data on target systems or on large numbers of systems "
        "in a network to interrupt availability to system files. AES RSA encryption "
        "ransomware file encryption CryptoAPI.",
        tactic_phases=["impact"],
    ),
]


@pytest.fixture
def index() -> ATTCKIndex:
    return ATTCKIndex.from_techniques(FIXTURE_TECHNIQUES)


@pytest.fixture
def validator(index: ATTCKIndex) -> ATTCKValidator:
    return ATTCKValidator.from_index(index)


# ---------------------------------------------------------------------------
# _parse_bundle()
# ---------------------------------------------------------------------------


class TestParseBundle:
    def _make_stix_obj(
        self,
        obj_type: str,
        technique_id: str,
        name: str,
        description: str = "",
        deprecated: bool = False,
        revoked: bool = False,
    ) -> dict:
        return {
            "type": obj_type,
            "name": name,
            "description": description,
            "x_mitre_deprecated": deprecated,
            "revoked": revoked,
            "x_mitre_is_subtechnique": "." in technique_id,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                }
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}
            ],
        }

    def test_parses_attack_patterns(self) -> None:
        bundle = {
            "objects": [
                self._make_stix_obj("attack-pattern", "T1055", "Process Injection", "desc"),
            ]
        }
        techniques = _parse_bundle(bundle)
        assert len(techniques) == 1
        assert techniques[0].technique_id == "T1055"

    def test_skips_non_attack_pattern(self) -> None:
        bundle = {
            "objects": [
                self._make_stix_obj("malware", "T1055", "SomeMalware"),
                self._make_stix_obj("attack-pattern", "T1071", "App Layer", "C2 traffic"),
            ]
        }
        techniques = _parse_bundle(bundle)
        assert len(techniques) == 1
        assert techniques[0].technique_id == "T1071"

    def test_skips_deprecated(self) -> None:
        bundle = {
            "objects": [
                self._make_stix_obj("attack-pattern", "T1055", "Old Tech", deprecated=True),
            ]
        }
        assert _parse_bundle(bundle) == []

    def test_skips_revoked(self) -> None:
        bundle = {
            "objects": [
                self._make_stix_obj("attack-pattern", "T1055", "Revoked", revoked=True),
            ]
        }
        assert _parse_bundle(bundle) == []

    def test_sub_technique_flag(self) -> None:
        bundle = {
            "objects": [
                self._make_stix_obj("attack-pattern", "T1055.001", "DLL Injection"),
            ]
        }
        techniques = _parse_bundle(bundle)
        assert techniques[0].is_subtechnique is True


# ---------------------------------------------------------------------------
# ATTCKIndex
# ---------------------------------------------------------------------------


class TestATTCKIndex:
    def test_size(self, index: ATTCKIndex) -> None:
        assert index.size == len(FIXTURE_TECHNIQUES)

    def test_get_by_id_found(self, index: ATTCKIndex) -> None:
        tech = index.get_by_id("T1055")
        assert tech is not None
        assert tech.name == "Process Injection"

    def test_get_by_id_case_insensitive(self, index: ATTCKIndex) -> None:
        assert index.get_by_id("t1055") is not None

    def test_get_by_id_not_found(self, index: ATTCKIndex) -> None:
        assert index.get_by_id("T9999") is None

    def test_technique_exists_true(self, index: ATTCKIndex) -> None:
        assert index.technique_exists("T1055") is True

    def test_technique_exists_false(self, index: ATTCKIndex) -> None:
        assert index.technique_exists("T9999") is False

    def test_search_returns_results(self, index: ATTCKIndex) -> None:
        results = index.search("process injection WriteProcessMemory remote thread")
        assert len(results) > 0
        assert all(isinstance(r, SearchResult) for r in results)

    def test_search_ranks_by_score(self, index: ATTCKIndex) -> None:
        results = index.search("process injection WriteProcessMemory")
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_search_top_k_respected(self, index: ATTCKIndex) -> None:
        results = index.search("process injection", top_k=2)
        assert len(results) <= 2

    def test_search_rank_sequential(self, index: ATTCKIndex) -> None:
        results = index.search("process injection", top_k=3)
        assert [r.rank for r in results] == list(range(1, len(results) + 1))

    def test_search_tactic_filter(self, index: ATTCKIndex) -> None:
        results = index.search("command control beaconing", filter_tactics=["command-and-control"])
        assert all("command-and-control" in r.technique.tactic_phases for r in results)

    def test_search_no_results_for_gibberish(self, index: ATTCKIndex) -> None:
        # Completely out-of-vocabulary query
        results = index.search("xyzqwmfoo barberizatorxxx")
        assert len(results) == 0

    def test_validate_and_score_known_match(self, index: ATTCKIndex) -> None:
        # "process injection WriteProcessMemory" should score well against T1055
        evidence = "process injection WriteProcessMemory VirtualAllocEx"
        score = index.validate_and_score("T1055", evidence)
        assert score > 0.0

    def test_validate_and_score_unknown_id(self, index: ATTCKIndex) -> None:
        score = index.validate_and_score("T9999", "any evidence text")
        assert score == 0.0

    def test_not_built_raises(self) -> None:
        idx = ATTCKIndex()
        with pytest.raises(RuntimeError, match="not built"):
            idx.search("any query")


# ---------------------------------------------------------------------------
# ATTCKValidator
# ---------------------------------------------------------------------------


class TestATTCKValidator:
    def test_validate_ttp_id_existing(self, validator: ATTCKValidator) -> None:
        assert validator.validate_ttp_id("T1055") is True

    def test_validate_ttp_id_nonexistent(self, validator: ATTCKValidator) -> None:
        assert validator.validate_ttp_id("T9999") is False

    def test_validate_ttp_id_case_insensitive(self, validator: ATTCKValidator) -> None:
        assert validator.validate_ttp_id("t1055") is True

    def test_validate_claim_returns_tuple(self, validator: ATTCKValidator) -> None:
        result = validator.validate_claim("T1055", "WriteProcessMemory process injection")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], float)

    def test_validate_claim_unknown_id_returns_false(self, validator: ATTCKValidator) -> None:
        is_plausible, score = validator.validate_claim("T9999", "any evidence")
        assert is_plausible is False
        assert score == 0.0

    def test_validate_claim_relevant_evidence(self, validator: ATTCKValidator) -> None:
        is_plausible, score = validator.validate_claim(
            "T1486",
            "AES encryption ransomware CryptoAPI file encryption impact",
        )
        assert score > 0.0

    def test_suggest_techniques_returns_results(self, validator: ATTCKValidator) -> None:
        results = validator.suggest_techniques("process injection dll remote thread")
        assert len(results) > 0

    def test_suggest_techniques_top_k(self, validator: ATTCKValidator) -> None:
        results = validator.suggest_techniques("any behavior", top_k=2)
        assert len(results) <= 2

    def test_get_technique_known(self, validator: ATTCKValidator) -> None:
        tech = validator.get_technique("T1055")
        assert tech is not None
        assert tech.technique_id == "T1055"

    def test_get_technique_unknown(self, validator: ATTCKValidator) -> None:
        assert validator.get_technique("T9999") is None

    def test_technique_count(self, validator: ATTCKValidator) -> None:
        assert validator.technique_count == len(FIXTURE_TECHNIQUES)

    def test_from_index_factory(self, index: ATTCKIndex) -> None:
        v = ATTCKValidator.from_index(index)
        assert v.technique_count == index.size


# ---------------------------------------------------------------------------
# ATTCKValidator.correct_isr_reports
# ---------------------------------------------------------------------------


def _isr(agent_id: str, domain: str, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id=agent_id, domain=domain, claims=list(claims))


def _claim(claim: str, evidence: str, technique_id: str | None) -> ClaimEvidence:
    return ClaimEvidence(
        claim=claim, evidence_ref=evidence, confidence=0.8, technique_id=technique_id
    )


class TestCorrectIsrReports:
    def test_invalid_id_replaced_with_suggestion(self, validator: ATTCKValidator) -> None:
        # T9999 is well-formed but not in the catalog; ransomware evidence
        # should re-ground onto T1486 (Data Encrypted for Impact).
        claim = _claim(
            "Encrypts files for ransom",
            "AES encryption ransomware file encryption CryptoAPI impact",
            "T9999",
        )
        reports = {"static": _isr("static", "static", claim)}

        n = validator.correct_isr_reports(reports)

        assert n == 1
        assert claim.technique_id == "T1486"

    def test_valid_well_aligned_untouched(self, validator: ATTCKValidator) -> None:
        claim = _claim(
            "Injects code into a remote process",
            "process injection WriteProcessMemory VirtualAllocEx CreateRemoteThread",
            "T1055",
        )
        reports = {"static": _isr("static", "static", claim)}

        n = validator.correct_isr_reports(reports, min_alignment=0.001)

        assert n == 0
        assert claim.technique_id == "T1055"

    def test_low_alignment_swapped_for_better_candidate(self, validator: ATTCKValidator) -> None:
        # Valid ID (T1071, C2) but the evidence is pure ransomware — a strictly
        # better-aligned candidate (T1486) exists, so it is swapped.
        claim = _claim(
            "Encrypts data on disk",
            "AES encryption ransomware file encryption CryptoAPI impact",
            "T1071",
        )
        reports = {"static": _isr("static", "static", claim)}

        n = validator.correct_isr_reports(reports, min_alignment=0.05)

        assert n == 1
        assert claim.technique_id == "T1486"

    def test_none_technique_untouched(self, validator: ATTCKValidator) -> None:
        claim = _claim("Generic observation", "some evidence ref", None)
        reports = {"static": _isr("static", "static", claim)}

        n = validator.correct_isr_reports(reports)

        assert n == 0
        assert claim.technique_id is None

    def test_layer0_sources_skipped(self, validator: ATTCKValidator) -> None:
        # yara/sigma IDs are rule-authoritative; even an invalid-looking ID
        # is left untouched.
        yara_claim = _claim("YARA rule match", "rule: Ransomware_Generic", "T9999")
        sigma_claim = _claim("Sigma rule match", "rule: susp_encrypt", "T9999")
        reports = {
            "yara_layer": _isr("yara_layer", "yara", yara_claim),
            "sigma_layer": _isr("sigma_layer", "sigma", sigma_claim),
        }

        n = validator.correct_isr_reports(reports)

        assert n == 0
        assert yara_claim.technique_id == "T9999"
        assert sigma_claim.technique_id == "T9999"

    def test_invalid_id_with_no_suggestion_dropped(self, validator: ATTCKValidator) -> None:
        # Out-of-vocabulary evidence yields no TF-IDF match -> the hallucinated
        # ID is dropped to None rather than left in place.
        claim = _claim("xyzqwmfoo", "barberizatorxxx zzzqqq", "T9999")
        reports = {"static": _isr("static", "static", claim)}

        n = validator.correct_isr_reports(reports)

        assert n == 1
        assert claim.technique_id is None


# ---------------------------------------------------------------------------
# SemanticATTCKIndex (drop-in embedding backend)
# ---------------------------------------------------------------------------


@pytest.fixture
def semantic_index() -> SemanticATTCKIndex:
    return SemanticATTCKIndex.from_techniques(FIXTURE_TECHNIQUES)


class TestSemanticATTCKIndex:
    """Smoke tests: the semantic index honours the ATTCKIndex interface.

    Uses whatever embedding backend is installed (real fastembed BGE, or the
    BoW fallback). Assertions are backend-agnostic — they check structure and
    ordering, not absolute similarity values.
    """

    def test_size_and_inherited_lookup(self, semantic_index: SemanticATTCKIndex) -> None:
        assert semantic_index.size == len(FIXTURE_TECHNIQUES)
        # get_by_id / technique_exists are inherited unchanged.
        assert semantic_index.get_by_id("T1055") is not None
        assert semantic_index.technique_exists("T1055") is True
        assert semantic_index.technique_exists("T9999") is False

    def test_search_returns_ranked_results(self, semantic_index: SemanticATTCKIndex) -> None:
        results = semantic_index.search("ransomware encrypts files for impact", top_k=3)
        assert all(isinstance(r, SearchResult) for r in results)
        assert len(results) <= 3
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)
        assert [r.rank for r in results] == list(range(1, len(results) + 1))

    def test_validate_and_score_range(self, semantic_index: SemanticATTCKIndex) -> None:
        score = semantic_index.validate_and_score("T1486", "encrypt files ransomware impact")
        assert 0.0 <= score <= 1.0001

    def test_validate_and_score_unknown_id(self, semantic_index: SemanticATTCKIndex) -> None:
        assert semantic_index.validate_and_score("T9999", "any evidence") == 0.0

    def test_not_built_raises(self) -> None:
        idx = SemanticATTCKIndex()
        with pytest.raises(RuntimeError, match="not built"):
            idx.search("any query")

    def test_correct_isr_reports_via_semantic_backend(
        self, semantic_index: SemanticATTCKIndex
    ) -> None:
        # The validator's correction logic is index-agnostic; an invalid ID must
        # still be replaced with a valid catalog ID through the semantic index.
        validator = ATTCKValidator.from_index(semantic_index)
        claim = _claim(
            "Encrypts victim files for ransom",
            "ransomware encrypts files AES impact unavailable",
            "T9999",
        )
        reports = {"static": _isr("static", "static", claim)}
        n = validator.correct_isr_reports(reports, min_alignment=0.0)
        # min_alignment=0.0 only forces invalid-ID replacement; the new ID must
        # exist in the catalog and differ from the hallucinated one.
        assert claim.technique_id != "T9999"
        assert claim.technique_id is None or semantic_index.technique_exists(claim.technique_id)
        assert n in (0, 1)


# ---------------------------------------------------------------------------
# _cosine_similarity
# ---------------------------------------------------------------------------


class TestCosineSimilarity:
    def test_identical_vectors(self) -> None:
        a = {"x": 1.0, "y": 2.0}
        assert _cosine_similarity(a, a) == pytest.approx(1.0)

    def test_orthogonal_vectors(self) -> None:
        a = {"x": 1.0}
        b = {"y": 1.0}
        assert _cosine_similarity(a, b) == pytest.approx(0.0)

    def test_empty_vector(self) -> None:
        assert _cosine_similarity({}, {"x": 1.0}) == 0.0
        assert _cosine_similarity({"x": 1.0}, {}) == 0.0

    def test_partial_overlap(self) -> None:
        a = {"x": 1.0, "y": 1.0}
        b = {"x": 1.0, "z": 1.0}
        sim = _cosine_similarity(a, b)
        # cos([1,1,0], [1,0,1]) = 1/(sqrt(2)*sqrt(2)) = 0.5
        assert sim == pytest.approx(0.5, abs=1e-6)


# ---------------------------------------------------------------------------
# ATTCKTechnique.searchable_text
# ---------------------------------------------------------------------------


class TestATTCKTechniqueSearchableText:
    def test_searchable_text_contains_id(self) -> None:
        tech = _make_technique("T1055", "Process Injection", "desc")
        assert "T1055" in tech.searchable_text

    def test_searchable_text_contains_name(self) -> None:
        tech = _make_technique("T1055", "Process Injection", "desc")
        assert "Process Injection" in tech.searchable_text

    def test_searchable_text_capped_description(self) -> None:
        long_desc = "x" * 5000
        tech = _make_technique("T1055", "Process Injection", long_desc)
        assert len(tech.searchable_text) < 5000 + 200
