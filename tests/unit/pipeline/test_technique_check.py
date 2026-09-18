"""The ATT&CK technique check, four parts, none of them a rewrite.

Validity says when it could not run instead of answering "nothing unknown".
Platform consistency puts the catalogue's domain and platforms against the
routed sample, in the analyst's loop and in the judge's bundle. The alignment
gate ranks a claim's text against the index only on a warm index, writes the
ranking on the claim, and questions an id the index neither ranked nor scored
above the threshold. Corroboration counts who asserted and who claimed each
technique, as two flat lists. In every part the analyst's id stays exactly as
written.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import pytest

from maljan.agents.base_agent import BaseAnalyst, alignment_gate
from maljan.pipeline.validation import (
    PLATFORM_MISMATCH_CODE,
    VALIDITY_CODE,
    WEAK_ALIGNMENT_CODE,
    _weak_alignment,
    corroboration,
    corroboration_sources,
    expected_technique_scope,
    platform_mismatch_message,
    technique_check_note,
    validate_isr,
    validate_verdict_bundle,
    validation_metrics,
    validity_check_available,
)
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import AttackPattern, Bundle
from maljan.tools import knowledge

CATALOGUE: dict[str, dict[str, Any]] = {
    "T1055": {"domain": "enterprise", "platforms": ["Windows", "Linux", "macOS"]},
    "T1547.001": {"domain": "enterprise", "platforms": ["Windows"]},
    "T1053.003": {"domain": "enterprise", "platforms": ["Linux", "macOS"]},
    "T1417": {"domain": "mobile", "platforms": ["Android", "iOS"]},
    "T1592": {"domain": "enterprise", "platforms": ["PRE"]},
    "T1071": {"domain": "enterprise", "platforms": []},
}


class _Attck:
    """A stand-in for ``tools.knowledge`` that never loads the real bundle."""

    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.lookups: list[str] = []
        # Per id, the tactics the catalogue would give it. Empty for most of
        # them: a catalogue that cannot say is not a reason to stay silent.
        self.tactics: dict[str, list[str]] = {}

    def attck_validate(self, ids: list[str]) -> dict[str, Any]:
        return {"invalid": [{"id": t} for t in ids if t not in CATALOGUE], "checked": len(ids)}

    def attck_lookup(self, technique_id: str) -> dict[str, Any]:
        self.lookups.append(technique_id)
        row = CATALOGUE.get(technique_id, {})
        return {
            "valid": technique_id in CATALOGUE,
            "technique_id": technique_id,
            "domain": row.get("domain"),
            "platforms": list(row.get("platforms") or []),
            "tactics": list(self.tactics.get(technique_id) or []),
        }

    def resolve_technique(self, text: str, k: int = 5) -> dict[str, Any]:
        return {"candidates": [{"technique_id": "T1055"}]}

    def catalogue_available(self) -> bool:
        return self.available


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=list(claims))


def _claim(technique: str | None, text: str = "the sample injects code") -> ClaimEvidence:
    return ClaimEvidence(
        claim=text, evidence_ref="[ev_0001] import table", confidence=0.6, technique_id=technique
    )


def _codes(violations: list[Any]) -> list[str]:
    return [v.code for v in violations]


PE = {"platform": "windows", "file_type": "pe"}
APK = {"platform": "android", "file_type": "apk"}


class TestThePlatformTable:
    @pytest.mark.parametrize(
        ("sample", "expected"),
        [
            ({"platform": "windows", "file_type": "pe"}, ("enterprise", ("Windows",))),
            ({"platform": "linux", "file_type": "elf"}, ("enterprise", ("Linux",))),
            ({"platform": "macos", "file_type": "mach-o"}, ("enterprise", ("macOS",))),
            ({"platform": "android", "file_type": "apk"}, ("mobile", ("Android",))),
            ({"platform": "android", "file_type": "dex"}, ("mobile", ("Android",))),
            ({"platform": "unknown", "file_type": "pe"}, ("enterprise", ("Windows",))),
            ({"platform": "", "file_type": "elf"}, ("enterprise", ("Linux",))),
            ({"platform": "unknown", "file_type": "unknown"}, (None, ())),
            ({"platform": "multi", "file_type": "jar"}, (None, ())),
            ({}, (None, ())),
            (None, (None, ())),
        ],
    )
    def test_the_routed_sample_maps_to_a_domain_and_platforms(self, sample, expected) -> None:
        assert expected_technique_scope(sample) == expected


class TestPlatformMismatchInTheAnalystsLoop:
    def test_a_mobile_technique_on_a_windows_pe_is_questioned(self) -> None:
        violations = validate_isr(_isr(_claim("T1417")), attck=_Attck(), sample=PE)
        assert _codes(violations) == [PLATFORM_MISMATCH_CODE]
        message = violations[0].message
        assert "T1417" in message and "mobile" in message
        assert "Android, iOS" in message
        assert "enterprise-domain, Windows" in message

    def test_a_linux_only_technique_on_a_windows_pe_is_questioned(self) -> None:
        violations = validate_isr(_isr(_claim("T1053.003")), attck=_Attck(), sample=PE)
        assert _codes(violations) == [PLATFORM_MISMATCH_CODE]
        assert "Linux, macOS" in violations[0].message

    def test_a_technique_that_fits_passes(self) -> None:
        assert validate_isr(_isr(_claim("T1547.001")), attck=_Attck(), sample=PE) == []
        assert validate_isr(_isr(_claim("T1417")), attck=_Attck(), sample=APK) == []

    def test_an_unknown_sample_platform_is_no_check(self) -> None:
        attck = _Attck()
        assert (
            validate_isr(_isr(_claim("T1417")), attck=attck, sample={"platform": "unknown"}) == []
        )
        assert validate_isr(_isr(_claim("T1417")), attck=attck) == []

    def test_a_technique_with_no_platforms_in_the_catalogue_is_not_questioned(self) -> None:
        assert validate_isr(_isr(_claim("T1071")), attck=_Attck(), sample=PE) == []

    def test_an_unknown_id_is_the_validity_finding_and_not_a_mismatch_too(self) -> None:
        violations = validate_isr(_isr(_claim("T9999")), attck=_Attck(), sample=PE)
        assert _codes(violations) == ["attck.unknown_id"]

    def test_the_id_is_left_exactly_as_written(self) -> None:
        isr = _isr(_claim("T1417"))
        validate_isr(isr, attck=_Attck(), sample=PE)
        assert isr.claims[0].technique_id == "T1417"
        assert isr.claims[0].technique_id_valid is True


class TestPlatformMismatchInTheVerdict:
    def _bundle(self, tid: str) -> Bundle:
        return Bundle(
            objects=[  # type: ignore[list-item]
                AttackPattern(
                    name="x",
                    external_references=[{"source_name": "mitre-attack", "external_id": tid}],
                )
            ]
        )

    def test_a_mobile_attack_pattern_on_a_windows_sample_is_questioned(self) -> None:
        violations = validate_verdict_bundle(self._bundle("T1417"), attck=_Attck(), sample=PE)
        assert PLATFORM_MISMATCH_CODE in _codes(violations)
        assert violations[0].message.startswith("TECHNIQUE T1417 belongs to")

    def test_a_fitting_attack_pattern_passes(self) -> None:
        assert validate_verdict_bundle(self._bundle("T1055"), attck=_Attck(), sample=PE) == []

    def test_without_a_sample_nothing_is_questioned(self) -> None:
        assert validate_verdict_bundle(self._bundle("T1417"), attck=_Attck()) == []


def _gate(candidates: list[tuple[str, float]], gate_score: float):
    seen: list[tuple[str, str]] = []

    def alignment(text: str, technique_id: str, k: int = 5) -> dict[str, Any]:
        seen.append((text, technique_id))
        return {
            "gate_score": gate_score,
            "candidates": [{"technique_id": tid, "score_gate": score} for tid, score in candidates],
        }

    alignment.seen = seen  # type: ignore[attr-defined]
    return alignment


class TestTheAlignmentGate:
    """It ranks, it records, and it questions only inside the sample's scope.

    The check as it shipped scored an id against a domain-blind index and
    questioned everything the index had not ranked. The audit measured what
    that costs: a claim about a Windows PE answered with Mobile and ICS
    techniques, and four runs in which nearly every technique claim was
    questioned, each batch a model turn. What a question now needs is a
    candidate from the sample's own domain and platforms, from another tactic
    than the claim's id, beating that id's score by the margin — and the
    question is only asked at all when it is turned on.
    """

    def test_a_better_in_scope_candidate_is_named_with_its_score(self) -> None:
        isr = _isr(_claim("T1547.001", "the sample allocates memory in another process"))
        gate = _gate([("T1055", 0.41), ("T1055.001", 0.33)], gate_score=0.01)
        violations = validate_isr(
            isr, attck=_Attck(), sample=PE, alignment=gate, weak_alignment_challenges=True
        )
        assert _codes(violations) == [WEAK_ALIGNMENT_CODE]
        message = violations[0].message
        assert "T1547.001" in message and "0.01" in message and "0.05" in message
        assert "T1055 (0.41), T1055.001 (0.33)" in message
        assert "Keep T1547.001 if the evidence says so" in message
        # The claim text, not the id, is what the index was asked about.
        assert gate.seen[0][0].startswith("the sample allocates memory")
        assert gate.seen[0][1] == "T1547.001"

    def test_it_questions_nothing_unless_it_is_turned_on(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.41)], gate_score=0.01)
        assert validate_isr(isr, attck=_Attck(), sample=PE, alignment=gate) == []
        assert isr.claims[0].alignment["gate_score"] == 0.01

    def test_the_ranking_is_written_on_the_claim_and_the_id_is_not_replaced(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.41)], gate_score=0.01)
        validate_isr(isr, attck=_Attck(), sample=PE, alignment=gate)
        assert isr.claims[0].technique_id == "T1547.001"
        assert isr.claims[0].alignment == {
            "gate_score": 0.01,
            "candidates": [{"technique_id": "T1055", "score_gate": 0.41}],
        }

    def test_an_out_of_scope_candidate_is_never_proposed(self) -> None:
        """``T1417`` is Mobile, and the index offered it for a Windows PE."""
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1417", 0.62), ("T1055", 0.10)], gate_score=0.01)
        violations = validate_isr(
            isr, attck=_Attck(), sample=PE, alignment=gate, weak_alignment_challenges=True
        )
        assert violations == []
        assert isr.claims[0].alignment["candidates"] == [
            {"technique_id": "T1055", "score_gate": 0.10}
        ]

    def test_a_candidate_inside_the_margin_is_a_ranking_not_a_question(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.15)], gate_score=0.01)
        assert (
            validate_isr(
                isr, attck=_Attck(), sample=PE, alignment=gate, weak_alignment_challenges=True
            )
            == []
        )

    def test_the_margin_is_the_caller_s(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.15)], gate_score=0.01)
        violations = validate_isr(
            isr,
            attck=_Attck(),
            sample=PE,
            alignment=gate,
            alignment_margin=0.1,
            weak_alignment_challenges=True,
        )
        assert _codes(violations) == [WEAK_ALIGNMENT_CODE]

    def test_a_candidate_from_the_claim_own_family_is_not_a_disagreement(self) -> None:
        isr = _isr(_claim("T1055"))
        gate = _gate([("T1055.001", 0.41)], gate_score=0.01)
        assert (
            validate_isr(
                isr, attck=_Attck(), sample=PE, alignment=gate, weak_alignment_challenges=True
            )
            == []
        )

    def test_a_candidate_from_the_claim_own_tactic_is_not_a_disagreement(self) -> None:
        attck = _Attck()
        attck.tactics = {"T1547.001": ["persistence"], "T1055": ["persistence"]}
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.41)], gate_score=0.01)
        assert (
            validate_isr(
                isr, attck=attck, sample=PE, alignment=gate, weak_alignment_challenges=True
            )
            == []
        )

    def test_an_id_among_the_candidates_passes_whatever_its_score(self) -> None:
        isr = _isr(_claim("T1055"))
        gate = _gate([("T1055", 0.02)], gate_score=0.02)
        assert (
            validate_isr(
                isr, attck=_Attck(), sample=PE, alignment=gate, weak_alignment_challenges=True
            )
            == []
        )
        assert isr.claims[0].alignment["gate_score"] == 0.02

    def test_an_id_above_the_threshold_passes_although_unranked(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.41)], gate_score=0.2)
        assert (
            validate_isr(
                isr, attck=_Attck(), sample=PE, alignment=gate, weak_alignment_challenges=True
            )
            == []
        )

    def test_the_threshold_is_the_caller_s(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.41)], gate_score=0.2)
        violations = validate_isr(
            isr,
            attck=_Attck(),
            sample=PE,
            alignment=gate,
            alignment_threshold=0.5,
            weak_alignment_challenges=True,
        )
        assert _codes(violations) == [WEAK_ALIGNMENT_CODE]

    def test_a_sample_with_no_scope_is_ranked_and_never_questioned(self) -> None:
        isr = _isr(_claim("T1547.001"))
        gate = _gate([("T1055", 0.41)], gate_score=0.01)
        violations = validate_isr(
            isr,
            attck=_Attck(),
            sample={"platform": "multi", "file_type": "jar"},
            alignment=gate,
            weak_alignment_challenges=True,
        )
        assert violations == []
        assert isr.claims[0].alignment["candidates"] == [
            {"technique_id": "T1055", "score_gate": 0.41}
        ]

    def test_no_gate_means_no_ranking_and_no_question(self) -> None:
        isr = _isr(_claim("T1547.001"))
        assert validate_isr(isr, attck=_Attck(), sample=PE, alignment=None) == []
        assert isr.claims[0].alignment is None

    def test_a_gate_that_raises_gates_nothing(self) -> None:
        def broken(text: str, technique_id: str) -> dict[str, Any]:
            raise RuntimeError("index gone")

        assert validate_isr(_isr(_claim("T1547.001")), attck=_Attck(), alignment=broken) == []


class _FakeResult:
    def __init__(self, tid: str, score: float) -> None:
        self.technique = type("T", (), {"technique_id": tid, "name": tid})()
        self.score = score


class _FakeIndex:
    def __init__(self) -> None:
        self.scored: list[tuple[str, str]] = []

    def search(self, text: str, top_k: int = 5) -> list[_FakeResult]:
        return [_FakeResult("T1055", 0.7), _FakeResult("T1055.001", 0.65)][:top_k]

    def validate_and_score(self, tid: str, text: str) -> float:
        self.scored.append((tid, text))
        return {"T1055": 0.4, "T1055.001": 0.3}.get(tid, 0.0)


class TestTheGateRunsOnlyOnAWarmIndex:
    @pytest.fixture(autouse=True)
    def _cold(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(knowledge, "_HYBRID_INDEX", None)
        monkeypatch.setattr(knowledge, "_HYBRID_FAILED", "")
        yield

    def test_a_cold_index_answers_nothing_and_is_not_built(self, monkeypatch) -> None:
        def _never(*_a: Any, **_k: Any) -> Any:
            raise AssertionError("the gate built the index")

        monkeypatch.setattr(knowledge, "_hybrid_index", _never)
        assert knowledge.index_is_warm() is False
        assert knowledge.technique_alignment("text", "T1055") is None

    def test_a_warm_index_scores_the_claimed_id_and_ranks_candidates(self, monkeypatch) -> None:
        fake = _FakeIndex()
        monkeypatch.setattr(knowledge, "_HYBRID_INDEX", fake)
        monkeypatch.setattr("maljan.memory.attck_loader.domain_of", lambda tid: "enterprise")
        assert knowledge.index_is_warm() is True
        answer = knowledge.technique_alignment("injects into a process", "T1547.001", k=2)
        assert answer["technique_id"] == "T1547.001"
        assert answer["gate_score"] == 0.0
        assert [c["technique_id"] for c in answer["candidates"]] == ["T1055", "T1055.001"]
        assert answer["candidates"][0]["score_gate"] == 0.4
        assert ("T1547.001", "injects into a process") in fake.scored

    def test_the_background_build_runs_once_and_never_in_the_caller(self, monkeypatch) -> None:
        import threading

        built: list[str] = []
        release = threading.Event()

        def _slow_build() -> tuple[Any, str]:
            release.wait(5)
            built.append(threading.current_thread().name)
            return None, "stopped"

        monkeypatch.setattr(knowledge, "_hybrid_index", _slow_build)
        monkeypatch.setattr(knowledge, "_WARM_STARTED", False)
        assert knowledge.warm_index_in_background() is True
        # A second caller while the first build runs starts nothing.
        assert knowledge.warm_index_in_background() is False
        release.set()
        for _ in range(100):
            if built:
                break
            threading.Event().wait(0.02)
        assert built == ["maljan-attck-index"]
        assert knowledge.index_is_warm() is False


class _Analyst(BaseAnalyst):
    def __init__(self) -> None:
        self.name = "static"
        self.logger = logging.getLogger("test.gate")
        self.validation_not_run = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""


class _Cfg:
    def __init__(self, gate: str = "auto", build: bool = False) -> None:
        self.alignment_gate = gate
        self.alignment_gate_build = build
        self.alignment_threshold = 0.05


class _Knowledge:
    def __init__(self, warm: bool) -> None:
        self.warm = warm
        self.builds = 0

    def index_is_warm(self) -> bool:
        return self.warm

    def technique_alignment(self, text: str, technique_id: str, k: int = 5) -> dict[str, Any]:
        return {"gate_score": 1.0, "candidates": []}

    def warm_index_in_background(self) -> bool:
        self.builds += 1
        return True


def _policy_gate(knowledge: Any, cfg: Any) -> Any | None:
    return alignment_gate(knowledge, cfg, logging.getLogger("test"), "static")


class TestTheGatePolicy:
    def test_auto_on_a_warm_worker_runs_the_gate(self) -> None:
        agent = _Analyst()
        assert alignment_gate(_Knowledge(warm=True), _Cfg(), agent.logger, agent.name) is not None

    def test_auto_on_a_cold_worker_runs_nothing_and_builds_nothing_by_default(self) -> None:
        knowledge_stub = _Knowledge(warm=False)
        assert _policy_gate(knowledge_stub, _Cfg()) is None
        assert knowledge_stub.builds == 0

    def test_the_build_switch_starts_one_build_and_this_run_still_goes_without(self) -> None:
        knowledge_stub = _Knowledge(warm=False)
        assert _policy_gate(knowledge_stub, _Cfg(build=True)) is None
        assert knowledge_stub.builds == 1

    def test_off_never_runs_it(self) -> None:
        knowledge_stub = _Knowledge(warm=True)
        assert _policy_gate(knowledge_stub, _Cfg(gate="off")) is None

    def test_a_knowledge_module_without_the_question_has_no_gate(self) -> None:
        assert _policy_gate(object(), _Cfg()) is None


class TestValidityAvailability:
    def test_a_catalogue_that_cannot_be_read_says_the_check_did_not_run(self) -> None:
        assert validity_check_available(_Attck(available=False)) is False
        assert validity_check_available(_Attck(available=True)) is True
        assert validity_check_available(None) is False

    def test_a_stub_without_the_probe_counts_as_available(self) -> None:
        class _Bare:
            def attck_validate(self, ids: list[str]) -> dict[str, Any]:
                return {"invalid": []}

        assert validity_check_available(_Bare()) is True

    def test_the_metrics_carry_the_row_and_an_empty_list_otherwise(self) -> None:
        with_row = validation_metrics(0, [], None, not_run=[VALIDITY_CODE, VALIDITY_CODE])
        assert with_row["not_run"] == ["attck.unknown_id"]
        assert validation_metrics(0, [], None)["not_run"] == []

    def test_the_analyst_records_it_once_and_hands_it_over_once(self, monkeypatch) -> None:
        from maljan.agents import base_agent

        monkeypatch.setattr(knowledge, "catalogue_available", lambda: False)
        agent = BaseAnalyst.__new__(_Analyst)
        agent.name = "static"
        agent.logger = logging.getLogger("test")
        agent.validation_not_run = []
        agent._evidence_entries = []
        agent.pack_ledger_ids = []
        agent.sample_format = ("pe", "windows")
        monkeypatch.setattr(
            base_agent,
            "validate_isr",
            lambda *_a, **_k: [],
        )
        agent._validate_isr(_isr(_claim("T1055")), "evidence")
        agent._validate_isr(_isr(_claim("T1055")), "evidence")
        assert agent.validation_not_run == ["attck.unknown_id"]
        assert agent.drain_validation_not_run() == ["attck.unknown_id"]
        assert agent.drain_validation_not_run() == []


class TestTheNoteTheJudgeReads:
    def test_it_lists_the_two_kinds_and_nothing_else(self) -> None:
        findings = {
            "static": [
                {"code": PLATFORM_MISMATCH_CODE, "message": "TECHNIQUE T1417 belongs to mobile"},
                {"code": WEAK_ALIGNMENT_CODE, "message": "TECHNIQUE T1547.001 aligns weakly"},
                {"code": "isr.ungrounded_technique", "message": "TECHNIQUE T1055 cites nothing"},
            ]
        }
        note = technique_check_note(findings)
        assert note.startswith("TECHNIQUE CHECK")
        assert "nothing here changed them" in note
        assert "- attck.platform_mismatch: TECHNIQUE T1417 belongs to mobile" in note
        assert "- attck.weak_alignment: TECHNIQUE T1547.001 aligns weakly" in note
        assert "T1055" not in note

    def test_nothing_questioned_is_no_note(self) -> None:
        assert technique_check_note({}) == ""
        assert technique_check_note(None) == ""


def _entry(tool: str, payload: dict[str, Any], seq: int):
    import json

    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent="pipeline",
        tool=tool,
        args={},
        server="pipeline",
        output=json.dumps(payload),
        stage="triage_pack",
    )


def _fixture(name: str) -> dict[str, Any]:
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2] / "fixtures" / "ledger"
    return json.loads((root / f"{name}.json").read_text(encoding="utf-8"))


class TestCorroborationCounts:
    def test_the_pack_s_sources_assert_and_the_agents_claim(self) -> None:
        """The four sources in the shapes they really emit: the capa and
        Sigma ledger fixtures, and the two knowledge tools called live.
        capa decorates its ids, Sigma lower-cases them under ``tags``."""
        from maljan.tools.knowledge import api_capability, lolbin_lookup

        capa = _fixture("capa")
        assert capa["capabilities"][0]["attck"] == ["Defense Evasion::Process Injection [T1055]"]
        sigma = _fixture("sigma_match")
        assert "attack.t1547.001" in sigma["matches"][0]["tags"]
        ledger = [
            _entry("capa", capa, 1),
            _entry("sigma_match_sandbox", sigma, 2),
            _entry(
                "lolbin_lookup", lolbin_lookup(["rundll32.exe C:\\Users\\Public\\x.dll,DllMain"]), 3
            ),
            _entry(
                "api_capability",
                api_capability(["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]),
                4,
            ),
        ]
        isrs = {
            "static": _isr(_claim("T1055"), _claim("T1071")),
            "dynamic": AgentISR(agent_id="dynamic", domain="dynamic", claims=[_claim("T1055")]),
        }
        rows = corroboration(isrs, ledger)
        # The API catalogue's association is shown apart and counts for nothing.
        assert rows["T1055"] == {
            "asserted_by": ["capa"],
            "claimed_by": ["dynamic", "static"],
            "associated_by": ["api_capability"],
        }
        assert rows["T1547.001"] == {"asserted_by": ["sigma"], "claimed_by": []}
        assert rows["T1218.011"] == {"asserted_by": ["lolbin"], "claimed_by": []}
        # A technique nothing asserted keeps its row, with the empty list showing.
        assert rows["T1071"] == {"asserted_by": [], "claimed_by": ["static"]}

    def test_a_rule_that_lists_an_api_but_did_not_fire_asserts_nothing(self) -> None:
        """The same floor the projection applies: one API under a two-API rule
        is a listing, not a hit, and corroboration does not count it."""
        payload = {
            "capabilities": [
                {
                    "api": "WriteProcessMemory",
                    "techniques": [
                        {
                            "technique_id": "T1055",
                            "name": "Process Injection",
                            "matched": ["WriteProcessMemory"],
                            "min_apis": 2,
                        }
                    ],
                }
            ]
        }
        rows = corroboration(
            {"static": _isr(_claim("T1055"))}, [_entry("api_capability", payload, 1)]
        )
        assert rows["T1055"] == {"asserted_by": [], "claimed_by": ["static"]}

    def test_no_weights_and_no_score_anywhere(self) -> None:
        rows = corroboration({"static": _isr(_claim("T1055"))}, [])
        assert set(rows["T1055"]) == {"asserted_by", "claimed_by"}

    def test_the_source_count_reads_both_shapes(self) -> None:
        assert corroboration_sources({"asserted_by": ["capa"], "claimed_by": ["static"]}) == [
            "capa",
            "static",
        ]
        assert corroboration_sources(["static", "dynamic"]) == ["static", "dynamic"]
        assert corroboration_sources(None) == []


class TestTheMatrixCarriesTheCatalogueScope:
    def test_cells_carry_domain_and_platforms_and_c1_reads_them(self, monkeypatch) -> None:
        from maljan.extractors.capability_matrix import build_capability_matrix
        from maljan.qa.fp_linter import lint_report

        monkeypatch.setattr(knowledge, "attck_lookup", _Attck().attck_lookup)
        monkeypatch.setattr(
            "maljan.extractors.capability_matrix._unknown_to_the_catalogue", lambda ids: set()
        )
        # The matrix names tactics through the ATT&CK index, and the configured
        # backend is the hybrid one; a test must never pay for that build.
        monkeypatch.setattr("maljan.extractors.capability_matrix._load_attck_index", lambda: None)
        isrs = {"static": _isr(_claim("T1417"), _claim("T1547.001"))}
        cells, _mappings = build_capability_matrix(stix_output=None, isr_reports=isrs)
        by_id = {cell.technique_id: cell for cell in cells}
        assert by_id["T1417"].domain == "mobile"
        assert by_id["T1417"].platforms == ["Android", "iOS"]
        assert by_id["T1547.001"].domain == "enterprise"

        class _Report:
            capability_matrix = cells
            defensive_recommendations: list[Any] = []
            executive_summary = ""
            attribution = None
            stix_bundle_extended = None
            run_summary: dict[str, Any] = {}
            sections: list[Any] = []
            ttp_mappings: list[Any] = []

        warnings = [w for w in lint_report(_Report(), "windows") if w.rule == "C1"]
        assert [w.field for w in warnings] == ["capability_matrix.T1417"]
        assert "mobile domain" in warnings[0].message
        assert lint_report(_Report(), "android") == [] or all(
            w.field != "capability_matrix.T1417" for w in lint_report(_Report(), "android")
        )


class TestTheWarmerIsSticky:
    def test_a_failed_build_is_remembered_and_nothing_starts_again(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.tools import knowledge

        starts: list[int] = []

        def _failing_build() -> tuple[Any, str]:
            starts.append(1)
            return None, "no model"

        monkeypatch.setattr(knowledge, "_hybrid_index", _failing_build)
        monkeypatch.setattr(knowledge, "_WARM_STARTED", False)
        assert knowledge.warm_index_in_background() is True
        for _ in range(200):
            if starts:
                break
            time.sleep(0.01)
        assert starts == [1]
        # The failure is remembered as an attempt: no second thread, no second log line.
        assert knowledge.warm_index_in_background() is False
        assert starts == [1]


class TestTheGateRanksTheClaimAlone:
    def test_the_evidence_reference_is_not_part_of_the_ranked_text(self) -> None:
        seen: list[str] = []

        def _alignment(text: str, tid: str, k: int = 5) -> dict[str, Any]:
            seen.append(text)
            return {"gate_score": 1.0, "candidates": []}

        claim = _claim("T1055")
        claim.evidence_ref = "[ev_0001] import table: VirtualAllocEx"
        _weak_alignment(claim, "T1055", _alignment, 0.05)
        assert seen == [claim.claim]
        assert "ev_0001" not in seen[0]


class TestTheNotRunSentence:
    def test_the_catalogue_code_has_its_sentence_and_another_code_is_named(self) -> None:
        from maljan.pipeline.validation import not_run_sentence

        assert not_run_sentence("attck.unknown_id").startswith(
            "the ATT&CK catalogue could not be read"
        )
        assert not_run_sentence("attck.unknown_id").endswith("(attck.unknown_id)")
        assert not_run_sentence("some.other_check") == (
            "a validation check could not run (some.other_check)"
        )


class TestThePlatformCheckLoadsNoCatalogue:
    def test_a_validation_turn_touches_no_bundle(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The scope comes from the two vendored files. Loading the STIX
        bundles inside an analyst's turn cost a second and a hundred
        megabytes on a warm cache and a network fetch on a cold one."""
        from maljan.memory import attck_loader
        from maljan.tools import knowledge

        def _no_load(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("the bundle catalogue was loaded in a validation turn")

        attck_loader.reset_caches()
        monkeypatch.setattr(attck_loader, "load_all_domains", _no_load)
        monkeypatch.setattr(knowledge, "_catalog", _no_load)
        isr = _isr(_claim("T1055"), _claim("T1633"))
        violations = validate_isr(isr, attck=knowledge, sample=PE)
        assert _codes(violations) == [PLATFORM_MISMATCH_CODE]
        assert "T1633 belongs to the ATT&CK mobile domain" in violations[0].message
        assert [c.technique_id for c in isr.claims] == ["T1055", "T1633"]

    def test_attck_scope_answers_from_the_vendored_files(self) -> None:
        from maljan.tools import knowledge

        assert knowledge.attck_scope("t1633") == {
            "technique_id": "T1633",
            "domain": "mobile",
            "platforms": ["Android", "iOS"],
        }
        assert knowledge.attck_scope("T9999") == {
            "technique_id": "T9999",
            "domain": None,
            "platforms": [],
        }


class TestAPreOnlyTechnique:
    def test_it_is_exempt_from_the_platform_half(self) -> None:
        """T1583 (Acquire Infrastructure) declares PRE alone: it happens before
        any host is touched, so a Windows sample cannot contradict it."""
        from maljan.tools import knowledge

        assert knowledge.attck_scope("T1583")["platforms"] == ["PRE"]
        assert platform_mismatch_message("T1583", knowledge, ("enterprise", ("Windows",))) == ""

    def test_the_exemption_is_for_pre_alone(self) -> None:
        class _Scope:
            @staticmethod
            def attck_scope(tid: str) -> dict[str, Any]:
                return {"technique_id": tid, "domain": "enterprise", "platforms": ["PRE", "Linux"]}

        message = platform_mismatch_message("T1000", _Scope(), ("enterprise", ("Windows",)))
        assert "declares the platforms PRE, Linux" in message

    def test_the_exemption_covers_the_domain_half_as_well(self) -> None:
        """A domain is a matrix a technique is filed in, not a host it runs on.

        Every PRE technique is filed in the enterprise matrix and mobile has
        none, so asking the domain first made each of them cross-domain on an
        Android sample. That was a warning while the check only annotated;
        once the report began reading it to decide what to publish, it took
        ``T1583 Acquire Infrastructure`` off an Android infostealer's C2
        registration and out of every published surface.
        """
        from maljan.tools import knowledge

        assert platform_mismatch_message("T1583", knowledge, ("mobile", ("Android",))) == ""

    def test_a_technique_that_also_names_a_host_is_still_a_mismatch(self) -> None:
        class _Scope:
            @staticmethod
            def attck_scope(tid: str) -> dict[str, Any]:
                return {"technique_id": tid, "domain": "mobile", "platforms": ["PRE", "Android"]}

        assert "belongs to the ATT&CK mobile domain" in platform_mismatch_message(
            "T1000", _Scope(), ("enterprise", ("Windows",))
        )


class TestARetiredId:
    """T1562.001 was a real id in the catalogue this tree shipped before 19.2.
    A stored report or a prompt that still names it must read as retired,
    not as invented."""

    def test_the_analyst_is_told_the_id_was_retired_and_in_which_release(self) -> None:
        from maljan.tools import knowledge

        isr = _isr(_claim("T1562.001"))
        violations = validate_isr(isr, attck=knowledge, sample=PE)
        assert [v.code for v in violations] == ["attck.unknown_id"]
        assert (
            "TECHNIQUE T1562.001 is not in the MITRE ATT&CK catalogue (retired in ATT&CK 19.2)"
            in (violations[0].message)
        )
        assert isr.claims[0].technique_id == "T1562.001"

    def test_the_knowledge_tools_say_so_too(self) -> None:
        from maljan.tools import knowledge

        row = knowledge.attck_validate(["T1562.001"])["invalid"][0]
        assert row["retired_in"] == "19.2"
        looked = knowledge.attck_lookup("T1562.001")
        assert looked["valid"] is False and looked["reason"] == "retired in ATT&CK 19.2"
        assert knowledge.attck_retired_in("T1055") is None

    def test_an_invented_id_carries_no_such_note(self) -> None:
        from maljan.tools import knowledge

        violations = validate_isr(_isr(_claim("T9999")), attck=knowledge, sample=PE)
        assert "retired" not in violations[0].message


class TestAssertionsFromYaraAndFromRetiredIds:
    def test_a_yara_ttp_rule_asserts_under_the_yara_label(self) -> None:
        yara = {
            "matches": [
                {"rule": "process_hollowing", "meta": {"technique_id": "T1055.012"}, "tags": []}
            ]
        }
        rows = corroboration({}, [_entry("yara_scan", yara, 1)])
        assert rows["T1055.012"] == {"asserted_by": ["yara"], "claimed_by": []}

    def test_an_upstream_rule_asserting_a_retired_id_is_marked(self) -> None:
        from maljan.analysis.corroboration import technique_label

        sigma = {"matches": [{"title": "x", "tags": ["attack.t1562.004"], "matched_fields": []}]}
        rows = corroboration({}, [_entry("sigma_match_sandbox", sigma, 1)])
        assert rows["T1562.004"]["asserted_by"] == ["sigma"]
        assert rows["T1562.004"]["retired_in"] == "19.2"
        assert technique_label("T1562.004", rows["T1562.004"]) == (
            "T1562.004 (retired in ATT&CK 19.2)"
        )
        # A live id carries no such key.
        assert "retired_in" not in corroboration({"static": _isr(_claim("T1055"))}, [])["T1055"]


class TestACatalogueAssociationIsNeverASource:
    def test_it_is_shown_apart_and_counts_for_nothing(self) -> None:
        """BitBlt plus CreateCompatibleDC reads as screen capture on any GUI
        program; the association is shown for reference and is not asserted."""
        from maljan.tools.knowledge import api_capability

        payload = api_capability(["BitBlt", "CreateCompatibleDC", "GetDC", "GetDIBits"])
        assert any(row["techniques"] for row in payload["capabilities"])
        rows = corroboration({}, [_entry("api_capability", payload, 1)])
        assert rows["T1113"] == {
            "asserted_by": [],
            "claimed_by": [],
            "associated_by": ["api_capability"],
        }
        assert corroboration_sources(rows["T1113"]) == []
