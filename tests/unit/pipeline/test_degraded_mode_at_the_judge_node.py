"""What degrades a run is decided at the judge node, over everything it adds.

A failed optional pack tool leaves its token on the record and does not flip
``degraded_mode``; a failed identity entry does. Asserted at the node, not on
the helper alone, because the node adds reasons of its own on the way and
the assertion has to survive them: this fixture neutralises each one.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

from maljan.agents.judge_agent import JudgeVerdict
from maljan.core.token_ledger import TokenLedger
from maljan.core.truncation_ledger import TruncationLedger
from maljan.pipeline.nodes import make_judge_node
from maljan.providers.sample_open import UNCOVERED, withheld_unpinned
from maljan.schemas.evidence import EvidenceCounter, build_entry, format_entry_id
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle
from tests.stages import paper_profile
from tests.unit.pipeline.test_evidence_ledger_channel import _JudgeContainer


class _Container(_JudgeContainer):
    def server_degradation_reasons(self) -> list[str]:
        return []

    def server_rests(self) -> list[dict]:
        return []

    def active_profile(self) -> Any:
        return paper_profile(["static"])

    def get_token_ledger(self) -> TokenLedger:
        return TokenLedger()

    def get_truncation_ledger(self) -> TruncationLedger:
        return TruncationLedger()


def _capa_entry() -> Any:
    fixture = Path(__file__).resolve().parents[2] / "fixtures" / "ledger" / "capa.json"
    return build_entry(
        entry_id=format_entry_id(1),
        seq=1,
        agent="pipeline",
        tool="capa",
        args={},
        server="pipeline",
        output=fixture.read_text(encoding="utf-8"),
        stage="triage_pack",
    )


def _listing_entry() -> Any:
    """A listing of a function of its own: a second source beside the capa row."""
    return build_entry(
        entry_id=format_entry_id(2),
        seq=2,
        agent="static",
        tool="decompile_function",
        args={"address": "0x7777"},
        server="ghidra",
        output="void FUN_00007777(void) { WriteProcessMemory(); }",
        stage="analysis",
    )


def _state(pack_reasons: list[str]) -> dict[str, Any]:
    # The capa rule and the analyst are two sayers; the capa row and the
    # analyst's own listing are two sources, one of them code: corroborated.
    claim = ClaimEvidence(
        claim="Allocates and writes memory in a remote process",
        evidence_ref="[ev_0001] capa: inject code; [ev_0002] the listing of 0x7777",
        confidence=0.8,
        technique_id="T1055",
    )
    return {
        "iteration_count": 1,
        "reports": {"static": "static findings"},
        "isr_reports": {"static": AgentISR(agent_id="static", domain="static", claims=[claim])},
        "evidence_ledger": [_capa_entry(), _listing_entry()],
        "sandbox_report": {"signatures": []},
        "sample_path": None,
        "triage_facts": {"degradation_reasons": pack_reasons},
        "validation_findings": {},
        "validation_not_run": [],
    }


def _run(state: dict[str, Any]) -> dict[str, Any]:
    container = _Container(EvidenceCounter())
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={})
    )
    return asyncio.run(make_judge_node(container)(state))


class TestACapaFailureAlone:
    def test_the_token_is_on_the_record_and_the_run_is_degraded(self) -> None:
        """T-338: a run that went without capa lost evidence it would have had."""
        update = _run(_state(["triage.capa_failed"]))
        assert "triage.capa_failed" in update["degradation_reasons"]
        assert update["degraded_mode"] is True
        summary = update["run_summary"]
        assert summary["degraded_mode"] is True
        assert "triage.capa_failed" in summary["degradation_reasons"]

    def test_a_failed_identity_entry_degrades_the_run(self) -> None:
        update = _run(_state(["triage.identify_file_failed"]))
        assert update["degraded_mode"] is True
        assert update["run_summary"]["degraded_mode"] is True


class TestTheJudgeRecordsItsOwnUncheckedIds:
    def test_an_unreadable_catalogue_is_a_not_run_check_at_the_judge_too(self, monkeypatch) -> None:
        from maljan.pipeline import nodes

        class _NoCatalogue:
            @staticmethod
            def catalogue_available() -> bool:
                return False

        monkeypatch.setattr(nodes, "_knowledge_module", lambda: _NoCatalogue())
        update = _run(_state([]))
        summary = update["run_summary"]
        assert "attck.unknown_id" in summary["validation"]["not_run"]
        assert any(
            reason.startswith("the ATT&CK catalogue could not be read")
            for reason in update["degradation_reasons"]
        )


class TestACaptureNotFetchedDegradesTheRun:
    """T-336: an artefact the sandbox offered and the job could not fetch is a reason."""

    def _update(self, failures: list[dict[str, str]]) -> dict[str, Any]:
        container = _Container(EvidenceCounter())
        container.artefact_fetch_failures = failures
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        return asyncio.run(make_judge_node(container)(_state([])))

    def test_the_reason_reaches_the_run_and_its_summary(self) -> None:
        from maljan.providers.errors import PACKET_CAPTURE, ArtefactFetchFailed

        lost = ArtefactFetchFailed(PACKET_CAPTURE, "HTTP 502").record()
        update = self._update([lost])
        assert "packet capture not fetched (HTTP 502)" in update["degradation_reasons"]
        assert update["degraded_mode"] is True
        summary = update["run_summary"]
        assert "packet capture not fetched (HTTP 502)" in summary["degradation_reasons"]

    def test_none_recorded_adds_nothing(self) -> None:
        update = self._update([])
        assert not any("packet capture" in r for r in update["degradation_reasons"])
        assert update["degraded_mode"] is False


class TestAnOperatorChoiceIsNoDegradation:
    """T-338: a tool withheld by policy or a key never set costs the run no evidence."""

    WITHHELD = withheld_unpinned(
        "remote http://localhost:8089 (backend 1)", "open_project", UNCOVERED
    )
    UNSET = (
        "server.threatintel.check_hash_unavailable(VIRUSTOTAL_API_KEY is not configured); "
        "set the credential or setting this tool needs in Settings and run the probe again"
    )
    LOST = "mcp server 'analysis' unavailable"

    def _judged(self, server_reasons: list[str]) -> tuple[dict[str, Any], str]:
        container = _Container(EvidenceCounter())
        container.server_degradation_reasons = lambda: list(server_reasons)  # type: ignore[method-assign]
        # The manifests' code marks the key unset (``ServerHandle.not_configured_reasons``).
        container.server_not_configured_reasons = lambda: [self.UNSET]  # type: ignore[attr-defined]
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        update = asyncio.run(make_judge_node(container)(_state([])))
        return update, str(judge.give_verdict.call_args.kwargs.get("degradation_note") or "")

    def test_it_is_listed_apart_and_the_run_is_not_degraded(self) -> None:
        update, _note = self._judged([self.WITHHELD, self.UNSET])

        assert update["degradation_reasons"] == []
        assert update["operator_choices"] == [self.WITHHELD, self.UNSET]
        assert update["degraded_mode"] is False
        summary = update["run_summary"]
        assert summary["degraded_mode"] is False
        assert summary["degradation_reasons"] == []
        assert summary["operator_choices"] == [self.WITHHELD, self.UNSET]

    def test_a_loss_beside_it_still_degrades_the_run(self) -> None:
        update, _note = self._judged([self.WITHHELD, self.LOST])

        assert update["degradation_reasons"] == [self.LOST]
        assert update["operator_choices"] == [self.WITHHELD]
        assert update["degraded_mode"] is True

    def test_the_judge_is_told_it_as_an_absence_not_a_degradation(self) -> None:
        _update, note = self._judged([self.UNSET])

        assert self.UNSET in note
        assert "degraded" not in note
        assert "Left out by the operator's configuration" in note

    def test_a_judge_that_fails_keeps_it_apart_too(self) -> None:
        container = _Container(EvidenceCounter())
        container.server_degradation_reasons = lambda: [self.UNSET, self.LOST]  # type: ignore[method-assign]
        container.server_not_configured_reasons = lambda: [self.UNSET]  # type: ignore[attr-defined]
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(side_effect=TimeoutError())
        update = asyncio.run(make_judge_node(container)(_state([])))

        assert self.UNSET not in update["degradation_reasons"]
        assert self.LOST in update["degradation_reasons"]
        assert update["operator_choices"] == [self.UNSET]
        summary = update["run_summary"]
        assert summary["operator_choices"] == [self.UNSET]
        assert self.UNSET not in summary["degradation_reasons"]


class TestARunThatWentWithoutCapaAmongOperatorChoices:
    """T-338, the haiku5 shape: capa missing is a loss, the rest is the operator's.

    Capa failed in the pack and is not installed on the analysis server, py7zr
    is missing for a tool that still answers zip and tar, sixteen Ghidra tools
    are withheld by the shared server's policy and three threat-intel tools
    have no key. The run is degraded, its banner names capa and nothing else,
    and the nineteen choices are listed apart.
    """

    SHARED = "remote http://localhost:8089 (backend 1)"
    UNCOVERED_TOOLS = (
        "close_program",
        "close_project",
        "create_project",
        "delete_file",
        "get_project_info",
        "import_data_types",
        "list_open_programs",
        "list_project_files",
        "load_program_from_project",
        "open_program",
        "open_project",
        "save_all_programs",
        "server_status",
    )
    LISTED_TOOLS = ("create_folder", "run_ghidra_script", "run_script_inline")

    def _losses(self) -> list[str]:
        from maljan.tools.capabilities import Unavailable
        from maljan.tools.errors import MISSING_DEPENDENCY, REMEDIATIONS

        install = REMEDIATIONS[MISSING_DEPENDENCY]
        return [
            "triage.capa_failed",
            Unavailable(
                "analysis",
                "capa",
                "capa is not installed (No module named 'capa')",
                install,
            ).degradation_reason,
            Unavailable(
                "analysis",
                "archive_list",
                "py7zr is not installed (No module named 'py7zr')",
                install,
                without="zip and tar members; 7z needs py7zr",
            ).degradation_reason,
        ]

    def _choices(self) -> list[str]:
        from maljan.providers.sample_open import LISTED_SHARED_WITHHELD
        from maljan.tools.capabilities import Unavailable
        from maljan.tools.errors import NOT_CONFIGURED, REMEDIATIONS

        withheld = [withheld_unpinned(self.SHARED, t, UNCOVERED) for t in self.UNCOVERED_TOOLS]
        withheld += [
            withheld_unpinned(self.SHARED, t, LISTED_SHARED_WITHHELD) for t in self.LISTED_TOOLS
        ]
        unset = [
            Unavailable("threatintel", tool, why, REMEDIATIONS[NOT_CONFIGURED]).degradation_reason
            for tool, why in (
                ("check_domain_reputation", "VIRUSTOTAL_API_KEY is not configured"),
                ("check_hash", "VIRUSTOTAL_API_KEY is not configured"),
                (
                    "check_ip_reputation",
                    "VIRUSTOTAL_API_KEY is not configured; ABUSEIPDB_API_KEY is not configured",
                ),
            )
        ]
        return sorted(withheld) + unset

    def test_it_is_degraded_with_capa_in_the_banner_and_the_choices_apart(self) -> None:
        from maljan.reporting.models import MalwareReport
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        pack, *server = self._losses()
        choices = self._choices()
        assert len(choices) == 19
        container = _Container(EvidenceCounter())
        container.server_degradation_reasons = lambda: [*server, *choices]  # type: ignore[method-assign]
        unset = [c for c in choices if c.startswith("server.threatintel.")]
        container.server_not_configured_reasons = lambda: unset  # type: ignore[attr-defined]
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        update = asyncio.run(make_judge_node(container)({**_state([pack]), "file_type": "pe"}))

        assert update["degraded_mode"] is True
        assert update["degradation_reasons"] == [pack, *server]
        assert update["operator_choices"] == choices
        assert update["run_summary"]["operator_choices"] == choices

        report = MalwareReport.model_validate(
            {
                "verdict": "Malware",
                "overall_confidence": 0.9,
                "identity": {"hashes": {"sha256": "e" * 64}, "file_type": "pe"},
                "degraded_mode": update["degraded_mode"],
                "degradation_reasons": update["degradation_reasons"],
                "operator_choices": update["operator_choices"],
            }
        )
        rendered = MarkdownRenderer().render(report)
        head = rendered.split("\n## 1.", 1)[0]
        banner = next(line for line in head.splitlines() if "[DEGRADED RUN]" in line)
        assert "the run went without capa;" in banner.lower()
        for other in ("archive_list", "py7zr", "threatintel", "check_hash", *self.LISTED_TOOLS):
            assert other not in head, other
        after = rendered.split("**Not configured or withheld by choice:**\n\n", 1)[1]
        listed = after.split("\n\n", 1)[0].splitlines()
        assert len(listed) == 19 and all(line.startswith("- ") for line in listed)


class TestAKeyNoManifestMarksUnset:
    """T-338: the words "is not configured" without the manifest's code are a loss."""

    def test_it_stays_a_degradation_and_degrades_the_run(self) -> None:
        unset = TestAnOperatorChoiceIsNoDegradation.UNSET
        container = _Container(EvidenceCounter())
        container.server_degradation_reasons = lambda: [unset]  # type: ignore[method-assign]
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        update = asyncio.run(make_judge_node(container)(_state([])))
        assert update["degradation_reasons"] == [unset]
        assert update["operator_choices"] == []
        assert update["degraded_mode"] is True


class TestTheZeroCorroborationNoteCountsClaims:
    def test_rule_only_tags_are_stated_apart_from_the_claimed_count(self) -> None:
        """capa and YARA firing richly on benign software used to read as
        thirty-three techniques; the count is the analysts' claims, and the
        rule-only tags are a sentence of their own."""
        import json

        state = _state([])
        capa = {
            "capabilities": [
                {"rule": "a", "namespace": "", "attck": ["X [T1027]"], "mbc": [], "match_count": 1},
                {"rule": "b", "namespace": "", "attck": ["X [T1497]"], "mbc": [], "match_count": 1},
            ]
        }
        entry = _capa_entry().model_copy(update={"output": json.dumps(capa), "structured": capa})
        state["evidence_ledger"] = [entry]
        update = _run(state)
        reasons = update["degradation_reasons"]
        assert "zero cross-layer corroboration (1 claimed technique)" in reasons
        assert "2 rule matches carry technique tags no analyst claimed" in reasons
        assert not any("single-layer" in r for r in reasons)


class _TeamContainer(_Container):
    """The paper's three analysts, each a role of its own name."""

    def analyst_keys(self) -> list[str]:
        return ["static", "dynamic", "network"]

    def active_profile(self) -> Any:
        return paper_profile(["static", "dynamic", "network"])

    def agent_role(self, key: str) -> str:
        return key


class TestASkippedAnalystIsSaidToBeSkipped:
    """An analyst skipped for want of sandbox data did not run, and the reason says so."""

    def _reasons(self, dynamic_claims: bool) -> list[str]:
        state = _state([])
        claimed = state["isr_reports"]["static"]
        dynamic = AgentISR(agent_id="dynamic", domain="dynamic", claims=[])
        if dynamic_claims:
            dynamic = AgentISR(agent_id="dynamic", domain="dynamic", claims=list(claimed.claims))
        network = AgentISR(agent_id="network", domain="network", claims=[])
        state["isr_reports"] = {"static": claimed, "dynamic": dynamic, "network": network}
        state["reports"] = {**state["reports"], "dynamic": "", "network": ""}
        # The mock sandbox's stand-in for a detonation that never ran.
        state["sandbox_report"] = {"synthetic": True, "signatures": []}
        container = _TeamContainer(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        return list(asyncio.run(make_judge_node(container)(state))["degradation_reasons"])

    def test_the_reason_names_them_skipped_for_no_sandbox_data(self) -> None:
        reasons = self._reasons(dynamic_claims=False)
        assert "analysts skipped (no sandbox data): dynamic, network" in reasons
        assert not any(r.startswith("analysts produced no claims:") for r in reasons)

    def test_an_analyst_that_claimed_is_not_named(self) -> None:
        reasons = self._reasons(dynamic_claims=True)
        assert "analysts skipped (no sandbox data): network" in reasons


class TestANoteOnPartOfAnAnswer:
    """An unread claim beside claims read is listed and does not degrade the run."""

    SENTENCE = (
        "The static analyst's answer began 2 claim(s), and 1 were read; 1 could not be "
        "read as a claim and are not in its findings."
    )

    def _judged(self) -> tuple[dict[str, Any], str]:
        state = _state([])
        isr = state["isr_reports"]["static"]
        isr.note_claims_unread(self.SENTENCE)
        container = _Container(EvidenceCounter())
        judge = container.get_judge_agent(role="judge")
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(
                bundle=Bundle(objects=[]), violations=[], retries=0, fed_back={}
            )
        )
        update = asyncio.run(make_judge_node(container)(state))
        return update, str(judge.give_verdict.call_args.kwargs.get("degradation_note") or "")

    def test_the_run_is_not_degraded_and_the_note_is_listed(self) -> None:
        update, _note = self._judged()

        assert self.SENTENCE in update["degradation_reasons"]
        assert update["degraded_mode"] is False
        assert update["run_summary"]["degraded_mode"] is False

    def test_the_judge_is_told_it_is_a_note_not_a_missing_tool(self) -> None:
        _update, note = self._judged()

        assert self.SENTENCE in note
        assert "degraded" not in note
        assert "claims it read standing" in note
        assert "missing tool" not in note


class _RememberingContainer(_Container):
    """A container with a memory store, and a report stage that runs or not."""

    def __init__(self, counter: EvidenceCounter, *, reporting: bool) -> None:
        super().__init__(counter)
        from maljan.memory.in_memory_store import InMemoryStore

        self._store = InMemoryStore()
        self.pending_memory_case: Any = None
        self.config.reporting.enabled = reporting

    def get_memory_store(self) -> Any:
        return self._store


def _thin_in_claims() -> dict[str, Any]:
    """One claimed technique, which no second source names."""
    import json

    state = _state([])
    empty = {"capabilities": []}
    entry = _capa_entry().model_copy(update={"output": json.dumps(empty), "structured": empty})
    state["evidence_ledger"] = [entry]
    return state


def _judged(state: dict[str, Any], *, reporting: bool, objects: list[dict]) -> Any:
    container = _RememberingContainer(EvidenceCounter(), reporting=reporting)
    judge = container.get_judge_agent(role="judge")
    judge.give_verdict = AsyncMock(
        return_value=JudgeVerdict(
            bundle=Bundle.model_validate({"objects": objects}),
            violations=[],
            retries=0,
            fed_back={},
        )
    )
    asyncio.run(make_judge_node(container)(state))
    return container.pending_memory_case


def _technique(tid: str) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


class TestThePublishedGateDecides:
    """The case is judged on what the run published, not on what was claimed."""

    def test_a_run_thin_in_claims_is_held_for_the_report_node(self) -> None:
        case = _judged(_thin_in_claims(), reporting=True, objects=[])

        assert case is not None, "the report node's published gate decides"
        assert case.technique_ids == ["T1055"]

    def test_without_a_report_node_the_case_holds_the_published_ids(self) -> None:
        case = _judged(
            _thin_in_claims(),
            reporting=False,
            objects=[_technique("T1055"), _technique("T1027")],
        )

        assert case is not None
        assert case.technique_ids == ["T1055", "T1027"]
        assert case.total_techniques == 2

    def test_without_a_report_node_a_tactic_reference_is_no_published_technique(self) -> None:
        tactic = {**_technique("TA0005"), "id": "attack-pattern--tactic", "name": "Evasion"}

        case = _judged(
            _thin_in_claims(),
            reporting=False,
            objects=[_technique("T1055"), tactic, _technique("T1027")],
        )

        assert case is not None
        assert case.technique_ids == ["T1055", "T1027"]

    def test_without_a_report_node_a_thin_publication_is_not_stored(self) -> None:
        case = _judged(_thin_in_claims(), reporting=False, objects=[_technique("T1055")])

        assert case is None


def test_a_bundle_that_could_not_be_read_keeps_the_claimed_ids_and_says_so() -> None:
    from maljan.memory.long_term_memory import StoredCase
    from maljan.pipeline.nodes import case_for_the_judge_alone

    claimed = StoredCase(
        sample_id="s", summary_text="t", technique_ids=["T1055", "T1027"], total_techniques=2
    )

    case, note = case_for_the_judge_alone(claimed, None, {}, [])

    assert case is claimed
    assert "claimed" in note


def test_a_profile_that_cannot_be_read_is_said(caplog: Any) -> None:
    import logging
    from unittest.mock import MagicMock

    from maljan.pipeline.nodes import a_report_node_follows

    container = MagicMock()
    container.config.reporting.enabled = True
    container.active_profile.side_effect = RuntimeError("no profile")

    with caplog.at_level(logging.WARNING):
        assert a_report_node_follows(container) is True

    assert any("report node" in record.getMessage() for record in caplog.records)
