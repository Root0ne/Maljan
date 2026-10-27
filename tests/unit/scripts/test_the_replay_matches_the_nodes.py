"""The replay's report is the one the real judge and report nodes build from the same answers.

The oracle: the platform's own ``make_judge_node`` and ``make_report_node`` run
over a stored run's state, every model in them a stub that answers what the run
stored (the judge's bundle as written, and the same again when the round
retries; its technique review as the stored matrix records it; the narrative
and each composer section as the stored report holds them). What the nodes
build must be what the replay builds: the verdict and its degradation, the
published techniques and the matrix's reasons, the IOC answers, the export,
the detection drafts, the claims the body leaves undiscussed, the narrative
and the sections, and the analysts' and the judge's unresolved findings. A
change to how a node composes its rules that the replay does not follow fails
here, in the default suite.

Besides the tiny run, small scenarios take the branches it never takes: a
judge answer that is not a bundle (the fallback verdict), a capture the
sandbox attributes no flow of the sample to (the judge's indicator asked with
the sandbox's fact), a blanked answer (absences advisory over a partial
corpus), the export and the detection drafts switched off, and a technique the
judge's review dropped.

What the oracle does not hold: the analyst node (its checks are the
platform's own functions, held by ``test_the_replay_knows_every_check``), the
reading of the transcript, the stand-in that hosts the analyst's parser, the
stored-run and database readers, the replay's own ``COMPOSER_PLACES`` (the stub
composer answers through it) and its read-back of the stored technique review
(``rules._stored_review``, the stub review's answer), and the state both sides
are fed (the claims
in force read as ISRs, the findings that survived, the corpus rebuilt from the
stored answers, the settings snapshot). An error there is on both sides and
passes. Retries and what was fed back are model turns the replay does not make,
and are not compared.
"""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import shutil
import typing
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from scripts.replay import rules
from scripts.replay.guard import replay_environment
from scripts.replay.stored import read_run

from tests.unit.scripts._replay_tiny import FIXTURE

_SECTION = re.compile(r"The evidence for the (\w+) section follows\.")


class _Stored(BaseChatModel):
    """A model that answers what the run stored, the same answer every time it is asked."""

    answer_for: Any

    @property
    def _llm_type(self) -> str:
        return "stored-answers"

    def _generate(
        self, messages: list[Any], stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        text = self.answer_for(messages)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        # Offered a tool (``read_evidence`` beside a call's schema), it calls
        # none: what the run stored is its answer, as a model that reads nothing.
        return self


def _section_payload(stored: dict[str, Any], section: str) -> Any:
    """A composer section's answer as the stored report holds it, or the section declined."""
    from maljan.reporting import composer as c

    place, key = rules.COMPOSER_PLACES.get(section, (f"technical_analysis.{section}", None))
    value = rules._stored_at(stored, place)
    if not value:
        return {section: None}
    if section in c._PROSE_SECTIONS:
        return {
            "body": str(value.get("body") or ""),
            "evidence_refs": list(value.get("evidence_refs") or []),
        }
    return dict(value) if key is None else {key: value}


class _Container:
    """What the judge and report nodes read of a service container, over a stored run."""

    is_mock = False
    event_sink = None
    pending_memory_case = None

    def __init__(self, run: Any, judge: Any, narrative: Any, composer: Any) -> None:
        from maljan.core.config import get_settings
        from maljan.core.token_ledger import TokenLedger
        from maljan.core.truncation_ledger import TruncationLedger

        self.config = get_settings()
        self._run = run
        self._judge = judge
        self._narrative = narrative
        self._composer = composer
        self._truncation = TruncationLedger()
        self._tokens = TokenLedger()
        self._corpus = rules._run_corpus(run)

    def get_evidence_corpus(self) -> Any:
        return self._corpus

    def analyst_keys(self) -> list[str]:
        return list(self._run.isrs)

    def agent_role(self, _name: str) -> str:
        return "generic"

    def get_judge_agent(self, role: str = "judge") -> Any:
        return self._judge

    def drain_all_judge_evidence(self) -> list[Any]:
        return []

    def get_memory_store(self) -> Any:
        return None

    def get_token_ledger(self) -> Any:
        return self._tokens

    def get_truncation_ledger(self) -> Any:
        return self._truncation

    def report_in_progress(self, *_args: Any, **_kwargs: Any) -> Any:
        return None

    def server_degradation_reasons(self) -> list[str]:
        return []

    def server_rests(self) -> list[Any]:
        return []

    def get_evidence_counter(self) -> Any:
        from maljan.schemas.evidence import EvidenceCounter

        return EvidenceCounter()

    def get_narrative_agent(self) -> Any:
        return self._narrative

    def get_report_composer(self) -> Any:
        return self._composer

    def get_static_provider(self) -> Any:
        return None

    def active_profile(self) -> Any:
        from tests.stages import paper_profile

        return paper_profile(list(self._run.isrs))


def _merge(state: dict[str, Any], update: dict[str, Any]) -> None:
    """A node's update on the state, through the state's own reducers."""
    from maljan.pipeline.state import AnalysisState

    hints = typing.get_type_hints(AnalysisState, include_extras=True)
    for key, value in update.items():
        reducer = getattr(hints.get(key), "__metadata__", (None,))[0]
        state[key] = reducer(state[key], value) if callable(reducer) and key in state else value


def _oracle(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any, dict[str, Any]]:
    """The replay's rebuilt report, and the report and verdict update the real nodes build."""
    stored = read_run(run_dir)
    seen: dict[str, Any] = {}
    against = rules._against_stored

    def _capture(run: Any, built: Any, values: Any) -> Any:
        seen["report"], seen["run"] = built.report, run
        return against(run, built, values)

    monkeypatch.setattr(rules, "_against_stored", _capture)
    rules.replay_run(stored)
    monkeypatch.undo()
    run, replayed = seen["run"], seen["report"]

    with replay_environment(stored.settings):
        from maljan.agents.judge_agent import JudgeAgent
        from maljan.pipeline.nodes import make_judge_node, make_report_node
        from maljan.reporting.composer import ReportComposer
        from maljan.reporting.models import MalwareReport
        from maljan.reporting.narrative_agent import NarrativeAgent
        from maljan.schemas.evidence import EvidenceCounter

        answer = json.dumps((stored.judge or {}).get("bundle") or {})
        judge = JudgeAgent(llm=_Stored(answer_for=lambda _messages: answer))
        judge.evidence_counter = EvidenceCounter()
        judge.decide_techniques = AsyncMock(return_value=rules._stored_review(run))
        report = stored.report or {}
        narrative_answer = json.dumps(
            {
                "executive_summary": report.get("executive_summary") or "",
                "key_findings": list(report.get("key_findings") or []),
                "defensive_recommendations": list(report.get("defensive_recommendations") or []),
            }
        )

        def _section_answer(messages: list[Any]) -> str:
            asked = _SECTION.findall("\n".join(str(m.content) for m in messages))
            return json.dumps(_section_payload(report, asked[-1] if asked else ""))

        container = _Container(
            run,
            judge,
            NarrativeAgent(llm=_Stored(answer_for=lambda _messages: narrative_answer)),
            ReportComposer(llm=_Stored(answer_for=_section_answer)),
        )
        identity = run.identity
        state: dict[str, Any] = {
            "iteration_count": 1,
            "reports": dict(stored.agent_reports),
            "isr_reports": copy.deepcopy(run.isrs),
            "evidence_ledger": list(run.ledger),
            "sandbox_report": None,
            "sample_path": None,
            "triage_facts": {},
            "validation_findings": {
                agent: [v.to_dict() for v in found]
                for agent, found in run.in_force_found.items()
                if found
            },
            "validation_not_run": [],
            "platform": identity.get("platform"),
            "file_type": identity.get("file_type"),
            "file_hash": identity.get("sha256"),
            "file_name": identity.get("file_name"),
        }
        verdict = asyncio.run(make_judge_node(container)(state))
        _merge(state, verdict)
        built = asyncio.run(make_report_node(container)(state))
        nodes = MalwareReport.model_validate(built["malware_report"])
    return replayed, nodes, verdict


def _unresolved(summary: Any) -> list[tuple[str, ...]]:
    """The analysts' and the judge's findings left standing, row by row: the verdict node's
    summary on one side, the replay's rebuilt one on the other (neither holds the report
    rounds' rows yet)."""
    rows = ((summary or {}).get("validation") or {}).get("unresolved") or []
    keys = ("agent", "code", "subject", "asked", "answered", "advisory")
    return sorted(tuple(str(row.get(k, "")) for k in keys) for row in rows)


def _view(report: Any) -> dict[str, Any]:
    """What the comparison reads of a report: the values the replay records, unprojected."""
    export = report.stix_bundle_extended or {}
    return {
        "verdict": str(report.verdict),
        "severity": getattr(report.severity, "rating", None),
        "confidence": report.overall_confidence,
        "category": report.malware_category,
        "degraded": report.degraded_mode,
        "reasons": list(report.degradation_reasons or []),
        "published": sorted(str(m.technique_id) for m in report.ttp_mappings or []),
        "matrix": sorted(
            (str(c.technique_id), str(c.not_published or ""))
            for c in report.capability_matrix or []
        ),
        "indicators": sorted(
            (str(i.kind or i.type), str(i.value), str(i.published or ""))
            for i in report.consolidated_iocs or []
        ),
        "export": dict(Counter(str(o.get("type")) for o in export.get("objects") or [])),
        "detection": sorted(str(s.kind) for s in report.detection_signatures or []),
        "not_discussed": sorted(
            (str(row.agent), int(row.claim_number)) for row in report.claims_not_discussed or []
        ),
        "summary": report.executive_summary,
        "key_findings": [k.model_dump(mode="json") for k in report.key_findings or []],
        "technical_analysis": (
            report.technical_analysis.model_dump(mode="json") if report.technical_analysis else None
        ),
        "sections": [str(s.key) for s in report.sections or []],
        # The summary's counts of the export and of the judge's bundle, which a
        # rebuilt export and a rebuilt bundle change.
        "stix_object_count": (report.run_summary or {}).get("stix_object_count"),
        "judge_stix_object_count": (report.run_summary or {}).get("judge_stix_object_count"),
    }


def _blank_an_answer(evidence: dict[str, Any]) -> None:
    entry = evidence["items"][1]
    entry["output"], entry["truncated"] = "", True


def _not_a_bundle(judge: dict[str, Any]) -> None:
    judge["bundle"] = {"answer": "The sample is malware: it decodes a second stage at run time."}


def _a_capture_with_a_flow(evidence: dict[str, Any]) -> None:
    entry = evidence["items"][2]
    entry["output"] = "one conversation, to 45.77.10.20 on port 443"
    entry["structured"] = {"conversations": [{"dst": "45.77.10.20", "dport": 443}]}


def _an_indicator_on_the_flow(judge: dict[str, Any]) -> None:
    judge["bundle"]["objects"].append(
        {
            "id": "indicator--3",
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '45.77.10.20']",
            "indicator_types": ["malicious-activity"],
            "description": "The capture holds a conversation to it (ev_0003).",
        }
    )


def _no_export_and_no_drafts(summary: dict[str, Any]) -> None:
    summary["settings_snapshot"]["reporting.include_extended_stix"] = False
    summary["settings_snapshot"]["reporting.auto_generate_detection_rules"] = False


def _the_judge_dropped_one(report: dict[str, Any]) -> None:
    report["capability_matrix"] = [
        {
            "technique_id": "T1105",
            "not_published": "the judge dropped it (no download is shown in any answer)",
        }
    ]


# Each scenario: the files of the tiny run it changes, and how.
SCENARIOS: dict[str, dict[str, list[Callable[[dict[str, Any]], None]]]] = {
    "tiny": {},
    "fallback verdict": {"stix-judge.json": [_not_a_bundle]},
    "sandbox facts": {
        "evidence.json": [_a_capture_with_a_flow],
        "stix-judge.json": [_an_indicator_on_the_flow],
    },
    "advisory absences": {"evidence.json": [_blank_an_answer]},
    "settings switched off": {"run-summary.json": [_no_export_and_no_drafts]},
    "technique review drops": {"report.json": [_the_judge_dropped_one]},
}


def _scenario(tmp_path: Path, name: str) -> Path:
    target = tmp_path / "run"
    shutil.copytree(FIXTURE, target)
    for file_name, edits in SCENARIOS[name].items():
        path = target / file_name
        data = json.loads(path.read_text(encoding="utf-8"))
        for edit in edits:
            edit(data)
        path.write_text(json.dumps(data), encoding="utf-8")
    return target


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_the_replay_builds_the_report_the_nodes_build(
    name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    replayed, nodes, verdict = _oracle(_scenario(tmp_path, name), monkeypatch)
    assert _view(replayed) == _view(nodes)
    assert _unresolved(replayed.run_summary) == _unresolved(verdict.get("run_summary"))

    # And the branch the scenario is for was taken.
    if name == "tiny":
        # Not two empty reports that compare equal.
        assert "T1027" in _view(nodes)["published"]
        assert verdict.get("final_decision") == "Malware"
    if name == "fallback verdict":
        assert verdict.get("verdict_fallback")
    if name == "sandbox facts":
        codes = {row[1] for row in _unresolved(verdict.get("run_summary"))}
        assert "stix.indicator_unattributed_flow" in codes
    if name == "advisory absences":
        rows = ((verdict.get("run_summary") or {}).get("validation") or {}).get("unresolved") or []
        assert any(row.get("advisory") for row in rows)
        assert any(r.startswith("grounding searched less") for r in nodes.degradation_reasons)
    if name == "settings switched off":
        assert not nodes.detection_signatures and "identity" not in _view(nodes)["export"]
    if name == "technique review drops":
        assert "T1105" not in _view(nodes)["published"]


@pytest.mark.skipif(
    not os.environ.get("MALJAN_REPLAY_RUN"), reason="no stored run named (MALJAN_REPLAY_RUN)"
)
def test_a_stored_run_replays_to_the_report_the_nodes_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A real stored run, compared on everything but its degradation.

    The record holds neither the sandbox report nor the analysts' answer-level
    findings that survived their retries, and the judge node decides reasons
    from both; the replay keeps the run's own for them.
    """
    replayed, nodes, verdict = _oracle(Path(os.environ["MALJAN_REPLAY_RUN"]), monkeypatch)
    mine, theirs = _view(replayed), _view(nodes)
    for key in ("degraded", "reasons"):
        mine.pop(key)
        theirs.pop(key)
    assert mine == theirs
    assert _unresolved(replayed.run_summary) == _unresolved(verdict.get("run_summary"))
