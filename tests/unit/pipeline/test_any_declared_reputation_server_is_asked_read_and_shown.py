"""Reputation is one declared path: a server declared only as data is treated as the built-ins are.

An invented reputation server, declared only in ``mcp.servers`` with a tool
name, an answer shape and an argument name no built-in has, is asked by the
triage pack, counted by the judge, shown in the run-state block, the report
and its re-render, and its failure reads as a reputation failure. A user's
tool that shares a built-in lookup's name but declares no reputation kind gets
nothing from the built-in treatment.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.core import declared_reading
from maljan.core.config import Settings, ToolRef, get_settings, install_settings
from maljan.core.container import ServiceContainer
from maljan.core.reputation import (
    ReputationRecord,
    is_lookup_entry,
    pack_lookups,
    read_answer,
    reputation_of,
)
from maljan.pipeline.nodes import _reputation_asked, _reputation_lookup
from maljan.pipeline.run_state import render_run_state
from maljan.pipeline.triage_pack import PIPELINE, reason_sentence, render_pack, run_pack
from maljan.reporting.builder import _reputation_answers
from maljan.reporting.models import EvidenceIndexRow, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import EvidenceCounter, build_entry
from tests.unit.pipeline.test_triage_pack import _inputs, _write
from tests.unit.tools.test_binary import _pe

SHA = "c" * 64

# Only data: a tool name, an argument name and an answer shape no built-in has.
INVENTED: dict[str, Any] = {
    "command": "hashrep-server",
    "enabled": True,
    "label": "HashRep",
    "tool_facts": {
        "lookup_digest": {
            "kind": "reputation",
            "arguments": {"hash": "digest"},
            "display_name": "HashRep",
            "reputation": {
                "malicious": "/verdict/flagged",
                "total": "/verdict/scanners",
                "labels": ["/verdict/names/*/label"],
                "first_seen": ["/history/first"],
                "last_seen": ["/history/latest"],
                "link": ["/links/self"],
                "rank": 5,
            },
        },
        "server_status": {"kind": "status"},
    },
}
ANSWER: dict[str, Any] = {
    "verdict": {
        "flagged": 9,
        "scanners": 40,
        "names": [{"label": "Stealer"}, {"label": "Loader"}, {"label": "Stealer"}],
    },
    "history": {"first": 1_700_000_000, "latest": "2026-01-02T03:04:05Z"},
    "links": {"self": "https://rep.invalid/s/abc"},
}
# A user's server whose tool shares the built-in lookup's name and is no lookup.
NAMESAKE: dict[str, Any] = {
    "command": "my-tools",
    "enabled": True,
    "tool_facts": {"get_file_report": {"kind": "file_info", "arguments": {"hash": "hash"}}},
}


def _settings(**servers: Any) -> Settings:
    return Settings.model_validate({"mcp": {"servers": servers}})


@pytest.fixture
def installed() -> Iterator[Any]:
    """Install a settings object for the entries' writer, and put the process's back."""
    previous = get_settings()

    def _install(settings: Settings) -> Settings:
        install_settings(settings)
        declared_reading.forget()
        return settings

    yield _install
    install_settings(previous)
    declared_reading.forget()


class _Tool:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.asked: list[dict[str, Any]] = []

    async def ainvoke(self, args: dict[str, Any]) -> str:
        self.asked.append(dict(args))
        return self.answer


class _Registry:
    def __init__(self, tool: _Tool) -> None:
        self.tool = tool
        self.refs: list[Any] = []

    def tools_for_ref(self, ref: Any, job_id: str, **_: Any) -> tuple[list[Any], list[str]]:
        self.refs.append(ref)
        return [self.tool], []


def _ask(settings: Settings, tmp_path: Path, answer: str) -> tuple[Any, _Registry]:
    container = ServiceContainer(settings, mock=True)
    registry = _Registry(_Tool(answer))
    container.get_server_registry = lambda: registry  # type: ignore[method-assign]
    recorder = EvidenceRecorder(PIPELINE, counter=EvidenceCounter(), stage="triage_pack")
    result = run_pack(
        recorder,
        _inputs(_write(tmp_path, "s.exe", _pe()), "pe", sha256=SHA),
        reputation=_reputation_lookup(container, SHA),
    )
    return result, registry


def _lookup_entry(**over: Any) -> Any:
    fields: dict[str, Any] = {
        "entry_id": "ev_0001",
        "seq": 1,
        "agent": PIPELINE,
        "tool": "lookup_digest",
        "args": {"digest": SHA},
        "server": "hashrep",
        "output": json.dumps(ANSWER),
        "source": "mcp:hashrep",
        "stage": "triage_pack",
    }
    fields.update(over)
    return build_entry(**fields)


def _report(ledger: list[Any]) -> MalwareReport:
    from maljan.reporting.ledger_report import build_sections

    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA)),
        sections=build_sections(ledger),
        evidence_index=[
            EvidenceIndexRow(
                id=e.id,
                agent=e.agent,
                server=e.server,
                tool=e.tool,
                ok=e.ok,
                source=e.source,
                facts=e.facts,
            )
            for e in ledger
        ],
        reputation=_reputation_answers(ledger),
    )


def _reputation_row(markdown: str) -> str:
    return next(line for line in markdown.splitlines() if line.startswith("| Reputation |"))


# ---------------------------------------------------------------------------
# The pack
# ---------------------------------------------------------------------------


class TestThePackAsksIt:
    def test_the_invented_server_is_asked_with_its_declared_argument(
        self, installed: Any, tmp_path: Path
    ) -> None:
        settings = installed(_settings(hashrep=INVENTED))
        result, registry = _ask(settings, tmp_path, json.dumps(ANSWER))

        assert registry.refs == [ToolRef(kind="mcp", server="hashrep", name="lookup_digest")]
        assert registry.tool.asked == [{"digest": SHA}]
        (entry,) = [e for e in result.entries if e.server == "hashrep"]
        assert entry.tool == "lookup_digest" and entry.source == "mcp:hashrep"
        assert entry.reputation == {
            "v": 1,
            "service": "HashRep",
            "malicious": 9,
            "total": 40,
            "labels": ["Stealer", "Loader"],
            "first_seen": "2023-11-14T22:13:20Z",
            "last_seen": "2026-01-02T03:04:05Z",
            "link": "https://rep.invalid/s/abc",
        }
        assert result.facts.reputation_malicious == 9
        assert "reputation" not in result.failed

    def test_its_failure_reads_as_a_reputation_failure(
        self, installed: Any, tmp_path: Path
    ) -> None:
        settings = installed(_settings(hashrep=INVENTED))
        result, _ = _ask(settings, tmp_path, '{"error": "the digest service is down"}')

        (entry,) = [e for e in result.entries if e.server == "hashrep"]
        assert entry.ok is False and entry.reputation is None
        (reason,) = [r for r in result.degradation_reasons if "reputation" in r]
        assert reason == "triage.reputation_failed"
        assert reason_sentence(reason) == ("the triage pack's reputation lookup did not answer")
        assert render_pack([entry], 0).startswith(f"[{entry.id}] reputation: failed (")
        assert result.facts.reputation_malicious is None

    def test_the_lookups_are_asked_by_declared_rank_then_by_server_order(
        self, installed: Any
    ) -> None:
        defaults = installed(Settings())
        shipped = pack_lookups(defaults.mcp.servers, declared_reading.declarations(defaults))
        assert [(lk.server, lk.tool, lk.hash_argument, lk.enabled) for lk in shipped] == [
            ("virustotal", "get_file_report", "hash", False),
            ("threatintel", "check_hash", "file_hash", True),
        ]

        with_invented = installed(_settings(hashrep=INVENTED))
        lookups = pack_lookups(
            with_invented.mcp.servers, declared_reading.declarations(with_invented)
        )
        assert [lk.server for lk in lookups] == ["hashrep", "virustotal", "threatintel"]

        unranked = {**INVENTED, "tool_facts": json.loads(json.dumps(INVENTED["tool_facts"]))}
        del unranked["tool_facts"]["lookup_digest"]["reputation"]["rank"]
        last = installed(_settings(hashrep=unranked))
        held = declared_reading.declarations(last)
        assert [lk.server for lk in pack_lookups(last.mcp.servers, held)] == [
            "virustotal",
            "threatintel",
            "hashrep",
        ]

    def test_with_none_enabled_the_skip_names_the_declared_servers(
        self, installed: Any, tmp_path: Path
    ) -> None:
        settings = installed(_settings(hashrep={**INVENTED, "enabled": False}))
        settings.mcp.servers["threatintel"].enabled = False
        result, registry = _ask(settings, tmp_path, "{}")

        assert registry.refs == []
        (entry,) = [e for e in result.entries if e.tool == "reputation"]
        assert entry.error == (
            "not run: no reputation server is enabled (hashrep, virustotal, threatintel); "
            "no lookup was made"
        )


# ---------------------------------------------------------------------------
# The judge, the run-state block, the report, the re-render
# ---------------------------------------------------------------------------


class TestEveryReaderReadsIt:
    def test_the_judge_holds_it_and_counts_it_as_asked(self, installed: Any) -> None:
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        installed(_settings(hashrep=INVENTED))
        judge = JudgeAgent.__new__(JudgeAgent)
        judge.logger = MagicMock()
        judge.tools = []
        judge._definition_tool_refs = lambda: [ToolRef(kind="mcp", server="hashrep")]  # type: ignore[method-assign]
        assert judge._can_ask_an_identity_question(False) is True

        judge._definition_tool_refs = lambda: []  # type: ignore[method-assign]
        judge.tools = [
            type("_T", (), {"name": "lookup_digest", "metadata": {"maljan_server": "hashrep"}})()
        ]
        assert judge._holds_attached_lookup_tool() is True

        entry = _lookup_entry()
        assert _reputation_asked({"evidence_ledger": [entry.model_dump()]}) is True

    def test_it_reaches_only_the_agents_its_own_settings_allow(self, installed: Any) -> None:
        """A capability reference never broadens access: an operator's server is bound by
        its own ``agents`` list alone, and reaches no agent that list leaves out."""
        from maljan.agents.composition import mcp_refs_for, servers_bound_to

        everyone = ("static", "dynamic", "network", "judge", "triage", "android_static")
        unscoped = installed(_settings(hashrep=INVENTED))
        for key in everyone:
            assert "hashrep" not in servers_bound_to(unscoped, key), key

        scoped = installed(_settings(hashrep={**INVENTED, "agents": ["judge"]}))
        assert "hashrep" in servers_bound_to(scoped, "judge")
        for key in everyone:
            assert "hashrep" not in [str(r.server) for r in mcp_refs_for(scoped, key)], key
            if key != "judge":
                assert "hashrep" not in servers_bound_to(scoped, key), key

    def test_the_run_state_block_shows_it(self, installed: Any) -> None:
        installed(_settings(hashrep=INVENTED))
        entry = _lookup_entry()
        block = render_run_state({"evidence_ledger": [entry.model_dump()]})
        assert (
            "[ev_0001] reputation: HashRep: 9 of 40 engines flag it as malicious, "
            "labels Stealer, Loader"
        ) in block

    def test_the_report_shows_it_and_a_re_render_without_its_settings_reads_the_same(
        self, installed: Any
    ) -> None:
        installed(_settings(hashrep=INVENTED))
        stored = _report([_lookup_entry()]).model_dump_json()
        in_the_worker = MarkdownRenderer().render(MalwareReport.model_validate_json(stored))

        installed(Settings())
        in_the_api = MarkdownRenderer().render(MalwareReport.model_validate_json(stored))

        assert in_the_api == in_the_worker
        assert _reputation_row(in_the_api) == (
            "| Reputation | HashRep: 9 of 40 engines flag it as malicious "
            "(analysis 2026-01-02T03:04:05Z; lookup_digest, ev_0001) |"
        )
        (answer,) = json.loads(stored)["reputation"]
        assert answer["entry_id"] == "ev_0001" and answer["service"] == "HashRep"
        assert answer["link"] == "https://rep.invalid/s/abc"

    def test_the_built_in_virustotal_answer_reads_as_it_did(self, installed: Any) -> None:
        """The shipped lookup through the same path: the report line a stored run printed."""
        installed(Settings())
        root = Path(__file__).resolve().parents[2]
        answer = (root / "fixtures" / "ledger" / "get_file_report.json").read_text()
        entry = _lookup_entry(
            tool="get_file_report", server="virustotal", source="mcp:virustotal", output=answer
        )
        markdown = MarkdownRenderer().render(_report([entry]))
        assert _reputation_row(markdown) == (
            "| Reputation | VirusTotal: 52 of 75 engines flag it as malicious "
            "(analysis 2026-08-23T08:03:36Z; get_file_report, ev_0001) |"
        )


# ---------------------------------------------------------------------------
# A namesake gets nothing
# ---------------------------------------------------------------------------


class TestANamesakeGetsNothing:
    def test_a_user_tool_named_like_the_built_in_lookup_is_not_one(
        self, installed: Any, tmp_path: Path
    ) -> None:
        settings = installed(_settings(mytools=NAMESAKE))
        settings.mcp.servers["threatintel"].enabled = False
        lookups = pack_lookups(settings.mcp.servers, declared_reading.declarations(settings))
        assert "mytools" not in {lk.server for lk in lookups}
        result, registry = _ask(settings, tmp_path, json.dumps(ANSWER))
        assert registry.refs == []

        entry = _lookup_entry(
            tool="get_file_report",
            server="mytools",
            source="mcp:mytools",
            output=json.dumps({"data": {"last_analysis_stats": {"malicious": 70}}}),
        )
        assert entry.reputation is None and reputation_of(entry) is None
        assert not is_lookup_entry(entry)
        assert _reputation_asked({"evidence_ledger": [entry.model_dump()]}) is False
        assert not render_pack([entry], 0).startswith("[ev_0001] reputation")
        report = _report([entry])
        assert report.reputation == []
        assert _reputation_row(MarkdownRenderer().render(report)) == (
            "| Reputation | no reputation lookup in this run |"
        )

    def test_a_server_that_declares_nothing_for_it_gets_nothing(self, installed: Any) -> None:
        installed(_settings(bare={"command": "bare", "enabled": True}))
        entry = _lookup_entry(tool="get_file_report", server="bare", source="mcp:bare")
        assert entry.facts == {"v": 1}
        assert entry.reputation is None and not is_lookup_entry(entry)


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------


def test_reading_a_hostile_answer_grows_linearly() -> None:
    from maljan.core.tool_declarations import ToolFacts

    facts = ToolFacts.model_validate(
        {
            "kind": "reputation",
            "reputation": {
                "stats": "/**/stats",
                "malicious": "/**/stats/malicious",
                "labels": ["/**/names/*"],
                "detections": "/**/detections",
                "text_patterns": [r"(?P<malicious>(\d+)+)/(?P<total>\d+) bad"],
            },
        }
    )

    def timed(n: int) -> float:
        answer = {
            "a": [{"names": [f"n{i}" for i in range(n)]}],
            "b": {"detections": [f"d{i % 97}" for i in range(n)]},
            "c": [{"x": i} for i in range(n)],
        }
        started = time.perf_counter()
        text = json.dumps(answer) + "1" * n
        read = read_answer(facts, output=text, structured=answer, server="x")
        assert isinstance(read, ReputationRecord) and len(read.detections) == n
        return time.perf_counter() - started

    timed(1_000)
    small = min(timed(5_000) for _ in range(3))
    large = min(timed(50_000) for _ in range(3))
    assert large < max(small, 0.001) * 30


# ---------------------------------------------------------------------------
# Only a service's own answer becomes a record
# ---------------------------------------------------------------------------


class TestOnlyTheServicesAnswerIsARecord:
    """A repeat, an answer not shown and one the platform cut hold the platform's text, not the
    service's: no record is written for them, and none is read back from them."""

    def test_a_repeated_call_gets_no_record(self, installed: Any) -> None:
        installed(_settings(hashrep=INVENTED))
        first = _lookup_entry()
        repeat = _lookup_entry(
            entry_id="ev_0002", seq=2, output="This call repeats [ev_0001].", repeated_of="ev_0001"
        )
        assert first.reputation is not None
        assert repeat.reputation is None and reputation_of(repeat) is None
        answers = _reputation_answers([first, repeat])
        assert [a.entry_id for a in answers] == ["ev_0001"]

    def test_an_answer_not_shown_gets_no_record(self, installed: Any) -> None:
        installed(_settings(hashrep=INVENTED))
        entry = _lookup_entry(not_shown=True)
        assert entry.truncated and entry.reputation is None
        assert reputation_of(entry) is None
        assert _reputation_answers([entry]) == []

    def test_an_answer_the_platform_cut_gets_no_record(self, installed: Any) -> None:
        installed(_settings(hashrep=INVENTED))
        prose = "HashRep: 9/40 flagged, and more that was cut"
        cut = _lookup_entry(output=prose, chars_dropped=500)
        assert cut.truncated and cut.reputation is None and reputation_of(cut) is None
        prefix = _lookup_entry(output=json.dumps(ANSWER), max_chars=20)
        assert prefix.truncated and prefix.reputation is None and reputation_of(prefix) is None

    def test_a_stored_entry_is_read_back_only_when_its_flags_say_it_holds_the_answer(
        self,
    ) -> None:
        """Entries written before records (no source, no facts) are read by their flags alone."""
        from maljan.schemas.evidence import LedgerEntry

        note = "the platform's own words about this call"
        repeat = LedgerEntry(
            id="ev_0002",
            tool="check_hash",
            server="threatintel",
            output=note,
            repeated_of="ev_0001",
        )
        not_shown = LedgerEntry(
            id="ev_0003", tool="check_hash", server="threatintel", output=note, truncated=True
        )
        answered = LedgerEntry(
            id="ev_0004",
            tool="check_hash",
            server="threatintel",
            output='{"last_analysis_stats": {"malicious": 3, "undetected": 6}}',
        )
        blanked = LedgerEntry(
            id="ev_0005", tool="check_hash", server="threatintel", output="", truncated=True
        )
        assert reputation_of(repeat) is None
        assert reputation_of(not_shown) is None
        held = reputation_of(answered)
        assert held is not None and held.malicious == 3
        blank = reputation_of(blanked)
        assert blank is None or not blank.says_something()

    def test_a_budget_blank_keeps_the_record_written_from_the_whole_answer(
        self, installed: Any
    ) -> None:
        from maljan.schemas.evidence import apply_budget

        installed(_settings(hashrep=INVENTED))
        entry = _lookup_entry()
        trimmed, _spent = apply_budget([entry], 1)
        assert trimmed == 1 and entry.truncated and not entry.output
        answer = reputation_of(entry)
        assert answer is not None and answer.malicious == 9


# ---------------------------------------------------------------------------
# A stored report's records, the dates and the denominator
# ---------------------------------------------------------------------------


def test_one_unreadable_record_never_costs_the_stored_report() -> None:
    good = {"v": 1, "entry_id": "ev_0001", "service": "HashRep", "malicious": 9, "total": 40}
    data = json.loads(
        MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256=SHA))).model_dump_json()
    )
    data["reputation"] = [
        {**good, "labels": "not a list"},
        {**good, "entry_id": "ev_0002", "a_later_field": {"x": 1}},
        "nonsense",
    ]
    report = MalwareReport.model_validate(data)
    assert report.reputation is not None
    assert [a.entry_id for a in report.reputation] == ["ev_0002"]
    data["reputation"] = {"not": "a list"}
    assert MalwareReport.model_validate(data).reputation is None


def test_a_build_date_is_never_a_first_seen_date() -> None:
    from maljan.core.tool_declarations import ToolDeclarations

    held = ToolDeclarations.from_settings(Settings()).declaration_for(
        ("mcp:virustotal", "get_file_report")
    )
    assert held is not None
    answer = {"data": {"attributes": {"creation_date": 1_600_000_000}}}
    assert read_answer(held, output=json.dumps(answer), server="virustotal").first_seen is None


def test_the_report_states_the_engines_the_service_counted_over_the_total(
    installed: Any,
) -> None:
    facts = json.loads(json.dumps(INVENTED))
    facts["tool_facts"]["lookup_digest"]["reputation"]["engines"] = "/verdict/engines"
    installed(_settings(hashrep=facts))
    answer = {**ANSWER, "verdict": {**ANSWER["verdict"], "engines": 38}}
    report = _report([_lookup_entry(output=json.dumps(answer))])
    assert _reputation_row(MarkdownRenderer().render(report)).startswith(
        "| Reputation | HashRep: 9 of 38 engines flag it as malicious"
    )


def test_the_service_s_name_and_date_cannot_write_markdown_into_the_report(
    installed: Any,
) -> None:
    # A declared service's name and its answer's date are words the report did not
    # write: a link or markup in them is escaped, and an address is defanged.
    from maljan.reporting.models import ReputationAnswer

    installed(_settings(hashrep=INVENTED))
    entry = _lookup_entry()
    report = _report([entry]).model_copy(
        update={
            "reputation": [
                ReputationAnswer(
                    entry_id=entry.id,
                    service="[Rep](https://evil.example/x) | extra",
                    malicious=3,
                    engines=10,
                    last_seen="<b>2026</b> `x` http://evil.example/y",
                )
            ]
        }
    )
    row = _reputation_row(MarkdownRenderer().render(report))
    assert "](https://evil.example" not in row
    assert "\\[Rep\\]" in row
    assert "<b>" not in row and "\\<b\\>" in row
    assert "http://evil.example/y" not in row
    # The separator is escaped once, by the row: the row keeps its two cells.
    assert "\\\\|" not in row
    import re

    assert len(re.split(r"(?<!\\)\|", row)) == 4
