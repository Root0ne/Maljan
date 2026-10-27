"""A value the sandbox attributes no flow of the sample to is kept only by a judge told so.

A local run published a CDN address as C2: the sandbox did not say which
process reached it, every other such address was refused, and the judge's
indicator naming it was the whole of its standing. The judge had never been
told the sandbox's fact. It is now asked once, through the verdict's own
question, with the fact beside the value; a keep after that question
publishes the value and says so, and a keep the judge was never asked about
publishes nothing. Every published row says why, on every surface.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.pipeline.validation import (
    UNATTRIBUTED_INDICATOR_CODE,
    Violation,
    kept_after_the_sandbox_fact,
    unattributed_indicator_violations,
)
from maljan.reporting.builder import build_consolidated_iocs
from maljan.reporting.defang import defang
from maljan.reporting.detection_signatures import build_detection_rules
from maljan.reporting.models import (
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import (
    JUDGE_KEPT_WHEN_TOLD,
    JUDGE_NOT_ASKED_IN_TIME,
    JUDGE_QUESTION_NOT_RECORDED,
    ExtendedSTIXRenderer,
    indicator_publish_reason,
    judge_indicator_rows,
    judge_not_told,
    publishes,
    sandbox_facts_for_the_judge,
    sandbox_row_kwargs,
)
from maljan.schemas.stix_models import Bundle
from tests.unit.reporting._sandbox_fact import answered_the_sandbox_fact

GUEST = "198.51.100.7"
OWN = "192.0.2.10"
NAME = "gate.example.com"
SHA256 = "a" * 64


def _network() -> NetworkIOCs:
    return NetworkIOCs(
        ips=[
            NetworkIP(address=GUEST, source="sandbox"),
            NetworkIP(address=OWN, source="sandbox", sample_process_tree=True),
        ],
        domains=[NetworkDomain(fqdn=NAME, source="sandbox")],
    )


def _indicator(pattern: str, index: int = 1) -> dict[str, Any]:
    return {
        "type": "indicator",
        "id": f"indicator--0f1e2d3c-4b5a-4968-8776-65544333221{index}",
        "name": f"judge indicator {index}",
        "pattern": pattern,
        "pattern_type": "stix",
        "indicator_types": ["malicious-activity"],
        "valid_from": "2026-01-01T00:00:00Z",
    }


def _judge(*patterns: str) -> dict[str, Any]:
    return {"type": "bundle", "objects": [_indicator(p, i) for i, p in enumerate(patterns)]}


class TestTheQuestion:
    def test_an_indicator_on_an_address_the_sample_did_not_reach_is_asked_with_the_fact(
        self,
    ) -> None:
        bundle = Bundle.model_validate(_judge(f"[ipv4-addr:value = '{GUEST}']"))

        (found,) = unattributed_indicator_violations(
            bundle, sandbox_facts_for_the_judge(_network())
        )

        assert found.code == UNATTRIBUTED_INDICATOR_CODE
        assert GUEST in found.message
        assert "does not say which process made the flows to it" in found.message
        assert found.subject == f"ip:{GUEST}"

    def test_an_address_the_sample_reached_is_not_asked_about(self) -> None:
        bundle = Bundle.model_validate(_judge(f"[ipv4-addr:value = '{OWN}']"))

        assert (
            unattributed_indicator_violations(bundle, sandbox_facts_for_the_judge(_network())) == []
        )

    def test_a_url_on_a_name_the_sample_did_not_reach_is_asked_about_its_host(self) -> None:
        network = _network()
        network.domains.append(NetworkDomain(fqdn=TLS_ONLY, source="sandbox", capture_only=True))
        bundle = Bundle.model_validate(_judge(f"[url:value = 'https://{TLS_ONLY}/gate']"))

        (found,) = unattributed_indicator_violations(bundle, sandbox_facts_for_the_judge(network))

        assert found.subject == f"domain:{TLS_ONLY}"
        # A URL in a finding row is cut to its scheme and host (safe_finding_value).
        assert f"https://{TLS_ONLY}/" in found.message
        assert f"its host {TLS_ONLY!r}" in found.message
        assert "a TLS name only the capture recorded" in found.message

    def test_a_url_on_an_address_no_row_carries_is_asked_about_the_address(self) -> None:
        bundle = Bundle.model_validate(_judge(f"[url:value = 'http://{GUEST}/in']"))

        (found,) = unattributed_indicator_violations(
            bundle, sandbox_facts_for_the_judge(_network())
        )

        assert found.subject == f"ip:{GUEST}"
        assert f"its host {GUEST!r}" in found.message

    def test_no_sandbox_record_asks_nothing(self) -> None:
        bundle = Bundle.model_validate(_judge(f"[ipv4-addr:value = '{GUEST}']"))

        assert unattributed_indicator_violations(bundle, None) == []
        assert unattributed_indicator_violations(bundle, sandbox_facts_for_the_judge(None)) == []

    def test_a_keep_after_the_question_is_recorded_as_the_judges_answer(self) -> None:
        asked = Violation(
            code=UNATTRIBUTED_INDICATOR_CODE, message="m", subject=f"ip:{GUEST}", asked=True
        )
        never = Violation(
            code=UNATTRIBUTED_INDICATOR_CODE, message="m", subject=f"ip:{OWN}", asked=False
        )

        kept = kept_after_the_sandbox_fact([asked, never])

        assert [(v.subject, v.answered, v.asked) for v in kept] == [
            (f"ip:{GUEST}", True, True),
            (f"ip:{OWN}", False, False),
        ]
        assert "kept" in kept[0].message


# A name only the capture's TLS list recorded: the sandbox does not say which
# process made the connection. The documentation ranges are never published
# whatever the judge says, so the decision is shown on a name; the address's
# own keep is read from the rule's arguments below.
TLS_ONLY = "relay.example.org"


def _report(*, told: bool) -> MalwareReport:
    rows = (
        [
            {
                "agent": "judge",
                "code": UNATTRIBUTED_INDICATOR_CODE,
                "message": "kept",
                "answered": "true",
                "subject": subject,
            }
            for subject in (f"ip:{GUEST}", f"domain:{TLS_ONLY}")
        ]
        if told
        else []
    )
    network = _network()
    network.domains.append(NetworkDomain(fqdn=TLS_ONLY, source="sandbox", capture_only=True))
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
        verdict="Malware",
        malware_category="loader",
        network=network,
        judge_indicators=[
            JudgeIndicator(kind="ip", value=GUEST),
            JudgeIndicator(kind="domain", value=TLS_ONLY),
        ],
        run_summary={"validation": {"unresolved": rows}},
    )


def _row(report: MalwareReport, value: str) -> Any:
    (row,) = [r for r in build_consolidated_iocs(report) if r.value == value]
    return row


class TestTheDecision:
    def test_an_address_kept_without_the_question_loses_the_judges_keep(self) -> None:
        said = sandbox_row_kwargs(_report(told=False), "ip", GUEST)

        assert said["kept_by"] == ""
        assert said["untold"] == judge_not_told(JUDGE_QUESTION_NOT_RECORDED)

    def test_an_address_kept_after_the_question_keeps_it_by_that_answer(self) -> None:
        said = sandbox_row_kwargs(_report(told=True), "ip", GUEST)

        assert said["kept_by"] == JUDGE_KEPT_WHEN_TOLD
        assert "untold" not in said

    def test_a_keep_the_judge_was_never_asked_about_publishes_nothing(self) -> None:
        report = _report(told=False)

        answer = _row(report, TLS_ONLY).published

        assert answer.startswith("no: a TLS name only the capture recorded")
        assert JUDGE_QUESTION_NOT_RECORDED in answer
        assert not publishes(answer)
        assert dict((i.value, a) for i, a in judge_indicator_rows(report))[TLS_ONLY] == answer

    def test_a_keep_after_the_question_publishes_and_says_so(self) -> None:
        answer = _row(_report(told=True), TLS_ONLY).published

        assert publishes(answer)
        assert answer.startswith("yes: ")
        assert "kept as an indicator by the judge when asked with the sandbox's fact" in answer
        assert "a TLS name only the capture recorded" in answer

    def test_the_export_carries_only_the_told_keep(self) -> None:
        judge = _judge(f"[domain-name:value = '{TLS_ONLY}']")
        for told, carried in ((False, False), (True, True)):
            bundle = ExtendedSTIXRenderer().render(_report(told=told), Bundle.model_validate(judge))

            assert (TLS_ONLY in str(bundle.model_dump(mode="json"))) is carried


class TestEveryPublishedRowSaysWhy:
    def test_the_table_says_why_on_every_published_row(self) -> None:
        rows = [r for r in build_consolidated_iocs(_report(told=True)) if publishes(r.published)]

        assert {r.value for r in rows} >= {SHA256, TLS_ONLY, NAME}
        for row in rows:
            assert row.published.startswith("yes: ") and len(row.published) > len("yes: ")

    def test_the_export_states_the_reason_on_every_indicator(self) -> None:
        judge = _judge(f"[domain-name:value = '{TLS_ONLY}']")
        bundle = ExtendedSTIXRenderer().render(_report(told=True), Bundle.model_validate(judge))
        indicators = [
            obj for obj in bundle.model_dump(mode="json")["objects"] if obj["type"] == "indicator"
        ]

        assert len(indicators) >= 3
        for obj in indicators:
            said = obj.get("description") or ""
            assert "Published because" in said, obj["pattern"]
            why = said.split("Published because: ", 1)[1].rstrip(".")
            assert said.count(why) == 1, said

    def test_the_drafts_state_the_reason_beside_each_value(self) -> None:
        report = _report(told=True)
        report.consolidated_iocs = build_consolidated_iocs(report)

        bodies = {rule.kind: rule.body for rule in build_detection_rules(report)}

        for kind in ("suricata", "yara"):
            assert (
                f"{defang(TLS_ONLY, 'domain')}: published because kept as an indicator"
                in (bodies[kind])
            ), kind


class TestTheVerdictAsksOnce:
    """Through the verdict's own retry, with the fact in the feedback."""

    @staticmethod
    def _answer(*patterns: str) -> str:
        import json

        objects: list[dict[str, Any]] = [
            {
                "type": "malware",
                "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                "name": "sample",
                "is_family": False,
            },
            *(
                {
                    "type": "indicator",
                    "id": f"indicator--0f1e2d3c-4b5a-4968-8776-6554433322{n:02d}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                }
                for n, pattern in enumerate(patterns)
            ),
        ]
        return json.dumps(
            {
                "type": "bundle",
                "id": "bundle--0f1e2d3c-4b5a-4968-8776-655443332200",
                "objects": objects,
                "x_maljan_assessment": {
                    "verdict": "Malware",
                    "severity": {"rating": "High", "rationale": "it does harm"},
                    "malware_category": "loader",
                },
            }
        )

    @staticmethod
    async def _verdict(
        *answers: str, published: list[tuple[str, Any]] | None = None
    ) -> tuple[Any, list[list[Any]]]:
        from unittest.mock import MagicMock

        from maljan.agents.judge_agent import JudgeAgent

        sent: list[list[Any]] = []
        queue = list(answers)

        class _Llm:
            async def ainvoke(self, messages: list[Any]) -> Any:
                sent.append(list(messages))
                return MagicMock(content=queue.pop(0))

        judge = JudgeAgent(llm=_Llm())  # type: ignore[arg-type]
        if published is not None:
            from types import SimpleNamespace

            judge._container = SimpleNamespace(
                event_sink=lambda kind, data: published.append((kind, data))
            )
        verdict = await judge.give_verdict(
            reports={"static": "It reaches a relay."},
            history=[],
            evidence_corpus={f"host {NAME} and {TLS_ONLY} seen"},
            sandbox_facts=sandbox_facts_for_the_judge(_report(told=False).network),
        )
        return verdict, sent

    @pytest.mark.asyncio
    async def test_a_keep_after_the_question_is_recorded_answered(self) -> None:
        kept = self._answer(f"[domain-name:value = '{TLS_ONLY}']")

        verdict, sent = await self._verdict(kept, kept)

        feedback = str(getattr(sent[1][-1], "content", ""))
        assert f"[{UNATTRIBUTED_INDICATOR_CODE}]" in feedback
        assert "a TLS name only the capture recorded" in feedback
        (row,) = [v for v in verdict.violations if v.code == UNATTRIBUTED_INDICATOR_CODE]
        assert (row.subject, row.answered, row.asked) == (f"domain:{TLS_ONLY}", True, True)

    @pytest.mark.asyncio
    async def test_the_conversation_shows_the_answered_question_as_resolved(self) -> None:
        kept = self._answer(f"[domain-name:value = '{TLS_ONLY}']")
        published: list[tuple[str, Any]] = []

        await self._verdict(kept, kept, published=published)

        states = [
            data["state"]
            for kind, data in published
            if kind == "validation_feedback" and data["code"] == UNATTRIBUTED_INDICATOR_CODE
        ]
        assert states == ["retried", "resolved"]

    @pytest.mark.asyncio
    async def test_an_indicator_removed_after_the_question_leaves_no_row(self) -> None:
        verdict, _sent = await self._verdict(
            self._answer(f"[domain-name:value = '{TLS_ONLY}']"),
            self._answer(f"[domain-name:value = '{NAME}']"),
        )

        assert not [v for v in verdict.violations if v.code == UNATTRIBUTED_INDICATOR_CODE]


class TestThePipelineReadsTheFacts:
    def test_the_verdict_node_reads_the_sandbox_record_the_report_reads(self) -> None:
        import json

        from maljan.pipeline.nodes import judge_sandbox_facts
        from maljan.schemas.evidence import build_entry

        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="pipeline",
            tool="sandbox_network",
            args={},
            server="pipeline",
            output=json.dumps({"tcp": [{"dst": GUEST, "dport": 443}]}),
        )

        facts = judge_sandbox_facts([entry], None, None)

        assert facts is not None
        assert "does not say which process made the flows to it" in facts("ip", GUEST)
        assert facts("domain", NAME) == ""

    def test_no_network_record_asks_nothing(self) -> None:
        from maljan.pipeline.nodes import judge_sandbox_facts

        assert judge_sandbox_facts([], None, None) is None


class TestTheWithheldReasonNamesItsCase:
    """Which of the three cases the run summary records, in the row's own words."""

    @staticmethod
    def _answer(rows: list[dict[str, str]]) -> str:
        report = _report(told=False)
        report.run_summary = {"validation": {"unresolved": rows}}
        return _row(report, TLS_ONLY).published

    def test_no_row_says_no_question_is_recorded(self) -> None:
        answer = self._answer([])

        assert JUDGE_QUESTION_NOT_RECORDED in answer
        assert "no question with this fact is recorded for this run" in answer
        assert answer.endswith("so its keep publishes nothing") or "publishes nothing" in answer

    def test_a_row_first_written_in_the_last_answer_says_so(self) -> None:
        answer = self._answer(
            [
                {
                    "agent": "judge",
                    "code": UNATTRIBUTED_INDICATOR_CODE,
                    "message": "m",
                    "asked": "false",
                    "subject": f"domain:{TLS_ONLY}",
                }
            ]
        )

        assert JUDGE_NOT_ASKED_IN_TIME in answer
        assert "the judge wrote it in its last answer" in answer
        assert not publishes(answer)

    def test_an_answered_row_publishes(self) -> None:
        answer = self._answer(
            answered_the_sandbox_fact(f"domain:{TLS_ONLY}")["validation"]["unresolved"]
        )

        assert publishes(answer)


class TestAURLOnAnAddressSaysItsAddressWasKept:
    # A routable address the reference run never reached: a documentation
    # address is refused by the address rule before attribution is asked.
    ADDRESS = "185.199.111.20"
    URL = f"http://{ADDRESS}/in"

    def _report(self, told: bool, indicator: JudgeIndicator | None = None) -> MalwareReport:
        from maljan.reporting.models import NetworkURL

        return MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
            verdict="Malware",
            overall_confidence=0.9,
            network=NetworkIOCs(
                ips=[NetworkIP(address=self.ADDRESS, source="sandbox")],
                urls=[NetworkURL(url=self.URL, source="sandbox")],
            ),
            judge_indicators=[indicator or JudgeIndicator(kind="ip", value=self.ADDRESS)],
            run_summary=answered_the_sandbox_fact(f"ip:{self.ADDRESS}") if told else {},
        )

    def test_told_the_url_says_its_address_was_kept(self) -> None:
        said = sandbox_row_kwargs(self._report(told=True), "url", self.URL)
        answer = indicator_publish_reason("url", self.URL, "sandbox", None, **said)

        assert answer is not None
        kept = f"its address {self.ADDRESS} was kept as an indicator by the judge"
        assert answer.startswith(kept)

    def test_untold_the_url_says_the_judge_named_its_address(self) -> None:
        said = sandbox_row_kwargs(self._report(told=False), "url", self.URL)

        assert f"the judge's indicator names its address {self.ADDRESS}" in said["untold"]

    def test_told_a_url_the_judge_kept_itself_says_the_judge_kept_it(self) -> None:
        report = self._report(told=True, indicator=JudgeIndicator(kind="url", value=self.URL))
        said = sandbox_row_kwargs(report, "url", self.URL)
        answer = indicator_publish_reason("url", self.URL, "sandbox", None, **said)

        assert answer is not None
        assert answer.startswith(
            "kept as an indicator by the judge when asked with its host's fact"
        )
        assert "its address" not in answer

    def test_untold_a_url_the_judge_named_itself_says_the_judge_names_it(self) -> None:
        report = self._report(told=False, indicator=JudgeIndicator(kind="url", value=self.URL))

        said = sandbox_row_kwargs(report, "url", self.URL)

        assert said["untold"] == judge_not_told(JUDGE_QUESTION_NOT_RECORDED)

    def test_a_told_judge_url_on_the_address_is_not_asked_again_under_the_url(self) -> None:
        report = self._report(told=True, indicator=JudgeIndicator(kind="url", value=self.URL))

        (answer,) = [a for _i, a in judge_indicator_rows(report)]

        assert publishes(answer), answer


def test_a_judge_url_on_a_host_it_published_names_the_judge_as_its_only_source() -> None:
    url = f"https://{TLS_ONLY}/gate"
    report = _report(told=True)
    report.judge_indicators = [JudgeIndicator(kind="url", value=url)]

    rows = {row.value: row.published for row in build_consolidated_iocs(report)}

    assert publishes(rows[TLS_ONLY])
    assert rows[url] == (
        "no: named only by the judge's indicator; no tool answer this report keeps holds it, "
        "and no second source records it"
    )


class TestAHostRowIsAskedAsAFlowIs:
    """A file, a digest, a key or a mutex no process of the sample's tree made.

    The publish rule kept such a row on the judge's keep against the
    sandbox's fact, and the question carried network facts only, so a host
    keep could never publish in a run. It is asked the same way now, for a
    value the rule could publish at all.
    """

    MUTEX = "Global\\QX7-lock"
    DROPPED = "C:\\Users\\Public\\upd.exe"
    OWN_FILE = "C:\\Users\\Public\\own.exe"
    FOLDER = "C:\\Users\\Public\\Staging\\"
    PARTIAL = "abcdef0123"

    def _dynamic(self) -> Any:
        from maljan.reporting.models import DynamicBehavior, ProcessNode

        return DynamicBehavior(
            process_tree=[ProcessNode(pid=100, name="sample.exe")],
            file_operations=[
                {"operation": "mutex", "name": self.MUTEX},
                {"operation": "write", "path": self.DROPPED, "pid": 812},
                {"operation": "write", "path": self.OWN_FILE, "pid": 100},
                {"operation": "write", "path": self.FOLDER},
                {"operation": "write", "sha256": self.PARTIAL},
            ],
        )

    def _asked(self, pattern: str) -> list[Violation]:
        bundle = Bundle.model_validate(_judge(pattern.replace("\\", "\\\\")))
        return unattributed_indicator_violations(
            bundle,
            sandbox_facts_for_the_judge(None, self._dynamic(), sample={"file_name": "sample.exe"}),
        )

    def test_a_mutex_no_record_attributes_is_asked_with_the_fact(self) -> None:
        (found,) = self._asked(f"[mutex:name = '{self.MUTEX}']")

        assert found.code == UNATTRIBUTED_INDICATOR_CODE
        assert found.subject == f"mutex:{self.MUTEX.lower()}"
        assert "does not say which process created it" in found.message
        assert "the sandbox's record of it names no process of the sample's tree" in found.message
        assert "an entry of this run shows a process of the sample's tree made it" in found.message
        # The question states what the record says, not what the row is.
        assert "own activity" not in found.message

    def test_a_file_a_process_outside_the_tree_wrote_is_asked_with_the_fact(self) -> None:
        (found,) = self._asked(f"[file:name = '{self.DROPPED}']")

        assert found.subject == f"path:{self.DROPPED.lower()}"
        assert "a process outside the sample's process tree" in found.message

    def test_a_file_the_sample_s_tree_wrote_is_not_asked_about(self) -> None:
        assert self._asked(f"[file:name = '{self.OWN_FILE}']") == []

    def test_a_value_no_keep_could_publish_is_not_asked_about(self) -> None:
        assert self._asked(f"[file:name = '{self.FOLDER}']") == []
        assert self._asked(f"[file:hashes.'SHA-256' = '{self.PARTIAL}']") == []

    def test_the_answer_to_the_question_is_the_keep_the_row_reads(self) -> None:
        from maljan.reporting.renderers.stix_renderer import sandbox_host_kwargs

        (found,) = self._asked(f"[mutex:name = '{self.MUTEX}']")
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256)),
            verdict="Malware",
            malware_category="loader",
            dynamic=self._dynamic(),
            judge_indicators=[JudgeIndicator(kind="mutex", value=self.MUTEX)],
            run_summary=answered_the_sandbox_fact(found.subject),
        )

        said = sandbox_host_kwargs(report, "mutex", self.MUTEX)

        assert said["kept_by"] == JUDGE_KEPT_WHEN_TOLD
        assert indicator_publish_reason("mutex", self.MUTEX, "sandbox", **said)

    def test_the_verdict_node_reads_the_host_record_the_report_reads(self) -> None:
        import json

        from maljan.pipeline.nodes import judge_sandbox_facts
        from maljan.schemas.evidence import build_entry

        entry = build_entry(
            entry_id="ev_0001",
            seq=1,
            agent="pipeline",
            tool="sandbox_mutexes",
            args={},
            server="pipeline",
            output=json.dumps({"mutexes": [self.MUTEX]}),
        )

        facts = judge_sandbox_facts([entry], None, None)

        assert facts is not None
        assert "does not say which process created it" in facts("mutex", self.MUTEX)
        assert facts("ip", GUEST) == ""


class TestAPidTheSandboxKeptDecidesTheQuestion:
    """From the sandbox's own report, through its tools and the ledger, to the question.

    No tool answer carried the process behind a dropped file, a key or a
    mutex, so every host row read as unattributed, and the judge would have
    been asked about its own sample's mutex. The pid the report keeps now
    rides each row; a row with none is still asked, in the record's words.
    """

    OWN_MUTEX = "Global\\OwnLock"
    SUMMARY_MUTEX = "Global\\SummaryOnly"
    OWN_KEY = "HKEY_CURRENT_USER\\Software\\Own\\cfg"
    LOST_KEY = "HKEY_CURRENT_USER\\Software\\Lost\\cfg"
    RUN_KEY = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    OWN_FILE = "C:\\Users\\Public\\upd.exe"
    LOST_FILE = "C:\\Users\\Public\\x.dat"
    # The routed identity the sample's process tree is found by.
    SAMPLE = {"file_name": "invoice.exe", "sha256": SHA256}

    def _report(self) -> dict[str, Any]:
        def _set(key: str) -> dict[str, Any]:
            return {
                "api": "RegSetValueExW",
                "arguments": [{"name": "FullName", "value": key}, {"name": "Buffer", "value": "1"}],
            }

        return {
            "target": {"sha256": SHA256, "name": "invoice.exe"},
            "behavior": {
                "summary": {"mutexes": [self.SUMMARY_MUTEX]},
                "processes": [
                    {
                        "pid": 1234,
                        "ppid": 1,
                        "process_name": "invoice.exe",
                        "calls": [
                            {
                                "api": "NtCreateMutant",
                                "arguments": [{"name": "MutexName", "value": self.OWN_MUTEX}],
                            },
                            _set(self.OWN_KEY),
                        ],
                    },
                    # A process the report kept no pid for: its calls name none.
                    {
                        "process_name": "unknown.exe",
                        "calls": [_set(self.LOST_KEY), _set(self.RUN_KEY)],
                    },
                ],
            },
            "dropped": [
                {"name": "upd.exe", "filepath": self.OWN_FILE, "sha256": "c" * 64, "pids": [1234]},
                {"name": "x.dat", "filepath": self.LOST_FILE, "sha256": "d" * 64},
            ],
        }

    def _ledger(self) -> list[Any]:
        from tests.unit._ledger_helpers import ledger_from_sandbox

        return ledger_from_sandbox(self._report())

    def test_each_tool_answer_carries_the_pid_the_report_kept(self) -> None:
        from maljan.providers import sandbox_tools

        report = self._report()
        dropped = sandbox_tools.sandbox_dropped_files(report)["dropped"]
        registry = sandbox_tools.sandbox_registry_ops(report)["registry"]
        mutexes = sandbox_tools.sandbox_mutexes(report)

        assert [row.get("pids") for row in dropped] == [["1234"], None]
        assert {row["key"]: row.get("pids") for row in registry} == {
            self.OWN_KEY: ["1234"],
            self.LOST_KEY: None,
            self.RUN_KEY: None,
        }
        assert mutexes["mutexes"] == [self.SUMMARY_MUTEX, self.OWN_MUTEX]
        assert mutexes["pids"] == {self.OWN_MUTEX: ["1234"]}

    def test_a_row_whose_pid_is_the_sample_s_is_not_asked_about(self) -> None:
        from maljan.pipeline.nodes import judge_sandbox_facts

        facts = judge_sandbox_facts(self._ledger(), None, None, sample=self.SAMPLE)

        assert facts is not None
        assert facts("mutex", self.OWN_MUTEX) == ""
        assert facts("registry", self.OWN_KEY) == ""
        assert facts("path", self.OWN_FILE) == ""
        assert facts("hash", "c" * 64) == ""

    def test_a_row_with_no_pid_gets_the_honest_question(self) -> None:
        from maljan.pipeline.nodes import judge_sandbox_facts

        facts = judge_sandbox_facts(self._ledger(), None, None, sample=self.SAMPLE)
        bundle = Bundle.model_validate(
            _judge(
                f"[mutex:name = '{self.SUMMARY_MUTEX}']".replace("\\", "\\\\"),
                f"[windows-registry-key:key = '{self.LOST_KEY}']".replace("\\", "\\\\"),
                f"[file:name = '{self.LOST_FILE}']".replace("\\", "\\\\"),
            )
        )

        found = unattributed_indicator_violations(bundle, facts)

        assert [v.subject for v in found] == [
            f"mutex:{self.SUMMARY_MUTEX.lower()}",
            f"registry:{self.LOST_KEY.lower()}",
            f"path:{self.LOST_FILE.lower()}",
        ]
        assert "does not say which process created it" in found[0].message
        assert "does not say which process wrote it" in found[1].message
        assert all("names no process of the sample's tree" in v.message for v in found)

    def test_a_run_key_a_persistence_mechanism_names_is_not_asked_about(self) -> None:
        from maljan.pipeline.nodes import judge_sandbox_facts

        facts = judge_sandbox_facts(self._ledger(), None, None, sample=self.SAMPLE)

        # The same unattributed write: the key with no mechanism is asked,
        # the Run key is the persistence row's, as the IOC table answers it.
        assert facts("registry", self.LOST_KEY)
        assert facts("registry", self.RUN_KEY) == ""
        assert facts("registry", self.RUN_KEY.lower() + " ") == ""

    def test_a_report_with_no_pid_reads_as_it_did(self) -> None:
        from maljan.reporting.ledger_projection import dynamic_from_ledger

        dynamic = dynamic_from_ledger(self._ledger())

        assert dynamic is not None
        (lost,) = [m for m in dynamic.registry_mods if m.key == self.LOST_KEY]
        assert "pids" not in lost.model_dump()
        (own,) = [m for m in dynamic.registry_mods if m.key == self.OWN_KEY]
        assert own.model_dump()["pids"] == ["1234"]


class TestTheFactsAreReadOnce:
    """Asking about every value of a bundle reads each sandbox block once."""

    def test_the_lookups_are_built_once_for_any_number_of_values(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.reporting.models import DynamicBehavior, ProcessNode
        from maljan.reporting.renderers import stix_renderer

        count = 3000
        reads = {"ips": 0, "tree": 0}

        class _Network:
            domains: list[Any] = []
            urls: list[Any] = []

            @property
            def ips(self) -> list[Any]:
                reads["ips"] += 1
                return [
                    NetworkIP(address=f"198.51.{i // 250}.{i % 250}", source="sandbox")
                    for i in range(count)
                ]

        walk = stix_renderer._tree_processes

        def _counted(roots: list[Any], *args: str) -> Any:
            reads["tree"] += 1
            return walk(roots, *args)

        monkeypatch.setattr(stix_renderer, "_tree_processes", _counted)
        dynamic = DynamicBehavior(
            process_tree=[ProcessNode(pid=1, name="s.exe")],
            file_operations=[{"operation": "mutex", "name": f"m{i}"} for i in range(count)],
        )

        facts = sandbox_facts_for_the_judge(_Network(), dynamic)
        asked = [facts("ip", f"198.51.{i // 250}.{i % 250}") for i in range(count)]
        asked += [facts("mutex", f"m{i}") for i in range(count)]

        assert all(asked)
        assert reads == {"ips": 1, "tree": 1}


def _mutex_call(api: str, name: str, **outcome: Any) -> dict[str, Any]:
    return {"api": api, "arguments": [{"name": "MutexName", "value": name}], **outcome}


class TestOnlyACreationNamesAMutexMaker:
    """A process that opened a mutex, or created one that was already there, did not make it."""

    @pytest.mark.parametrize(
        "call",
        [
            _mutex_call("NtOpenMutant", "Global\\Z"),
            _mutex_call("NtCreateMutant", "Global\\Z", status=True, **{"return": "0x40000000"}),
            _mutex_call("CreateMutexW", "Global\\Z", status=True, last_error=183),
            _mutex_call("CreateMutexW", "Global\\Z", pretty_return="ERROR_ALREADY_EXISTS"),
            _mutex_call("NtCreateMutant", "Global\\Z", status=False),
        ],
        ids=["open", "native exists", "win32 exists", "win32 exists by name", "failed"],
    )
    def test_no_pid_is_kept_for_a_mutex_the_process_did_not_create(
        self, call: dict[str, Any]
    ) -> None:
        from maljan.providers import sandbox_tools

        report = {"behavior": {"processes": [{"pid": 7, "calls": [call]}]}}

        answer = sandbox_tools.sandbox_mutexes(report)

        assert answer["mutexes"] == ["Global\\Z"]
        assert "pids" not in answer

    def test_a_creation_keeps_its_pid(self) -> None:
        from maljan.providers import sandbox_tools

        call = _mutex_call("NtCreateMutant", "Global\\Z", status=True, **{"return": "0x00000000"})
        report = {"behavior": {"processes": [{"pid": 7, "calls": [call]}]}}

        assert sandbox_tools.sandbox_mutexes(report)["pids"] == {"Global\\Z": ["7"]}


class TestTheSampleSTreeIsItsLineage:
    """The tree a host row is attributed to is the sample's lineage, not every listed root."""

    KEY = "HKEY_CURRENT_USER\\Software\\Example\\cfg"

    @staticmethod
    def _facts(processes: list[Any], pids: list[str]) -> Any:
        from maljan.reporting.models import DynamicBehavior, RegistryMod

        dynamic = DynamicBehavior(
            process_tree=processes,
            registry_mods=[
                RegistryMod(key=TestTheSampleSTreeIsItsLineage.KEY, operation="modify", pids=pids)
            ],
        )
        return sandbox_facts_for_the_judge(
            None, dynamic, sample={"file_name": "invoice.exe", "sha256": SHA256}
        )

    @staticmethod
    def _node(pid: int, name: str, ppid: int = 0, **more: Any) -> Any:
        from maljan.reporting.models import ProcessNode

        return ProcessNode(pid=pid, ppid=ppid, name=name, **more)

    def test_a_child_of_the_process_running_the_sample_is_the_sample_s(self) -> None:
        processes = [self._node(10, "invoice.exe", 1), self._node(11, "cmd.exe", 10)]

        assert self._facts(processes, ["11"])("registry", self.KEY) == ""

    def test_an_unrelated_listed_root_is_not_the_sample_s(self) -> None:
        processes = [self._node(10, "invoice.exe", 1), self._node(40, "svchost.exe", 4)]

        said = self._facts(processes, ["40"])("registry", self.KEY)

        assert (
            said
            == "the sandbox report attributes it to a process outside the sample's process tree"
        )

    def test_an_injected_process_listed_as_a_root_is_asked_about(self) -> None:
        # explorer.exe the sample wrote into is listed, but runs none of its
        # names and descends from none of its processes.
        processes = [self._node(10, "invoice.exe", 1), self._node(2200, "explorer.exe", 2100)]

        assert self._facts(processes, ["2200"])("registry", self.KEY)

    def test_with_no_identity_no_listed_process_is_the_sample_s(self) -> None:
        from maljan.reporting.models import DynamicBehavior, RegistryMod

        dynamic = DynamicBehavior(
            process_tree=[self._node(10, "invoice.exe", 1)],
            registry_mods=[RegistryMod(key=self.KEY, operation="modify", pids=["10"])],
        )

        assert sandbox_facts_for_the_judge(None, dynamic)("registry", self.KEY)

    def test_a_mark_alone_names_the_tree(self) -> None:
        processes = [self._node(10, "stage.exe", 1, marked=True), self._node(11, "x.exe", 10)]

        assert self._facts(processes, ["11"])("registry", self.KEY) == ""

    def test_a_process_the_two_facts_disagree_about_is_unattributed(self) -> None:
        # The sandbox marks a desktop process that runs none of the sample's
        # names; the process running the sample is not marked.
        processes = [
            self._node(10, "invoice.exe", 1, marked=True),
            self._node(30, "notepad.exe", 2, marked=True),
        ]

        said = self._facts(processes, ["30"])("registry", self.KEY)

        assert said == "the sandbox report does not say which process wrote it"

    def test_a_pid_two_listed_processes_of_different_lineage_carry_is_unattributed(self) -> None:
        processes = [self._node(10, "invoice.exe", 1), self._node(10, "svchost.exe", 4)]

        said = self._facts(processes, ["10"])("registry", self.KEY)

        assert said == "the sandbox report does not say which process wrote it"


class TestFromTheSandboxToTheExport:
    """A CAPE-shaped report through the real tools and the ledger to the IOC table and STIX.

    The guest writes temporary files, zone keys and mutexes under the
    sample's own processes too, so a host row is published only as an
    indicator the judge names: a row of the sample's tree on that keep, with
    no question, and a row whose record names no process of the tree only on
    the judge's answer to the question that told it so.
    """

    NAMED_FILE = "C:\\Users\\Public\\upd.exe"
    TEMP_FILE = "C:\\Users\\Admin\\AppData\\Local\\Temp\\~DF1A.tmp"
    ZONE_KEY = (
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
        "\\ZoneMap\\ProxyBypass"
    )
    ZONE_MUTEX = "Local\\ZonesCacheCounterMutex"
    LOST_MUTEX = "Global\\Lost"
    SAMPLE = {"file_name": "invoice.exe", "sha256": SHA256}

    def _raw(self) -> dict[str, Any]:
        return {
            "target": {"sha256": SHA256, "name": "invoice.exe"},
            "behavior": {
                "summary": {"mutexes": [self.LOST_MUTEX]},
                "processes": [
                    {
                        "pid": 1234,
                        "ppid": 1,
                        "process_name": "invoice.exe",
                        "calls": [
                            _mutex_call("NtCreateMutant", self.ZONE_MUTEX),
                            {
                                "api": "RegSetValueExW",
                                "arguments": [
                                    {"name": "FullName", "value": self.ZONE_KEY},
                                    {"name": "Buffer", "value": "1"},
                                ],
                            },
                        ],
                    }
                ],
            },
            "dropped": [
                {
                    "name": "upd.exe",
                    "filepath": self.NAMED_FILE,
                    "sha256": "e" * 64,
                    "pids": [1234],
                },
                {
                    "name": "~DF1A.tmp",
                    "filepath": self.TEMP_FILE,
                    "sha256": "f" * 64,
                    "pids": [1234],
                },
            ],
        }

    def _report(self, *, told: bool = False) -> tuple[MalwareReport, Any]:
        from maljan.pipeline.nodes import judge_sandbox_facts
        from maljan.reporting.ledger_projection import dynamic_from_ledger, persistence_from_ledger
        from tests.unit._ledger_helpers import ledger_from_sandbox

        ledger = ledger_from_sandbox(self._raw())
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256=SHA256), file_name="invoice.exe"),
            verdict="Malware",
            malware_category="loader",
            dynamic=dynamic_from_ledger(ledger),
            persistence=persistence_from_ledger(ledger),
            judge_indicators=[
                JudgeIndicator(kind="path", value=self.NAMED_FILE),
                JudgeIndicator(kind="mutex", value=self.LOST_MUTEX),
            ],
            run_summary=answered_the_sandbox_fact(f"mutex:{self.LOST_MUTEX.lower()}")
            if told
            else {},
        )
        return report, judge_sandbox_facts(ledger, None, None, sample=self.SAMPLE)

    @staticmethod
    def _rows(report: MalwareReport) -> dict[str, str]:
        return {row.value: str(row.published) for row in build_consolidated_iocs(report)}

    @staticmethod
    def _stix(report: MalwareReport) -> str:
        return ExtendedSTIXRenderer().render(report).model_dump_json()

    def test_a_host_row_of_the_tree_the_judge_did_not_name_is_not_published(self) -> None:
        report, _facts = self._report()
        rows, stix = self._rows(report), self._stix(report)

        for value in (self.TEMP_FILE, "f" * 64, self.ZONE_KEY, self.ZONE_MUTEX, "e" * 64):
            assert rows[value].startswith("no: the sandbox recorded it, and a file, digest"), value
        assert "~DF1A.tmp" not in stix
        assert "ZoneMap" not in stix
        assert "ZonesCacheCounterMutex" not in stix

    def test_a_host_row_of_the_tree_the_judge_named_publishes_without_a_question(self) -> None:
        report, facts = self._report()
        bundle = Bundle.model_validate(
            _judge(f"[file:name = '{self.NAMED_FILE}']".replace("\\", "\\\\"))
        )

        assert unattributed_indicator_violations(bundle, facts) == []
        assert self._rows(report)[self.NAMED_FILE] == (
            "yes: kept as an indicator by the judge's indicator; the sandbox recorded it from "
            "the sample's process tree"
        )
        assert "upd.exe" in self._stix(report)

    def test_a_host_row_the_judge_named_with_no_process_is_asked(self) -> None:
        report, facts = self._report()
        bundle = Bundle.model_validate(
            _judge(f"[mutex:name = '{self.LOST_MUTEX}']".replace("\\", "\\\\"))
        )

        (found,) = unattributed_indicator_violations(bundle, facts)

        assert found.subject == f"mutex:{self.LOST_MUTEX.lower()}"
        assert "names no process of the sample's tree" in found.message
        # Untold, the keep publishes nothing; answered, it publishes.
        assert not publishes(self._rows(report)[self.LOST_MUTEX])
        assert self.LOST_MUTEX.replace("\\", "\\\\") not in self._stix(report)
        told, _facts = self._report(told=True)
        assert publishes(self._rows(told)[self.LOST_MUTEX])


class TestADeepLineageIsReadInLinearTime:
    """A parent chain thousands deep is walked once, not once per step over the steps walked."""

    @staticmethod
    def _chain(depth: int) -> list[Any]:
        from maljan.reporting.models import ProcessNode

        return [ProcessNode(pid=1, ppid=0, name="invoice.exe")] + [
            ProcessNode(pid=n, ppid=n - 1, name="cmd.exe") for n in range(2, depth + 1)
        ]

    @staticmethod
    def _tree_of(processes: list[Any]) -> Any:
        from maljan.reporting.renderers.stix_renderer import _tree_processes

        return _tree_processes(processes, "invoice.exe", SHA256)

    def test_every_step_of_the_chain_is_the_sample_s(self) -> None:
        tree = self._tree_of(self._chain(8000))

        assert len(tree.pids) == 8000
        assert "8000" in tree.pids

    def test_four_times_the_depth_costs_less_than_the_limit(self) -> None:
        from tests.linear_cost import TIME_RATIO_LIMIT, cpu_seconds

        # A walk that tests each step against the chain so far costs the
        # square of the depth: sixteen times as much for four times the depth.
        # The shallow chain is sized to cost tens of milliseconds.
        shallow, deep = self._chain(8000), self._chain(32000)

        small = cpu_seconds(lambda: self._tree_of(shallow), repeats=5)
        large = cpu_seconds(lambda: self._tree_of(deep), repeats=5)

        assert large < small * TIME_RATIO_LIMIT, (small, large)


class TestTheVerdictNodeFindsTheTreeByTheReportSIdentity:
    def test_the_sample_s_path_names_it_when_it_arrived_with_no_name(self) -> None:
        from maljan.pipeline.nodes import judge_facts_identity

        state = {"file_name": None, "sample_path": "/jobs/7/invoice.exe", "file_hash": SHA256}

        assert judge_facts_identity(state) == {"file_name": "invoice.exe", "sha256": SHA256}

    def test_the_name_it_arrived_with_comes_first(self) -> None:
        from maljan.pipeline.nodes import judge_facts_identity

        state = {"file_name": "a.exe", "sample_path": "/jobs/7/b.bin", "file_hash": SHA256}

        assert judge_facts_identity(state)["file_name"] == "a.exe"
        assert judge_facts_identity({}) == {"file_name": "", "sha256": ""}
