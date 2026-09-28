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
            assert f"{TLS_ONLY}: published because kept as an indicator" in bodies[kind], kind


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
        "no: named only by the judge's indicator, and no second source in this run records it"
    )
