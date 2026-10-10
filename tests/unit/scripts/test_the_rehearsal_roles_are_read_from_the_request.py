"""The stub's scripted answers: each role read from the product's own prompts, in its own form.

Every role marker is taken from the product's prompt constants and builders,
and every test here builds its request from those same constants, so a
reworded prompt moves the marker and these tests together; a prompt the
product no longer builds the way the stub reads it is answered as ``other``,
which the checklist fails. Each scenario faults the first call of every role
instance — each analyst, each composer section — and an analyst calls the
tools it was given before it answers with claims citing ids its request
carries.
"""

from __future__ import annotations

import json
import re

import pytest
from scripts.rehearsal import wire
from scripts.rehearsal.roles import (
    SCENARIOS,
    Brain,
    _as_schema_call,
    _corrected,
    _keep_every_item,
    _original_claims,
    claims_in,
    composer_section,
    instance_of,
    markers,
    role_of,
)

from maljan.agents.base_agent import _REVISION_ISR_FRAMING
from maljan.agents.judge_agent import (
    JUDGE_VERDICT_SYSTEM,
    MEDIATION_EXTRACTION_SYSTEM,
    MEDIATOR_SYSTEM_HEAD,
    TECHNIQUE_QUESTION_SYSTEM,
)
from maljan.agents.prompt_fragments import no_tool_call_question
from maljan.agents.static_analyst import _extract_load_hint
from maljan.pipeline.validation import FEEDBACK_PREAMBLE, RetryDrops, retry_drop_question
from maljan.reporting import composer, narrative_agent

SAMPLE = "/w/sample_1.exe"
PACK = (
    "Facts established before analysis (ledger ids in brackets; cite them)\n"
    "[ev_0001] identity: pe windows, 3,584 bytes\n"
    "[ev_0006] iocs: 1 domain, 1 url (http://rehearsal.example.net/beacon, rehearsal.example.net)\n"
    + _extract_load_hint(json.dumps({"analysis_file_path": SAMPLE}), frozenset({"pe_info"}))
    + "Format each finding as:\nCLAIM: <claim text>\n"
)
PE_INFO = {
    "name": "pe_info",
    "description": "",
    "schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
}


def _request(
    system: str,
    user: str,
    tools: list | None = None,
    turns: list | None = None,
    api: str = "openai",
):
    return wire.Request(
        api=api,
        model="m",
        system=system,
        turns=turns or [wire.Turn(role="user", text=user)],
        tools=tools or [],
        max_tokens=None,
        stream=False,
        raw={},
    )


def _section_request(section: str, contract: str) -> wire.Request:
    evidence = composer._bundle_text(section, {"claims": [], "tool_outputs": [], "facts": {}}, None)
    return _request(composer._SYSTEM, f"{contract}\n\n{evidence}")


class TestTheRoleComesFromTheProductsOwnPrompts:
    @pytest.mark.parametrize(
        ("system", "role"),
        [
            (TECHNIQUE_QUESTION_SYSTEM, "technique_question"),
            (MEDIATION_EXTRACTION_SYSTEM, "mediator_extract"),
            (MEDIATOR_SYSTEM_HEAD + "HARD RULES: ...", "mediator"),
            (JUDGE_VERDICT_SYSTEM, "judge"),
            (narrative_agent._SYSTEM_PROMPT, "narrative"),
            (composer._SYSTEM, "composer"),
            ("You are an expert analyst.\n\n" + _REVISION_ISR_FRAMING, "revision"),
        ],
    )
    def test_each_role(self, system: str, role: str) -> None:
        assert role_of(_request(system, "x")) == role

    def test_an_agent_with_tools_is_an_analyst_whatever_it_is_called(self) -> None:
        assert role_of(_request("You are Someone New.", "x", tools=[PE_INFO])) == "analyst"

    def test_a_request_no_script_knows_is_other(self) -> None:
        assert role_of(_request("A prompt nobody wrote.", "hello")) == "other"

    def test_the_markers_are_the_product_s_words(self) -> None:
        found = markers()
        assert found.feedback == FEEDBACK_PREAMBLE
        assert found.no_tool_nudge in no_tool_call_question(["x"])
        assert found.keep_question in retry_drop_question(RetryDrops())
        assert PACK.count(found.sample_path) == 1

    def test_a_composer_section_is_named_by_the_composer_s_own_header(self) -> None:
        schema = composer.SECTION_SCHEMAS["execution_flow"]
        request = _section_request(
            "execution_flow", composer.section_contract("execution_flow", schema)
        )
        assert composer_section(request) == "execution_flow"


class TestTheScenarios:
    def test_an_unknown_scenario_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown scenario"):
            Brain(scenario="no-such")

    def test_a_deadline_aimed_at_a_stage_holds_only_that_stage_s_calls(self) -> None:
        brain = Brain(scenario="deadline_hit", deadline_in="debate")
        mediator = _request(MEDIATOR_SYSTEM_HEAD, "--- STATIC ---")
        analyst = _request("You are the static analyst.", PACK, tools=[PE_INFO])
        assert brain.answer(mediator)[1].delay >= 600
        assert brain.answer(analyst)[1].delay == 0.0

    @pytest.mark.parametrize(
        ("scenario", "stage"), [("normal", "report"), ("deadline_hit", "no-such-stage")]
    )
    def test_a_deadline_is_aimed_only_from_deadline_hit_at_a_known_stage(
        self, scenario: str, stage: str
    ) -> None:
        with pytest.raises(ValueError, match="aims deadline_hit"):
            Brain(scenario=scenario, deadline_in=stage)

    @pytest.mark.parametrize(
        ("scenario", "check"),
        [
            ("cut_at_cap", lambda r: r.stop == "max_tokens" and r.thinking and not r.text),
            ("empty_answer", lambda r: r.text == "" and not r.tool_calls),
            ("server_error_once", lambda r: r.status == 500),
            ("rate_limited", lambda r: r.status == 429 and r.headers.get("retry-after")),
            ("overloaded", lambda r: r.status == 503),
            ("schema_break", lambda r: "agreement_confidence" not in r.text),
            ("unusual_stop", lambda r: r.stop == "refusal"),
        ],
    )
    def test_faults_a_role_instance_s_first_call_only(self, scenario: str, check) -> None:
        brain = Brain(scenario=scenario)
        request = _request(MEDIATOR_SYSTEM_HEAD, "--- STATIC ---")
        role, first, fault = brain.answer(request)
        assert (role, fault) == ("mediator", scenario)
        assert check(first)
        _role, second, fault = brain.answer(request)
        assert fault == "" and second.status == 200 and "agreement_confidence" in second.text

    def test_every_analyst_and_every_section_sees_its_own_first_call_faulted(self) -> None:
        brain = Brain(scenario="empty_answer")
        static = _request("You are the static analyst.", PACK, tools=[PE_INFO])
        dynamic = _request("You are the dynamic analyst.", PACK, tools=[PE_INFO])
        assert instance_of("analyst", static) != instance_of("analyst", dynamic)
        assert brain.answer(static)[2] == "empty_answer"
        assert brain.answer(dynamic)[2] == "empty_answer"
        assert brain.answer(static)[2] == ""

    def test_a_composer_section_s_empty_answer_is_whitespace_alone(self) -> None:
        schema = composer.SECTION_SCHEMAS["execution_flow"]
        request = _section_request(
            "execution_flow", composer.section_contract("execution_flow", schema)
        )
        role, reply, fault = Brain(scenario="empty_answer").answer(request)
        assert (role, fault) == ("composer", "empty_answer")
        assert reply.text and not reply.text.strip() and not reply.tool_calls

    def test_overloaded_is_529_on_the_anthropic_wire(self) -> None:
        reply = Brain(scenario="overloaded").answer(
            _request(MEDIATOR_SYSTEM_HEAD, "x", api="anthropic")
        )[1]
        assert reply.status == 529

    def test_prose_instead_of_tool_answers_a_schema_request_in_text(self) -> None:
        tool = {"name": "NarrativeOutput", "description": "", "schema": {"properties": {}}}
        request = _request(narrative_agent._SYSTEM_PROMPT, "x", tools=[tool], api="anthropic")
        _role, reply, fault = Brain(scenario="prose_instead_of_tool").answer(request)
        assert fault == "prose_instead_of_tool"
        assert not reply.tool_calls and "executive_summary" in reply.text

    def test_a_wire_a_scenario_cannot_carry_runs_as_normal(self) -> None:
        tool = {"name": "NarrativeOutput", "description": "", "schema": {"properties": {}}}
        request = _request(narrative_agent._SYSTEM_PROMPT, "x", tools=[tool], api="openai")
        assert Brain(scenario="prose_instead_of_tool").answer(request)[2] == ""

    def test_redacted_thinking_marks_anthropic_answers_that_think(self) -> None:
        reply = Brain(scenario="redacted_thinking").answer(
            _request(MEDIATOR_SYSTEM_HEAD, "x", api="anthropic")
        )[1]
        assert reply.redacted and reply.note["redacted"]

    @pytest.mark.parametrize("scenario", ["slow_model", "deadline_hit"])
    def test_a_slow_scenario_delays_every_reply(self, scenario: str) -> None:
        reply = Brain(scenario=scenario, slow_seconds=0.5).answer(
            _request(MEDIATOR_SYSTEM_HEAD, "x")
        )[1]
        assert reply.delay == 0.5

    def test_every_scenario_has_a_sentence(self) -> None:
        assert all(SCENARIOS.values())


class TestTheAnalyst:
    def test_calls_a_tool_on_the_run_s_sample_first(self) -> None:
        _role, reply, _ = Brain().answer(_request("An analyst.", PACK, tools=[PE_INFO]))
        assert [(c.name, c.args) for c in reply.tool_calls] == [("pe_info", {"path": SAMPLE})]

    def test_answers_with_claims_citing_the_request_s_ids_after_its_steps(self) -> None:
        turns = [wire.Turn(role="user", text=PACK)]
        for n in range(2):
            turns.append(
                wire.Turn(role="assistant", tool_calls=[wire.ToolCall("pe_info", {}, f"c{n}")])
            )
            turns.append(
                wire.Turn(
                    role="user",
                    tool_results=[wire.ToolResult(f"c{n}", f'[ev_00{30 + n}]\n{{"machine": 1}}')],
                )
            )
        _role, reply, _ = Brain().answer(_request("An analyst.", "", [PE_INFO], turns))
        assert not reply.tool_calls
        cited = set(re.findall(r"ev_\d{4}", reply.text))
        assert cited <= {"ev_0001", "ev_0006", "ev_0030", "ev_0031"}
        assert "TECHNIQUE: T1071.001" in reply.text
        assert reply.note["answer"] == "final" and reply.note["claims"] == claims_in(reply.text)

    def test_writes_its_answer_when_the_tools_are_withheld(self) -> None:
        request = _request("An analyst.", PACK, tools=[PE_INFO])
        request.raw["tool_choice"] = {"type": "none"}
        reply = Brain().answer(request)[1]
        assert not reply.tool_calls and "CLAIM:" in reply.text

    def test_a_drops_question_keeps_every_item(self) -> None:
        question = "C1. CLAIM: one\nF2. FINDING: two\n" + markers().keep_question
        assert _keep_every_item(question).splitlines() == [
            "KEEP C1: the cited entry still shows it",
            "KEEP F2: the cited entry still shows it",
        ]

    def test_a_retry_rewrites_only_the_claims_the_check_named(self) -> None:
        previous = (
            "CLAIM: a.\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.6\nTECHNIQUE: T1071.001\n---\n"
            "CLAIM: b.\nEVIDENCE: [ev_0002]\nCONFIDENCE: 0.6\nTECHNIQUE: T1055\n---"
        )
        answer = _corrected(previous, "- [isr.ungrounded_technique] (static.claims[1]) ...")
        assert answer.startswith("CLAIM 2: b.")
        assert "TECHNIQUE: NONE" in answer and "CLAIM: a." not in answer

    def test_a_revision_restates_its_own_claims(self) -> None:
        text = (
            "YOUR ORIGINAL REPORT:\n[STATIC ANALYST — round 0]\n"
            "  Claim 1: It talks HTTP. (T1071.001) | Evidence: [ev_0006] iocs | Confidence: 0.80\n"
            "  Claim 2: It is a PE. | Evidence: [ev_0001] identity | Confidence: 0.60\n\n"
            "PEER REPORTS:\n  Claim 1: Other. | Evidence: [ev_0009] x | Confidence: 0.5\n"
        )
        blocks = _original_claims(text)
        assert len(blocks) == 2
        assert "TECHNIQUE: T1071.001" in blocks[0] and "TECHNIQUE: NONE" in blocks[1]

    def test_a_later_round_s_revision_restates_the_answer_in_force_as_written(self) -> None:
        """A later round shows the revision in force in ``CLAIM:`` blocks; every claim stays."""
        written = (
            "CLAIM: It talks HTTP.\nEVIDENCE: [ev_0006] iocs\nCONFIDENCE: 0.80\n"
            "TECHNIQUE: T1071.001\n---\n"
            "CLAIM: The pe_info answer records what it read from the sample.\n"
            'EVIDENCE: [ev_0026] pe_info: { "machine": 34404 }\nCONFIDENCE: 0.60\n'
            "TECHNIQUE: NONE\n---\n"
            "CLAIM: It is a PE.\nEVIDENCE: [ev_0001] identity\nCONFIDENCE: 0.60\n"
            "TECHNIQUE: NONE\n---\nDISPUTES: NONE\n"
        )
        text = (
            f"YOUR ORIGINAL REPORT:\n{written}\nPEER REPORTS:\nOTHER REPORT:\n"
            "CLAIM: Other.\nEVIDENCE: [ev_0009] x\nCONFIDENCE: 0.5\nTECHNIQUE: NONE\n---\n"
        )
        blocks = _original_claims(text)
        assert claims_in("\n".join(blocks)) == claims_in(written)
        assert "EVIDENCE: [ev_0026] pe_info" in blocks[1]
        assert "CONFIDENCE: 0.80" in blocks[0] and "TECHNIQUE: T1071.001" in blocks[0]
        role, reply, _fault = Brain().answer(_request(_REVISION_ISR_FRAMING, text))
        assert role == "revision"
        assert reply.note["claims"] == claims_in(written)


class TestTheJudgeAndTheReport:
    def test_the_mediator_blocks_once_then_agrees(self) -> None:
        brain = Brain()
        request = _request(MEDIATOR_SYSTEM_HEAD, "--- STATIC ANALYST ---")
        first = brain.answer(request)[1].text
        second = brain.answer(request)[1].text
        assert "[blocking:" in first and first.rstrip().endswith("agreement_confidence: 0.6")
        assert "CONTRADICTIONS: NONE" in second

    def test_the_bundle_carries_the_assessment_and_leaves_the_last_technique_out(self) -> None:
        user = PACK + "Expert Reports:\nTECHNIQUE: T1055\nTECHNIQUE: T1071.001\n"
        reply = Brain().answer(_request(JUDGE_VERDICT_SYSTEM, user))[1]
        bundle = json.loads(reply.text)
        assert bundle["x_maljan_assessment"]["verdict"] == "Malware"
        carried = [
            o["external_references"][0]["external_id"]
            for o in bundle["objects"]
            if o["type"] == "attack-pattern"
        ]
        assert carried == ["T1055"]

    def test_a_prose_section_cites_the_claims_it_was_shown_by_their_labels(self) -> None:
        schema = composer.SECTION_SCHEMAS["prose"]
        contract = composer.section_contract("payloads", schema)
        evidence = (
            composer._bundle_text("payloads", {}, None).splitlines()[0]
            + "\n- [static claim 1] It talks HTTP. — [ev_0006] iocs\n"
        )
        reply = Brain().answer(_request(composer._SYSTEM, f"{contract}\n\n{evidence}"))[1]
        body = json.loads(reply.text)["body"]
        assert "static claim 1" in body and "[static claim 1]" not in body
        assert reply.note["section"] == "payloads" and reply.note["content"] is True

    def test_a_section_the_sample_cannot_fill_is_answered_empty_on_purpose(self) -> None:
        schema = composer.SECTION_SCHEMAS["cli_flags"]
        request = _section_request("cli_flags", composer.section_contract("cli_flags", schema))
        reply = Brain().answer(request)[1]
        assert json.loads(reply.text) == {"flags": []}
        assert reply.note == {"section": "cli_flags", "content": False, "deliberately_empty": True}

    @pytest.mark.parametrize(
        ("section", "key", "value"),
        [
            ("host_identifiers", "identifiers", "Global\\RehearsalMutex"),
            ("commands", "commands", "cmd.exe /c whoami"),
            ("cli_flags", "flags", "--install"),
        ],
    )
    def test_a_list_section_carries_the_sample_s_own_value(
        self, section: str, key: str, value: str
    ) -> None:
        schema = composer.SECTION_SCHEMAS[section]
        contract = composer.section_contract(section, schema)
        evidence = composer._bundle_text(section, {}, None).splitlines()[0]
        user = f"[ev_0005] strings: 11 of 11 runs recorded\n{contract}\n\n{evidence}"
        reply = Brain().answer(_request(composer._SYSTEM, user))[1]
        (row,) = json.loads(reply.text)[key]
        assert value in json.dumps(row).replace("\\\\", "\\")
        assert reply.note["content"] is True and reply.note["deliberately_empty"] is False

    def test_a_structured_request_is_answered_through_its_schema_tool(self) -> None:
        tool = {"name": "NarrativeOutput", "description": "", "schema": {"properties": {}}}
        reply = _as_schema_call(_request("x", "y", tools=[tool]), '{"executive_summary": "s"}')
        assert [(c.name, c.args) for c in reply.tool_calls] == [
            ("NarrativeOutput", {"executive_summary": "s"})
        ]
        assert _as_schema_call(_request("x", "y"), '{"a": 1}').text == '{"a": 1}'
