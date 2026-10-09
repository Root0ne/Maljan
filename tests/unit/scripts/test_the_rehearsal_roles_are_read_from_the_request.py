"""The stub's scripted answers: each role read from the request, each answer in its role's form.

A role is read from the request's own words and tools, never from an agent's
configured name; each scenario faults a role's first call only; an analyst
calls the tools it was given against the run's sample before it answers with
claims citing ids the request carries.
"""

from __future__ import annotations

import json

import pytest
from scripts.rehearsal import wire
from scripts.rehearsal.roles import (
    SCENARIOS,
    Brain,
    _as_schema_call,
    _corrected,
    _keep_every_item,
    _original_claims,
    composer_section,
    role_of,
)

PACK = (
    "Facts established before analysis (ledger ids in brackets; cite them)\n"
    "[ev_0001] identity: pe windows, 3,584 bytes\n"
    "[ev_0006] iocs: 1 domain, 1 url (http://rehearsal.example.net/beacon, rehearsal.example.net)\n"
    "Sample path (use exactly this string wherever a tool asks for a file): /w/sample_1.exe\n"
    "Format each finding as:\nCLAIM: <claim text>\n"
)
PE_INFO = {
    "name": "pe_info",
    "description": "",
    "schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
}


def _request(system: str, user: str, tools: list | None = None, turns: list | None = None):
    return wire.Request(
        api="openai",
        model="m",
        system=system,
        turns=turns or [wire.Turn(role="user", text=user)],
        tools=tools or [],
        max_tokens=None,
        stream=False,
        raw={},
    )


class TestTheRole:
    @pytest.mark.parametrize(
        ("system", "role"),
        [
            (
                "You are the Chief Malware Judge. Your verdict is given. The analysts",
                "technique_question",
            ),
            ("You are the Lead Cyber Security Mediator. Your ONLY task", "mediator"),
            (
                "Extract the final structured verdict from the mediator's reasoning log.",
                "mediator_extract",
            ),
            ("You are the Chief Malware Judge. Based on the expert reports", "judge"),
            (
                "You are a senior malware reverse engineer producing a CTI analyst report.",
                "narrative",
            ),
            (
                "You are writing ONE section of a technical analysis report.",
                "composer",
            ),
            ("You are an expert analyst.\n\nYou are in a negotiation round. You MUST:", "revision"),
        ],
    )
    def test_is_read_from_the_system_prompt(self, system: str, role: str) -> None:
        assert role_of(_request(system, "x")) == role

    def test_an_agent_with_tools_is_an_analyst_whatever_it_is_called(self) -> None:
        assert role_of(_request("You are Someone New.", "x", tools=[PE_INFO])) == "analyst"

    def test_a_composer_section_is_named_by_its_evidence_line(self) -> None:
        request = _request("x", "The evidence for the execution_flow section follows.\n...")
        assert composer_section(request) == "execution_flow"


class TestTheScenarios:
    def test_an_unknown_scenario_is_refused(self) -> None:
        with pytest.raises(ValueError, match="unknown scenario"):
            Brain(scenario="no-such")

    @pytest.mark.parametrize(
        ("scenario", "check"),
        [
            ("cut_at_cap", lambda r: r.stop == "max_tokens" and r.thinking and not r.text),
            ("empty_answer", lambda r: r.text == "" and not r.tool_calls),
            ("server_error_once", lambda r: r.status == 500),
            ("schema_break", lambda r: "CLAIM" not in r.text),
        ],
    )
    def test_faults_a_role_s_first_call_only(self, scenario: str, check) -> None:
        brain = Brain(scenario=scenario)
        request = _request("You are the Lead Cyber Security Mediator.", "--- STATIC ---")
        role, first, fault = brain.answer(request)
        assert (role, fault) == ("mediator", scenario)
        assert check(first)
        _role, second, fault = brain.answer(request)
        assert fault == "" and second.status == 200 and "agreement_confidence" in second.text

    def test_a_slow_model_delays_every_reply(self) -> None:
        _role, reply, _fault = Brain(scenario="slow_model", slow_seconds=0.5).answer(
            _request("You are the Lead Cyber Security Mediator.", "x")
        )
        assert reply.delay == 0.5

    def test_every_scenario_has_a_sentence(self) -> None:
        assert all(SCENARIOS.values())


class TestTheAnalyst:
    def test_calls_a_tool_on_the_run_s_sample_first(self) -> None:
        _role, reply, _ = Brain().answer(_request("An analyst.", PACK, tools=[PE_INFO]))
        assert [(c.name, c.args) for c in reply.tool_calls] == [
            ("pe_info", {"path": "/w/sample_1.exe"})
        ]

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
        assert "CLAIM:" in reply.text
        cited = set(__import__("re").findall(r"ev_\d{4}", reply.text))
        assert cited <= {"ev_0001", "ev_0006", "ev_0030", "ev_0031"}
        assert "TECHNIQUE: T1071.001" in reply.text

    def test_a_drops_question_keeps_every_item(self) -> None:
        question = "C1. CLAIM: one\nF2. FINDING: two\nwrite one line: KEEP <label>: <reason>"
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


class TestTheJudgeAndTheReport:
    def test_the_mediator_blocks_once_then_agrees(self) -> None:
        brain = Brain()
        request = _request("You are the Lead Cyber Security Mediator.", "--- STATIC ANALYST ---")
        first = brain.answer(request)[1].text
        second = brain.answer(request)[1].text
        assert "[blocking:" in first and first.rstrip().endswith("agreement_confidence: 0.6")
        assert "CONTRADICTIONS: NONE" in second

    def test_the_bundle_carries_the_assessment_and_leaves_the_last_technique_out(self) -> None:
        user = PACK + "Expert Reports:\nTECHNIQUE: T1055\nTECHNIQUE: T1071.001\n"
        reply = Brain().answer(_request("You are the Chief Malware Judge. Based on", user))[1]
        bundle = json.loads(reply.text)
        assert bundle["x_maljan_assessment"]["verdict"] == "Malware"
        carried = [
            o["external_references"][0]["external_id"]
            for o in bundle["objects"]
            if o["type"] == "attack-pattern"
        ]
        assert carried == ["T1055"]

    def test_a_configuration_row_holds_a_value_its_cited_entry_holds(self) -> None:
        user = (
            "Answer with exactly this JSON object, these keys and no others:\n"
            '{"items": [{"key": "...", "value": "...", "how_obtained": "decrypted or observed '
            'or static-string or inferred", "evidence_refs": ["..."]}]}\n'
            "The evidence for the configuration section follows.\n"
            "- [static claim 1] It talks HTTP. — [ev_0006] iocs: 1 url "
            "(http://rehearsal.example.net/beacon)\n"
        )
        reply = Brain().answer(
            _request("writing ONE section of a technical analysis report", user)
        )[1]
        (row,) = json.loads(reply.text)["items"]
        assert row["value"] == "http://rehearsal.example.net/beacon"
        assert row["evidence_refs"] == ["ev_0006"]
        assert reply.note == {"section": "configuration", "content": True}

    def test_a_section_nothing_supports_is_answered_empty(self) -> None:
        user = (
            "Answer with exactly this JSON object, these keys and no others:\n"
            '{"flags": [{"flag": "...", "description": "...", "evidence_ref": "..."}]}\n'
            "The evidence for the cli_flags section follows.\n"
        )
        reply = Brain().answer(
            _request("writing ONE section of a technical analysis report", user)
        )[1]
        assert json.loads(reply.text) == {"flags": []}
        assert reply.note["content"] is False

    def test_a_structured_request_is_answered_through_its_schema_tool(self) -> None:
        tool = {"name": "NarrativeOutput", "description": "", "schema": {"properties": {}}}
        reply = _as_schema_call(_request("x", "y", tools=[tool]), '{"executive_summary": "s"}')
        assert [(c.name, c.args) for c in reply.tool_calls] == [
            ("NarrativeOutput", {"executive_summary": "s"})
        ]
        assert _as_schema_call(_request("x", "y"), '{"a": 1}').text == '{"a": 1}'
