"""The mediator's agreement score must be read correctly or not at all.

``_extract_confidence_from_text`` is the *only* path that ever runs in
production: the capability check above it routes every provider to the text
fallback (``ChatOpenAI._llm_type`` is ``"openai-chat"``, which is absent from
``PROVIDER_CAPABILITIES``), and the ``cfg.llm.provider`` branch that would have
said "openai" is dead code because ``JudgeAgent`` is never given a config. So
whatever this function returns *is* the consensus decision.

Two defects, both measured on 2026-07-29 against the shipped implementation:

1. **The silent 0.5.** No line containing "confidence" with a parseable float
   meant ``return 0.5`` — indistinguishable from a mediator that genuinely
   scored 0.5, logged nowhere, and permanently below ``CONSENSUS_THRESHOLD``
   (0.85). The live run showed exactly ``confidence=0.50`` on both negotiation
   rounds, so every analysis burned all five revision rounds (~23 min each)
   toward a threshold it could not reach.

2. **The wrong number, clamped.** ``max(0.0, min(1.0, float(part)))`` accepted
   *any* token on the line. Scanning in reverse, ``"Confidence: 0.95 (based on
   3 agents)"`` hit ``3``, clamped it to **1.0**, and declared instant
   consensus off a hallucinated agreement. Clamping is what made the wrong
   token look legitimate, so the fix rejects out-of-range values instead.

The reasoning prompt asks the model for ``agreement_confidence``, so both that
key and the bare word must parse.
"""

from __future__ import annotations

import pytest

from maljan.agents.judge_agent import JudgeAgent

_extract = JudgeAgent._extract_confidence_from_text


class TestTheScoreIsReadWhenItIsThere:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Contradictions: none\nagreement_confidence: 0.95", 0.95),
            ("**agreement_confidence**: 0.95", 0.95),
            ("agreement_confidence = 0.95", 0.95),
            ('{"agreement_confidence": 0.95}', 0.95),
            ("Confidence: 0.8", 0.8),
            ("AGREEMENT_CONFIDENCE: 1.0", 1.0),
            ("agreement_confidence: 0", 0.0),
        ],
    )
    def test_supported_formats(self, text: str, expected: float) -> None:
        assert _extract(text) == pytest.approx(expected)

    def test_a_percentage_is_normalised(self) -> None:
        assert _extract("agreement_confidence: 95%") == pytest.approx(0.95)

    def test_the_last_score_wins_when_the_model_restates_it(self) -> None:
        """Later lines are the model's final answer, earlier ones are drafts."""
        text = "agreement_confidence: 0.40\n...on reflection...\nagreement_confidence: 0.90"
        assert _extract(text) == pytest.approx(0.90)


class TestAnUnrelatedNumberIsNeverMistakenForTheScore:
    """The defect that could end a negotiation on a hallucinated agreement."""

    def test_a_trailing_parenthetical_count_is_not_the_score(self) -> None:
        assert _extract("Confidence: 0.95 (based on 3 agents)") == pytest.approx(0.95)

    def test_a_bare_count_on_a_confidence_line_is_rejected(self) -> None:
        assert _extract("Confidence in this assessment: derived from 3 agents") is None

    def test_ordinary_phrasing_between_key_and_separator_still_parses(self) -> None:
        """Adjacency is about the *number*, not about forbidding words."""
        assert _extract("The confidence score is: 0.78") == pytest.approx(0.78)

    def test_an_out_of_range_number_is_rejected_not_clamped(self) -> None:
        """Clamping is what made the wrong token look legitimate."""
        assert _extract("agreement_confidence: 3") is None
        assert _extract("agreement_confidence: -2") is None


class TestFailureIsReportedNotInvented:
    @pytest.mark.parametrize(
        "text",
        [
            "The agreement_confidence is high.",
            "Contradictions: none. Agents aligned.",
            "",
            "   \n\n  ",
            "confidence",
        ],
    )
    def test_unparseable_text_returns_none(self, text: str) -> None:
        assert _extract(text) is None


class TestTheStructuredOutputDecisionIsDeliberate:
    """It was previously an accident of LangChain's ``_llm_type`` spelling.

    ``JudgeAgent`` read ``self._config`` but nothing ever assigned it, so the
    provider name came from ``ChatOpenAI._llm_type`` = ``"openai-chat"`` — a
    key absent from ``PROVIDER_CAPABILITIES``, so the unknown-provider default
    (unsupported) applied to every provider ever configured.
    """

    @staticmethod
    def _agent(config: object | None, llm_type: str = "openai-chat") -> JudgeAgent:
        from unittest.mock import MagicMock

        llm = MagicMock()
        llm._llm_type = llm_type
        return JudgeAgent(llm=llm, config=config)

    @staticmethod
    def _config(provider: str, base_url: str | None) -> object:
        from types import SimpleNamespace

        return SimpleNamespace(
            llm=SimpleNamespace(provider=provider, openai=SimpleNamespace(base_url=base_url))
        )

    def test_a_local_openai_compatible_server_is_not_the_vendor_api(self) -> None:
        """Measured 13+ min without completing on llama-server; text path ~3 min."""
        agent = self._agent(self._config("openai", "http://127.0.0.1:8080/v1"))
        assert agent._supports_structured_output() is False

    def test_real_openai_keeps_structured_output(self) -> None:
        agent = self._agent(self._config("openai", None))
        assert agent._supports_structured_output() is True

    def test_a_provider_the_table_rejects_stays_rejected(self) -> None:
        agent = self._agent(self._config("ollama", None))
        assert agent._supports_structured_output() is False

    def test_without_config_the_llm_type_suffix_does_not_misclassify(self) -> None:
        """The backstop for the exact bug: 'openai-chat' must resolve to 'openai'."""
        agent = self._agent(None, llm_type="openai-chat")
        assert agent._supports_structured_output() is True


class TestTheVerdictNeverSilentlyClaimsHalf:
    def test_an_unreadable_log_does_not_produce_a_consensus(self) -> None:
        """A mediator we could not read must not be able to end the loop."""
        from maljan.agents.judge_agent import CONSENSUS_THRESHOLD

        agent = JudgeAgent.__new__(JudgeAgent)
        agent.logger = JudgeAgent.__init__.__globals__["logger"].getChild("judge")
        verdict = agent._fallback_mediate("Agents aligned. No numbers here.")

        assert verdict.confidence < CONSENSUS_THRESHOLD

    def test_a_readable_log_is_passed_through(self) -> None:
        agent = JudgeAgent.__new__(JudgeAgent)
        agent.logger = JudgeAgent.__init__.__globals__["logger"].getChild("judge")
        verdict = agent._fallback_mediate("all aligned\nagreement_confidence: 0.97")

        assert verdict.confidence == pytest.approx(0.97)


# The shape of a mediation that drafted contradictions, argued some away, and
# ended on a final block with the two that still stand.
DRAFTED_THEN_FINAL = (
    "Comparing the reports.\n"
    "- static says the file writes a library beside itself; dynamic saw no such file.\n"
    "- network says the file contacts a host; entry ev_0012 shows no such flow.\n"
    "- reverser says a loop waits between attempts; static does not mention it.\n"
    "- triage names a packer; static names none.\n"
    "On reflection the third and fourth are compatible readings and are withdrawn.\n\n"
    "CONTRADICTIONS:\n"
    "- static: the file writes a library beside itself — dynamic: no such file was created\n"
    "- network: the file contacts a host — ev_0012 shows no such flow\n"
    "agreement_confidence: 1.0"
)


class TestOnlyTheFinalContradictionsBlockIsCounted:
    """The mediator's closing ``CONTRADICTIONS:`` block is its word; drafts are not."""

    def test_the_final_block_s_lines_are_the_contradictions(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        assert final_contradictions(DRAFTED_THEN_FINAL) == [
            "static: the file writes a library beside itself — dynamic: no such file was created",
            "network: the file contacts a host — ev_0012 shows no such flow",
        ]

    def test_none_is_an_empty_list(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        assert (
            final_contradictions("All aligned.\nCONTRADICTIONS: NONE\nagreement_confidence: 1.0")
            == []
        )

    def test_a_drafted_block_before_the_final_one_is_not_counted(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            "CONTRADICTIONS:\n- a: x — b: y\n- c: z — ev_0003\n"
            "Both resolve on a closer reading.\n"
            "CONTRADICTIONS: NONE\nagreement_confidence: 0.95"
        )
        assert final_contradictions(text) == []

    def test_markdown_emphasis_around_the_label_still_reads(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = "**CONTRADICTIONS:**\n1. a: x — b: y\nagreement_confidence: 0.4"
        assert final_contradictions(text) == ["a: x — b: y"]

    def test_no_block_is_none_rather_than_no_contradictions(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        assert final_contradictions("Contradictions: a says x.\nagreement_confidence: 1.0") is None
        assert final_contradictions("") is None

    def test_the_fallback_reads_the_block_and_keeps_the_number(self) -> None:
        agent = JudgeAgent.__new__(JudgeAgent)
        agent.logger = JudgeAgent.__init__.__globals__["logger"].getChild("judge")
        verdict = agent._fallback_mediate(DRAFTED_THEN_FINAL)

        assert len(verdict.contradictions) == 2
        assert verdict.confidence == pytest.approx(1.0)


class TestTheBlockIsReadForWhatItSays:
    """A "none" empties the block only as its whole content; every other line is a contradiction."""

    @pytest.mark.parametrize(
        "rest",
        [
            "NONE",
            "none",
            "None.",
            "(none)",
            "N/A",
            "n/a",
            "NONE still standing.",
            "None remain.",
            "No contradictions stand.",
            "no contradiction remains",
        ],
    )
    def test_a_none_on_the_label_line_is_empty(self, rest: str) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = f"reasoning\nCONTRADICTIONS: {rest}\nagreement_confidence: 1.0"
        assert final_contradictions(text) == []

    @pytest.mark.parametrize(
        "line", ["No contradictions stand.", "NONE", "(none)", "N/A", "none still standing"]
    )
    def test_a_none_under_the_label_is_empty(self, line: str) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = f"CONTRADICTIONS:\n{line}\nagreement_confidence: 0.9"
        assert final_contradictions(text) == []

    LEDGER = (
        "None of the analysts cites ev_0015, which records 0 dropped files, against "
        "the reverser's dropped DLL"
    )

    def test_a_bullet_that_opens_with_none_of_is_a_contradiction(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = f"CONTRADICTIONS:\n- {self.LEDGER}\nagreement_confidence: 1.0"
        assert final_contradictions(text) == [self.LEDGER]

    def test_it_is_kept_beside_another_item(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            f"CONTRADICTIONS:\n- {self.LEDGER}\n- static: x — dynamic: y\nagreement_confidence: 0.8"
        )
        assert final_contradictions(text) == [self.LEDGER, "static: x — dynamic: y"]

    def test_a_label_line_that_opens_with_none_of_is_a_contradiction(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = "CONTRADICTIONS: None of the analysts agree on the packer\nagreement_confidence: 1"
        assert final_contradictions(text) == ["None of the analysts agree on the packer"]

    def test_no_contradiction_on_one_thing_but_another_is_a_contradiction(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        line = "No contradiction on C2, but the reverser's DLL claim contradicts ev_0015"
        text = f"CONTRADICTIONS:\n- {line}\nagreement_confidence: 1.0"
        assert final_contradictions(text) == [line]

    def test_a_none_beside_items_is_ignored_and_the_block_said_to_be_mixed(self) -> None:
        from maljan.agents.judge_agent import final_contradictions, read_contradictions_block

        text = "CONTRADICTIONS:\n- static: x — dynamic: y\nNONE\nagreement_confidence: 0.7"
        assert final_contradictions(text) == ["static: x — dynamic: y"]
        reading = read_contradictions_block(text)
        assert reading.mixed is True
        assert read_contradictions_block("CONTRADICTIONS: NONE").mixed is False

    def test_plain_lines_one_per_contradiction_are_items(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            "CONTRADICTIONS:\n"
            "reverser: drops a library — ev_0015 records 0 dropped files\n"
            "static: x — dynamic: y\n"
            "agreement_confidence: 1.0"
        )
        assert final_contradictions(text) == [
            "reverser: drops a library — ev_0015 records 0 dropped files",
            "static: x — dynamic: y",
        ]

    def test_table_borders_and_headers_are_not_contradictions(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            "CONTRADICTIONS:\n"
            "| Analyst | Claim | Contradicted by |\n"
            "|---|---|---|\n"
            "- static: x — ev_0003 holds none\n"
            "agreement_confidence: 0.4"
        )
        assert final_contradictions(text) == ["static: x — ev_0003 holds none"]

    def test_a_block_that_is_only_a_table_is_unreadable_and_asked_for(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            "CONTRADICTIONS:\n"
            "| Analyst | Claim | Contradicted by |\n"
            "|---|---|---|\n"
            "| static | x | ev_0003 |\n"
            "agreement_confidence: 0.4"
        )
        assert final_contradictions(text) is None

    def test_a_trailing_summary_line_is_not_a_contradiction(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            "CONTRADICTIONS:\n"
            "- static: x — dynamic: y\n"
            "Summary: one contradiction stands.\n"
            "agreement_confidence: 0.6"
        )
        assert final_contradictions(text) == ["static: x — dynamic: y"]

    def test_a_wrapped_line_continues_its_item(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = (
            "CONTRADICTIONS:\n"
            "1. static: x — dynamic: y\n"
            "   which dynamic did not observe\n"
            "2) network: z — ev_0012\n"
            "* triage: w — static: v\n"
            "agreement_confidence: 0.3"
        )
        assert final_contradictions(text) == [
            "static: x — dynamic: y which dynamic did not observe",
            "network: z — ev_0012",
            "triage: w — static: v",
        ]

    def test_the_block_ends_at_a_blank_line_followed_by_prose(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        text = "CONTRADICTIONS:\n- static: x — dynamic: y\n\nThen prose.\n- not in the block"
        assert final_contradictions(text) == ["static: x — dynamic: y"]

    def test_an_empty_block_is_empty(self) -> None:
        from maljan.agents.judge_agent import final_contradictions

        assert final_contradictions("CONTRADICTIONS:\nagreement_confidence: 1.0") == []


R5_SHAPES = [
    "CONTRADICTIONS: NONE\nAll analysts agree on the core behaviours.\nagreement_confidence: 1.0",
    "CONTRADICTIONS: NONE\nThe remaining differences are granularity, not contradictions.\n"
    "agreement_confidence: 1.0",
    "CONTRADICTIONS:\n- NONE\nAll core behaviours agree.\nagreement_confidence: 1.0",
]


class TestANoneBesidePlainLinesIsAskedAbout:
    """A NONE followed by the mediator's own closing sentence is not a contradiction list."""

    @pytest.mark.parametrize("text", R5_SHAPES)
    def test_the_block_is_ambiguous(self, text: str) -> None:
        from maljan.agents.judge_agent import read_contradictions_block

        assert read_contradictions_block(text).ambiguous == "none_beside_plain_lines"

    def test_a_none_beside_bulleted_items_is_mixed_not_ambiguous(self) -> None:
        from maljan.agents.judge_agent import read_contradictions_block

        reading = read_contradictions_block(
            "CONTRADICTIONS: NONE\n- static: x — dynamic: y\nagreement_confidence: 0.7"
        )
        assert reading.items == ["static: x — dynamic: y"]
        assert reading.mixed is True
        assert reading.ambiguous == ""

    def test_a_label_line_intro_ending_in_a_colon_is_not_an_item(self) -> None:
        from maljan.agents.judge_agent import read_contradictions_block

        reading = read_contradictions_block(
            "CONTRADICTIONS: the following still stand:\n- static: x — dynamic: y\n"
            "agreement_confidence: 0.5"
        )
        assert reading.items == ["static: x — dynamic: y"]
        assert reading.ambiguous == ""

    def test_a_lone_none_phrase_outside_the_wording_is_asked_about(self) -> None:
        from maljan.agents.judge_agent import read_contradictions_block

        reading = read_contradictions_block(
            "CONTRADICTIONS: none that survive scrutiny\nagreement_confidence: 1.0"
        )
        assert reading.ambiguous == "none_phrase"
        # Beside a real item it is not the block's whole content: the item stands.
        reading = read_contradictions_block(
            "CONTRADICTIONS: none that survive scrutiny\n- static: x — ev_0003\n"
            "agreement_confidence: 1.0"
        )
        assert reading.ambiguous == ""
        assert "static: x — ev_0003" in (reading.items or [])
