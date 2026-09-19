"""A grounding check asks what the run saw, not what the ledger kept.

``schemas.evidence.apply_budget`` blanks an entry's ``output`` and
``structured`` once an agent's answers pass ``reporting.evidence_budget_bytes``
— **after** the model has read them. The judge's corpus was built from the
stored entries, so a C2 a tool really returned, and the judge really read, was
absent from it: the judge was told the value *"appears nowhere in the evidence
this run collected"*, spent its one retry, and the indicator was dropped from
the exported bundle. A deterministic statement the platform makes is right or
absent, and that one was wrong.

Two rules are pinned here. The corpus is what the run saw — kept in memory by
the recorder, before the budget trims what is stored. And the platform never
asserts an absence over evidence it knows is partial: when the corpus could not
hold everything, or there is no corpus and a stored entry it fell back on was
blanked, the finding is advisory — said once, in a sentence that names what was
not searched, and nothing is dropped for it.
"""

from __future__ import annotations

from typing import Any

import pytest

from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.run_evidence_corpus import NO_CORPUS, CorpusState, RunEvidenceCorpus
from maljan.pipeline.nodes import _what_the_run_saw
from maljan.pipeline.validation import (
    Violation,
    drop_ungrounded_indicators,
    partial_evidence_note,
    validate_verdict_bundle,
)
from maljan.schemas.evidence import apply_budget
from maljan.schemas.stix_models import Bundle, Indicator

# A name no reserved TLD rule refuses and no denylist carries, so what decides
# the row is the evidence question and nothing else.
C2 = "gate9.example.org"
PATTERN = f"[domain-name:value = '{C2}']"


def _recorded(corpus: RunEvidenceCorpus | None, answers: list[tuple[str, str]]) -> list[Any]:
    """Drive the real recorder, so what is kept is what the model was handed."""
    recorder = EvidenceRecorder("network", corpus=corpus)
    for tool, output in answers:
        recorder.record(tool=tool, args={}, server="analysis", output=output)
    return list(recorder.entries)


class TestTheBudgetBlanksWhatTheModelRead:
    """The defect, reproduced before anything is asked of the fix."""

    def test_the_stored_entry_loses_the_answer_the_model_read(self) -> None:
        entries = _recorded(
            None, [("strings", "a" * 900), ("get_dns", f"resolved {C2} " + "b" * 500)]
        )

        trimmed, _spent = apply_budget(entries, 1000)

        assert trimmed == 1
        # The first answer fitted; the one carrying the C2 did not, and it is
        # blanked after the model has already read it.
        assert entries[0].output
        assert entries[1].output == ""
        assert entries[1].structured is None
        assert entries[1].truncated is True

    def test_the_corpus_still_holds_it(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        entries = _recorded(
            corpus, [("strings", "a" * 900), ("get_dns", f"resolved {C2} " + "b" * 500)]
        )

        apply_budget(entries, 1000)

        assert C2 in corpus.haystack()
        assert corpus.state() == CorpusState(complete=True)


class TestTheJudgeIsGroundedAgainstWhatTheRunSaw:
    class _Container:
        def __init__(self, corpus: RunEvidenceCorpus | None) -> None:
            self._corpus = corpus

        def get_evidence_corpus(self) -> RunEvidenceCorpus | None:
            return self._corpus

    @staticmethod
    def _violations(seen: list[str], state: CorpusState) -> list[Violation]:
        from maljan.agents.judge_postprocess import build_evidence_corpus

        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        return validate_verdict_bundle(
            bundle,
            build_evidence_corpus(extra=seen),
            corpus_state=state,
        )

    def test_a_value_the_budget_blanked_is_grounded_through_the_corpus(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        entries = _recorded(
            corpus, [("strings", "a" * 900), ("get_dns", f"resolved {C2} " + "b" * 500)]
        )
        apply_budget(entries, 1000)

        seen, state = _what_the_run_saw(self._Container(corpus), entries)

        assert state.complete
        assert self._violations(seen, state) == []

    def test_without_the_corpus_the_same_run_calls_the_c2_invented(self) -> None:
        """The defect, through the same call path, so the fix is what differs."""
        entries = _recorded(
            None, [("strings", "a" * 900), ("get_dns", f"resolved {C2} " + "b" * 500)]
        )
        apply_budget(entries, 1000)

        seen, state = _what_the_run_saw(self._Container(None), entries)
        violations = self._violations(seen, state)

        assert [v.code for v in violations] == ["stix.ungrounded_indicator"]
        # …and because the fallback knows an entry was blanked, it is a note.
        assert violations[0].advisory is True
        assert state.partial
        assert state.missing_tools == ("get_dns",)


class TestAnAbsenceOverPartialEvidenceDropsNothing:
    @staticmethod
    def _advisory_row() -> Violation:
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        found = validate_verdict_bundle(
            bundle,
            {"unrelated"},
            corpus_state=CorpusState(
                complete=False, missing_answers=2, missing_tools=("get_dns", "strings")
            ),
        )
        return found[0]

    def test_the_row_is_written_and_says_what_was_not_searched(self) -> None:
        row = self._advisory_row()

        assert row.code == "stix.ungrounded_indicator"
        assert row.advisory is True
        assert "not this run's whole record" in row.message
        assert "2 answers from get_dns, strings were not kept" in row.message
        assert "nothing is dropped for it" in row.message

    def test_the_judge_keeps_its_object(self) -> None:
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]

        dropped = drop_ungrounded_indicators(bundle, [self._advisory_row()])

        assert dropped == 0
        assert len(bundle.objects) == 1

    def test_a_whole_corpus_still_drops_an_invented_value(self) -> None:
        """The rule is unchanged where the platform may state it."""
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        found = validate_verdict_bundle(bundle, {"unrelated"}, corpus_state=CorpusState())

        assert found[0].advisory is False
        assert drop_ungrounded_indicators(bundle, found) == 1

    def test_no_corpus_at_all_is_partial(self) -> None:
        """A report rebuilt later, a run resumed in another process."""
        assert NO_CORPUS.partial
        assert partial_evidence_note(NO_CORPUS)

    def test_a_refusal_no_evidence_could_answer_is_never_advisory(self) -> None:
        bundle = Bundle(  # type: ignore[list-item]
            objects=[Indicator(pattern="[directory:path = 'application/json']")]
        )
        found = validate_verdict_bundle(bundle, {"unrelated"}, corpus_state=NO_CORPUS)

        assert "is not written as a directory" in found[0].message
        assert found[0].advisory is False
        assert "whole record" not in found[0].message

    def test_the_flag_survives_the_state_channel(self) -> None:
        from maljan.pipeline.nodes import _violations_from_rows

        (rebuilt,) = _violations_from_rows([self._advisory_row().to_dict()])

        assert rebuilt.advisory is True


class TestTheCeilingIsHonest:
    def test_an_answer_that_does_not_fit_is_counted_rather_than_kept(self) -> None:
        corpus = RunEvidenceCorpus(100)

        corpus.remember("ev_0001", "strings", "a" * 50)
        corpus.remember("ev_0002", "get_dns", "b" * 500)

        assert corpus.text_for("ev_0001") == "a" * 50
        assert corpus.text_for("ev_0002") == ""
        assert corpus.state() == CorpusState(
            complete=False, missing_answers=1, missing_tools=("get_dns",)
        )

    def test_a_zero_ceiling_keeps_nothing_and_says_so(self) -> None:
        corpus = RunEvidenceCorpus(0)

        corpus.remember("ev_0001", "strings", "anything")

        assert len(corpus) == 0
        assert corpus.state().partial

    def test_the_haystack_follows_what_was_kept(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0001", "get_dns", f"resolved {C2}")

        assert C2 in corpus.haystack()
        corpus.remember("ev_0002", "strings", "MiXeD Case Value")
        assert "mixed case value" in corpus.haystack()

    def test_one_entry_is_remembered_once(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0001", "get_dns", "first")
        corpus.remember("ev_0001", "get_dns", "second")

        assert corpus.text_for("ev_0001") == "first"


class TestNothingDropsAnObjectOverPartialEvidence:
    """The guard the ruling asks for, over the source rather than one path."""

    def test_no_consumer_removes_an_object_on_an_absence_it_cannot_assert(self) -> None:
        import ast
        import pathlib

        src = pathlib.Path(__file__).resolve().parents[3] / "src" / "maljan"
        # Every function that reads a violation's code to decide what to remove
        # must also read ``advisory``. The scan is over the whole tree so a
        # second consumer written later is caught rather than assumed absent.
        offenders: list[str] = []
        for path in src.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue
                # The docstring is prose: ``_judge_indicator_problem`` names
                # the code to say whose question it is *not*, and naming a
                # thing is not acting on it.
                statements = list(node.body)
                if ast.get_docstring(node) is not None:
                    statements = statements[1:]
                body = "\n".join(ast.unparse(statement) for statement in statements)
                if "stix.ungrounded_indicator" not in body:
                    continue
                if "advisory" in body:
                    continue
                offenders.append(f"{path.relative_to(src)}: {node.name}")

        assert not offenders, (
            "These decide something from an ungrounded-indicator row without asking "
            "whether the row is advisory. An advisory absence was measured against "
            "evidence the run knows is partial and is not a reason to remove "
            "anything:\n  " + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize("advisory", [True, False])
    def test_the_drop_is_decided_by_the_flag_and_nothing_else(self, advisory: bool) -> None:
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        row = Violation(
            code="stix.ungrounded_indicator",
            message="whatever it says",
            path="objects[0]",
            advisory=advisory,
        )

        assert drop_ungrounded_indicators(bundle, [row]) == (0 if advisory else 1)
