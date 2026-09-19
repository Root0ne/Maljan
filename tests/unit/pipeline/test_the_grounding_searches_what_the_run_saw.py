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

import ast
import pathlib
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
from tests.unit.pipeline._source_names import names_bound_to, names_imported_from

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

        assert any(C2 in part for part in corpus.parts())
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
            complete=False,
            missing_answers=1,
            missing_tools=("get_dns",),
            why="ceiling reached",
        )

    def test_a_zero_ceiling_keeps_nothing_and_says_so(self) -> None:
        corpus = RunEvidenceCorpus(0)

        corpus.remember("ev_0001", "strings", "anything")

        assert len(corpus) == 0
        assert corpus.state().partial

    def test_what_is_kept_is_kept_lower_cased_once(self) -> None:
        """Every reader compares lower-cased, so the fold happens here.

        Folding it at each read copied the whole record per check, which is the
        cost this shape exists to remove.
        """
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0001", "get_dns", f"resolved {C2}")
        corpus.remember("ev_0002", "strings", "MiXeD Case Value")

        assert corpus.text_for("ev_0002") == "mixed case value"
        assert any(C2 in part for part in corpus.parts())
        assert any("mixed case value" in part for part in corpus.parts())

    def test_the_parts_are_the_answers_and_not_one_string(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0001", "get_dns", "first answer")
        corpus.remember("ev_0002", "strings", "second answer")

        assert corpus.parts() == ("first answer", "second answer")

    def test_one_entry_is_remembered_once(self) -> None:
        corpus = RunEvidenceCorpus(1 << 20)
        corpus.remember("ev_0001", "get_dns", "first")
        corpus.remember("ev_0001", "get_dns", "second")

        assert corpus.text_for("ev_0001") == "first"


# The code an advisory row carries, and the shortest prefix a ``startswith``
# test can single it out by. A guard that looked for the bare literal alone was
# blind to a module-level constant, which is how every other code in this
# repository is written.
UNGROUNDED_CODE = "stix.ungrounded_indicator"
_CODE_PREFIX = "stix.ungrounded"
_SRC = pathlib.Path(__file__).resolve().parents[3] / "src" / "maljan"


def _needles(tree: ast.AST, defined_elsewhere: set[str]) -> set[str]:
    """Every way this module can write the ungrounded code."""
    bound = names_bound_to(tree, UNGROUNDED_CODE)
    return {UNGROUNDED_CODE} | bound | names_imported_from(tree, defined_elsewhere | bound)


def _names_the_code(statements: list[ast.stmt], needles: set[str]) -> bool:
    """Whether this run of code singles the ungrounded row out, however written.

    The literal, a name bound to it here or imported from wherever it is
    defined, or a prefix of it in a ``startswith`` — which is the same decision
    written as a test rather than as an equality.
    """
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, ast.Name) and node.id in needles:
                return True
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in needles or (
                    node.value.startswith(_CODE_PREFIX) and UNGROUNDED_CODE.startswith(node.value)
                ):
                    return True
    return False


def _asks(statements: list[ast.stmt]) -> bool:
    """Whether this run of code reads ``advisory`` at all."""
    return any(
        (isinstance(node, ast.Attribute) and node.attr == "advisory")
        or (isinstance(node, ast.Name) and node.id == "advisory")
        or (isinstance(node, ast.Constant) and node.value == "advisory")
        # The writer's side of the same word: ``Violation(advisory=…)`` reads
        # what an absence may claim just as a consumer's ``row.advisory`` does.
        or (isinstance(node, ast.keyword) and node.arg == "advisory")
        for statement in statements
        for node in ast.walk(statement)
    )


def _decides_without_asking_in(sources: dict[str, str]) -> list[str]:
    """The scan, over sources given by name, so a probe drives the real rule."""
    trees = {name: ast.parse(text, filename=name) for name, text in sources.items()}
    # Wherever the code is defined, under whatever name, so an importer of it
    # is resolved rather than missed.
    defined: set[str] = set()
    for tree in trees.values():
        defined |= names_bound_to(tree, UNGROUNDED_CODE)

    offenders: list[str] = []
    for name, tree in sorted(trees.items()):
        needles = _needles(tree, defined)
        for where, statements in _runs_of_code(tree):
            if not _names_the_code(statements, needles):
                continue
            if _asks(statements):
                continue
            offenders.append(f"{name}: {where}")
    return offenders


def _is_a_definition(statement: ast.stmt) -> bool:
    """Whether this statement binds a name rather than acting on a row."""
    if isinstance(statement, ast.Import | ast.ImportFrom):
        return True
    if isinstance(statement, ast.Assign) and isinstance(statement.value, ast.Constant):
        return all(isinstance(target, ast.Name) for target in statement.targets)
    if isinstance(statement, ast.AnnAssign) and isinstance(statement.value, ast.Constant):
        return isinstance(statement.target, ast.Name)
    return False


def _runs_of_code(tree: ast.AST) -> list[tuple[str, list[ast.stmt]]]:
    """Every function body, and the module's own top level beside them.

    A decision taken at module level is a decision, and a scan that read only
    functions never saw one. A function's docstring is left out: naming a code
    in prose is not acting on it.
    """
    found: list[tuple[str, list[ast.stmt]]] = []
    inside: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        statements = list(node.body)
        if ast.get_docstring(node) is not None:
            statements = statements[1:]
        found.append((node.name, statements))
        inside.update(id(child) for statement in statements for child in ast.walk(statement))
    top = [
        statement
        for statement in getattr(tree, "body", [])
        if not isinstance(statement, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        and id(statement) not in inside
        # Defining the code, and importing it, are not deciding anything with
        # it — they are what the resolution above reads.
        and not _is_a_definition(statement)
    ]
    if top:
        found.append(("module-level code with no function at all", top))
    return found


def _decides_without_asking(root: pathlib.Path) -> list[str]:
    """The scan over the tree, with the code resolved through every module."""
    sources = {
        str(path.relative_to(root)): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.py"))
    }
    return _decides_without_asking_in(sources)


class TestNothingDropsAnObjectOverPartialEvidence:
    """The guard the ruling asks for, over the source rather than one path."""

    def test_no_consumer_removes_an_object_on_an_absence_it_cannot_assert(self) -> None:
        offenders = _decides_without_asking(_SRC)

        assert not offenders, (
            "These decide something from an ungrounded-indicator row without asking "
            "whether the row is advisory. An advisory absence was measured against "
            "evidence the run knows is partial and is not a reason to remove "
            "anything:\n  " + "\n  ".join(offenders)
        )

    @pytest.mark.parametrize(
        ("where", "source"),
        [
            (
                "act",
                "def act(rows):\n"
                "    return [r for r in rows if r.code != 'stix.ungrounded_indicator']\n",
            ),
            (
                "act",
                "UNGROUNDED = 'stix.ungrounded_indicator'\n"
                "def act(rows):\n"
                "    return [r for r in rows if r.code != UNGROUNDED]\n",
            ),
            (
                "act",
                "UNGROUNDED_INDICATOR_CODE = 'stix.ungrounded_indicator'\n"
                "def act(rows):\n"
                "    return [r for r in rows if r.code != UNGROUNDED_INDICATOR_CODE]\n",
            ),
            (
                "act",
                "def act(rows):\n"
                "    return [r for r in rows if not r.code.startswith('stix.ungrounded')]\n",
            ),
            (
                "act",
                "def act(rows):\n"
                "    return list(filter(lambda r: r.code != 'stix.ungrounded_indicator', rows))\n",
            ),
            (
                "module-level code with no function at all",
                "KEPT = [r for r in ROWS if r.code != 'stix.ungrounded_indicator']\n",
            ),
        ],
    )
    def test_the_guard_catches_each_way_the_code_can_be_named(
        self, where: str, source: str
    ) -> None:
        """The scan passes trivially if it is broken, so prove it is not.

        Every shape the review measured as missed: a module-level constant, one
        in this repository's own ``*_CODE`` idiom, a ``startswith`` test, and a
        decision taken at module level with no function to find it in.
        """
        assert _decides_without_asking_in({"probe.py": source}) == [f"probe.py: {where}"]

    def test_an_imported_constant_is_resolved_across_modules(self) -> None:
        sources = {
            "codes.py": "UNGROUNDED_INDICATOR_CODE = 'stix.ungrounded_indicator'\n",
            "consumer.py": (
                "from maljan.codes import UNGROUNDED_INDICATOR_CODE as GONE\n"
                "def act(rows):\n"
                "    return [r for r in rows if r.code != GONE]\n"
            ),
        }

        assert _decides_without_asking_in(sources) == ["consumer.py: act"]

    def test_a_consumer_that_asks_is_left_alone(self) -> None:
        sources = {
            "consumer.py": (
                "UNGROUNDED_INDICATOR_CODE = 'stix.ungrounded_indicator'\n"
                "def act(rows):\n"
                "    return [\n"
                "        r for r in rows\n"
                "        if r.code != UNGROUNDED_INDICATOR_CODE or r.advisory\n"
                "    ]\n"
            ),
        }

        assert _decides_without_asking_in(sources) == []

    def test_naming_the_code_in_prose_is_not_acting_on_it(self) -> None:
        """``_judge_indicator_problem`` says whose question it is *not*."""
        sources = {
            "renderer.py": (
                "def problem(indicator):\n"
                '    """Whether any evidence holds this up is '
                'stix.ungrounded_indicator\'s question."""\n'
                "    return None\n"
            ),
        }

        assert _decides_without_asking_in(sources) == []

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


class TestACorpusThatKeptNothingIsStillTheCorpus:
    """The ceiling is an operator's control and it said the opposite of the truth.

    Asking the corpus only when it *held* something threw away the verdict of
    one that kept nothing — which is exactly what ``evidence_corpus_bytes = 0``
    produces — and the check fell back to the stored ledger, was told the
    evidence was whole, and dropped the judge's object. Four surfaces said a
    zero ceiling makes every absence a note.

    Driven end to end here rather than against the corpus object's own verdict,
    which is what the first round's test asserted and why it passed.
    """

    class _Container:
        def __init__(self, corpus: RunEvidenceCorpus | None) -> None:
            self._corpus = corpus

        def get_evidence_corpus(self) -> RunEvidenceCorpus | None:
            return self._corpus

    @staticmethod
    def _answers() -> list[tuple[str, str]]:
        """Three answers, one of them carrying the C2 the judge will cite."""
        return [
            ("get_strings", "a" * 300),
            ("get_dns", f"resolved {C2}"),
            ("pe_info", "b" * 300),
        ]

    def _run(self, corpus: RunEvidenceCorpus | None) -> tuple[list[Violation], int, CorpusState]:
        from maljan.agents.judge_postprocess import build_evidence_corpus

        entries = _recorded(corpus, self._answers())
        # Nothing here overruns the byte budget, so the stored ledger looks
        # whole — which is what let the fallback claim completeness.
        seen, state = _what_the_run_saw(self._Container(corpus), entries)
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        violations = validate_verdict_bundle(
            bundle, build_evidence_corpus(extra=seen), corpus_state=state
        )
        return violations, drop_ungrounded_indicators(bundle, violations), state

    def test_a_zero_ceiling_makes_the_absence_a_note_and_keeps_the_object(self) -> None:
        violations, dropped, state = self._run(RunEvidenceCorpus(0))

        assert state.partial
        assert state.missing_answers == 3
        assert [v.advisory for v in violations] == [True]
        assert dropped == 0
        assert "3 answers from" in violations[0].message
        assert "nothing is dropped for it" in violations[0].message

    def test_a_ceiling_too_small_for_any_answer_does_the_same(self) -> None:
        # Ten bytes: shorter than the shortest of the three answers.
        violations, dropped, state = self._run(RunEvidenceCorpus(10))

        assert state.partial
        assert state.missing_answers == 3
        assert [v.advisory for v in violations] == [True]
        assert dropped == 0

    def test_a_ceiling_that_fits_one_answer_is_partial_too(self) -> None:
        """The first answer fits and the one carrying the C2 does not."""
        violations, dropped, state = self._run(RunEvidenceCorpus(300))

        assert state.partial
        assert state.missing_answers == 2
        assert state.missing_tools == ("get_dns", "pe_info")
        assert [v.advisory for v in violations] == [True]
        assert dropped == 0

    def test_a_whole_corpus_still_drops_the_invented_value(self) -> None:
        """The rule is unchanged where the platform may state it."""
        violations, dropped, state = self._run(RunEvidenceCorpus(1 << 20))

        assert state.complete
        # The C2 really was answered, so nothing is wrong with the indicator.
        assert violations == []
        assert dropped == 0

    def test_a_resumed_run_with_no_corpus_never_asserts_an_absence(self) -> None:
        """No corpus and stored entries that all survived the byte budget.

        The fallback reported itself whole and laundered the missing corpus
        into a statement nobody could make. Completeness is the conjunction of
        what was searched, and a corpus that is gone is partial by
        construction.
        """
        entries = _recorded(None, [("get_strings", "a" * 300)])
        assert all(not e.truncated for e in entries)

        seen, state = _what_the_run_saw(self._Container(None), entries)
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        violations = validate_verdict_bundle(bundle, set(seen), corpus_state=state)

        assert state.partial
        assert [v.advisory for v in violations] == [True]
        assert drop_ungrounded_indicators(bundle, violations) == 0

    def test_a_resumed_run_counts_the_entries_the_budget_blanked_too(self) -> None:
        entries = _recorded(None, [("get_strings", "a" * 900), ("get_dns", "b" * 500)])
        apply_budget(entries, 1000)

        _seen, state = _what_the_run_saw(self._Container(None), entries)

        assert state.partial
        assert state.missing_answers == 1
        assert state.missing_tools == ("get_dns",)

    def test_the_conjunction_never_launders_a_partial_source(self) -> None:
        from maljan.agents.run_evidence_corpus import both_searched

        whole = CorpusState()
        partial = CorpusState(complete=False, missing_answers=2, missing_tools=("get_dns",))

        assert both_searched(whole, whole).complete
        assert not both_searched(whole, partial).complete
        assert not both_searched(partial, whole).complete
        assert both_searched(partial, partial) == CorpusState(
            complete=False, missing_answers=4, missing_tools=("get_dns",)
        )


class TestTheCeilingBoundsWhatTheProcessSpends:
    """A ceiling only bounds what it says if the text is not copied.

    The run's record used to be copied three more times on the way to a check:
    into the corpus's joined cache, into the token set as one element, and into
    the string the check finally searched. One check over 400 answers of 6 000
    characters allocated 6 MB on top of a 2.4 MB corpus, so the setting's
    number was a quarter of what the process spent.
    """

    ANSWERS = 120
    SIZE = 6_000

    def _corpus(self) -> RunEvidenceCorpus:
        corpus = RunEvidenceCorpus(1 << 30)
        for index in range(self.ANSWERS):
            corpus.remember(
                f"ev_{index:04d}", "get_strings", (f"answer {index} " + "Xy7Z " * 2000)[: self.SIZE]
            )
        return corpus

    def test_a_check_copies_nothing_of_the_record_it_searches(self) -> None:
        import tracemalloc

        from maljan.agents.judge_postprocess import build_evidence_corpus

        corpus = self._corpus()
        parts = list(corpus.parts())
        text = self.ANSWERS * self.SIZE
        # Warm every path, so what is measured is the search and not an import.
        validate_verdict_bundle(
            Bundle(objects=[Indicator(pattern=PATTERN)]),  # type: ignore[list-item]
            build_evidence_corpus(extra=["warm"]),
            searched=["warm"],
        )

        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        validate_verdict_bundle(
            Bundle(objects=[Indicator(pattern=PATTERN)]),  # type: ignore[list-item]
            build_evidence_corpus(),
            searched=parts,
        )
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # A tenth of the record would already mean a copy of part of it; the
        # measured figure is a hundredth of one per cent.
        assert peak - before < text // 10, f"{(peak - before) / 1e6:.2f} MB over {text} characters"

    def test_the_corpus_holds_the_text_once(self) -> None:
        import tracemalloc

        text = self.ANSWERS * self.SIZE
        tracemalloc.start()
        before = tracemalloc.get_traced_memory()[0]
        corpus = self._corpus()
        current, _peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert len(corpus) == self.ANSWERS
        # Once, with room for the bookkeeping beside it — never the four times
        # the joined shape cost.
        assert current - before < text * 2


_ORDINARY = Violation(code="isr.confidence_range", message="a confidence outside 0..1")


class TestTheFlagSurvivesEveryPlaceARowIsRebuilt:
    """A row the platform declined to act on must not be stored as an unfixed one.

    ``record_unresolved`` rebuilt its row as ``{agent, code, message}``, so the
    run summary, the report and the console showed an advisory absence as a
    producer's own unfixed finding — and an operator had to read inside the
    message to learn that nothing had been dropped for it.
    """

    @staticmethod
    def _row() -> Violation:
        return Violation(
            code="stix.ungrounded_indicator",
            message="a value appears nowhere in the evidence this run collected.",
            path="objects[0]",
            advisory=True,
        )

    def test_the_violation_serialises_it(self) -> None:
        assert self._row().to_dict()["advisory"] == "true"
        assert Violation(code="x", message="y").to_dict()["advisory"] == ""

    def test_the_state_channel_carries_it_back(self) -> None:
        from maljan.pipeline.nodes import _violations_from_rows

        (rebuilt,) = _violations_from_rows([self._row().to_dict()])

        assert rebuilt.advisory is True

    def test_the_tally_keeps_it_on_the_stored_row(self) -> None:
        from maljan.pipeline.validation import ValidationTally

        tally = ValidationTally()
        tally.record_unresolved("judge", [self._row(), Violation(code="x", message="y")])

        advisory, ordinary = tally.unresolved
        assert advisory["advisory"] == "true"
        assert "advisory" not in ordinary

    def test_the_run_summary_carries_it_to_the_console(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder
        from maljan.pipeline.validation import validation_metrics

        builder = RunSummaryBuilder(start_time=0.0)
        builder.set_sample("d" * 64, "sample.exe")
        summary = builder.set_validation(
            validation_metrics(0, [("judge", self._row()), ("static", _ORDINARY)])
        ).build()

        advisory, ordinary = summary.to_dict()["validation"]["unresolved"]
        assert advisory["advisory"] == "true"
        assert "advisory" not in ordinary

    def test_the_cli_read_back_keeps_it(self) -> None:
        """The one other place a stored row is rebuilt into a metrics object."""
        import inspect

        from maljan import cli

        source = inspect.getsource(cli)
        # ``dict(row)`` rather than three named keys, which is what keeps a
        # field nobody edited here from being dropped on the way back.
        assert 'unresolved=[dict(row) for row in v_data.get("unresolved") or []]' in source


class TestTheCheckRunsOnWhicheverSourceTheRunHas:
    """A run with no sandbox network block still has a record to ground against.

    The token corpus holds the sandbox report's ``network`` entries and nothing
    else; the run's own answers travel beside it. A gate that asked only
    whether the token corpus existed therefore skipped the whole indicator
    branch on every run without a sandbox network block — mock mode, a
    static-only team, a failed submission, a sample that made no network call —
    and the judge could export an invented indicator with no finding row at
    all. The inverse of the absence this file's first class is about: that one
    stated something it could not, this one stated nothing.

    Driven through the arguments the judge node itself passes, which is the gap
    that let it through a green suite.
    """

    @staticmethod
    def _as_the_node_passes_it(
        sandbox_report: dict[str, Any] | None, answers: list[str]
    ) -> list[Violation]:
        from maljan.agents.judge_postprocess import build_evidence_corpus

        # ``interesting_strings`` is None at the node's call site, so the token
        # set is the sandbox report's network entries and nothing else.
        token_corpus = build_evidence_corpus(
            interesting_strings=None,
            sandbox_report=sandbox_report if isinstance(sandbox_report, dict) else None,
        )
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        return validate_verdict_bundle(
            bundle,
            # The node collapses an empty set to None, as it always has.
            token_corpus or None,
            searched=answers,
            corpus_state=CorpusState(),
        )

    def test_a_run_with_no_sandbox_block_still_checks_the_judge(self) -> None:
        """Mock mode, a static-only team, a failed submission."""
        violations = self._as_the_node_passes_it({}, ["the tool answered about something else"])

        assert [v.code for v in violations] == ["stix.ungrounded_indicator"]
        assert violations[0].advisory is False

    def test_and_grounds_a_value_the_run_really_saw(self) -> None:
        violations = self._as_the_node_passes_it({}, [f"resolved {C2}"])

        assert violations == []

    def test_no_sandbox_report_at_all_is_the_same(self) -> None:
        violations = self._as_the_node_passes_it(None, ["an answer about something else"])

        assert [v.code for v in violations] == ["stix.ungrounded_indicator"]

    def test_a_sandbox_block_with_no_corpus_still_checks_the_judge(self) -> None:
        """The mirror: the token corpus is the only source this run has."""
        report = {"network": {"dns": [{"request": "unrelated.example.org"}]}}

        violations = self._as_the_node_passes_it(report, [])

        assert [v.code for v in violations] == ["stix.ungrounded_indicator"]

    def test_a_sandbox_block_that_holds_the_value_grounds_it(self) -> None:
        report = {"network": {"dns": [{"request": C2}]}}

        violations = self._as_the_node_passes_it(report, [])

        assert violations == []

    def test_neither_source_says_so_rather_than_passing_in_silence(self) -> None:
        """Nothing was searched, so nothing may be asserted — and it is recorded.

        A run with no sandbox block and no answers at all searched an empty
        record. Staying silent would export the judge's object with nothing
        said about it; asserting an absence would state something over evidence
        that does not exist. The row is written and it is advisory, which is
        the same answer a partial corpus gets.
        """
        violations = self._as_the_node_passes_it(None, [])

        assert [v.code for v in violations] == ["stix.ungrounded_indicator"]
        assert violations[0].advisory is True
        assert "nothing is dropped for it" in violations[0].message

    def test_and_the_object_survives_it(self) -> None:
        bundle = Bundle(objects=[Indicator(pattern=PATTERN)])  # type: ignore[list-item]
        violations = validate_verdict_bundle(bundle, None, searched=[], corpus_state=CorpusState())

        assert drop_ungrounded_indicators(bundle, violations) == 0
        assert len(bundle.objects) == 1


class TestTheClosedContainerFailsSafe:
    """A closed container's corpus reads as no corpus, not as a whole one.

    The drop replaced it with an empty ``RunEvidenceCorpus``, which with
    nothing recorded reports ``complete=True`` — so anything grounding after
    teardown would have been told the evidence was whole. Unreachable today,
    because every reader runs inside the graph, and a sentinel that fails open
    on this rule is the wrong sentinel whether or not anything reaches it.
    """

    @staticmethod
    def _container() -> Any:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        return ServiceContainer(config=Settings(_env_file=None), mock=True)

    def test_a_live_container_hands_out_a_corpus(self) -> None:
        container = self._container()

        assert container.get_evidence_corpus() is not None

    @pytest.mark.asyncio
    async def test_a_closed_one_hands_out_nothing(self) -> None:
        container = self._container()
        await container.aclose()

        assert container.get_evidence_corpus() is None

    @pytest.mark.asyncio
    async def test_and_a_check_after_teardown_searches_nothing_and_says_so(self) -> None:
        container = self._container()
        await container.aclose()

        seen, state = _what_the_run_saw(container, [])

        assert seen == []
        assert state.partial
        assert state.why == "run resumed without its corpus"
