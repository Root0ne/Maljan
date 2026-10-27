"""A similar case of another sample the judge was shown decides nothing.

The judge is shown up to three similar cases of other samples as weighted
priors. A technique such a case carried could reach the verdict, or an
analyst claim the judge keeps, with no source of this run behind it, and
nothing said so. The publish rules read this run alone: the published set and
every row's reason not to publish are byte for byte the ones the run has
without the cases, round after round. The platform records which cases'
techniques the judge's prompt carried on its bundle, read once per job and
never exported, and a recorded technique no source of this run stands behind
carries a note saying so.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Any

import pytest

from maljan.extractors.capability_matrix import (
    EARLIER_RUN_UNSUPPORTED_NOTE,
    SIMILAR_CASE_UNSUPPORTED_NOTE,
    build_capability_matrix,
    similar_case_techniques,
)
from maljan.memory import embeddings
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import (
    StoredCase,
    build_stored_case,
    similar_case_head,
    similar_cases,
    similar_cases_shown,
    with_published_techniques,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import (
    EARLIER_RUN_PROPERTY,
    SIMILAR_CASES_PROPERTY,
    Bundle,
    EarlierRun,
    SimilarCase,
    SimilarCases,
)
from maljan.tools import knowledge
from tests.unit.memory.test_an_earlier_run_on_the_sample_is_a_hypothesis import (
    CAPA,
    _bundle,
    _cell,
    _claim,
    _entry,
    _failed_entry,
    _published,
)

SHA = "ab" * 32
OTHER = "cd" * 32
THIRD = "ef" * 32


@pytest.fixture
def fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)


def _similar(*tids: str, sample: str = OTHER) -> dict[str, Any]:
    return SimilarCases(cases=[SimilarCase(sample_id=sample, techniques=list(tids))]).model_dump()


def _matrix(stix: dict[str, Any], isrs: Any, ledger: Any) -> tuple[list[Any], list[Any]]:
    return build_capability_matrix(stix_output=stix, isr_reports=isrs or {}, ledger=ledger)


def _rows(cells: list[Any]) -> str:
    """Every row as JSON, its note left out: what publishes and why not."""
    return json.dumps([c.model_dump(mode="json", exclude={"note"}) for c in cells])


def _mappings(mappings: list[Any]) -> str:
    return json.dumps([m.model_dump(mode="json") for m in mappings])


class TestTheSimilarCasesDecideNothing:
    LEDGER = [_entry("capa", CAPA, 1, agent="pipeline")]

    @pytest.mark.parametrize(
        ("stix", "isrs", "extra"),
        [
            # The judge alone names it.
            (_bundle("T1055"), {}, []),
            # An analyst cites only a lookup.
            (
                _bundle(),
                _claim("T1055", "[ev_0002] a similar sample did it"),
                [_entry("attck_lookup", knowledge.attck_lookup("T1055"), 2)],
            ),
            # An analyst cites nothing.
            (_bundle(), _claim("T1055", "a similar sample did it"), []),
            # An analyst cites only a call that failed.
            (_bundle(), _claim("T1055", "[ev_0002] the listing"), [_failed_entry(2)]),
        ],
        ids=["judge-only", "lookup-only", "no-citation", "failed-calls-only"],
    )
    def test_the_published_set_is_byte_identical_and_only_a_note_differs(
        self, stix: dict[str, Any], isrs: Any, extra: list[Any]
    ) -> None:
        ledger = [*self.LEDGER, *extra]
        cells_before, before = _matrix(stix, isrs, ledger)
        cells_after, after = _matrix(
            {**stix, SIMILAR_CASES_PROPERTY: _similar("T1055")}, isrs, ledger
        )

        assert _mappings(after) == _mappings(before)
        assert _rows(cells_after) == _rows(cells_before)
        was, now = _cell(cells_before, "T1055"), _cell(cells_after, "T1055")
        assert now.not_published == was.not_published
        assert SIMILAR_CASE_UNSUPPORTED_NOTE not in was.note
        assert now.note == "; ".join(n for n in (was.note, SIMILAR_CASE_UNSUPPORTED_NOTE) if n)

    @pytest.mark.parametrize("unreadable", [False, True], ids=["no-ledger", "unreadable-rows"])
    def test_without_a_corroboration_record_nothing_differs_and_nothing_is_noted(
        self, monkeypatch: pytest.MonkeyPatch, unreadable: bool
    ) -> None:
        ledger: Any = None
        if unreadable:
            from maljan.pipeline import validation

            def _raise(*_a: Any, **_k: Any) -> Any:
                raise RuntimeError("the record cannot be read")

            monkeypatch.setattr(validation, "corroboration", _raise)
            ledger = self.LEDGER
        stix, isrs = _bundle("T1055"), _claim("T1082", "a similar sample did it")
        cells_before, before = _matrix(stix, isrs, ledger)
        cells_after, after = _matrix(
            {**stix, SIMILAR_CASES_PROPERTY: _similar("T1055", "T1082")}, isrs, ledger
        )

        assert _mappings(after) == _mappings(before)
        assert _rows(cells_after) == _rows(cells_before)
        assert all(SIMILAR_CASE_UNSUPPORTED_NOTE not in c.note for c in cells_after)
        assert [c.note for c in cells_after] == [c.note for c in cells_before]

    def test_a_technique_a_rule_of_this_run_asserts_carries_no_note(self) -> None:
        stix = _bundle("T1027")
        cells_before, before = _matrix(stix, {}, self.LEDGER)
        cells_after, after = _matrix(
            {**stix, SIMILAR_CASES_PROPERTY: _similar("T1027")}, {}, self.LEDGER
        )

        assert "T1027" in _published(after) and _mappings(after) == _mappings(before)
        assert _cell(cells_after, "T1027").note == _cell(cells_before, "T1027").note

    def test_a_claim_citing_an_entry_that_reads_the_sample_carries_no_note(self) -> None:
        isrs = _claim("T1027", "[ev_0001] RC4 PRGA")
        cells_before, _ = _matrix(_bundle(), isrs, self.LEDGER)
        cells_after, _ = _matrix(
            {**_bundle(), SIMILAR_CASES_PROPERTY: _similar("T1027")}, isrs, self.LEDGER
        )

        assert _cell(cells_after, "T1027").note == _cell(cells_before, "T1027").note

    def test_a_technique_no_similar_case_carried_carries_no_note(self) -> None:
        cells, _ = _matrix(
            {**_bundle("T1082"), SIMILAR_CASES_PROPERTY: _similar("T1055")}, {}, self.LEDGER
        )

        assert SIMILAR_CASE_UNSUPPORTED_NOTE not in _cell(cells, "T1082").note

    def test_an_earlier_run_and_a_similar_case_each_say_their_own(self) -> None:
        stix = {
            **_bundle("T1055"),
            EARLIER_RUN_PROPERTY: EarlierRun(sample_id=SHA, techniques=["T1055"]).model_dump(),
            SIMILAR_CASES_PROPERTY: _similar("t1055"),
        }

        cells, mappings = _matrix(stix, {}, self.LEDGER)
        _, bare = _matrix(_bundle("T1055"), {}, self.LEDGER)

        note = _cell(cells, "T1055").note
        assert EARLIER_RUN_UNSUPPORTED_NOTE in note and SIMILAR_CASE_UNSUPPORTED_NOTE in note
        # The earlier run on this sample first, then the other samples.
        assert note.index(EARLIER_RUN_UNSUPPORTED_NOTE) < note.index(SIMILAR_CASE_UNSUPPORTED_NOTE)
        assert _mappings(mappings) == _mappings(bare)

    def test_the_published_set_is_stable_over_rounds_of_memory(self, fallback: None) -> None:
        # Two samples analysed in turn: each round's judge is shown the case
        # the other sample's last round stored, and each round stores what it
        # publishes, as the judge and the report node do.
        runs = {
            SHA: (
                _bundle("T1105", "T1082"),
                {
                    **_claim("T1055", "a similar sample did it"),
                    "dynamic": AgentISR(
                        agent_id="dynamic",
                        domain="dynamic",
                        claims=[
                            ClaimEvidence(
                                claim="RC4 PRGA",
                                evidence_ref="[ev_0001]",
                                confidence=0.6,
                                technique_id="T1027",
                            )
                        ],
                    ),
                },
            ),
            OTHER: (
                _bundle("T1055", "T1547.001"),
                _claim("T1082", "[ev_0002] the listing"),
            ),
        }
        ledger = [*self.LEDGER, _failed_entry(2)]
        store = InMemoryStore()
        rounds: dict[str, list[str]] = {SHA: [], OTHER: []}
        for _ in range(4):
            for sample, (stix, isrs) in runs.items():
                others = _others(store, sample)
                shown = similar_cases_shown(others, _shown_text(others))
                recorded = (
                    stix if shown is None else {**stix, SIMILAR_CASES_PROPERTY: shown.model_dump()}
                )
                _cells, mappings = _matrix(recorded, isrs, ledger)
                rounds[sample].append(_mappings(mappings))
                store.store(
                    with_published_techniques(
                        build_stored_case(sample, isrs), [m.technique_id for m in mappings], isrs
                    )
                )

        for sample, published in rounds.items():
            assert published == [published[0]] * 4, sample
        assert {"T1027", "T1055", "T1082", "T1105"} <= {
            m["technique_id"] for m in json.loads(rounds[SHA][0])
        }


def _others(store: InMemoryStore, sample: str) -> list[StoredCase]:
    """The cases of the other samples, as the judge's three similar cases."""
    return similar_cases(store, "T1055 T1082 RC4", exclude_sample_id=sample)


def _shown_text(cases: list[StoredCase], total: int | None = None) -> str:
    """The lines the judge's block writes for ``cases``, numbered of ``total``."""
    of = len(cases) if total is None else total
    return "".join(f"{similar_case_head(i, of, c)}\n" for i, c in enumerate(cases, 1))


def _case(sample: str = OTHER, techniques: list[str] | None = None) -> StoredCase:
    return StoredCase(
        sample_id=sample,
        summary_text="[STATIC] injects into explorer.exe [ev_0007] T1055",
        technique_ids=techniques if techniques is not None else ["T1055", "t1547.001", "TA0005"],
        malware_category="RAT",
        created_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
    )


class _Container:
    def __init__(self) -> None:
        # The unscoped cases, as a job with no owner reads them.
        self.memory_owner = None
        self.similar_cases: dict[str, Any] = {}


class TestTheCasesAreReadOncePerJob:
    def test_a_second_read_of_the_job_shows_the_same_cases(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case())
        container = _Container()

        first = similar_cases(store, "injects", exclude_sample_id=SHA, container=container)
        store.store(_case(THIRD))
        again = similar_cases(store, "injects", exclude_sample_id=SHA, container=container)

        assert [c.sample_id for c in first] == [OTHER]
        assert [c.sample_id for c in again] == [OTHER]
        # Without a container every read is its own.
        assert {c.sample_id for c in similar_cases(store, "injects", exclude_sample_id=SHA)} == {
            OTHER,
            THIRD,
        }

    def test_a_read_that_fails_is_not_kept(self) -> None:
        class _Broken:
            def retrieve(self, *_a: Any, **_k: Any) -> Any:
                raise RuntimeError("qdrant is down")

        container = _Container()
        with pytest.raises(RuntimeError):
            similar_cases(_Broken(), "q", exclude_sample_id=SHA, container=container)
        assert container.similar_cases == {}


class TestTheRecordIsWhatThePromptCarried:
    def test_only_technique_ids_each_once_upper_cased(self) -> None:
        case = _case(techniques=["t1055", "T1055", "TA0005", "not an id"])

        record = similar_cases_shown([case], _shown_text([case]))

        assert record == SimilarCases(cases=[SimilarCase(sample_id=OTHER, techniques=["T1055"])])

    def test_a_case_cut_before_its_techniques_line_is_not_recorded(self) -> None:
        first, second = _case(), _case(THIRD, ["T1082"])

        record = similar_cases_shown([first, second], _shown_text([first], total=2))

        assert record is not None and [c.sample_id for c in record.cases] == [OTHER]
        assert similar_cases_shown([first], similar_case_head(1, 1, first)[:-3]) is None
        assert similar_cases_shown([_case(techniques=[])], "") is None

    def test_a_case_with_the_same_techniques_cut_before_its_lines_is_not_recorded(self) -> None:
        # The third case carries the first one's list: its own lines were cut.
        first, second, third = (
            _case(techniques=["T1055"]),
            _case(THIRD, ["T1082"]),
            _case(SHA, ["T1055"]),
        )

        record = similar_cases_shown([first, second, third], _shown_text([first, second], 3))

        assert record is not None
        assert [c.sample_id for c in record.cases] == [OTHER, THIRD]

    def test_the_lines_the_record_matches_are_the_ones_the_judge_writes(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        cases = [_case(techniques=["T1055"]), _case(THIRD, ["T1055"])]
        block = JudgeAgent._memory_block(cases)

        for idx, case in enumerate(cases, 1):
            assert f"{similar_case_head(idx, 2, case)}\n  Behavioral summary: " in block

    def test_the_matrix_reads_the_record_off_the_dumped_bundle(self) -> None:
        bundle = Bundle(
            x_maljan_similar_cases=SimilarCases(
                cases=[
                    SimilarCase(sample_id=OTHER, techniques=["t1055"]),
                    SimilarCase(sample_id=THIRD, techniques=["T1082"]),
                ]
            )
        )

        assert similar_case_techniques(bundle.model_dump()) == {"T1055", "T1082"}
        assert similar_case_techniques(Bundle().model_dump()) == set()
        assert similar_case_techniques({SIMILAR_CASES_PROPERTY: "garbage"}) == set()
        assert similar_case_techniques({SIMILAR_CASES_PROPERTY: {"cases": ["x"]}}) == set()

    def test_a_bundle_with_no_record_dumps_as_before(self) -> None:
        assert SIMILAR_CASES_PROPERTY not in Bundle().model_dump(exclude_none=True)


def _memory_of(prompt: str) -> str:
    """The similar-case block of one verdict prompt."""
    return prompt.split("=== LONG-TERM MEMORY")[1].split("=== END LONG-TERM MEMORY ===")[0]


class TestTheJudgeRecordsWhatItsVerdictPromptShowed:
    def _judge(self, seen: list[str], container: Any) -> Any:
        from tests.unit.agents.test_the_judge_prompt_is_sized_from_its_window import _judge

        judge = _judge(seen, window_tokens=None)
        judge._container = container
        return judge

    def _verdict(self, judge: Any, store: Any) -> None:
        claim = ClaimEvidence(
            claim="injects into explorer.exe", evidence_ref="[ev_0001]", confidence=0.7
        )
        asyncio.run(
            judge.give_verdict(
                reports={"static": "It injects."},
                history=[],
                isr_reports={
                    "static": AgentISR(agent_id="static", domain="static", claims=[claim])
                },
                evidence_summary="",
                memory_store=store,
                current_sample_id=SHA,
            )
        )

    def test_the_cases_shown_are_recorded_and_read_once(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case())
        container = _Container()
        seen: list[str] = []
        judge = self._judge(seen, container)

        self._verdict(judge, store)
        store.store(_case(THIRD, ["T1082"]))
        self._verdict(judge, store)

        assert "Past techniques: T1055, t1547.001, TA0005" in seen[0]
        # Each verdict prompt of the job shows the same cases (a retry is a
        # call of its own), the case stored in between in none of them.
        blocks = {_memory_of(prompt) for prompt in seen}
        assert len(seen) > 1 and len(blocks) == 1 and THIRD not in blocks.pop()
        assert judge.similar_cases_shown == SimilarCases(
            cases=[SimilarCase(sample_id=OTHER, techniques=["T1055", "T1547.001"])]
        )

    def test_a_case_the_fitted_prompt_cut_before_its_techniques_is_not_recorded(
        self, fallback: None
    ) -> None:
        store = InMemoryStore()
        long = _case()
        long.summary_text = "injects into explorer.exe " * 400
        store.store(long)
        store.store(_case(THIRD, ["T1082"]))
        seen: list[str] = []
        container = _Container()
        judge = self._judge(seen, container)
        judge._question_room = lambda fixed, cap: 4_000  # type: ignore[method-assign]

        self._verdict(judge, store)

        # Both were read; the cut left the second one's techniques out.
        assert [c.sample_id for c in container.similar_cases[SHA]] == [OTHER, THIRD]
        block = _memory_of(seen[0])
        assert "Past techniques: T1055" in block and "Past techniques: T1082" not in block
        assert judge.similar_cases_shown == SimilarCases(
            cases=[SimilarCase(sample_id=OTHER, techniques=["T1055", "T1547.001"])]
        )

    def test_no_case_is_no_record(self, fallback: None) -> None:
        judge = self._judge([], _Container())
        judge.similar_cases_shown = SimilarCases(cases=[SimilarCase(sample_id=OTHER)])

        self._verdict(judge, InMemoryStore())

        assert judge.similar_cases_shown is None


class TestTheJudgeNodeSetsTheRecordOnEveryBundle:
    def _run(self, shown: Any, written: SimilarCases | None) -> dict[str, Any]:
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container as _Base
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _state

        class _WithMemory(_Base):
            memory_owner = None

            def __init__(self) -> None:
                super().__init__(EvidenceCounter())
                self.earlier_cases: dict[str, Any] = {}

            def get_memory_store(self) -> Any:
                return InMemoryStore()

        container = _WithMemory()
        judge = container.get_judge_agent(role="judge")
        # A record the model wrote into its own answer is never read as the platform's.
        bundle = Bundle(objects=[], x_maljan_similar_cases=written)
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(bundle=bundle, violations=[], retries=0, fed_back={})
        )
        judge.decide_techniques = AsyncMock(return_value=None)
        judge.similar_cases_shown = shown
        return asyncio.run(make_judge_node(container)({**_state([]), "file_hash": SHA}))

    def test_the_bundle_carries_what_the_judge_was_shown(self, fallback: None) -> None:
        shown = SimilarCases(cases=[SimilarCase(sample_id=OTHER, techniques=["T1055"])])

        update = self._run(shown, SimilarCases(cases=[SimilarCase(sample_id=THIRD)]))

        assert update["stix_output"][SIMILAR_CASES_PROPERTY] == shown.model_dump()

    @pytest.mark.parametrize("shown", [None, "T1055", {"cases": []}])
    def test_anything_else_clears_a_written_record(self, fallback: None, shown: Any) -> None:
        update = self._run(shown, SimilarCases(cases=[SimilarCase(sample_id=THIRD)]))

        assert update["stix_output"].get(SIMILAR_CASES_PROPERTY) is None


class TestAStoredRunWithTheRecordReplaysTheSame:
    def test_the_tiny_run_publishes_the_same_with_every_technique_recorded(
        self, tmp_path: Any
    ) -> None:
        import shutil

        from scripts.replay.rules import replay_run
        from scripts.replay.stored import read_run

        from tests.unit.scripts._replay_tiny import FIXTURE

        before = replay_run(read_run(FIXTURE))["report"]["techniques"]
        copy = tmp_path / "tiny"
        shutil.copytree(FIXTURE, copy)
        judge = json.loads((copy / "stix-judge.json").read_text(encoding="utf-8"))
        judge["bundle"][SIMILAR_CASES_PROPERTY] = _similar(*sorted(before))
        (copy / "stix-judge.json").write_text(json.dumps(judge), encoding="utf-8")

        after = replay_run(read_run(copy))["report"]["techniques"]

        assert after == before


class TestTheReportsBundleCarriesNoOtherSample:
    def _stored(self, judge: Bundle) -> Any:
        from app.worker.analysis_worker import _report_inputs
        from maljan.core.config import Settings

        stored, _ = _report_inputs(
            {"stix_output": judge.model_dump()},
            core_settings=Settings(_env_file=None),
            override_keys=(),
            hash_mismatch_reason=None,
        )
        return stored

    def test_the_judge_s_draft_stored_as_the_report_s_drops_both_records(self) -> None:
        judge = Bundle(
            objects=[{"type": "malware", "id": "malware--1", "name": "x", "is_family": False}],
            x_maljan_earlier_run=EarlierRun(sample_id=SHA, techniques=["T1055"]),
            x_maljan_similar_cases=SimilarCases(
                cases=[SimilarCase(sample_id=OTHER, techniques=["T1055"])]
            ),
        )

        stored = self._stored(judge)

        assert EARLIER_RUN_PROPERTY not in stored and SIMILAR_CASES_PROPERTY not in stored
        assert OTHER not in json.dumps(stored)
        # The judge's own bundle keeps them as the run's facts.
        assert judge.model_dump()[SIMILAR_CASES_PROPERTY]["cases"][0]["sample_id"] == OTHER

    def test_a_bundle_without_the_records_loses_only_their_empty_keys(self) -> None:
        judge = Bundle(
            objects=[{"type": "malware", "id": "malware--1", "name": "x", "is_family": False}]
        )
        plain = judge.model_dump()

        stored = self._stored(judge)

        assert {k for k in stored if k in plain} == {
            k for k in plain if k not in (EARLIER_RUN_PROPERTY, SIMILAR_CASES_PROPERTY)
        }
