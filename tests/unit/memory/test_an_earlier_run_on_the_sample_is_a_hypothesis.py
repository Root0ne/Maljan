"""An earlier run on the same sample reaches the agents as hypotheses, never as evidence.

Every similarity read of the memory leaves the sample's own case out
(``exclude_sample_id``), so what an earlier run on the same sha256 reported
never reached a run at all. It is read now by the sample's id, under the owner
rule, and shown to every agent after the pack under a heading that says it is
a hypothesis to check with this run's tools. It has no evidence id, so nothing
can cite it and nothing corroborates with it, and it decides nothing: the
published set is the one the run publishes without it, round after round, and
a technique it reported that no source of this run stands behind only carries
a note saying so. The report writer is not shown it. Without an earlier case
the prompts are unchanged, byte for byte.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from maljan.extractors.capability_matrix import (
    EARLIER_RUN_UNSUPPORTED_NOTE,
    build_capability_matrix,
    earlier_run_techniques,
)
from maljan.memory import embeddings
from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import (
    EARLIER_RUN_HEADING,
    NO_MEMORY,
    MemoryStoreDefaults,
    StoredCase,
    build_stored_case,
    earlier_case,
    earlier_case_of,
    earlier_run_block,
    earlier_run_of,
    recall,
    with_published_techniques,
)
from maljan.memory.qdrant_store import QdrantStore
from maljan.schemas.evidence import build_entry, entry_ids_in, format_entry_id
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import EARLIER_RUN_PROPERTY, Bundle, EarlierRun
from maljan.tools import knowledge

SHA = "ab" * 32
OTHER = "cd" * 32
ALICE, BOB = "user-alice", "user-bob"


def _case(sample: str = SHA, owner: str | None = None) -> StoredCase:
    return StoredCase(
        sample_id=sample,
        # The earlier run's claims, with that run's evidence ids.
        summary_text="[STATIC] injects into explorer.exe [ev_0007] T1055",
        technique_ids=["T1055", "t1547.001", "TA0005", "not an id"],
        malware_category="RAT",
        created_at=datetime(2026, 10, 1, 12, 0, tzinfo=UTC),
        owner=owner,
    )


class _Container:
    def __init__(self, store: Any, owner: Any = None) -> None:
        self._store = store
        self.memory_owner = owner
        self.earlier_cases: dict[str, Any] = {}
        self.reads = 0

    def get_memory_store(self) -> Any:
        self.reads += 1
        if isinstance(self._store, Exception):
            raise self._store
        return self._store


@pytest.fixture
def fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: False)


class TestTheEarlierCaseIsReadBySampleUnderTheOwnerRule:
    def test_the_sample_s_own_case_is_read_by_its_id(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case())
        store.store(_case(OTHER))

        found = earlier_case(store, SHA)

        assert found is not None and found.sample_id == SHA
        # The similarity reads still leave it out.
        assert all(c.sample_id != SHA for c in recall(store, "injects", exclude_sample_id=SHA))

    def test_an_owner_reads_its_own_case_and_no_one_else_s(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case(owner=ALICE))

        assert earlier_case(store, SHA, owner=ALICE) is not None
        assert earlier_case(store, SHA, owner=BOB) is None
        assert earlier_case(store, SHA) is None
        assert earlier_case(store, SHA, owner=NO_MEMORY) is None

    def test_a_backend_without_a_read_by_id_or_without_owners_shows_none(self) -> None:
        class _Plain(MemoryStoreDefaults):
            pass

        class _Unscoped:
            def case_of(self, sample_id: str, owner: str | None = None) -> StoredCase:
                return _case()

        assert earlier_case(_Plain(), SHA) is None
        assert earlier_case(object(), SHA) is None
        # A backend that keeps no owners is never read for an owned job.
        assert earlier_case(_Unscoped(), SHA, owner=ALICE) is None
        assert earlier_case(_Unscoped(), SHA) is not None

    def test_an_answer_for_another_sample_is_not_this_one_s(self) -> None:
        class _Wrong:
            def case_of(self, sample_id: str, owner: str | None = None) -> Any:
                return _case(OTHER)

        assert earlier_case(_Wrong(), SHA) is None

    def test_qdrant_reads_the_case_by_its_point_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import qdrant_client
        from qdrant_client import QdrantClient

        class _Vector:
            def __init__(self, text: str) -> None:
                self._text = text

            def tolist(self) -> list[float]:
                return embeddings._bow_projection(self._text)

        class _Model:
            def embed(self, texts: list[str], batch_size: int | None = None) -> Any:
                yield from (_Vector(text) for text in texts)

        monkeypatch.setattr(embeddings, "_try_load_fastembed", lambda: _Model())
        client = QdrantClient(location=":memory:")
        monkeypatch.setattr(qdrant_client, "QdrantClient", lambda **_kw: client)
        store = QdrantStore(url="http://qdrant.test:6333", collection="cases")
        assert earlier_case(store, SHA) is None

        store.store(_case(owner=ALICE))
        store.store(_case())

        mine = earlier_case(store, SHA, owner=ALICE)
        assert mine is not None and mine.owner == ALICE
        assert mine.created_at == datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
        assert earlier_case(store, SHA, owner=BOB) is None
        unscoped = earlier_case(store, SHA)
        assert unscoped is not None and unscoped.owner is None

    def test_the_job_reads_it_once_and_a_store_that_fails_is_no_case(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case())
        container = _Container(store)

        assert earlier_case_of(container, SHA) is not None
        assert earlier_case_of(container, SHA) is not None
        assert container.reads == 1

        broken = _Container(RuntimeError("qdrant is down"))
        assert earlier_case_of(broken, SHA) is None
        assert earlier_case_of(None, SHA) is None
        assert earlier_case_of(container, "") is None


class TestTheAgentsAreShownAHypothesisWithNoEvidenceId:
    def test_the_block_says_hypothesis_and_lists_only_technique_ids(self) -> None:
        block = earlier_run_block(_case())

        assert block.startswith(EARLIER_RUN_HEADING)
        assert "hypothesis to check with this run's tools, not as evidence" in block
        assert "it cannot be cited" in block
        assert "Earlier techniques: T1055, T1547.001\n" in block
        # An earlier verdict's word is no hypothesis a tool can check.
        assert "RAT" not in block and "category" not in block
        assert "Stored: 2026-10-01" in block
        assert "TA0005" not in block and "not an id" not in block

    def test_the_block_carries_no_evidence_id_of_the_earlier_run(self) -> None:
        block = earlier_run_block(_case())

        # The earlier run's summary names that run's ledger; it is not shown.
        assert "explorer.exe" not in block
        assert entry_ids_in(block) == set()

    def test_no_earlier_case_is_no_block(self) -> None:
        assert earlier_run_block(None) == ""

    def test_the_block_says_nothing_of_publishing(self) -> None:
        assert "published" not in earlier_run_block(_case())


class TestEveryAgentButTheReportWriterIsShownIt:
    def _state(self) -> dict[str, Any]:
        return {"file_hash": SHA, "evidence_ledger": []}

    def _container(self, store: Any) -> Any:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        container = ServiceContainer(Settings(_env_file=None), mock=True)
        container.get_memory_store = lambda: store  # type: ignore[method-assign]
        return container

    def test_the_agents_get_it_after_the_pack_and_the_reporter_does_not(
        self, fallback: None
    ) -> None:
        from maljan.pipeline.nodes import pack_text

        store = InMemoryStore()
        store.store(_case())
        container = self._container(store)

        assert pack_text(self._state(), container) == earlier_run_block(_case())
        assert pack_text(self._state(), container, for_reporter=True) == ""

    def test_without_an_earlier_case_the_pack_is_unchanged(self, fallback: None) -> None:
        from maljan.pipeline.nodes import pack_text

        store = InMemoryStore()
        store.store(_case(OTHER))
        container = self._container(store)

        assert pack_text(self._state(), container) == ""

    @pytest.mark.parametrize(("bound", "room"), [(4000, None), (0, 0), (10, 1)])
    def test_the_pack_and_the_earlier_run_share_the_one_bound(
        self, fallback: None, monkeypatch: pytest.MonkeyPatch, bound: int, room: int | None
    ) -> None:
        from maljan.pipeline import nodes

        store = InMemoryStore()
        store.store(_case())
        seen: list[int] = []
        monkeypatch.setattr(nodes, "upstream_chars", lambda *_a, **_k: bound)
        monkeypatch.setattr(nodes, "pack_block", lambda _entries, chars: seen.append(chars) or "")

        nodes.pack_text(self._state(), self._container(store))
        nodes.pack_text(self._state(), self._container(store), for_reporter=True)

        earlier = earlier_run_block(_case())
        # Taken off the pack's room with its break; no bound stays none, and
        # the pack's smallest room is 1. The reporter's pack keeps the whole bound.
        expected = bound - len(earlier) - 2 if room is None else room
        assert seen == [expected, bound]


def _pattern(tid: str) -> dict[str, Any]:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": tid,
        "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
    }


def _bundle(*tids: str, earlier: list[str] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {
        "type": "bundle",
        "objects": [{"type": "malware", "id": "malware--1"}, *(_pattern(t) for t in tids)],
    }
    if earlier is not None:
        out[EARLIER_RUN_PROPERTY] = EarlierRun(sample_id=SHA, techniques=earlier).model_dump()
    return out


def _entry(tool: str, payload: dict[str, Any], seq: int, *, agent: str = "static") -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=agent,
        tool=tool,
        args={},
        server="knowledge",
        output=json.dumps(payload),
        stage="analysis",
    )


CAPA = {
    "capabilities": [
        {"rule": "encrypt data using RC4 PRGA", "attck": ["Defense Evasion::Obfuscation [T1027]"]}
    ]
}


def _claim(tid: str, ref: str) -> dict[str, AgentISR]:
    claim = ClaimEvidence(
        claim="the sample does it", evidence_ref=ref, confidence=0.7, technique_id=tid
    )
    return {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}


def _published(mappings: list[Any]) -> set[str]:
    return {m.technique_id for m in mappings}


def _cell(cells: list[Any], tid: str) -> Any:
    (cell,) = [c for c in cells if c.technique_id == tid]
    return cell


def _with_and_without(
    tid: str, *, stix: dict[str, Any] | None = None, isrs: Any = None, ledger: Any = None
) -> tuple[tuple[list[Any], list[Any]], tuple[list[Any], list[Any]]]:
    """The matrix over one run without the earlier run's record and with it naming ``tid``."""
    bare = stix if stix is not None else _bundle()
    recorded = {
        **bare,
        EARLIER_RUN_PROPERTY: EarlierRun(sample_id=SHA, techniques=[tid]).model_dump(),
    }
    before = build_capability_matrix(stix_output=bare, isr_reports=isrs or {}, ledger=ledger)
    after = build_capability_matrix(stix_output=recorded, isr_reports=isrs or {}, ledger=ledger)
    return before, after


def _failed_entry(seq: int) -> Any:
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent="static",
        tool="strings",
        args={"path": "sample.bin"},
        server="analysis",
        output="",
        stage="analysis",
        ok=False,
        error="the server did not answer",
    )


class TestTheEarlierRunDecidesNothing:
    LEDGER = [_entry("capa", CAPA, 1, agent="pipeline")]

    @pytest.mark.parametrize(
        ("stix", "isrs", "extra"),
        [
            # The judge alone names it.
            (_bundle("T1055"), {}, []),
            # An analyst cites only a lookup.
            (
                _bundle(),
                _claim("T1055", "[ev_0002] the earlier run reported it"),
                [_entry("attck_lookup", knowledge.attck_lookup("T1055"), 2)],
            ),
            # An analyst cites nothing.
            (_bundle(), _claim("T1055", "an earlier run on this sample reported it"), []),
            # An analyst cites only a call that failed.
            (_bundle(), _claim("T1055", "[ev_0002] the listing"), [_failed_entry(2)]),
        ],
        ids=["judge-only", "lookup-only", "no-citation", "failed-calls-only"],
    )
    def test_the_published_set_is_the_one_without_the_record_and_only_a_note_differs(
        self, stix: dict[str, Any], isrs: Any, extra: list[Any]
    ) -> None:
        ledger = [*self.LEDGER, *extra]
        (cells_before, before), (cells_after, after) = _with_and_without(
            "T1055", stix=stix, isrs=isrs, ledger=ledger
        )

        assert _published(after) == _published(before)
        was, now = _cell(cells_before, "T1055"), _cell(cells_after, "T1055")
        assert now.not_published == was.not_published
        assert EARLIER_RUN_UNSUPPORTED_NOTE not in was.note
        assert now.note == "; ".join(n for n in (was.note, EARLIER_RUN_UNSUPPORTED_NOTE) if n)

    def test_a_technique_a_rule_of_this_run_asserts_carries_no_note(self) -> None:
        (cells_before, before), (cells_after, after) = _with_and_without(
            "T1027", stix=_bundle("T1027"), ledger=self.LEDGER
        )

        assert _published(after) == _published(before) and "T1027" in _published(after)
        assert _cell(cells_after, "T1027").note == _cell(cells_before, "T1027").note

    def test_a_claim_citing_an_entry_that_reads_the_sample_carries_no_note(self) -> None:
        (cells_before, _), (cells_after, after) = _with_and_without(
            "T1027", isrs=_claim("T1027", "[ev_0001] RC4 PRGA"), ledger=self.LEDGER
        )

        assert "T1027" in _published(after)
        assert _cell(cells_after, "T1027").note == _cell(cells_before, "T1027").note

    def test_a_technique_the_earlier_run_did_not_report_carries_no_note(self) -> None:
        cells, _ = build_capability_matrix(
            stix_output={
                **_bundle("T1082"),
                EARLIER_RUN_PROPERTY: EarlierRun(sample_id=SHA, techniques=["T1055"]).model_dump(),
            },
            isr_reports={},
            ledger=self.LEDGER,
        )

        assert EARLIER_RUN_UNSUPPORTED_NOTE not in _cell(cells, "T1082").note

    def test_the_published_set_is_stable_over_rounds_of_memory(self) -> None:
        # One run, repeated: each round is shown what the round before stored,
        # and stores what it publishes, as the judge and the report node do.
        isrs = {
            **_claim("T1055", "an earlier run on this sample reported it"),
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
        }
        stix = _bundle("T1105")
        earlier: list[str] | None = None
        rounds: list[set[str]] = []
        for _ in range(4):
            shown = (
                stix
                if earlier is None
                else {
                    **stix,
                    EARLIER_RUN_PROPERTY: EarlierRun(
                        sample_id=SHA, techniques=earlier
                    ).model_dump(),
                }
            )
            _cells, mappings = build_capability_matrix(
                stix_output=shown, isr_reports=isrs, ledger=self.LEDGER
            )
            rounds.append(_published(mappings))
            case = with_published_techniques(
                build_stored_case(SHA, isrs), [m.technique_id for m in mappings], isrs
            )
            earlier = list(case.technique_ids)

        assert rounds == [rounds[0]] * 4
        assert {"T1027", "T1055", "T1105"} <= rounds[0]


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
        judge["bundle"][EARLIER_RUN_PROPERTY] = EarlierRun(
            sample_id=SHA, techniques=sorted(before)
        ).model_dump()
        (copy / "stix-judge.json").write_text(json.dumps(judge), encoding="utf-8")

        after = replay_run(read_run(copy))["report"]["techniques"]

        assert after == before


class TestTheRecordTheBundleCarries:
    def test_the_record_is_what_the_agents_were_shown(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case())

        record = earlier_run_of(_Container(store), SHA)

        assert record == EarlierRun(
            sample_id=SHA,
            techniques=["T1055", "T1547.001"],
            stored="2026-10-01",
        )
        assert earlier_run_of(_Container(InMemoryStore()), SHA) is None

    def test_the_matrix_reads_the_record_off_the_dumped_bundle(self) -> None:
        bundle = Bundle(x_maljan_earlier_run=EarlierRun(sample_id=SHA, techniques=["t1055"]))

        assert earlier_run_techniques(bundle.model_dump()) == {"T1055"}
        assert earlier_run_techniques(Bundle().model_dump()) == set()
        assert earlier_run_techniques({EARLIER_RUN_PROPERTY: "garbage"}) == set()

    def test_a_bundle_with_no_record_dumps_as_before(self) -> None:
        assert EARLIER_RUN_PROPERTY not in Bundle().model_dump(exclude_none=True)


class TestTheJudgeNodeSetsTheRecordOnEveryBundle:
    def _run(self, store: Any, written: EarlierRun | None) -> dict[str, Any]:
        import asyncio
        from unittest.mock import AsyncMock

        from maljan.agents.judge_agent import JudgeVerdict
        from maljan.pipeline.nodes import make_judge_node
        from maljan.schemas.evidence import EvidenceCounter
        from tests.unit.pipeline.test_degraded_mode_at_the_judge_node import _Container, _state

        class _WithMemory(_Container):
            memory_owner = None

            def __init__(self) -> None:
                super().__init__(EvidenceCounter())
                self.earlier_cases: dict[str, Any] = {}

            def get_memory_store(self) -> Any:
                return store

        container = _WithMemory()
        judge = container.get_judge_agent(role="judge")
        # A record the model wrote into its own answer is never read as the platform's.
        bundle = Bundle(objects=[], x_maljan_earlier_run=written)
        judge.give_verdict = AsyncMock(
            return_value=JudgeVerdict(bundle=bundle, violations=[], retries=0, fed_back={})
        )
        judge.decide_techniques = AsyncMock(return_value=None)
        return asyncio.run(make_judge_node(container)({**_state([]), "file_hash": SHA}))

    def test_the_bundle_carries_what_the_agents_were_shown(self, fallback: None) -> None:
        store = InMemoryStore()
        store.store(_case())

        update = self._run(store, EarlierRun(sample_id=SHA, techniques=["T1082"]))

        assert update["stix_output"][EARLIER_RUN_PROPERTY]["techniques"] == ["T1055", "T1547.001"]

    def test_without_an_earlier_case_a_written_record_is_cleared(self, fallback: None) -> None:
        update = self._run(InMemoryStore(), EarlierRun(sample_id=SHA, techniques=["T1082"]))

        assert update["stix_output"].get(EARLIER_RUN_PROPERTY) is None
