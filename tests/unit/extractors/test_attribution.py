"""Unit tests for :func:`maljan.extractors.attribution.populate_similar_samples`."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from maljan.extractors.attribution import _build_query, populate_similar_samples
from maljan.memory.long_term_memory import StoredCase


def test_build_query_includes_suspicious_network_iocs() -> None:
    report = {
        "malware_category": "botnet",
        "network": {
            "domains": [
                {"fqdn": "evil-c2.net", "is_suspicious": True},
                {"fqdn": "benign.example.org", "is_suspicious": False},
            ],
            "ips": [{"address": "185.220.101.47", "is_suspicious": True}],
        },
    }
    query = _build_query(report)
    assert "Infrastructure:" in query
    assert "evil-c2.net" in query
    assert "185.220.101.47" in query
    # Non-suspicious infra is not used to link samples.
    assert "benign.example.org" not in query


class _StubStore:
    """Minimal MemoryStore stand-in — duck-typed against the Protocol."""

    def __init__(self, cases: list[StoredCase], *, raise_exc: Exception | None = None) -> None:
        self._cases = cases
        self._raise = raise_exc
        self.calls: list[tuple[str, int]] = []

    def retrieve(self, query: str, top_k: int = 3) -> list[StoredCase]:
        self.calls.append((query, top_k))
        if self._raise is not None:
            raise self._raise
        return self._cases[:top_k]


def _make_case(
    sample_id: str, *, category: str = "RAT", tids: list[str] | None = None
) -> StoredCase:
    return StoredCase(
        sample_id=sample_id,
        summary_text=f"Synthetic case {sample_id}",
        technique_ids=tids or ["T1055", "T1071"],
        malware_category=category,
        stix_bundle_json="",
        created_at=datetime.now(UTC),
    )


def _malware_report(*, sha256: str = "a" * 64, with_existing: bool = False) -> dict[str, Any]:
    mr: dict[str, Any] = {
        "identity": {"hashes": {"sha256": sha256}},
        "malware_category": "RAT",
        "attribution": {"family": "ExampleRAT", "similar_samples": []},
        "ttp_mappings": [
            {"technique_id": "T1055", "technique_name": "Process Injection"},
            {"technique_id": "T1071", "technique_name": "Application Layer Protocol"},
        ],
        "dynamic": {
            "sandbox_signatures": [
                {"name": "antivm_check"},
                {"name": "creates_service"},
            ]
        },
    }
    if with_existing:
        mr["attribution"]["similar_samples"] = [{"sample_id": "preset", "source": "preset"}]
    return mr


class TestPopulateSimilarSamples:
    def test_store_none_is_noop(self) -> None:
        mr = _malware_report()
        out = populate_similar_samples(mr, None)
        assert out["attribution"]["similar_samples"] == []

    def test_populates_top_k(self) -> None:
        store = _StubStore(
            [
                _make_case("b" * 64, category="STEALER"),
                _make_case("c" * 64),
                _make_case("d" * 64),
            ]
        )
        mr = _malware_report()
        populate_similar_samples(mr, store, top_k=2)
        sims = mr["attribution"]["similar_samples"]
        assert len(sims) == 2
        assert sims[0]["sample_id"] == "b" * 64
        assert sims[0]["malware_category"] == "STEALER"
        assert sims[0]["source"] == "maljan-ltm"
        # Store called with top_k+1 to allow self-removal.
        assert store.calls[0][1] == 3

    def test_filters_own_sha256(self) -> None:
        own = "a" * 64
        store = _StubStore(
            [
                _make_case(own),  # same as report — must be skipped
                _make_case("b" * 64),
                _make_case("c" * 64),
            ]
        )
        mr = _malware_report(sha256=own)
        populate_similar_samples(mr, store, top_k=2)
        sims = mr["attribution"]["similar_samples"]
        assert len(sims) == 2
        assert all(s["sample_id"] != own for s in sims)

    def test_idempotent_when_already_populated(self) -> None:
        store = _StubStore([_make_case("b" * 64)])
        mr = _malware_report(with_existing=True)
        populate_similar_samples(mr, store)
        assert mr["attribution"]["similar_samples"] == [{"sample_id": "preset", "source": "preset"}]
        assert store.calls == []  # store never consulted

    def test_store_failure_is_swallowed(self) -> None:
        store = _StubStore([], raise_exc=RuntimeError("qdrant down"))
        mr = _malware_report()
        out = populate_similar_samples(mr, store)
        # No raise, no entries added.
        assert out["attribution"]["similar_samples"] == []

    def test_empty_query_skips_retrieval(self) -> None:
        store = _StubStore([_make_case("b" * 64)])
        # A report with no category, no TTPs, no signatures yields an empty query.
        mr: dict[str, Any] = {
            "identity": {"hashes": {"sha256": "z" * 64}},
            "attribution": {"similar_samples": []},
        }
        populate_similar_samples(mr, store)
        assert mr["attribution"]["similar_samples"] == []
        assert store.calls == []

    def test_attribution_block_created_when_missing(self) -> None:
        store = _StubStore([_make_case("b" * 64)])
        mr: dict[str, Any] = {
            "identity": {"hashes": {"sha256": "z" * 64}},
            "malware_category": "RAT",
            "ttp_mappings": [
                {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter"}
            ],
        }
        populate_similar_samples(mr, store)
        assert "attribution" in mr
        assert len(mr["attribution"]["similar_samples"]) == 1

    def test_summary_is_trimmed(self) -> None:
        long_case = StoredCase(
            sample_id="b" * 64,
            summary_text="x" * 1000,
            technique_ids=["T1055"],
            malware_category="RAT",
        )
        store = _StubStore([long_case])
        mr = _malware_report()
        populate_similar_samples(mr, store, top_k=1)
        sims = mr["attribution"]["similar_samples"]
        assert len(sims[0]["summary"]) <= 240


class TestBuildQuery:
    def test_includes_category_family_techniques_signatures(self) -> None:
        mr = _malware_report()
        q = _build_query(mr)
        assert "RAT" in q
        assert "ExampleRAT" in q
        assert "T1055" in q
        assert "Process Injection" in q
        assert "antivm_check" in q

    def test_skips_malformed_ttp_entries(self) -> None:
        mr: dict[str, Any] = {
            "malware_category": "STEALER",
            "ttp_mappings": [
                "garbage",
                {"technique_id": "T1059", "technique_name": "Cmd"},
                {"technique_id": 123, "technique_name": "Bad Type"},  # non-string id
            ],
        }
        q = _build_query(mr)
        assert "T1059" in q
        assert "Bad Type" not in q

    def test_empty_inputs_yield_empty_string(self) -> None:
        assert _build_query({}) == ""


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"attribution": {}},
        {"attribution": {"similar_samples": None}},
    ],
)
def test_handles_missing_attribution_shape(report: dict[str, Any]) -> None:
    store = _StubStore([_make_case("b" * 64)])
    # Build a tiny query so _build_query doesn't short-circuit.
    report["malware_category"] = "RAT"
    out = populate_similar_samples(report, store, top_k=1)
    assert out["attribution"]["similar_samples"] == [
        {
            "sample_id": "b" * 64,
            "malware_category": "RAT",
            "technique_ids": ["T1055", "T1071"],
            "summary": "Synthetic case " + "b" * 64,
            "source": "maljan-ltm",
        }
    ]
