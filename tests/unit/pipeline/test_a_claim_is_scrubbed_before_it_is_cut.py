"""A claim sent as an event is scrubbed and then cut, never cut and then scrubbed.

A cut in front of the scrub leaves the head of a secret, which no longer has the
shape the scrub knows, and the event carries it.
"""

from __future__ import annotations

from types import SimpleNamespace

from maljan.pipeline.events import claims_to_payload, scrub, summarize_claims
from tests.credential_shapes import prefixed_key


def _claim(text: str) -> SimpleNamespace:
    return SimpleNamespace(claim=text, evidence_ref="", confidence=0.5, technique_id=None)


def test_a_key_straddling_the_cut_leaves_no_head_in_the_payload() -> None:
    key = prefixed_key("key-", 32)
    text = "a" * (400 - 12) + " " + key + " tail"
    (shown,) = claims_to_payload([_claim(text)])
    assert key[:12] not in shown["claim"]
    assert scrub(shown["claim"]) == shown["claim"]


def test_a_key_straddling_the_headline_cut_leaves_no_head() -> None:
    key = prefixed_key("key-", 32)
    text = "word " * 45 + key[:20] + key[20:] + " tail"
    headline = summarize_claims([_claim(text)], speaker="x")
    assert key[:12] not in headline


def test_a_claim_keeps_its_lines() -> None:
    (shown,) = claims_to_payload([_claim("first\nsecond")])
    assert shown["claim"] == "first\nsecond"


def _urls(n: int) -> str:
    return " ".join(f"http://host{i}.example/path{i}" for i in range(n))


def test_a_claim_of_many_urls_keeps_its_first_urls() -> None:
    text = "Contacts " + _urls(40)
    (shown,) = claims_to_payload([_claim(text)])
    assert "host0.example" in shown["claim"] and "host1.example" in shown["claim"]
    assert len(shown["claim"]) <= 400
    headline = summarize_claims([_claim(text)], speaker="x")
    assert "host0.example" in headline


def test_a_huge_claim_is_scrubbed_over_a_window_only() -> None:
    import time

    key = prefixed_key("key-", 32)
    text = "word " * 79 + key + " " + "filler " * 600_000
    began = time.perf_counter()
    (shown,) = claims_to_payload([_claim(text)])
    assert time.perf_counter() - began < 1.0
    assert key[:12] not in shown["claim"]
    assert len(shown["claim"]) <= 400


def test_a_huge_single_token_is_masked_at_the_window_edge() -> None:
    import time

    text = "q" * 4_000_000
    began = time.perf_counter()
    (shown,) = claims_to_payload([_claim(text)])
    headline = summarize_claims([_claim(text)], speaker="x")
    assert time.perf_counter() - began < 1.0
    assert shown["claim"].startswith("***") and "q" * 8 not in shown["claim"]
    assert "q" * 8 not in headline


def test_an_argument_of_many_urls_keeps_its_first_urls() -> None:
    from maljan.pipeline.events import summarize_args

    shown = summarize_args({"text": "Contacts " + _urls(40)})
    assert "host0.example" in shown
