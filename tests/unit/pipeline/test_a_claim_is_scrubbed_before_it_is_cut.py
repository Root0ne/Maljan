"""A claim sent as an event is scrubbed and then cut, never cut and then scrubbed.

A cut in front of the scrub leaves the head of a secret, which no longer has the
shape the scrub knows, and the event carries it.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

from maljan.pipeline.events import claims_to_payload, scrub, summarize_claims
from tests.credential_shapes import prefixed_key
from tests.linear_cost import assert_scales


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
    key = prefixed_key("key-", 32)

    def huge(filler: int) -> str:
        return "word " * 79 + key + " " + "filler " * filler

    (shown,) = claims_to_payload([_claim(huge(600_000))])
    assert_scales(
        lambda filler: _claim(huge(filler)), 75_000, lambda claim: claims_to_payload([claim])
    )
    assert key[:12] not in shown["claim"]
    assert len(shown["claim"]) <= 400


def test_a_huge_single_token_is_masked_at_the_window_edge() -> None:
    text = "q" * 4_000_000
    (shown,) = claims_to_payload([_claim(text)])
    headline = summarize_claims([_claim(text)], speaker="x")

    def both(size: int) -> Callable[[], Any]:
        claim = _claim("q" * size)
        return lambda: (claims_to_payload([claim]), summarize_claims([claim], speaker="x"))

    assert_scales(both, 500_000)
    assert shown["claim"].startswith("***") and "q" * 8 not in shown["claim"]
    assert "q" * 8 not in headline


def test_an_argument_of_many_urls_keeps_its_first_urls() -> None:
    from maljan.pipeline.events import summarize_args

    shown = summarize_args({"text": "Contacts " + _urls(40)})
    assert "host0.example" in shown
