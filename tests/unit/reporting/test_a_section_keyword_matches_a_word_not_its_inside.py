"""A section's keyword picks a claim where a word begins, never inside an unrelated word.

``rsa`` used to match inside ``rehearsal`` and ``conversation``, ``c2`` inside a
hex address such as ``0xc2c4``: the encryption section was asked for a claim
about an HTTP beacon. A short keyword now matches a whole word or a word's
prefix (``RSA1``, ``rsaenh``, ``KeyBlob``) or a word's end (``ARC4``,
``pubkey``, ``schtasks``, ``createmutexw``), never in an ordinary word that
ends with it by chance (``monkey``) nor inside a hex number; a stem of six or more letters
still matches inside a compound word (``deobfuscation``, ``stackstrings``).
"""

from __future__ import annotations

import time

import pytest

from maljan.reporting.evidence_bundles import _SECTION_CLAIM_KEYWORDS, _filter_claims, mentions


def _claim(text: str) -> dict[str, str]:
    return {"claim": text, "evidence_ref": "", "agent": "static", "label": "static claim 1"}


ENCRYPTION = _SECTION_CLAIM_KEYWORDS["encryption_scheme"]
C2 = _SECTION_CLAIM_KEYWORDS["command_and_control"]


@pytest.mark.parametrize(
    "text",
    [
        "The beacon reaches http://rehearsal.example.net/beacon",
        "17 capture conversations, none to the domain",
        "a monkey patch of the loader",
        "the caesar shift table",
    ],
)
def test_a_short_keyword_inside_an_unrelated_word_picks_nothing(text: str) -> None:
    assert not mentions(text, ENCRYPTION)


@pytest.mark.parametrize(
    "text",
    [
        "imports CryptAcquireContextW and CryptEncrypt",
        "a BCRYPT_RSAKEY_BLOB of type RSA1",
        "loads rsaenh.dll",
        "a 16-byte KeyBlob is imported",
        "RC4 with a hard-coded key",
        "XOR-decoded strings",
        "AES-256 in CBC mode",
    ],
)
def test_a_real_crypto_token_is_still_picked(text: str) -> None:
    assert mentions(text, ENCRYPTION)


def test_a_hex_address_is_no_command_and_control() -> None:
    assert not mentions("fcn.0xc2c4 dispatches through 0x3c2c", C2)
    assert mentions("the C2 server answers", C2)
    assert mentions("an HTTP POST to the panel", C2)


@pytest.mark.parametrize(
    ("text", "section"),
    [
        ("an ARC4 key schedule", "encryption_scheme"),
        ("a pxor loop over the blob", "encryption_scheme"),
        ("the embedded pubkey", "encryption_scheme"),
        ("loads winhttp.dll", "communications"),
        ("an xmlhttp object", "communications"),
        ("runs schtasks /create", "host_identifiers"),
        ("calls createmutexw", "host_identifiers"),
        ("opens a namedpipe", "host_identifiers"),
        ("apihashing over the export table", "string_resolution"),
        ("a djb2hash of each name", "string_resolution"),
        ("a multistage loader", "payloads"),
        ("the image is repacked", "packing_obfuscation"),
    ],
)
def test_a_short_keyword_where_a_word_ends_is_picked(text: str, section: str) -> None:
    assert mentions(text, _SECTION_CLAIM_KEYWORDS[section])


@pytest.mark.parametrize(
    "text", ["a monkey patch", "two monkeys", "and vice versa", "see the footnote"]
)
def test_an_ordinary_word_ending_with_a_keyword_picks_nothing(text: str) -> None:
    assert not mentions(text, ENCRYPTION + _SECTION_CLAIM_KEYWORDS["ransom_note"])


@pytest.mark.parametrize("text", ["toc2", "the epic2 file", "abc2 and a1c2", "keyc2"])
def test_a_two_character_keyword_does_not_end_a_word(text: str) -> None:
    assert not mentions(text, C2)


@pytest.mark.parametrize(
    "text", ["the C2 server", "C2Server answers", "c2-domain.example", "ratC2 beacons", "c2s"]
)
def test_a_two_character_keyword_still_starts_a_word(text: str) -> None:
    assert mentions(text, C2)


def test_no_keyword_starts_or_ends_inside_a_hex_number() -> None:
    for text in ("0xC2C4", "0xc2c4", "at 0C2C4h", "digest 1360bc03c2c2"):
        assert not mentions(text, C2), text
    assert mentions("the C2 at 0x140001000", C2)


def test_a_stem_still_matches_inside_a_compound_word() -> None:
    packing = _SECTION_CLAIM_KEYWORDS["packing_obfuscation"]
    assert mentions("[decoding / deobfuscation — confirmed]", packing)
    assert mentions("the payload is unpacked in memory", packing)
    assert mentions(
        "obfuscated stackstrings at 0x9484", _SECTION_CLAIM_KEYWORDS["string_resolution"]
    )


def test_case_and_wide_lowering_keep_every_index() -> None:
    # "İ" lowers to two characters; the word starts must still line up.
    assert mentions("İİİ RSA key", ENCRYPTION)
    assert not mentions("İİİ rehearsal", ENCRYPTION)


def test_the_filter_keeps_the_claims_it_matches_in_order() -> None:
    claims = [_claim("rehearsal beacon"), _claim("RSA1 key blob"), _claim("XOR loop")]
    assert [c["claim"] for c in _filter_claims(claims, ENCRYPTION)] == ["RSA1 key blob", "XOR loop"]
    assert _filter_claims(claims, ()) == []


def test_matching_stays_linear_on_a_hostile_text() -> None:
    def took(size: int) -> float:
        text = "aB" * size + " rehearsal" * size
        start = time.perf_counter()
        for _ in range(5):
            mentions(text, ENCRYPTION + C2)
        return time.perf_counter() - start

    small, large = took(2_000), took(20_000)
    assert large < small * 30, (small, large)
