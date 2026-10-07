"""A TECHNIQUE line that writes an id with its catalogue name in brackets is that id.

Models write "T1027 (Obfuscated Files or Information)" on a technique line,
and the reader kept such a line whole and asked about it, so the claim carried
no technique. When the bracketed words are the vendored catalogue's own name
for the id they follow, the bracket names the id and decides nothing: the id
is read. Any other words in brackets keep the line whole, as before.
"""

from __future__ import annotations

import pytest

from maljan.agents.base_agent import read_claim_blocks, read_technique_line


@pytest.mark.parametrize(
    ("line", "ids"),
    [
        ("T1027 (Obfuscated Files or Information)", ("T1027",)),
        ("T1140 (Deobfuscate/Decode Files or Information)", ("T1140",)),
        ("t1140 (deobfuscate decode files or information)", ("T1140",)),
        ("T1055.012 (Process Hollowing)", ("T1055.012",)),
        ("T1055.012 (Process Injection: Process Hollowing)", ("T1055.012",)),
        ("**T1106 (Native API)**", ("T1106",)),
        (
            "T1027 (Obfuscated Files or Information), T1106 (Native API)",
            ("T1027", "T1106"),
        ),
        ("T1027 (Obfuscated Files or Information) and T1106", ("T1027", "T1106")),
    ],
)
def test_an_id_with_its_own_catalogue_name_is_read(line: str, ids: tuple[str, ...]) -> None:
    assert read_technique_line(line) == (ids, None)


@pytest.mark.parametrize(
    "line",
    [
        # Words that are not the catalogue's name for the id stay unread.
        "T1027 (Obfuscated/Hidden Files and Information)",
        "T1055 (unproven)",
        "T1027 (candidate)",
        # Another technique's name beside an id is not that id's name.
        "T1027 (Native API)",
        # A sub-technique's name beside its parent is not the parent's name.
        "T1055 (Process Hollowing)",
        # An id the catalogue does not have has no name to compare.
        "T1999 (Obfuscated Files or Information)",
        "T1027 (Obfuscated Files or Information) or T1106",
    ],
)
def test_other_bracketed_words_keep_the_line_whole(line: str) -> None:
    assert read_technique_line(line) == ((), line)


def test_the_claim_carries_the_id_and_no_unread_line() -> None:
    (claim,) = read_claim_blocks(
        "CLAIM: The loader hides its strings until run time.\n"
        "EVIDENCE: [ev_0004] decoder routine\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: T1027 (Obfuscated Files or Information)\n"
    ).claims

    assert (claim.technique_id, claim.technique_line) == ("T1027", None)
