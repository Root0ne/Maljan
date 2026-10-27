"""A TECHNIQUE line that writes a note in brackets after an id is read by what the note says.

Models write a note beside an id ("T1071.001 (configured channel)"), and the
reader kept every such line whole and asked about it, so the claim carried no
technique: a paid run asked twenty times. A note is read only by an allow-list:
it is neutral, and the id is read, when every content word of it is a word the
vendored data writes for that id (its catalogue name, its card, its API rule)
or a reference or layout word of a closed set ("claim", "per", "one",
"listed", "channel" ...), with only the function words of another closed set
between them ("the", "of", "this" ...): an ordinary word that hedges or
negates ("perhaps", "cannot", "formerly") is no function word. A note that
says the id is not asserted, followed only by where or by what ("T1547.001
(not supported by the traced code)", "none (T1055 withdrawn)"), claims none,
which is what the unread line claimed too. Any other note keeps the line whole
and asked about, as before: a doubt or a hedge (even one the id's card
writes), a provenance, a tool's word, a word of fewer than three letters, a
slash in a word, a second clause after a negation, or a negating note after a
list, which may be said of every id of it. Ids written as a list separated by semicolons
are a list. A dash before a bracketed note claims none as "none" does, and a
one-word catalogue name that is an ordinary English word ("At") names a
technique only written with its capital.
"""

from __future__ import annotations

import time

import pytest

from maljan.agents.base_agent import read_claim_blocks, read_technique_line
from maljan.pipeline.validation import TECHNIQUE_LINE_UNREAD_CODE, parse_violations
from maljan.schemas.isr_models import AgentISR


@pytest.mark.parametrize(
    ("line", "ids"),
    [
        # The id's own vendored words.
        ("T1071.001 (configured channel)", ("T1071.001",)),
        ("T1012 (query)", ("T1012",)),
        ("T1218.011 (rundll32)", ("T1218.011",)),
        # Reference and layout words.
        ("T1071.001 (same channel as claim 18)", ("T1071.001",)),
        ("T1071.001 (entry ev_0024, round 2)", ("T1071.001",)),
        ("T1071.001 (the channel of this claim)", ("T1071.001",)),
        # A note on each id of a list.
        ("T1057 (process); T1083 (file); T1012 (registry)", ("T1057", "T1083", "T1012")),
        ("T1027 (obfuscated strings); T1140 (decode)", ("T1027", "T1140")),
        ("T1622 (debugger), T1218.011 (rundll32)", ("T1622", "T1218.011")),
        # A note on how a list is laid out.
        ("T1082, T1016, T1033 (one per command)", ("T1082", "T1016", "T1033")),
        ("T1082, T1016, T1033 (one per command, as listed).", ("T1082", "T1016", "T1033")),
        ("T1105; T1620 (memory)", ("T1105", "T1620")),
        # A list separated by semicolons.
        ("T1027; T1140", ("T1027", "T1140")),
    ],
)
def test_an_id_with_a_note_of_its_own_words_is_read(line: str, ids: tuple[str, ...]) -> None:
    assert read_technique_line(line) == (ids, None)


@pytest.mark.parametrize(
    "line",
    [
        "T1547.001 (not supported)",
        "T1082 (not attributed to the sample)",
        "T1547.001 (rejected)",
        "NONE (T1055 not supported)",
        "none (T1547.001 is not supported by the traced code)",
        "none (T1547.001 withdrawn)",
        "none asserted (T1055 not supported by code evidence)",
        "none supported (T1547.001 not established)",
        "none supported (T1055 withdrawn from my round-0 claim 11)",
        # A dash before a bracketed note, as "none" with words after it.
        "— (provenance)",
        "— (lead-level)",
        # An ordinary word in small letters that is a one-word catalogue name.
        "none asserted at this level",
    ],
)
def test_a_line_that_asserts_no_id_claims_none(line: str) -> None:
    assert read_technique_line(line) == ((), None)


# Notes no allow-list word makes neutral, on an id whose vendored words hold none of them.
NOT_ALLOWED = (
    "unlikely",
    "improbable",
    "hypothetical",
    "TBD",
    "low conf",
    "false positive",
    "FP",
    "n/a",
    "excluded",
    "retracted",
    "wrong",
    "superseded",
    "dead code",
    "unreachable",
    "stub",
    "disabled",
    "capa rule",
    "per VirusTotal",
    "YARA hit",
    "sandbox",
    "heuristic",
    "claimed by static",
    "code path",
    "in-memory path",
    "see entry ev_0024",
)
# Hedges and negations, an ordinary stopword list's words among them, asked
# whatever the id's own vendored words hold ("otherwise" is a card's word).
HEDGES = (
    "perhaps",
    "cannot",
    "seems",
    "nothing",
    "formerly packed",
    "otherwise read",
    "as above, rather",
    "formerly",
    "rather",
    "except",
    "whether",
    "less",
    "otherwise",
    "however",
    "although",
    "yet",
    "almost",
    "against",
)


@pytest.mark.parametrize("note", NOT_ALLOWED)
def test_a_note_outside_the_allow_list_keeps_the_line_whole(note: str) -> None:
    line = f"T1071.001 ({note})"
    assert read_technique_line(line) == ((), line)


@pytest.mark.parametrize("note", HEDGES)
@pytest.mark.parametrize("technique", ["T1071.001", "T1055", "T1027"])
def test_a_hedge_or_a_negation_keeps_the_line_whole(note: str, technique: str) -> None:
    line = f"{technique} ({note})"
    assert read_technique_line(line) == ((), line)


@pytest.mark.parametrize(
    "line",
    [
        "T1218.011 (LOLBin hit [ev_0011])",
        # A doubt, an observation state, a provenance or a confidence.
        "T1071.001 (candidate)",
        "T1497.001 (candidate only).",
        "T1071.001 (code path only).",
        "T1071.001 (not observed in run)",
        "T1055 (capability only)",
        "T1027.005 (capa's assertion only)",
        "T1027 (rule-asserted [ev_0008])",
        "T1027.007 (my mapping)",
        "T1622 (discovery/evasion context)",
        "T1564.004 (ADS storage, candidate, 0.6)",
        "T1070.004 (delete, 0.6); T1564.004 (ADS, 0.55)",
        "T1218.011 (observed execution; initiator unattributed)",
        "T1218.011 (code capability only, not attributed observed behaviour)",
        # A negation followed by anything but where or by what.
        "T1218.011 (rule match; not attributed to the sample)",
        "T1547.001 (rejected by peer but I keep it)",
        "T1547.001 (withdrawn earlier, now reinstated)",
        "T1547.001 (not supported statically; sandbox shows it)",
        "T1055 (not attributed to the loader; the payload does it)",
        "T1547.001 (rejected for this binary, kept only to mark the hypothesis)",
        # Another id in the note, or a negation of anything but the id.
        "T1041 (T1048 not observed)",
        "T1071.001 (one claim covering the set; not nine separate claims)",
        # A negating note after a list may be said of every id of it.
        "T1027, T1140 (not supported)",
        "T1027 (candidate), T1140",
        # A note that is not the last thing on the line.
        "T1027.007 (dynamic resolution). capa's T1027.005 is not adopted.",
        # Words after an id with no bracket.
        "T1055 is not supported for the three named APIs",
        "T1218.011 for the rundll32 hits only",
        # A "none" line whose bracketed id is not negated, or names a technique.
        "none asserted (T1105 if a download is shown)",
        "none for the sample (T1547.014 is the sandbox's label)",
        "None; Process Injection is likely",
        "— (supports T1027 at application level)",
        "none (At job)",
        # A dash with no bracketed note after it.
        "— provenance",
    ],
)
def test_a_note_that_bears_on_the_id_keeps_the_line_whole(line: str) -> None:
    assert read_technique_line(line) == ((), line)


def test_a_read_note_leaves_no_question() -> None:
    claims = read_claim_blocks(
        "CLAIM: The beacon posts its report to the configured hosts over HTTPS.\n"
        "EVIDENCE: [ev_0024] request routine\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: T1071.001 (configured channel)\n"
        "\n"
        "CLAIM: No autostart value is written.\n"
        "EVIDENCE: [ev_0024] install routine\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: none (T1547.001 not supported)\n"
    ).claims
    isr = AgentISR(agent_id="static", domain="static", claims=claims)

    assert [(c.technique_id, c.technique_line) for c in claims] == [
        ("T1071.001", None),
        (None, None),
    ]
    assert TECHNIQUE_LINE_UNREAD_CODE not in [v.code for v in parse_violations(isr)]


def test_a_line_of_notes_is_read_in_linear_time() -> None:
    def cost(repeats: int) -> float:
        line = "; ".join(["T1071.001 (configured channel as listed)"] * repeats)
        start = time.perf_counter()
        read_technique_line(line)
        return time.perf_counter() - start

    cost(50)
    small = cost(280)
    large = cost(2800)  # about 112 KB of notes
    assert large <= max(small, 1e-3) * 30
