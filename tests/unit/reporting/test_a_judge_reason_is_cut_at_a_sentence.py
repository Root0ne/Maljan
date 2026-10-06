"""A judge's reason in the ATT&CK table is cut at a sentence, under one rule.

A dropped technique's reason was cut at a fixed width inside the status cell,
mid-word, while a kept one printed whole, the judge's own working included
("Wait, looking at …"). Both now print whole sentences up to the first that
opens the model's working and as many as fit one width, marked where anything
is left out. The record keeps the reason whole.
"""

from __future__ import annotations

from maljan.reporting.judge_reasons import (
    JUDGE_REASON_WIDTH,
    JUDGE_WORKING_ONLY,
    judge_reason_shown,
    judge_reasons_shown,
)
from maljan.utils.marked_cut import CUT_MARK

FIRST = "The evidence shows the routine decoding its strings."
SECOND = "This matches the technique named."


def test_a_short_reason_prints_whole() -> None:
    assert judge_reason_shown(f"{FIRST} {SECOND}") == f"{FIRST} {SECOND}"


def test_the_model_s_working_is_not_printed_as_a_reason() -> None:
    reason = f"{FIRST} Wait, looking at the check list again, it is not there. So keep."

    assert judge_reason_shown(reason) == f"{FIRST} {CUT_MARK}"


def test_a_reason_that_is_all_working_says_so() -> None:
    assert judge_reason_shown("Hmm, let me look again.") == JUDGE_WORKING_ONLY


def test_a_long_reason_is_cut_at_a_sentence_and_marked() -> None:
    reason = " ".join([FIRST] * 10)
    shown = judge_reason_shown(reason)

    assert shown.endswith(f". {CUT_MARK}")
    assert len(shown) <= JUDGE_REASON_WIDTH + len(CUT_MARK) + 1
    assert shown.removesuffix(f" {CUT_MARK}").count(FIRST) == len(shown) // (len(FIRST) + 1)


def test_a_first_sentence_longer_than_the_width_is_cut_at_a_word() -> None:
    sentence = "The evidence shows " + "a decoding routine and " * 20 + "nothing else."
    shown = judge_reason_shown(sentence)

    assert shown.endswith(CUT_MARK)
    assert len(shown) <= JUDGE_REASON_WIDTH
    assert shown.removesuffix(CUT_MARK).split()[-1] in {"a", "decoding", "routine", "and"}


def test_both_openers_are_read_and_the_rest_of_the_text_is_kept() -> None:
    text = (
        f"published; kept by the judge when asked ({FIRST} Wait, (no) it is not.)"
        f"; the judge dropped it ({SECOND} Let me check.), asked after a finding"
    )
    said, through = judge_reasons_shown(text)

    assert said == (
        f"published; kept by the judge when asked ({FIRST} {CUT_MARK})"
        f"; the judge dropped it ({SECOND} {CUT_MARK}), asked after a finding"
    )
    assert said[:through].endswith(f"{CUT_MARK})")


def test_a_text_with_no_judge_reason_is_unchanged() -> None:
    text = "TECHNIQUE T1059.004 declares other platforms (not this one)."

    assert judge_reasons_shown(text) == (text, 0)


def test_the_attck_table_prints_the_reason_by_the_rule() -> None:
    from maljan.reporting.models import (
        CapabilityCell,
        FileHashes,
        MalwareReport,
        SampleIdentity,
    )
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    working = "Wait, looking at the check list again, the id is not on it."
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        capability_matrix=[
            CapabilityCell(
                tactic="TA0005",
                tactic_name="Defense Evasion",
                technique_id="T1140",
                technique_name="Deobfuscate/Decode Files or Information",
                evidence=["The routine decodes its strings."],
                note=f"kept by the judge when asked ({FIRST} {working})",
            ),
            CapabilityCell(
                tactic="TA0007",
                tactic_name="Discovery",
                technique_id="T1082",
                technique_name="System Information Discovery",
                evidence=["The routine reads the host name."],
                not_published=f"the judge dropped it ({' '.join([SECOND] * 12)})",
            ),
        ],
    )
    markdown = MarkdownRenderer().render(report)

    assert f"kept by the judge when asked ({FIRST} {CUT_MARK})" in markdown
    assert "Wait, looking" not in markdown
    dropped = markdown.split("the judge dropped it (", 1)[1].split(")", 1)[0]
    assert dropped.endswith(f". {CUT_MARK}")
    assert len(dropped) <= JUDGE_REASON_WIDTH + len(CUT_MARK) + 1
