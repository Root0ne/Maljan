"""Model tool-call syntax is scaffolding, not a finding.

A live job's ``static_r2`` analyst -- the static
analyst under r2 tools, on the local model -- produced ISR claims whose text
was raw tool-call syntax, and the Pipeline tab showed them to the operator as
findings. A local model that emits its tool calls into the assistant channel
(rather than through the API's own tool-call field) leaves those blocks in the
text the ISR extraction then reads, and nothing in either claim parser knew
they were not prose.

Both parsers strip the scaffolding before deriving claims, and a claim whose
content is nothing but scaffolding is dropped rather than shown empty.
"""

from __future__ import annotations

import pytest

from maljan.agents.base_agent import parse_structured_claims, strip_tool_call_scaffolding
from maljan.agents.static_analyst import _parse_claim_blocks

# The captured shape: a Qwen-family model writing its call into the answer.
CAPTURED = (
    "<tool_call>\n"
    '{"name": "list_imports", "arguments": {"path": "/data/samples/ab12.exe"}}\n'
    "</tool_call>"
)


@pytest.mark.parametrize(
    ("label", "scaffolding"),
    [
        ("the captured tool_call block", CAPTURED),
        (
            "a function_call block",
            '<function_call>{"name": "read_strings", "arguments": {}}</function_call>',
        ),
        (
            "a fenced json tool invocation",
            '```json\n{"name": "list_imports", "arguments": {"path": "/x"}}\n```',
        ),
    ],
)
def test_scaffolding_is_stripped_out_of_the_text(label, scaffolding):
    text = f"The sample imports VirtualAlloc.\n{scaffolding}\nIt then writes to a new region."
    cleaned = strip_tool_call_scaffolding(text)
    assert "tool_call" not in cleaned, label
    assert "function_call" not in cleaned, label
    assert "arguments" not in cleaned, label
    assert "The sample imports VirtualAlloc." in cleaned, label
    assert "It then writes to a new region." in cleaned, label


def test_a_truncated_tool_call_takes_the_rest_of_the_output_with_it():
    """A generation cut off mid-call leaves an opening tag and half an argument
    object, and there is no prose after it to keep -- that is what truncated
    means."""
    text = (
        "The sample imports VirtualAlloc.\n"
        '<tool_call>\n{"name": "list_imports", "arguments": {"path": "/x"'
    )
    cleaned = strip_tool_call_scaffolding(text)
    assert cleaned == "The sample imports VirtualAlloc."


def test_a_fenced_json_block_that_is_evidence_is_kept():
    """Only a tool invocation goes; a model quoting real JSON evidence stays."""
    text = '```json\n{"imports": ["VirtualAlloc", "WriteProcessMemory"]}\n```'
    assert "VirtualAlloc" in strip_tool_call_scaffolding(text)


def test_a_claim_that_is_only_scaffolding_is_dropped():
    text = (
        f"CLAIM: {CAPTURED}\n"
        "EVIDENCE: r2 output\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: NONE\n"
        "---\n"
        "CLAIM: The sample resolves APIs at runtime.\n"
        "EVIDENCE: GetProcAddress in the import table\n"
        "CONFIDENCE: 0.7\n"
        "TECHNIQUE: T1027\n"
    )
    for parser in (parse_structured_claims, _parse_claim_blocks):
        claims = parser(text)
        assert len(claims) == 1, f"{parser.__name__} kept the scaffolding claim"
        assert claims[0].claim == "The sample resolves APIs at runtime."
        assert claims[0].technique_id == "T1027"


def test_scaffolding_around_a_real_claim_leaves_the_claim_intact():
    text = (
        f"{CAPTURED}\n"
        "CLAIM: The sample allocates executable memory.\n"
        "EVIDENCE: VirtualAlloc with PAGE_EXECUTE_READWRITE\n"
        "CONFIDENCE: 0.9\n"
        "TECHNIQUE: T1055\n"
    )
    for parser in (parse_structured_claims, _parse_claim_blocks):
        claims = parser(text)
        assert len(claims) == 1, parser.__name__
        assert claims[0].claim == "The sample allocates executable memory."
        assert "tool_call" not in claims[0].claim


def test_an_ordinary_report_is_returned_unchanged():
    """No scaffolding, no rewriting: the parsers behave exactly as before."""
    text = (
        "CLAIM: The sample contacts a hardcoded host.\n"
        "EVIDENCE: string 'evil.example'\n"
        "CONFIDENCE: 0.6\n"
        "TECHNIQUE: T1071\n"
    )
    assert strip_tool_call_scaffolding(text) == text
    for parser in (parse_structured_claims, _parse_claim_blocks):
        claims = parser(text)
        assert len(claims) == 1
        assert claims[0].claim == "The sample contacts a hardcoded host."
        assert claims[0].evidence_ref == "string 'evil.example'"
        assert claims[0].confidence == pytest.approx(0.6)
        assert claims[0].technique_id == "T1071"


def _isr_from_text(text: str):
    """The free-text ISR path of a real analyst, with no LLM behind it.

    ``__new__`` rather than a constructor: ``_text_to_isr`` reads only the
    agent's name and its own class attributes, and building a StaticAnalyst
    for real would need a model, a provider and a job.
    """
    import logging

    from maljan.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "static_r2"
    analyst.logger = logging.getLogger("test")
    return analyst._text_to_isr(text, revision_round=1)


def test_the_free_text_path_never_turns_a_tool_call_into_a_claim():
    isr = _isr_from_text(
        f"{CAPTURED}\nThe sample allocates executable memory and copies a payload into it."
    )
    assert len(isr.claims) == 1
    assert "tool_call" not in isr.claims[0].claim
    assert isr.claims[0].claim.startswith("The sample allocates")


def test_a_report_that_is_only_scaffolding_yields_no_claims():
    assert _isr_from_text(f"{CAPTURED}\n{CAPTURED}").claims == []


# --- C1 follow-up: every free-text ISR field, not only the claim -------------
#
# Re-review of the first C1 commit: the stripping reached ``claim`` and the
# free-text path, and stopped there. A model that writes a tool call while it
# is citing an artifact puts the block on the EVIDENCE line instead, and that
# text went into the ISR untouched -- it reaches the operator on the same card,
# under the claim it was supposed to support. The DISPUTES section is filled
# from model output the same way and had the same hole.


def test_scaffolding_on_the_evidence_line_does_not_reach_the_isr():
    text = (
        "CLAIM: The sample allocates executable memory.\n"
        f"EVIDENCE: VirtualAlloc with PAGE_EXECUTE_READWRITE {CAPTURED}\n"
        "CONFIDENCE: 0.9\n"
        "TECHNIQUE: T1055\n"
    )
    for parser in (parse_structured_claims, _parse_claim_blocks):
        claims = parser(text)
        assert len(claims) == 1, parser.__name__
        assert "tool_call" not in claims[0].evidence_ref, parser.__name__
        assert "arguments" not in claims[0].evidence_ref, parser.__name__
        assert claims[0].evidence_ref.startswith("VirtualAlloc"), parser.__name__
        # The claim it supports is untouched by the evidence's own cleaning.
        assert claims[0].claim == "The sample allocates executable memory."


def test_evidence_that_is_only_scaffolding_leaves_the_claim_unsourced():
    """The two parsers differ, as they already do for a missing EVIDENCE line.

    ``parse_structured_claims`` is the lenient one: a finding without a
    citation is still a finding, recorded as unsourced. ``_parse_claim_blocks``
    is the strict one and requires a citation, so a block whose only evidence
    was a tool call fails the requirement it already had.
    """
    text = (
        "CLAIM: The sample resolves APIs at runtime.\n"
        f"EVIDENCE: {CAPTURED}\n"
        "CONFIDENCE: 0.7\n"
        "TECHNIQUE: T1027\n"
    )
    lenient = parse_structured_claims(text)
    assert len(lenient) == 1
    assert lenient[0].claim == "The sample resolves APIs at runtime."
    assert lenient[0].evidence_ref == ""

    assert _parse_claim_blocks(text) == []


def test_a_dispute_item_that_is_scaffolding_is_not_a_dispute():
    from maljan.agents.static_analyst import _parse_disputes

    text = (
        "DISPUTES:\n"
        "- The network analyst's C2 attribution is unsupported.\n"
        f"- {CAPTURED}\n"
        "- The dropped file is a decoy.\n"
        "SUMMARY: done\n"
    )
    disputes = _parse_disputes(text)
    assert disputes == [
        "The network analyst's C2 attribution is unsupported.",
        "The dropped file is a decoy.",
    ]


def test_a_multi_line_tool_call_inside_disputes_is_removed_whole():
    """The block spans lines, so a per-line check alone would never see it."""
    from maljan.agents.static_analyst import _parse_disputes

    text = (
        "DISPUTES:\n"
        "- <tool_call>\n"
        '  {"name": "list_imports", "arguments": {"path": "/x"}}\n'
        "  </tool_call>\n"
        "- The dropped file is a decoy.\n"
    )
    assert _parse_disputes(text) == ["The dropped file is a decoy."]


def test_an_ordinary_disputes_section_is_unchanged():
    from maljan.agents.static_analyst import _parse_disputes

    text = "DISPUTES:\n- One thing.\n- Another thing.\n"
    assert _parse_disputes(text) == ["One thing.", "Another thing."]
