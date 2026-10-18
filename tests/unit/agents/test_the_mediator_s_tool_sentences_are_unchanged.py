"""The mediator's sentences about its tools, now module constants, are the same bytes as before.

They were written inline in ``JudgeAgent.mediate``; the run fingerprint reads
them as templates, so they moved to constants. What the model reads is
unchanged, the sha256 written into the first exactly where it was.
"""

from __future__ import annotations

from maljan.agents.judge_agent import (
    MEDIATOR_LOOKUP_ONCE,
    MEDIATOR_LOOKUP_ONCE_BY_HASH,
    MEDIATOR_TI_TOOLS,
)

SHA = "ab" * 32


def test_the_three_sentences_read_as_they_did() -> None:
    assert MEDIATOR_LOOKUP_ONCE_BY_HASH.replace("{sha256}", SHA) == (
        "You have reputation tools and no analyst has consulted one. "
        f"Look the sample's hash up once — its sha256 is {SHA} "
        "and it is in the sample identity block below — cite what comes back "
        "as evidence, and treat a reputation label as one source rather than "
        "as the verdict.\n"
    )
    assert MEDIATOR_LOOKUP_ONCE == (
        "You have reputation tools and no analyst has consulted one. "
        "Look the sample up once to settle its identity, cite what comes "
        "back as evidence, and treat a reputation label as one source "
        "rather than as the verdict.\n"
    )
    assert MEDIATOR_TI_TOOLS == (
        "You have Threat Intelligence tools to verify disputed "
        "IPs/domains/hashes — use them only to resolve contradictions.\n"
    )
