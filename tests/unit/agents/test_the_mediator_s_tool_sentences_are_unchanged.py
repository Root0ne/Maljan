"""The mediator's sentences about a lookup, now module constants, are the same bytes as before.

They were written inline in ``JudgeAgent.mediate``; the run fingerprint reads
them as templates, so they moved to constants. What the model reads is
unchanged, the sha256 written into the first exactly where it was. The third
sentence, which told the mediator to use its tools only to resolve
contradictions, is gone: the sentence about the tools the request carries
follows the lookup (``mediator_system_prompt``).
"""

from __future__ import annotations

from maljan.agents.judge_agent import (
    MEDIATOR_LOOKUP_ONCE,
    MEDIATOR_LOOKUP_ONCE_BY_HASH,
)

SHA = "ab" * 32


def test_the_two_sentences_read_as_they_did() -> None:
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
