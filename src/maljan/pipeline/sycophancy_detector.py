"""Sycophancy detector for the multi-agent negotiation loop.

Agents in a multi-agent debate tend to converge on the dominant opinion
regardless of evidence quality — a phenomenon known as "sycophancy" or
the "Silent Agreement" problem (Free-MAD, arXiv:2509.11035; CONSENSAGENT).

This module detects premature convergence by measuring the cosine similarity
between agent ISR text summaries. If the similarity is suspiciously high
within too few rounds, a "devil's advocate" directive is injected into the
revision prompt to force genuine disagreement.

Literature basis:
  - CONSENSAGENT (Pitre et al., ACL 2025): trigger-based prompt refinement.
  - Free-MAD (arXiv:2509.11035): Silent Agreement problem.
  - Wu et al. (arXiv:2511.07784): majority pressure suppresses correction.
  - Ohagi et al. (ACL 2024): AI agents polarise in echo chambers.
"""

from __future__ import annotations

import math

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR

# Similarity threshold above which convergence is flagged as suspicious.
# 0.90 = agents' summaries are 90%+ similar — almost certainly sycophantic.
SYCOPHANCY_THRESHOLD: float = 0.90

DEVIL_ADVOCATE_DIRECTIVE: str = (
    "IMPORTANT: The other analysts appear to be converging on a shared conclusion. "
    "You MUST challenge this consensus. Find the strongest counter-evidence in your "
    "raw data. Identify at least one claim in the current consensus that your data "
    "does NOT support, and include it in your dissent_items. Do not simply agree."
)


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=False))


def _norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Pure-Python cosine similarity — no numpy/scipy dependency at import time."""
    na, nb = _norm(a), _norm(b)
    if na == 0.0 or nb == 0.0:
        return 0.0
    return _dot(a, b) / (na * nb)


def _bag_of_words_vector(text: str, vocab: dict[str, int]) -> list[float]:
    """Simple BoW vector over a shared vocabulary."""
    vec = [0.0] * len(vocab)
    for token in text.lower().split():
        if token in vocab:
            vec[vocab[token]] += 1.0
    return vec


def _build_vocab(texts: list[str]) -> dict[str, int]:
    vocab: dict[str, int] = {}
    for text in texts:
        for token in text.lower().split():
            if token not in vocab:
                vocab[token] = len(vocab)
    return vocab


def detect_sycophancy(
    isrs: list[AgentISR],
    threshold: float = SYCOPHANCY_THRESHOLD,
) -> bool:
    """Return True if any pair of agent ISRs exceeds the similarity threshold.

    Uses a lightweight bag-of-words cosine similarity — no heavy ML dependencies.
    At negotiation time we want this to be fast and dependency-free.

    Args:
        isrs: List of AgentISR objects from the current round.
        threshold: Cosine similarity value above which sycophancy is flagged.

    Returns:
        True if at least one pair of ISRs is suspiciously similar.
    """
    if len(isrs) < 2:
        return False

    summaries = [isr.to_text_summary() for isr in isrs]
    vocab = _build_vocab(summaries)
    vectors = [_bag_of_words_vector(s, vocab) for s in summaries]

    for i in range(len(vectors)):
        for j in range(i + 1, len(vectors)):
            sim = _cosine_similarity(vectors[i], vectors[j])
            logger.debug(
                "Sycophancy check: %s vs %s — similarity=%.3f",
                isrs[i].agent_id,
                isrs[j].agent_id,
                sim,
            )
            if sim > threshold:
                logger.warning(
                    "Sycophancy detected between '%s' and '%s' (sim=%.3f > %.2f). "
                    "Devil's advocate directive will be injected.",
                    isrs[i].agent_id,
                    isrs[j].agent_id,
                    sim,
                    threshold,
                )
                return True

    return False


def build_revision_directive(
    is_sycophantic: bool,
    mediator_feedback: str,
) -> str:
    """Compose the revision prompt directive for agents.

    If sycophancy is detected, prepend the devil's advocate directive to the
    mediator feedback to force genuine re-evaluation.

    Args:
        is_sycophantic: Whether sycophancy was detected this round.
        mediator_feedback: The mediator's contradiction summary.

    Returns:
        The final directive string to inject into each agent's revision prompt.
    """
    if is_sycophantic:
        return f"{DEVIL_ADVOCATE_DIRECTIVE}\n\n{mediator_feedback}"
    return mediator_feedback
