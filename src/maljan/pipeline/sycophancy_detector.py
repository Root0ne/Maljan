"""Sycophancy detector for the multi-agent negotiation loop.

Detects premature convergence between agent ISRs via bag-of-words cosine
similarity. When the similarity is suspiciously high, a "devil's advocate"
directive is injected into the revision prompt to force genuine disagreement.

Literature basis:
  - CONSENSAGENT (Pitre et al., ACL 2025): trigger-based prompt refinement.
  - Free-MAD (arXiv:2509.11035): Silent Agreement problem.
  - Wu et al. (arXiv:2511.07784): majority pressure suppresses correction.
  - Ohagi et al. (ACL 2024): AI agents polarise in echo chambers.
"""

from __future__ import annotations

import math
import re

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR

# Similarity threshold above which convergence is flagged as suspicious.
SYCOPHANCY_THRESHOLD: float = 0.90

# Minimum total token volume across all summaries before similarity is meaningful.
# Short or empty summaries can trivially produce 1.0 cosine — those should not
# count as sycophancy but as a content failure.
MIN_TOTAL_TOKENS: int = 32

DEVIL_ADVOCATE_DIRECTIVE: str = (
    "IMPORTANT: The other analysts appear to be converging on a shared conclusion. "
    "You MUST challenge this consensus. Find the strongest counter-evidence in your "
    "raw data. Identify at least one claim in the current consensus that your data "
    "does NOT support, and include it in your dissent_items. Do not simply agree."
)

# Unicode-aware word tokenizer; drops punctuation glued to JSON keys/paths.
_TOKEN_RE = re.compile(r"\w+", flags=re.UNICODE)


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def _dot(a: list[float], b: list[float]) -> float:
    return sum(x * y for x, y in zip(a, b, strict=True))


def _norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    na, nb = _norm(a), _norm(b)
    if na == 0.0 or nb == 0.0:
        return 0.0
    return _dot(a, b) / (na * nb)


def _bag_of_words_vector(tokens: list[str], vocab: dict[str, int]) -> list[float]:
    vec = [0.0] * len(vocab)
    for token in tokens:
        idx = vocab.get(token)
        if idx is not None:
            vec[idx] += 1.0
    return vec


def _build_vocab(token_lists: list[list[str]]) -> dict[str, int]:
    vocab: dict[str, int] = {}
    for tokens in token_lists:
        for token in tokens:
            if token not in vocab:
                vocab[token] = len(vocab)
    return vocab


def detect_sycophancy(
    isrs: list[AgentISR],
    threshold: float = SYCOPHANCY_THRESHOLD,
    iteration: int = 0,
) -> bool:
    """Return True if any pair of agent ISRs exceeds the similarity threshold.

    Args:
        isrs: ISRs from the current round.
        threshold: Cosine similarity threshold.
        iteration: Negotiation round counter. The first round (iteration<=0)
            never triggers sycophancy because agents have not had a chance to
            converge intentionally yet.

    Returns:
        True if a pair of summaries is suspiciously similar and content is
        substantive enough to be meaningful.
    """
    if iteration <= 0:
        return False
    if len(isrs) < 2:
        return False

    summaries = [isr.to_text_summary() for isr in isrs]
    token_lists = [_tokenize(s) for s in summaries]

    total_tokens = sum(len(t) for t in token_lists)
    if total_tokens < MIN_TOTAL_TOKENS:
        logger.debug(
            "Sycophancy check skipped: insufficient content (%d tokens < %d).",
            total_tokens,
            MIN_TOTAL_TOKENS,
        )
        return False

    vocab = _build_vocab(token_lists)
    vectors = [_bag_of_words_vector(t, vocab) for t in token_lists]

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


def build_revision_directive(is_sycophantic: bool, mediator_feedback: str) -> str:
    """Compose the revision prompt directive for agents."""
    if is_sycophantic:
        return f"{DEVIL_ADVOCATE_DIRECTIVE}\n\n{mediator_feedback}"
    return mediator_feedback
