"""Sycophancy detector for the multi-agent negotiation loop.

``convergence_flags`` is what the debate reads: a revision that moved towards
a peer's answer beyond the sources both cite, with no citation added and no
tool call made, is flagged. Two answers alike because they restate the same
ledger rows are not sycophancy: the words of every entry or item both cite
are left out of both before they are compared, and only a rise across the
round (the analyst's answer before it against after it, each against the
peer's) is flagged. A flag is a fact told to the mediator and kept in the
round's record; it never overrides the mediator's consensus and never widens
a round that asks only the analysts the mediator named, and no analyst's prompt carries it.

``detect_sycophancy`` reads the flags the round recorded; given none, it
compares whole answers by bag-of-words cosine, as it always did.

Literature basis:
  - CONSENSAGENT (Pitre et al., ACL 2025): trigger-based prompt refinement.
  - Free-MAD (arXiv:2509.11035): Silent Agreement problem.
  - Wu et al. (arXiv:2511.07784): majority pressure suppresses correction.
  - Ohagi et al. (ACL 2024): AI agents polarise in echo chambers.
"""

from __future__ import annotations

import math
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any

from maljan.core.logger import logger
from maljan.schemas.isr_models import AgentISR

# Similarity threshold above which convergence is flagged as suspicious.
SYCOPHANCY_THRESHOLD: float = 0.90

# Minimum total token volume across all summaries before similarity is meaningful.
# Short or empty summaries can trivially produce 1.0 cosine — those should not
# count as sycophancy but as a content failure.
MIN_TOTAL_TOKENS: int = 32

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
    revised: Collection[str] | None = None,
    converged: Sequence[Mapping[str, Any]] | None = None,
) -> bool:
    """Return True if any pair of agent ISRs exceeds the similarity threshold.

    Args:
        isrs: ISRs from the current round.
        threshold: Cosine similarity threshold.
        iteration: Negotiation round counter. The first round (iteration<=0)
            never triggers sycophancy because agents have not had a chance to
            converge intentionally yet.
        revised: The ``agent_id`` of every analyst revised in the round being
            judged, or ``None`` when the round did not record them (every
            pair is judged, as before). Two answers neither of which was
            revised in the round are the answers in force from before it:
            alike or not, they are not evidence of converging in it, and that
            pair is not judged. A pair with at least one revised answer is.

        converged: The flags the round before recorded (``convergence_flags``),
            or ``None`` for a round that recorded none: given, the answer is
            whether any was recorded, and whole answers are not compared.

    Returns:
        True if a pair of summaries is suspiciously similar and content is
        substantive enough to be meaningful.
    """
    if iteration <= 0:
        return False
    if converged is not None:
        return bool(converged)
    if len(isrs) < 2:
        return False
    if revised is not None:
        unrevised = [isr.agent_id for isr in isrs if isr.agent_id not in revised]
        if unrevised:
            logger.info(
                "Sycophancy check: %s not revised in round %d; their answers in force are "
                "compared only with an answer revised in it.",
                ", ".join(unrevised),
                iteration,
            )
        if len(unrevised) == len(isrs):
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
            if revised is not None and not (
                isrs[i].agent_id in revised or isrs[j].agent_id in revised
            ):
                continue
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
                    "The mediator is told.",
                    isrs[i].agent_id,
                    isrs[j].agent_id,
                    sim,
                    threshold,
                )
                return True

    return False


def _citations(isr: AgentISR) -> set[str]:
    """The ledger entries and sandbox items an answer cites, lower-cased."""
    from maljan.analysis.sandbox_sections import item_ids_in
    from maljan.schemas.evidence import entry_ids_in

    found: set[str] = set()
    for claim in isr.claims or []:
        said = f"{getattr(claim, 'claim', '') or ''} {getattr(claim, 'evidence_ref', '') or ''}"
        found.update(i.lower() for i in entry_ids_in(said))
        found.update(i.lower() for i in item_ids_in(said))
    for finding in getattr(isr, "findings", None) or []:
        found.update(str(i).lower() for i in getattr(finding, "evidence_ids", None) or [] if i)
    return found


def _residual(text: str, drop: set[str]) -> list[str]:
    return [token for token in _tokenize(text) if token not in drop]


def _similarity(a: list[str], b: list[str]) -> float:
    if len(a) + len(b) < MIN_TOTAL_TOKENS:
        return 0.0
    vocab = _build_vocab([a, b])
    return _cosine_similarity(_bag_of_words_vector(a, vocab), _bag_of_words_vector(b, vocab))


def convergence_flags(
    before: Mapping[str, AgentISR],
    after: Mapping[str, AgentISR],
    revised: Iterable[str],
    tool_calls: Mapping[str, int],
    entry_texts: Mapping[str, str],
    threshold: float = SYCOPHANCY_THRESHOLD,
    shown: Mapping[str, Iterable[str]] | None = None,
) -> list[dict[str, Any]]:
    """The revisions of a round that moved towards a peer beyond their shared sources.

    For each analyst revised in the round that made no tool call in it and
    whose revision cites nothing its answer before the round did not, and for
    each peer's answer in force: the words of every entry or item both the
    revision and the peer cite (``entry_texts``, by lower-cased id) are left
    out of both, and the similarity of the analyst's answer before the round
    and of its revision to the peer's is measured on what remains. A
    revision whose similarity is above ``threshold`` and above the one before
    the round is flagged ``{agent, towards, before, after}``. Linear in the
    pairs and their words.

    ``shown`` is, per analyst, the entries the platform showed its revision
    (a peer's tool results among them): citing one of those is no citation
    added, since the analyst read it in no call of its own. Its words are
    left out like any shared entry's, so agreeing with what the entry states
    is no move; agreeing beyond it still is.
    """
    flags: list[dict[str, Any]] = []
    for name in revised:
        old, new = before.get(name), after.get(name)
        if old is None or new is None or int(tool_calls.get(name, 0) or 0) > 0:
            continue
        cited_new = _citations(new)
        given = {str(e).lower() for e in ((shown or {}).get(name) or ())}
        if cited_new - _citations(old) - given:
            continue
        old_text, new_text = old.to_text_summary(), new.to_text_summary()
        for peer, answer in after.items():
            if peer == name:
                continue
            # The entries both cite, and the shown entries the revision cites:
            # what such an entry states is no move towards anyone.
            shared = (cited_new & _citations(answer)) | (cited_new & given)
            drop: set[str] = set()
            for entry in shared:
                drop.update(_tokenize(str(entry_texts.get(entry, "") or "")))
            drop.update(shared)
            peer_tokens = _residual(answer.to_text_summary(), drop)
            was = _similarity(_residual(old_text, drop), peer_tokens)
            now = _similarity(_residual(new_text, drop), peer_tokens)
            logger.debug(
                "Convergence check: %s towards %s beyond %d shared source(s): %.3f -> %.3f",
                name,
                peer,
                len(shared),
                was,
                now,
            )
            if now > threshold and now > was:
                logger.warning(
                    "Convergence flagged: %s's revision moved towards %s's answer beyond the "
                    "sources both cite (%.3f -> %.3f), with no citation added and no tool call.",
                    name,
                    peer,
                    was,
                    now,
                )
                flags.append(
                    {
                        "agent": name,
                        "towards": peer,
                        "before": round(was, 3),
                        "after": round(now, 3),
                    }
                )
    return flags


def convergence_sentence(flags: Sequence[Mapping[str, Any]]) -> str:
    """The fact a mediation is told about the flags of the round before it, or ``""``."""
    if not flags:
        return ""
    said = "; ".join(
        f"{flag.get('agent')} moved towards {flag.get('towards')} "
        f"(similarity {float(flag.get('before') or 0):.2f} to {float(flag.get('after') or 0):.2f})"
        for flag in flags
    )
    return (
        "The platform's reading of the last revision round: beyond the ledger entries and "
        f"sandbox items both answers cite, {said}, with no citation added and no tool call made. "
        "A fact for your reading; it decides nothing."
    )
