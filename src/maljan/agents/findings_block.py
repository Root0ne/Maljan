"""The optional structured channel an analyst may append to its answer.

The ISR contract — CLAIM / EVIDENCE / CONFIDENCE / TECHNIQUE — is what the
negotiation runs on and it is untouched. What it cannot carry is the *table* an
analyst built: the import list it read, the permissions it enumerated, the six
endpoints it found. Those arrive in the report today only if some in-process
extractor happens to recompute them, which is exactly the arrangement this
phase removes.

So an agent may end its answer with a fenced ``maljan-findings`` block holding
JSON, and everything in it is optional. Anything that does not validate is
dropped and counted rather than repaired: a half-parsed artifact in a report is
worse than an absent one, and an agent that keeps emitting malformed blocks
should show up in the logs as a number, not as a subtly wrong table.

The block is stripped from the prose before the prose goes anywhere else, so a
reader never sees the machine channel and the ISR parser never tries to read a
JSON brace as a claim.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel

from maljan.core.logger import logger
from maljan.schemas.isr_models import Artifact, Finding, OpenQuestion

# The fence, with the language tag that names it. Non-greedy so an answer that
# somehow carries two blocks yields two matches rather than one that swallows
# the prose between them.
_BLOCK_RE = re.compile(
    r"```[ \t]*maljan-findings[ \t]*\r?\n(?P<body>.*?)```",
    re.DOTALL | re.IGNORECASE,
)
# The opening fence alone: a block cut before its closing fence (an answer the
# output cap ended inside the block) has this and no end.
_OPEN_RE = re.compile(r"```[ \t]*maljan-findings[ \t]*\r?\n", re.IGNORECASE)


# A claim heading in the text after an unclosed fence.
_CLAIM_HEADING_RE = re.compile(r"^[ \t>*_#-]*CLAIM[ \t*_]*:", re.IGNORECASE | re.MULTILINE)


class FindingsBlock:
    """What one answer's structured channel carried, and what was dropped."""

    def __init__(
        self,
        prose: str,
        findings: list[Finding] | None = None,
        artifacts: list[Artifact] | None = None,
        dropped: int = 0,
        open_questions: list[OpenQuestion] | None = None,
    ) -> None:
        self.prose = prose
        self.findings = findings or []
        self.artifacts = artifacts or []
        self.dropped = dropped
        self.open_questions = open_questions or []

    def __bool__(self) -> bool:
        return bool(self.findings or self.artifacts or self.open_questions)


def has_findings_block(text: str) -> bool:
    """Whether ``text`` carries a fenced ``maljan-findings`` block at all.

    The cheap half of :func:`parse_findings_block`, for the tool loop's
    question "is this answer a final report or is the model still thinking".
    """
    return bool(text) and bool(_BLOCK_RE.search(text))


def parse_findings_block(text: str) -> FindingsBlock:
    """Split an answer into its prose and the structured channel it appended.

    An answer with no block comes back unchanged with nothing in it, which is
    the common case and must stay free: the channel is optional and a model
    that ignores it is not misbehaving.
    """
    if not text or "maljan-findings" not in text:
        return FindingsBlock(text or "")

    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    open_questions: list[OpenQuestion] = []
    dropped = 0

    def _take(payload: dict[str, Any]) -> int:
        parsed_findings, bad_findings = _validate(payload.get("findings"), Finding)
        parsed_artifacts, bad_artifacts = _validate(payload.get("artifacts"), Artifact)
        parsed_questions, bad_questions = _validate(
            _without_source(payload.get("open_questions")), OpenQuestion
        )
        findings.extend(parsed_findings)
        artifacts.extend(parsed_artifacts)
        open_questions.extend(parsed_questions)
        return bad_findings + bad_artifacts + bad_questions

    for match in _BLOCK_RE.finditer(text):
        payload = _load(match.group("body"))
        if payload is None:
            dropped += 1
            continue
        dropped += _take(payload)

    prose = _BLOCK_RE.sub("", text)
    # A block cut before its closing fence is the machine channel too. Its
    # JSON object is decoded from where it starts, and what follows the object
    # goes back to the prose (a claim written after an unclosed fence is still
    # a claim). With no object to decode, a rest that holds a claim heading
    # stays in the prose; only when nothing readable follows is it cut.
    opened = _OPEN_RE.search(prose)
    if opened is not None:
        rest = prose[opened.end() :]
        body = rest.lstrip()
        tail_payload: dict[str, Any] | None = None
        after = ""
        try:
            decoded, end = json.JSONDecoder().raw_decode(body)
            if isinstance(decoded, dict):
                tail_payload, after = decoded, body[end:]
        except (ValueError, TypeError):
            pass
        if tail_payload is not None:
            dropped += _take(tail_payload)
            after = after.lstrip(" \t").removeprefix("```")
            prose = prose[: opened.start()] + after
        else:
            dropped += 1
            prose = prose[: opened.start()] + (rest if _CLAIM_HEADING_RE.search(rest) else "")
    prose = prose.strip()
    if dropped:
        logger.warning(
            "findings block: dropped %d item(s) that did not validate; kept %d finding(s), "
            "%d artifact(s) and %d open question(s).",
            dropped,
            len(findings),
            len(artifacts),
            len(open_questions),
        )
    return FindingsBlock(prose, findings, artifacts, dropped, open_questions)


def _without_source(rows: Any) -> Any:
    """Open questions as written, each without a ``source`` the model wrote.

    Which agent left a question open is the platform's to say: a delegation
    names the specialist when it hands the question to the lead
    (``agents.delegation``), and a question an analyst writes is its own.
    """
    if not isinstance(rows, list):
        return rows
    return [
        {key: value for key, value in row.items() if key != "source"}
        if isinstance(row, dict)
        else row
        for row in rows
    ]


def _load(body: str) -> dict[str, Any] | None:
    """The block's JSON object, or None when it is not one."""
    try:
        parsed = json.loads(body.strip())
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _validate(rows: Any, model: type[BaseModel]) -> tuple[list[Any], int]:
    """Validate each row against ``model``, returning the good ones and the loss."""
    if not isinstance(rows, list):
        return [], 0
    kept: list[Any] = []
    dropped = 0
    for row in rows:
        if isinstance(row, model):
            kept.append(row)
            continue
        if not isinstance(row, dict):
            dropped += 1
            continue
        try:
            kept.append(model.model_validate(row))
        except Exception:  # noqa: BLE001 — a malformed item is dropped, not repaired
            dropped += 1
    return kept, dropped
