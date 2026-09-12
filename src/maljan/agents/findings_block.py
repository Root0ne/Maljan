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
from maljan.schemas.isr_models import Artifact, Finding

# The fence, with the language tag that names it. Non-greedy so an answer that
# somehow carries two blocks yields two matches rather than one that swallows
# the prose between them.
_BLOCK_RE = re.compile(
    r"```[ \t]*maljan-findings[ \t]*\r?\n(?P<body>.*?)```",
    re.DOTALL | re.IGNORECASE,
)


class FindingsBlock:
    """What one answer's structured channel carried, and what was dropped."""

    def __init__(
        self,
        prose: str,
        findings: list[Finding] | None = None,
        artifacts: list[Artifact] | None = None,
        dropped: int = 0,
    ) -> None:
        self.prose = prose
        self.findings = findings or []
        self.artifacts = artifacts or []
        self.dropped = dropped

    def __bool__(self) -> bool:
        return bool(self.findings or self.artifacts)


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
    dropped = 0

    for match in _BLOCK_RE.finditer(text):
        payload = _load(match.group("body"))
        if payload is None:
            dropped += 1
            continue
        parsed_findings, bad_findings = _validate(payload.get("findings"), Finding)
        parsed_artifacts, bad_artifacts = _validate(payload.get("artifacts"), Artifact)
        findings.extend(parsed_findings)
        artifacts.extend(parsed_artifacts)
        dropped += bad_findings + bad_artifacts

    prose = _BLOCK_RE.sub("", text).strip()
    if dropped:
        logger.warning(
            "findings block: dropped %d item(s) that did not validate; kept %d finding(s) "
            "and %d artifact(s).",
            dropped,
            len(findings),
            len(artifacts),
        )
    return FindingsBlock(prose, findings, artifacts, dropped)


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
