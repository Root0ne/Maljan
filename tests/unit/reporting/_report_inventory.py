"""What a rendered report holds, read from its text alone, for the split's lossless check.

The analyst report and its evidence bundle together must hold everything the
single-file report printed: every citation id, technique id, address, hash,
defanged network value, quoted value, value-like token and clause of five or
more words. The classes are read from the rendered Markdown only, never by a
tool's or a sample's name, so the check holds for any run.

``plain`` is how a passage is compared: Markdown marks, the analyst report's
note markers and every evidence id taken out, quotes straightened and white
space collapsed, so a sentence whose citation moved into a note is the same
sentence.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK = Path(".superpowers") / "sdd" / "mandate-2026-09-17" / "benchmark" / "deepseek"


def stored_runs() -> Path | None:
    """The stored runs: in this checkout, or in the checkout a worktree belongs to."""
    for base in (ROOT, *(p for p in ROOT.parents if (p / ".claude" / "worktrees").is_dir())):
        if (base / BENCHMARK).is_dir():
            return base / BENCHMARK
    return None


_NOTE_MARKER = re.compile(r"\[\[\d+\]\]\([^)\s]*\)")
_ID_LINK = re.compile(r"\[(ev_\d+)\]\([^)\s]*\)")
_CITATION_RUN = re.compile(r"(?:\s*[\[(]\s*ev_\d+(?:\s*[,;]\s*ev_\d+)*\s*[\])])+")
_BARE_ID = re.compile(r"\bev_\d+\b")


def plain(text: str) -> str:
    """``text`` as passages are compared: no marks, no note markers, no evidence ids."""
    text = _NOTE_MARKER.sub("", text)
    text = _ID_LINK.sub(r"\1", text)
    text = _CITATION_RUN.sub("", text)
    text = _BARE_ID.sub("", text)
    text = re.sub(r"[`*_\\]", "", text)
    text = text.replace("“", '"').replace("”", '"').replace("’", "'").replace("‘", "'")
    return re.sub(r"\s+", " ", text).strip()


def _norm(text: str) -> str:
    text = re.sub(r"[`*_\\]", "", text)
    text = text.replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", text)


_SEGMENT = re.compile(r"(?<=[:;.!?])\s+|\s\|\s|^\s*[-|]\s*|\"|\(|\)")
_TOKEN = re.compile(r"[\w./\\%\[\]#@&=?-]{3,}")


def _segments(text: str) -> set[str]:
    out: set[str] = set()
    for line in text.splitlines():
        for part in _SEGMENT.split(_norm(line)):
            part = part.strip(" -|:;.,")
            if len(part.split()) >= 5:
                out.add(part)
    return out


def inventory(text: str) -> dict[str, set[str]]:
    """The classes of what ``text`` holds."""
    normed = _norm(text)
    return {
        "evidence_ids": set(re.findall(r"\bev_\d{4,}\b", text)),
        "techniques": set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text)),
        "addresses": set(re.findall(r"\b0x[0-9a-fA-F]+\b", text)),
        "hashes": set(re.findall(r"\b[0-9a-f]{32,64}\b", text)),
        "defanged": {x.strip(".,:;”\"'()`*") for x in re.findall(r"\S*(?:\[\.\]|hxxp)\S*", text)},
        "quoted": {q.strip() for q in re.findall(r"[\"“]([^\"”\n]{8,200})[\"”]", text)},
        "tokens": {x.rstrip(".") for x in _TOKEN.findall(normed)},
        "segments": _segments(text),
    }


def missing(old: str, new: str) -> dict[str, list[str]]:
    """Each class of ``old``'s inventory, with what ``new`` does not hold of it."""
    before, after = inventory(old), inventory(new)
    normed = _norm(new)
    out: dict[str, list[str]] = {}
    for key, values in before.items():
        if key == "segments":
            lost = [s for s in values if s not in normed]
        elif key == "quoted":
            lost = [q for q in values if _norm(q) not in normed]
        else:
            lost = sorted(values - after[key])
        out[key] = sorted(lost)
    return out
