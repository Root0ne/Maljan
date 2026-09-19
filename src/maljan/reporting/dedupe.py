"""The same indicator or finding said twice, written once.

Two analysts that both read the same C2 endpoint out of the same sample give
the report two rows that mean one thing, and a reader counting rows counts it
twice. The same happens to a finding a static analyst and a reverser both
reach. What is wanted is one row, and what must not happen is a merge that
invents anything: severity, confidence, a verdict, a category, a family, a
technique id and every sentence a model wrote belong to the model that wrote
them, and a merge that raised a confidence because two agents agreed would be
this codebase inventing agreement.

So a merge here only ever grows a set. The first occurrence's text is what the
row keeps — its notes, its title, its confidence — and what the second
occurrence contributes is the ids, the sources, the agents and the stages it
brings with it. A merge that had nothing set-shaped to contribute leaves the
row exactly as it was and is still counted, because the count is what tells a
reader the two rows were the same thing rather than two.

Fingerprinting is deliberately shy. An indicator is ``(kind, canonical
value)`` where canonicalising is lower-casing, trimming and undoing the two
ways an analyst writes an address it does not want a reader to click; a
finding is ``(first technique id, normalised title)``. Anything cleverer —
substring matching, edit distance, a URL parser's idea of equivalence — can
merge two indicators that are not the same one, and a wrongly merged indicator
is a fact removed from a report with nothing saying it happened.
"""

from __future__ import annotations

import re
from typing import Any

# The two ways an analyst writes an address it does not want a reader to open,
# undone so the defanged spelling and the plain one fingerprint alike. Only
# these: a substitution table that guessed would merge indicators that differ.
_DEFANGED = {
    "[.]": ".",
    "(.)": ".",
    "[:]": ":",
    "[://]": "://",
    "[at]": "@",
    "(at)": "@",
    "hxxps": "https",
    "hxxp": "http",
}
# Matched whatever case it was written in, longest spelling first so ``hxxps``
# is not read as ``hxxp`` with a stray ``s``.
_DEFANGED_RE = re.compile(
    "|".join(re.escape(spelling) for spelling in sorted(_DEFANGED, key=len, reverse=True)),
    re.IGNORECASE,
)

_WHITESPACE = re.compile(r"\s+")
# Trailing punctuation a title picks up from the sentence it was written in.
_TITLE_TAIL = ".,;:!-–— "


def canonical_value(value: Any, *, fold_case: bool = True) -> str:
    """One indicator value in the spelling two copies of it share.

    ``fold_case`` is false where the case is part of the value. A URL path is
    case-sensitive on most of the servers that serve it, so ``/Gate.php`` and
    ``/gate.php`` are two paths, and folding them would remove one of them
    from the report with nothing saying it happened — the thing this module
    exists to prevent.

    Defanging is undone whatever case it was written in, even where the value
    keeps its own: ``hXXp://a[.]com/Gate.php`` and ``http://a.com/Gate.php``
    are one endpoint, and the only thing the writer changed is the part that
    was never meant to be read literally.
    """
    text = _DEFANGED_RE.sub(lambda hit: _DEFANGED[hit.group(0).lower()], str(value or "").strip())
    return text.lower() if fold_case else text


# The indicator kinds whose value means the same thing however it is typed: a
# digest, a host name, an address, a mailbox. Listed rather than inferred, and
# everything not on it keeps its case — the shy direction, which leaves two
# rows where there might be one rather than one where there are two.
_CASE_BLIND = frozenset(
    {
        "md5",
        "sha1",
        "sha256",
        "sha512",
        "hash",
        "imphash",
        "domain",
        "domain-name",
        "hostname",
        "fqdn",
        "ip",
        "ipv4",
        "ipv6",
        "ipv4-addr",
        "ipv6-addr",
        "ip_address",
        "email",
        "email-addr",
    }
)


# The kinds whose value is a place on a filesystem. A path is written several
# ways that mean one place — with and without a trailing separator, with the
# separators doubled, and on Windows in any case at all — and comparing the
# literals kept one live bundle carrying the same Pylance directory twice, once
# with the slash and once without.
_PATH_LIKE = frozenset(
    {
        "path",
        "file",
        "file-name",
        "file_name",
        "filename",
        "directory",
        "registry",
        "registry_key",
        "windows-registry-key",
    }
)

# A path whose separators and case are Windows': a drive letter, or a UNC root.
_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:[\\/]|\\\\[^\\/]")
_RUNS_OF_SEPARATOR_RE = re.compile(r"/{2,}")
# One literal a STIX pattern quotes.
_QUOTED_RE = re.compile(r"'([^']*)'")


def folds_case(kind: Any) -> bool:
    """Whether two spellings of this kind that differ only in case are one thing."""
    return str(kind or "").strip().lower() in _CASE_BLIND


def canonical_path(value: Any) -> str:
    """One path in the spelling two writers of it share.

    Separators written one way, runs of them collapsed, no trailing separator,
    and a Windows path folded to one case — Windows filesystems are
    case-insensitive, so ``c:\\users\\x`` and ``C:\\Users\\X`` are one file. A
    POSIX path keeps its case, because two POSIX paths differing in case are
    two files and folding them would remove one from the report with nothing
    saying it happened.
    """
    text = canonical_value(value, fold_case=False)
    windows = bool(_WINDOWS_PATH_RE.search(text)) or ("\\" in text and "/" not in text)
    text = text.replace("\\", "/")
    if windows:
        text = text.lower()
    text = _RUNS_OF_SEPARATOR_RE.sub("/", text)
    return text.rstrip("/") if len(text) > 1 else text


def indicator_fingerprint(kind: Any, value: Any) -> tuple[str, str]:
    """What makes two indicator rows the same indicator."""
    name = str(kind or "").strip().lower()
    if name in _PATH_LIKE:
        return (name, canonical_path(value))
    return (name, canonical_value(value, fold_case=folds_case(name)))


# The object path a STIX comparison expression opens with, mapped to the kind
# ``folds_case`` knows. A pattern this cannot read keeps its case.
_STIX_PATHS: tuple[tuple[str, str], ...] = (
    ("file:hashes", "hash"),
    ("file:name", "path"),
    ("directory:path", "path"),
    ("windows-registry-key:key", "registry"),
    ("domain-name:value", "domain"),
    ("ipv4-addr:value", "ipv4"),
    ("ipv6-addr:value", "ipv6"),
    ("email-addr:value", "email"),
)


def pattern_fingerprint(pattern_type: Any, pattern: Any) -> tuple[str, str]:
    """What makes two STIX indicators the same indicator.

    The same rule the report's table uses, read off the pattern itself: a
    pattern over a digest or a host name folds its case, a pattern over a path
    is normalised the way a path is, and a pattern over a URL or anything this
    cannot read keeps what it was written with. Defanging is undone either way,
    because ``[.]`` never meant anything but ``.``.
    """
    text = str(pattern or "")
    lowered = text.lower()
    kind = next((name for path, name in _STIX_PATHS if path in lowered), "")
    family = str(pattern_type or "stix").strip().lower()
    if kind in _PATH_LIKE:
        # Each quoted literal on its own: a trailing separator sits inside the
        # quotes, where normalising the whole pattern string cannot reach it.
        return (family, _QUOTED_RE.sub(lambda hit: f"'{canonical_path(hit.group(1))}'", text))
    return (family, canonical_value(text, fold_case=folds_case(kind)))


def normalised_title(title: Any) -> str:
    """A finding's title with the spelling two writers of it would share."""
    text = _WHITESPACE.sub(" ", str(title or "")).strip().lower()
    return text.strip(_TITLE_TAIL)


def finding_fingerprint(technique_ids: Any, title: Any) -> tuple[str, str]:
    """What makes two findings the same finding: its techniques and what it says.

    Every technique id, not the first. Two findings under one title where one
    claims ``T1055`` and the other ``T1055`` and ``T1027`` are not the same
    finding: folding them would drop the second id, and merging the column
    instead would put a technique against an analyst that never claimed it.
    The ids are sorted so the order two analysts wrote them in does not make
    one finding two. A finding with none is fingerprinted on its title alone,
    which is why the title is normalised rather than compared as written.
    """
    ids = sorted({str(tid).strip().upper() for tid in (technique_ids or []) if str(tid).strip()})
    return (",".join(ids), normalised_title(title))


def merge_cell(kept: str, arriving: str, *, separator: str = ", ") -> str:
    """Two set-shaped cells as one, in the order they were first seen.

    A cell that holds a list of ledger ids or agent names is a set written
    down; merging it is a union. Nothing else in a row is merged this way,
    because nothing else in a row is a set.
    """
    seen: list[str] = []
    for part in (*kept.split(separator.strip()), *arriving.split(separator.strip())):
        item = part.strip()
        if item and item not in seen:
            seen.append(item)
    return separator.join(seen)


class MergeTally:
    """How many rows were merged away, for the run summary to state.

    A number, not a list: the report shows the merged rows themselves, and
    what a reader needs from the summary is whether merging happened at all
    and how much of the run's output it accounts for.
    """

    def __init__(self) -> None:
        self.indicators_merged = 0
        self.findings_merged = 0

    def indicator(self) -> None:
        self.indicators_merged += 1

    def finding(self) -> None:
        self.findings_merged += 1

    def as_dict(self, *, extra_indicators: int = 0) -> dict[str, int]:
        """``run_summary.dedupe``, with merges counted elsewhere added in.

        ``extra_indicators`` is the STIX bundle's own indicator merge, counted
        by the integrity pass in the judge long before a report is assembled.
        Both are the same act on the same run, so the summary states one
        number for it.
        """
        return {
            "indicators_merged": self.indicators_merged + max(0, int(extra_indicators)),
            "findings_merged": self.findings_merged,
        }
