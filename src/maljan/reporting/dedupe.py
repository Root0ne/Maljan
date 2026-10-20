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

from maljan.schemas.stix_pattern import Comparison, canonical_pattern, read_comparisons

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


def canonical_value(value: Any, *, fold_case: bool = True, strip: bool = True) -> str:
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

    ``strip`` is false where a space at the edge is part of the value: a mutex
    named `` x`` is not the mutex named ``x``.
    """
    raw = str(value or "")
    text = _DEFANGED_RE.sub(
        lambda hit: _DEFANGED[hit.group(0).lower()], raw.strip() if strip else raw
    )
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


def folds_case(kind: Any) -> bool:
    """Whether two spellings of this kind that differ only in case are one thing."""
    return str(kind or "").strip().lower() in _CASE_BLIND


def is_windows_path(text: str) -> bool:
    """Whether a path is written the Windows way: a drive, a UNC root, or backslashes alone."""
    unc = text.startswith("\\\\") or text.startswith("//")
    return unc or bool(_WINDOWS_PATH_RE.search(text)) or ("\\" in text and "/" not in text)


def canonical_path(value: Any, *, strip: bool = True) -> str:
    """One path in the spelling two writers of it share.

    Separators written one way, runs of them collapsed, no trailing separator,
    and a Windows path folded to one case — Windows filesystems are
    case-insensitive, so ``c:\\users\\x`` and ``C:\\Users\\X`` are one file. A
    POSIX path keeps its case, because two POSIX paths differing in case are
    two files and folding them would remove one from the report with nothing
    saying it happened.

    A UNC path keeps the two separators it opens with. Collapsing them and
    folding the case rewrote ``\\\\SRV\\Share\\F`` into ``/srv/share/f``, which is
    also what the POSIX path ``/srv/share/f`` canonicalises to — two locations
    that cannot be the same file merging into one indicator row.
    """
    text = canonical_value(value, fold_case=False, strip=strip)
    unc = text.startswith("\\\\") or text.startswith("//")
    windows = is_windows_path(text)
    text = text.replace("\\", "/")
    if windows:
        text = text.lower()
    text = _RUNS_OF_SEPARATOR_RE.sub("/", text)
    text = text.rstrip("/") if len(text) > 1 else text
    return f"/{text}" if unc else text


def indicator_fingerprint(kind: Any, value: Any) -> tuple[str, str]:
    """What makes two indicator rows the same indicator."""
    name = str(kind or "").strip().lower()
    if name in _PATH_LIKE:
        return (name, canonical_path(value))
    return (name, canonical_value(value, fold_case=folds_case(name)))


# The object path a STIX comparison is made against, mapped to the kind
# ``indicator_fingerprint`` knows. Every other path keeps its value's case. A
# ``hashes`` property of any object is a digest (``_comparison_kind``).
_STIX_PATH_KINDS = {
    "url:value": "url",
    "file:name": "path",
    "directory:path": "path",
    "file:parent_directory_ref.path": "path",
    "windows-registry-key:key": "registry",
    "domain-name:value": "domain",
    "ipv4-addr:value": "ipv4",
    "ipv6-addr:value": "ipv6",
    "email-addr:value": "email",
}
# The kinds whose value means nothing by a space at its edge: a digest, an
# address, a host, a mailbox, a URL. Any other value (a mutex, a file name, a
# command line, a registry value) keeps its spaces, as the pattern wrote them.
_EDGE_SPACE_BLIND = frozenset({"hash", "domain", "ipv4", "ipv6", "email", "url"})


def _comparison_kind(comparison: Comparison) -> str:
    if comparison.prop.startswith("hashes"):
        return "hash"
    return _STIX_PATH_KINDS.get(comparison.path, "")


def _comparison_value(comparison: Comparison) -> str:
    r"""One comparison's value in the spelling two copies of it share, by the kind of its path.

    A ``MATCHES`` value is a regular expression and is kept exactly as written
    (``\D`` is not ``\d``). A ``LIKE`` value has two wildcards, ``%`` and ``_``,
    and nothing in it is defanging: its case is folded where the kind's is (a
    host, a digest, a Windows path) and nothing else is touched.
    """
    literal = comparison.literal
    kind = _comparison_kind(comparison)
    if "matches" in comparison.operator:
        return literal
    if "like" in comparison.operator:
        windows = kind in _PATH_LIKE and is_windows_path(literal)
        return literal.lower() if folds_case(kind) or windows else literal
    if kind in _EDGE_SPACE_BLIND:
        return indicator_fingerprint(kind, literal)[1]
    if kind in _PATH_LIKE:
        return canonical_path(literal, strip=False)
    return canonical_value(literal, fold_case=False, strip=False)


def pattern_fingerprint(pattern_type: Any, pattern: Any) -> tuple[str, str]:
    """What makes two STIX indicators the same indicator.

    The same rule the report's table uses, applied to each comparison the
    pattern makes (``schemas.stix_pattern``): a value compared with a digest
    or a host name folds its case, a value compared with a path is normalised
    the way a path is, and a value compared with a URL or any other property
    keeps the case it was written in. Defanging is undone, because ``[.]``
    never meant anything but ``.``. The syntax around the values is folded
    and its whitespace closed up, so ``[URL:value = …]`` and
    ``[url:value=…]`` are one pattern.

    Each value by the kind of its own path, not by the first path found
    anywhere in the text: a URL quoting ``file:name`` or ``C:/`` is a URL, and
    two URLs that differ in case stay two indicators. A value the reader
    cannot read keeps its written text, and a pattern in any language other
    than STIX is compared as written: two rows where there might be one,
    never one where there are two.
    """
    family = str(pattern_type or "stix").strip().lower()
    text = str(pattern or "").strip()
    if family != "stix":
        return (family, text)
    # A file named in a Windows directory is a Windows file: its name folds its
    # case as the directory does, so ``C:\\Windows`` + ``Evil.exe`` and
    # ``c:\\windows`` + ``evil.exe`` are one indicator, as the whole path was.
    # The directory folds with it (``%TEMP%`` is ``%temp%``). Per observation
    # expression: a name folds only beside its own directory.
    windows = {
        comparison.observation
        for comparison in read_comparisons(text)
        if comparison.path == _PARENT_DIRECTORY_PATH and is_windows_directory(comparison.literal)
    }
    if windows:

        def _value(comparison: Comparison) -> str:
            value = _comparison_value(comparison)
            if (
                comparison.path in ("file:name", _PARENT_DIRECTORY_PATH)
                and comparison.observation in windows
                and "matches" not in comparison.operator
            ):
                return value.lower()
            return value

        return (family, canonical_pattern(text, _value))
    return (family, canonical_pattern(text, _comparison_value))


_PARENT_DIRECTORY_PATH = "file:parent_directory_ref.path"
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


def is_windows_directory(directory: str) -> bool:
    """Whether a directory is written the Windows way: a backslash, a drive or a ``%VARIABLE%``."""
    return "\\" in directory or "%" in directory or bool(_DRIVE_RE.match(directory))


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


def process_identity(node: Any) -> tuple[int, int, str, str]:
    """One sandbox process: its pid, parent pid, image and command line.

    A run reads one sandbox task, so two rows that agree on all four are the
    same process read twice (the pack's call and an analyst's), and two rows
    that differ in any of them are two processes.
    """
    return (
        int(getattr(node, "pid", 0) or 0),
        int(getattr(node, "ppid", 0) or 0),
        str(getattr(node, "name", "") or ""),
        str(getattr(node, "command_line", "") or ""),
    )


def distinct_processes(nodes: list[Any]) -> list[Any]:
    """A process tree with each process once, at its first place.

    A repeated process keeps the first row's place; what the repeat adds is a
    set (its children, the pids it injected into), and that is unioned, so no
    child and no injection one reading recorded is lost. A root that is also a
    child in another root's tree (a reading that lacked its parent) is that
    child, and joins it there. The rows are copies: the report's own tree is
    left as it was stored.

    Linear in the number of processes: one identity map of every process below
    a root, read once per root, and each merge visits a process once.
    """
    roots = _distinct_level(nodes)
    below: dict[tuple[int, int, str, str], tuple[Any, int]] = {}
    for index, root in enumerate(roots):
        for node in _descendants(root):
            below.setdefault(process_identity(node), (node, index))
    # Which root's tree each folded root went into, and which node stands for
    # a node a merge folded into another.
    home = list(range(len(roots)))
    merged_into: dict[int, Any] = {}
    folded: set[int] = set()
    for index, root in enumerate(roots):
        hit = below.get(process_identity(root))
        if hit is None:
            continue
        node, owner = hit
        if _home(home, owner) == index:
            continue
        while id(node) in merged_into:
            node = merged_into[id(node)]
        _merge(node, root, merged_into)
        home[index] = _home(home, owner)
        folded.add(index)
    return [root for index, root in enumerate(roots) if index not in folded]


def _home(home: list[int], index: int) -> int:
    """The root whose tree ``index``'s tree now stands in."""
    while home[index] != index:
        home[index] = home[home[index]]
        index = home[index]
    return index


def _merge(target: Any, source: Any, merged_into: dict[int, Any]) -> None:
    """``source``'s children and injections joined into ``target``, level by level."""
    pending = [(target, source)]
    while pending:
        kept, arriving = pending.pop()
        injected = set(kept.injected_into)
        for pid in arriving.injected_into:
            if pid not in injected:
                injected.add(pid)
                kept.injected_into.append(pid)
        children = {process_identity(child): child for child in reversed(kept.children)}
        for child in arriving.children:
            same = children.get(process_identity(child))
            if same is None:
                kept.children.append(child)
                children[process_identity(child)] = child
                continue
            merged_into[id(child)] = same
            pending.append((same, child))


def _descendants(node: Any) -> list[Any]:
    """Every process below ``node``, depth first."""
    out: list[Any] = []
    pending = list(reversed(node.children))
    while pending:
        child = pending.pop()
        out.append(child)
        pending.extend(reversed(child.children))
    return out


def _distinct_level(nodes: list[Any]) -> list[Any]:
    """``nodes`` with each identity once at this level, every level below likewise."""
    kept: dict[tuple[int, int, str, str], Any] = {}
    children: dict[tuple[int, int, str, str], list[Any]] = {}
    injected: dict[tuple[int, int, str, str], set[int]] = {}
    for node in nodes:
        key = process_identity(node)
        first = kept.get(key)
        if first is None:
            kept[key] = node.model_copy(
                update={"children": [], "injected_into": list(node.injected_into)}
            )
            children[key] = list(node.children)
            injected[key] = set(node.injected_into)
            continue
        children[key].extend(node.children)
        for pid in node.injected_into:
            if pid not in injected[key]:
                injected[key].add(pid)
                first.injected_into.append(pid)
    for key, node in kept.items():
        node.children = _distinct_level(children[key])
    return list(kept.values())


def signature_identity(signature: Any) -> tuple[Any, ...]:
    """A sandbox signature row by everything it states; the same row read twice is one."""
    return (
        str(getattr(signature, "name", "") or ""),
        str(getattr(signature, "description", "") or ""),
        getattr(signature, "severity", None),
        tuple(getattr(signature, "technique_ids", None) or ()),
        tuple(getattr(signature, "marks", None) or ()),
    )


def distinct_signatures(signatures: list[Any]) -> list[Any]:
    """``signatures`` with each row once, at its first place."""
    seen: set[tuple[Any, ...]] = set()
    out: list[Any] = []
    for signature in signatures:
        key = signature_identity(signature)
        if key not in seen:
            seen.add(key)
            out.append(signature)
    return out
