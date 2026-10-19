"""The answer-key leak check: no shipped prompt, manifest or default carries a scoring key's terms.

A pre-promotion check, run locally. It scans the files under :data:`SHIPPED`
that ship what a model is told (the agents' prompts and the provider fragments,
the built-in agent definitions, profiles and teams in ``src/maljan``, the
sidecars' tool descriptions in ``services``, the API's seeded defaults and
migrations in ``apps/api``, the knowledge files in ``data``, and the
validation scenarios' prompts in ``scripts/validation``), tracked or not (a
file git ignores is not read), and, with ``--settings-export FILE``, every
string of a settings export (the agents, teams and profiles the database
holds). The terms:

- every calibration case's generated values (``leak_terms`` of each manifest,
  both halves of the split) and the generator's template phrases
  (``cases.TEMPLATE_PHRASES``);
- the private term list, a gitignored file supplied locally (by default
  :data:`PRIVATE_TERMS`, ``answer-key-terms.txt`` at the repository root): the
  reference samples' answer-key terms, which are not published. UTF-8, one term
  per line; blank lines and lines starting with ``#`` are skipped; a term is
  matched case-folded unless the line starts with ``cs:`` (the rest of the line
  is then matched as written). When the default file is absent the check says
  so and runs on the other terms; a file named with ``--terms`` that is absent
  is an error.

A term matches where it stands as a whole token: an alphanumeric end of the
term may not touch another letter or digit. A term that is hex (an even number
of hex digits, at least one a digit) also matches with ``0x`` before it and
with a space or a colon between its bytes, in any case. Every hit is printed as
``path:line: term`` and fails the check, unless an allow-list allows that
occurrence. Each entry is a path, the SHA-256 of the term, the SHA-256 of the
exact line, and a one-line reason, and it allows one occurrence on that line.
Two lists: the committed :data:`ALLOW_LIST`, which may allow only a
calibration term (public anyway; an unsalted digest of a private word could be
reversed by a dictionary), and the private, gitignored :data:`PRIVATE_ALLOW`
(``answer-key-allow.json`` beside the private term list, same format) for the
private terms. An allowed hit is printed with its reason; an entry that
matched nothing is named. A file under a
scanned folder that is not UTF-8 text is an error naming it; the third-party
tables in :data:`THIRD_PARTY` are named and not scanned.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scripts.calibration import cases

ROOT = Path(__file__).resolve().parents[2]
PRIVATE_TERMS = ROOT / "answer-key-terms.txt"
ALLOW_LIST = Path(__file__).resolve().parent / "leak_allow.json"
PRIVATE_ALLOW = ROOT / "answer-key-allow.json"
CASE_SENSITIVE_PREFIX = "cs:"
ALLOW_KEYS: tuple[str, ...] = ("path", "term_sha256", "line_sha256", "reason")
# What ships to a model, by directory.
SHIPPED: dict[str, str] = {
    "src/maljan": "prompts, provider fragments, built-in agent definitions, profiles and teams",
    "services": "the sidecars' tool declarations and descriptions",
    "apps/api": "seeded defaults and the migrations that write them",
    "data": "knowledge files tools and agents read",
    "scripts/validation": "the validation scenarios' prompts",
}
# Tracked tables copied from a third party, not written by this project.
THIRD_PARTY: dict[str, str] = {
    "data/tlds-alpha-by-domain.txt": "IANA's root zone list",
    "data/windows_export_names_v1.json": "export names from the Wine project's DLL spec files",
    "data/attck_techniques.json": "MITRE ATT&CK's technique table",
    "data/attck_valid_ids.json": "MITRE ATT&CK's technique ids",
    "data/attck_retired_ids.json": "MITRE ATT&CK's retired technique ids",
}
_HEX = re.compile(r"(?:[0-9a-f]{2})+")
_HEX_SEPARATOR = r"[ :]?"


class LeakCheckError(RuntimeError):
    """The check cannot run, or an input is invalid; the message names why."""


@dataclass(frozen=True)
class Term:
    text: str
    case_sensitive: bool
    source: str
    private: bool = False


@dataclass(frozen=True)
class Hit:
    path: str
    line: int
    term: Term
    content: str


@dataclass(frozen=True)
class Allowed:
    path: str
    term_sha256: str
    line_sha256: str
    reason: str
    private: bool = False


@dataclass
class Result:
    hits: list[Hit] = field(default_factory=list)
    allowed: list[tuple[Hit, Allowed]] = field(default_factory=list)
    scanned: int = 0
    notices: list[str] = field(default_factory=list)
    private: str = "not read"


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_private_terms(path: Path) -> list[Term] | None:
    """The private list's terms, or ``None`` when the file is absent."""
    path = Path(path)
    if not path.is_file():
        return None
    terms: list[Term] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        sensitive = text.startswith(CASE_SENSITIVE_PREFIX)
        if sensitive:
            text = text[len(CASE_SENSITIVE_PREFIX) :].strip()
        if text:
            terms.append(Term(text, sensitive, path.name, private=True))
    return terms


def read_allow_list(path: Path = ALLOW_LIST, private: bool = False) -> list[Allowed]:
    """The allow-list's entries; anything but the known keys is refused, naming the file."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LeakCheckError(f"cannot read the allow-list {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("allow"), list):
        raise LeakCheckError(f"{path}: needs an object with an 'allow' list")
    unknown = set(document) - {"about", "allow"}
    if unknown:
        raise LeakCheckError(f"{path}: unknown keys {sorted(unknown)}")
    entries: list[Allowed] = []
    for row in document["allow"]:
        if not isinstance(row, dict) or set(row) != set(ALLOW_KEYS):
            raise LeakCheckError(f"{path}: an entry has exactly the keys {ALLOW_KEYS}: {row}")
        values = [str(row[k] or "").strip() for k in ALLOW_KEYS]
        if not all(values):
            raise LeakCheckError(f"{path}: an entry needs every one of {ALLOW_KEYS}: {row}")
        path_value, term_sha, line_sha, reason = values
        entries.append(Allowed(path_value, term_sha, line_sha, reason, private=private))
    return entries


def allow_entry(hit: Hit, reason: str) -> dict[str, str]:
    """The allow-list entry that allows ``hit``: no term, only digests."""
    return {
        "path": hit.path,
        "term_sha256": digest(hit.term.text),
        "line_sha256": digest(hit.content),
        "reason": reason,
    }


def calibration_terms(seeds: Path = cases.SEEDS) -> list[Term]:
    """Every calibration case's generated values and the generator's template phrases."""
    terms = [
        Term(value, False, case.case_id)
        for case in cases.build_all(seeds)
        for value in case.leak_terms
    ]
    return terms + [Term(p, False, "generator") for p in cases.TEMPLATE_PHRASES]


def shipped_files(root: Path = ROOT) -> list[str]:
    """The files under :data:`SHIPPED`, tracked or untracked, that git does not ignore."""
    try:
        answer = subprocess.run(  # noqa: S603 — fixed arguments, no shell
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", *SHIPPED],  # noqa: S607
            cwd=root,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise LeakCheckError(f"cannot list the files under {root}: {exc}") from exc
    return sorted({p for p in answer.stdout.decode("utf-8").split("\0") if p})


def _normal(text: str, sensitive: bool) -> str:
    """One spelling for a term and for what matched it: case-folded unless case-sensitive,
    and a hex term without ``0x`` and without separators between its bytes."""
    if sensitive:
        return text
    folded = text.casefold()
    bare = re.sub(r"[ :]", "", folded.removeprefix("0x"))
    return bare if _HEX.fullmatch(bare) and any(c.isdigit() for c in bare) else folded


_BEFORE, _AFTER = r"(?<![A-Za-z0-9])", r"(?![A-Za-z0-9])"


def _core(text: str) -> str:
    """A term's own pattern, without the token boundaries around it."""
    if _HEX.fullmatch(text) and any(c.isdigit() for c in text):
        pairs = [text[i : i + 2] for i in range(0, len(text), 2)]
        return r"(?:0x)?" + _HEX_SEPARATOR.join(pairs)
    return re.escape(text)


def _piece(text: str) -> str:
    """A term's pattern with a boundary at each alphanumeric end."""
    before = _BEFORE if text[:1].isalnum() else ""
    after = _AFTER if text[-1:].isalnum() else ""
    return before + _core(text) + after


def _combined(ordered: list[str]) -> str:
    """One alternation: the terms with both ends alphanumeric share one pair of
    boundaries, hoisted out of their group so a position costs one look, not
    one per term; the few others keep their own."""
    both = [t for t in ordered if t[:1].isalnum() and t[-1:].isalnum()]
    rest = [t for t in ordered if not (t[:1].isalnum() and t[-1:].isalnum())]
    parts = [f"{_BEFORE}(?:{'|'.join(_core(t) for t in both)}){_AFTER}"] if both else []
    return "|".join(parts + [_piece(t) for t in rest])


class _Matcher:
    """One pattern per case rule; what matched is named back by the same normalisation."""

    def __init__(self, terms: list[Term]) -> None:
        self.patterns: list[tuple[re.Pattern[str], bool, dict[str, Term]]] = []
        for sensitive in (True, False):
            table = {_normal(t.text, sensitive): t for t in terms if t.case_sensitive is sensitive}
            if not table:
                continue
            # Longest first, so a term that holds a shorter one is the one named.
            ordered = sorted(table, key=lambda t: (-len(t), t))
            pattern = re.compile(_combined(ordered))
            self.patterns.append((pattern, sensitive, table))

    def find(self, line: str) -> Iterator[Term]:
        # Case-folded terms are matched against the case-folded line, and what
        # matched is looked up after the same folding: one normalisation.
        folded = line.casefold()
        for pattern, sensitive, table in self.patterns:
            for match in pattern.finditer(line if sensitive else folded):
                key = _normal(match.group(0), sensitive)
                if key not in table:
                    raise LeakCheckError(f"a match names no term: {match.group(0)!r}")
                yield table[key]


def _scan_text(result: Result, matcher: _Matcher, where: str, text: str) -> None:
    for number, line in enumerate(text.splitlines(), start=1):
        for term in matcher.find(line):
            result.hits.append(Hit(where, number, term, line))


def scan(root: Path, paths: Iterable[str], terms: list[Term]) -> Result:
    """Every hit of ``terms`` in ``paths`` (relative to ``root``), line by line."""
    result = Result()
    matcher = _Matcher(terms)
    for relative in paths:
        if relative in THIRD_PARTY:
            result.notices.append(f"not scanned (third-party: {THIRD_PARTY[relative]}): {relative}")
            continue
        try:
            text = (Path(root) / relative).read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise LeakCheckError(f"{relative}: not UTF-8 text ({exc.reason})") from exc
        result.scanned += 1
        _scan_text(result, matcher, relative, text)
    return result


def _settings_strings(value: Any, path: str) -> Iterator[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _settings_strings(item, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _settings_strings(item, f"{path}[{index}]")


def scan_settings_export(path: Path, terms: list[Term], into: Result) -> None:
    """Every string of a settings export, each named ``FILE#json.path``."""
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LeakCheckError(f"cannot read the settings export {path}: {exc}") from exc
    matcher = _Matcher(terms)
    into.scanned += 1
    for where, text in _settings_strings(document, ""):
        _scan_text(into, matcher, f"{path}#{where}", text)


def check(
    root: Path = ROOT,
    private: Path | None = None,
    seeds: Path = cases.SEEDS,
    paths: list[str] | None = None,
    allow: Path = ALLOW_LIST,
    settings_export: Path | None = None,
    private_allow: Path | None = None,
) -> Result:
    """The leak check over the shipped files (or ``paths``) and a settings export.

    ``private`` and ``private_allow`` name the private lists; ``None`` reads the
    default path, whose absence is a notice. A named list that is absent is an
    error.
    """
    terms = calibration_terms(seeds)
    notices: list[str] = []
    own = read_private_terms(PRIVATE_TERMS if private is None else private)
    if own is None and private is not None:
        raise LeakCheckError(f"no private term list at {private}")
    if own is None:
        notices.append(
            f"notice: no private term list at {PRIVATE_TERMS}; only the calibration terms were "
            "checked"
        )
        state = "not read"
    else:
        terms += own
        state = f"read ({len(own)} terms)"
    entries = read_allow_list(allow)
    own_allow = PRIVATE_ALLOW if private_allow is None else private_allow
    if Path(own_allow).is_file():
        entries += read_allow_list(own_allow, private=True)
    elif private_allow is not None:
        raise LeakCheckError(f"no private allow-list at {private_allow}")
    else:
        notices.append(f"notice: no private allow-list at {PRIVATE_ALLOW}")
    result = scan(root, shipped_files(root) if paths is None else paths, terms)
    if settings_export is not None:
        scan_settings_export(settings_export, terms, result)
    result.private = state
    remaining: dict[tuple[str, str, str], list[Allowed]] = {}
    for entry in entries:
        remaining.setdefault((entry.path, entry.term_sha256, entry.line_sha256), []).append(entry)
    failing: list[Hit] = []
    for hit in result.hits:
        pool = remaining.get((hit.path, digest(hit.term.text), digest(hit.content))) or []
        # A committed entry allows only a calibration term; a private term is
        # allowed by the private list alone.
        usable = [e for e in pool if e.private or not hit.term.private]
        if usable:
            pool.remove(usable[-1])
            result.allowed.append((hit, usable[-1]))
        else:
            failing.append(hit)
    result.hits = failing
    notices += [
        f"allow-list entry matched nothing: {e.path} ({e.reason})"
        for pool in remaining.values()
        for e in pool
    ]
    result.notices = notices + result.notices
    return result


def render(result: Result) -> str:
    lines = list(result.notices)
    for hit, entry in result.allowed:
        lines.append(f"allowed: {hit.path}:{hit.line}: {hit.term.text} ({entry.reason})")
    for hit in result.hits:
        lines.append(f"{hit.path}:{hit.line}: {hit.term.text} (from {hit.term.source})")
    verdict = "FAIL" if result.hits else "PASS"
    lines.append(
        f"{verdict}: {len(result.hits)} hits in {result.scanned} files scanned;"
        f" private list: {result.private}"
    )
    return "\n".join(lines)
