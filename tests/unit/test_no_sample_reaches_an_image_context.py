"""No sample reaches a build context on any builder; every tracked file an image needs does.

A sample is live malware whatever it is called. ``docker/Dockerfile.backend``
copies all of ``apps/`` and ``data/``, so the ignore file is the only thing
between a working copy's samples and an image layer. The ignore file the
production images' builds read, ``.dockerignore``, leaves out every file below
any ``data/samples/`` but the JSON fixtures the repository tracks. It is read
here the way builders read it, over a synthetic tree of what a working copy
holds and over the tracked tree.

No dockerignore matcher is among the dependencies (pathspec, which mypy brings
in, follows gitignore's rules, which anchor patterns and re-include files
differently), so this file holds a minimal one for the rules Docker documents
for ``.dockerignore``:

* a line starting with ``#`` is a comment, and a blank line is skipped;
* a pattern is trimmed, cleaned the way Go's ``filepath.Clean`` cleans a path
  (a trailing ``/`` and ``.`` segments go) and read from the context root (a
  leading ``/`` goes);
* ``*`` matches any run of characters but ``/``, ``?`` any one character but
  ``/``, and ``**`` any number of directories, none included;
* a line starting with ``!`` makes an exception, and the last line that matches
  a path decides whether it is left out.

Builders differ in how a pattern that matches a directory reaches the files
below it, and both families are modelled:

* parent-aware: a pattern matching any parent directory of a path matches the
  path (BuildKit 0.10 and later carry the parent's match down the walk; Docker
  Engine 23 and later check every parent);
* depth-limited: a pattern is tried on the path and on the one parent prefix
  with as many components as the pattern has, and on no other parent (Docker
  Engine 20.10 in both its builders, moby v20.10.24 ``pkg/fileutils``, and
  docker-py).

Builders also skip a directory a pattern leaves out unless an exception
pattern lies inside it: Docker's own walkers when an exception starts with the
directory and a slash, docker-py when an exception merely starts with the
directory's name (so it walks into more), and BuildKit 0.10 and later never
while an exception holds a wildcard, as ``!**/.env.example`` does. A path
counts as left out when the least-excluding builder of each family leaves it
out, by its own match or a skipped parent, and as kept when the most-excluding
builder of each family keeps it.

Character classes, backslash escapes and a ``**`` that is followed by anything
but ``/`` are not implemented; a pattern that uses one fails
``test_every_pattern_uses_only_what_the_matchers_read``.
"""

from __future__ import annotations

import functools
import posixpath
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

IGNORE_FILES = {
    "production": ROOT / ".dockerignore",
}

# What each file leaves out of the tracked tree on purpose. The production
# images carry neither the tests nor the documentation nor the build and CI
# configuration.
LEFT_OUT_ON_PURPOSE: dict[str, tuple[str, ...]] = {
    "production": ("tests/", "docs/", "apps/docs/", ".github/", "docker/", ".gitattributes"),
}

# What a working copy can hold beside the tracked tree: samples under any
# samples directory, whatever their names, and what is derived from them.
SAMPLE_LIKE = (
    "data/samples/payload.zip",
    "data/samples/payload.exe",
    "data/samples/library.dll",
    "data/samples/program.elf",
    "data/samples/application.apk",
    "data/samples/payload",
    "data/samples/report.json",
    "data/samples/payload.json.exe",
    "data/samples/static/payload.json.exe",
    "data/samples/static/payload.exe",
    "data/samples/static/payload",
    "data/samples/static/nested/fixture.json",
    "data/samples/static/folder.json/payload.exe",
    "data/samples/static/folder.json/deeper/payload",
    "data/samples/dynamic/payload.zip",
    "data/samples/network/capture.pcap",
    "data/samples/network/nested/capture.json",
    "data/samples/dyn/payload.exe",
    "data/samples/stat/payload.exe",
    "data/samples/net/payload.exe",
    "data/samples/.tmp/upload",
    "data/samples/.work/carved.bin",
    "data/samples/r2-work/project/analysis",
    "data/samples/linux-batch/program",
    "data/samples/linux-batch/nested/deeper/library.so",
    "apps/api/data/samples/application.apk",
    "apps/api/data/samples/nested/payload",
    "data/uploads/document.doc",
    "apps/api/data/uploads/document.doc",
    "data/cape_reports/1.json",
)

# Secrets a working copy can hold; every ignore file leaves them out wherever they sit.
SECRET_LIKE = (
    ".env",
    "bootstrap.env",
    "docker/.env",
    "apps/api/.env",
    "apps/web/.env.local",
    "apps/web/.env.production.local",
    "services/analysis-mcp/.env",
)

# A fixture added beside the tracked ones is kept as they are.
NEW_FIXTURES = (
    "data/samples/dynamic/sample_2.json",
    "data/samples/network/sample_2.json",
    "data/samples/static/sample_2.json",
)

Rule = tuple[bool, str, re.Pattern[str]]
Matcher = Callable[[tuple[Rule, ...], str], bool]


def _compile(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            parts.append("(?:.*/)?")
            index += 3
        elif pattern.startswith("**", index):
            parts.append(".*")
            index += 2
        elif pattern[index] == "*":
            parts.append("[^/]*")
            index += 1
        elif pattern[index] == "?":
            parts.append("[^/]")
            index += 1
        else:
            parts.append(re.escape(pattern[index]))
            index += 1
    return re.compile("".join(parts) + r"\Z")


def _read_rules(text: str) -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        exception = line.startswith("!")
        if exception:
            line = line[1:].strip()
        cleaned = posixpath.normpath(line).lstrip("/")
        rules.append((exception, cleaned, _compile(cleaned)))
    return tuple(rules)


@functools.cache
def _rules(name: str) -> tuple[Rule, ...]:
    return _read_rules(IGNORE_FILES[name].read_text(encoding="utf-8"))


def _left_out(rules: tuple[Rule, ...], path: str) -> bool:
    """Parent-aware matching: a pattern that matches any parent matches the path."""
    segments = path.split("/")
    candidates = ["/".join(segments[:depth]) for depth in range(1, len(segments) + 1)]
    left_out = False
    for exception, _, pattern in rules:
        if exception != left_out:
            continue
        if any(pattern.match(candidate) for candidate in candidates):
            left_out = not exception
    return left_out


def _left_out_depth_limited(rules: tuple[Rule, ...], path: str) -> bool:
    """Depth-limited matching: the path, or the one parent at the pattern's depth."""
    parents = path.split("/")[:-1]
    left_out = False
    for exception, cleaned, pattern in rules:
        hit = pattern.match(path) is not None
        depth = len(cleaned.split("/"))
        if not hit and parents and depth <= len(parents):
            hit = pattern.match("/".join(parents[:depth])) is not None
        if hit:
            left_out = not exception
    return left_out


MATCHERS: dict[str, Matcher] = {
    "parent-aware": _left_out,
    "depth-limited": _left_out_depth_limited,
}


def _directories(path: str) -> list[str]:
    segments = path.split("/")
    return ["/".join(segments[:depth]) for depth in range(1, len(segments))]


@functools.cache
def _skipped(name: str, matcher: str, directory: str, *, loose: bool) -> bool:
    """Whether a walker skips ``directory``: left out, with no exception pattern inside it.

    Docker's walkers look for an exception that starts with the directory and a
    slash; docker-py's (``loose``) for one that starts with the directory's name.
    """
    rules = _rules(name)
    if not MATCHERS[matcher](rules, directory):
        return False
    if loose:
        return not any(
            exception and cleaned.startswith(directory) for exception, cleaned, _ in rules
        )
    return not any(
        exception and f"{cleaned}/".startswith(f"{directory}/") for exception, cleaned, _ in rules
    )


@functools.cache
def _left_out_by_every_builder(name: str, path: str) -> bool:
    rules = _rules(name)
    return _left_out(rules, path) and (
        _left_out_depth_limited(rules, path)
        or any(_skipped(name, "depth-limited", d, loose=True) for d in _directories(path))
    )


@functools.cache
def _kept_by_every_builder(name: str, path: str) -> bool:
    rules = _rules(name)
    return all(
        not matcher(rules, path)
        and not any(_skipped(name, key, d, loose=False) for d in _directories(path))
        for key, matcher in MATCHERS.items()
    )


@pytest.fixture(scope="module")
def tracked() -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return listing.splitlines()


def test_the_matchers_read_dockers_documented_examples() -> None:
    """The examples Docker's .dockerignore documentation gives, under both families.

    They hold the matchers to Docker's reading, so the tests below do not merely
    agree with themselves.
    """
    cases = [
        (["*/temp*"], "somedir/temporary.txt", True),
        (["*/temp*"], "somedir/temp", True),
        (["*/temp*"], "temp", False),
        (["*/*/temp*"], "somedir/subdir/temporary.txt", True),
        (["temp?"], "tempa", True),
        (["temp?"], "temp", False),
        (["**/*.go"], "main.go", True),
        (["**/*.go"], "cmd/tool/main.go", True),
        (["*.md", "!README.md"], "README.md", False),
        (["*.md", "!README.md"], "CHANGES.md", True),
        (["*.md", "!README.md"], "docs/guide.md", False),
        (["*.md", "!README*.md", "README-secret.md"], "README-secret.md", True),
        (["*.md", "!README*.md", "README-secret.md"], "README-public.md", False),
        (["*.md", "README-secret.md", "!README*.md"], "README-secret.md", False),
        (["/foo/bar"], "foo/bar", True),
        (["foo/bar/"], "foo/bar/baz", True),
    ]
    wrong = [
        (family, lines, path)
        for family, matcher in MATCHERS.items()
        for lines, path, left_out in cases
        if matcher(_read_rules("\n".join(lines)), path) is not left_out
    ]
    assert wrong == []


def test_the_families_part_where_a_pattern_reaches_a_file_only_through_a_parent() -> None:
    """A samples rule that leans on parent matching holds under one family only.

    ``**/data/samples/*`` matches the fixture directory, not the file in it; a
    depth-limited builder never tries the directory for that file, so the file
    gets in there and stays out under parent-aware matching. The rule in the
    ignore file matches every file below a samples directory directly instead.
    """
    rules = _read_rules("**/data/samples/*\n!data/samples/static/*.json\n")
    path = "data/samples/static/payload.exe"
    assert _left_out(rules, path)
    assert not _left_out_depth_limited(rules, path)


@pytest.mark.parametrize("name", sorted(IGNORE_FILES))
def test_every_pattern_uses_only_what_the_matchers_read(name: str) -> None:
    unread = [
        cleaned for _, cleaned, _ in _rules(name) if re.search(r"[\[\]\\]|\*\*(?!/|\Z)", cleaned)
    ]
    assert unread == [], f"{IGNORE_FILES[name].name}: patterns this test cannot judge: {unread}"


@pytest.mark.parametrize("name", sorted(IGNORE_FILES))
def test_every_sample_and_secret_a_working_copy_holds_is_left_out_by_every_builder(
    name: str,
) -> None:
    let_in = [
        path for path in (*SAMPLE_LIKE, *SECRET_LIKE) if not _left_out_by_every_builder(name, path)
    ]
    assert let_in == [], f"{IGNORE_FILES[name].name} lets these into a build context: {let_in}"


@pytest.mark.parametrize("name", sorted(IGNORE_FILES))
def test_the_tracked_fixtures_and_new_ones_beside_them_are_kept_by_every_builder(
    name: str, tracked: list[str]
) -> None:
    fixtures = [path for path in tracked if "data/samples/" in path]
    assert fixtures, "the repository tracks sample fixtures, and this test reads them from git"
    dropped = [
        path for path in (*fixtures, *NEW_FIXTURES) if not _kept_by_every_builder(name, path)
    ]
    assert dropped == [], f"{IGNORE_FILES[name].name} leaves out {dropped}"


@pytest.mark.parametrize("name", sorted(IGNORE_FILES))
def test_a_tracked_file_is_left_out_by_every_builder_exactly_where_the_file_means_to(
    name: str, tracked: list[str]
) -> None:
    meant = LEFT_OUT_ON_PURPOSE[name]
    wrong = [
        path
        for path in tracked
        if not (
            _left_out_by_every_builder(name, path)
            if path.startswith(meant)
            else _kept_by_every_builder(name, path)
        )
    ]
    assert wrong == [], (
        f"{IGNORE_FILES[name].name} leaves out a tracked file it should keep, or keeps one it "
        f"should leave out, on some builder: {wrong[:20]}"
    )
