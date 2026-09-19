"""Curated denylists / allowlists for indicator filtering.

A 2026-05-28 noise audit surfaced ~50 hallucinated indicator SDOs whose
pattern values were toolchain/build paths, bundled bytecode class refs,
or random extracted short strings (``/I FyD``, ``/urLU4b``, etc.) — all
substrings of the analyst report so the corpus-presence check passed
them through.

The constants here drive the acceptance-based tightening implemented in
:mod:`maljan.agents.judge_postprocess`. Kept in a separate module so
the audit surface (what's deny / what's allow) is easy to read.
"""

from __future__ import annotations

import re

# Real, persisted file extensions worth treating as IOCs. Driven by what
# malware analysts actually care about — dropper / payload / staged
# artefact / persistence file extensions across all platforms. Anything
# not in this set must hit one of the OS-resource prefixes below or be
# corroborated by sandbox file_operations to survive.
IOC_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".exe",
        ".dll",
        ".sys",
        ".scr",
        ".com",
        ".bat",
        ".cmd",
        ".ps1",
        ".psm1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".msi",
        ".msp",
        ".reg",
        ".lnk",
        ".inf",
        ".cpl",
        ".so",
        ".dylib",
        ".elf",
        ".o",
        ".apk",
        ".dex",
        ".aab",
        ".ipa",
        ".jar",
        ".war",
        ".py",
        ".pyc",
        ".pl",
        ".rb",
        ".php",
        ".sh",
        ".bin",
        ".dat",
        ".enc",
        ".locked",
        ".crypt",
        ".crypto",
        ".vault",
    }
)

# OS-resource prefixes. A path starting with any of these is anchored
# into a real filesystem location (Windows registry hive / Unix mount).
# Random extracted strings rarely look like this.
IOC_OS_RESOURCE_PREFIXES: tuple[str, ...] = (
    "/data/",
    "/sdcard/",
    "/system/",
    "/etc/",
    "/var/",
    "/usr/",
    "/tmp/",
    "/dev/",
    "/proc/",
    "/Users/",
    "/Library/",
    "/Applications/",
    "C:\\",
    "D:\\",
    "%appdata%",
    "%programdata%",
    "%temp%",
    "%localappdata%",
    "%systemroot%",
    "%windir%",
    "HKLM\\",
    "HKCU\\",
    "HKEY_LOCAL_MACHINE\\",
    "HKEY_CURRENT_USER\\",
)


# Compile-artefact regex — matches NDK / LLVM / toolchain paths embedded
# in shipped binaries. These leak into the static extractor's
# interesting_strings list when scanning bundled native libraries and
# would otherwise pass the corpus check (they ARE in the corpus, but
# they aren't IOCs).
COMPILE_ARTIFACT_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"/buildbot/"
    r"|/ndk-?r?\d+"
    r"|/toolchain/"
    r"|/llvm-project"
    r"|/libcxx/include/"
    r"|/aarch64-(?:linux|unknown)"
    r"|/x86_64-(?:linux|unknown)"
    r"|/armv7-?[ahw]"
    r"|/clang/"
    r"|/gcc/"
    r"|/include/c\+\+/"
    r")",
    re.IGNORECASE,
)


# JVM/bytecode class-namespace refs (e.g. ``/lang/ClassCastException``,
# ``/io/IOException``, ``/util/HashMap``). These class-namespace paths are
# surfaced by string extraction over bundled bytecode — not malicious file
# paths.
FOREIGN_CLASS_REF_RE: re.Pattern[str] = re.compile(
    r"^/(?:lang|util|io|net|awt|nio|sql|text|reflect|math|security)"
    r"/[A-Z][A-Za-z]+(?:Exception|Error)?$"
)


# URL denylist — developer / build / SDK hosts. Indicators pointing at
# these are almost certainly extracted from compile artefacts (e.g. a
# ``toolchain/llvm-project`` NDK header URL baked into a shipped binary).
URL_DENY_HOSTS: tuple[str, ...] = (
    "android.googlesource.com",
    "developer.android.com",
    "schemas.android.com",
    "kotlinlang.org",
    "golang.org",
    "go.dev",
    "crates.io",
    "pypi.org",
    "rubygems.org",
    "nuget.org",
    "github.com/golang/",
    "github.com/rust-lang/",
    "raw.githubusercontent.com/golang/",
    "raw.githubusercontent.com/rust-lang/",
)


# Maximum number of file:name indicators kept per report. Beyond this we
# truncate, sorted by surviving evidence corroboration.
MAX_FILE_NAME_INDICATORS: int = 10

# Hard cap on the total number of indicator SDOs in the STIX bundle.
# A Linux ELF audit hit 19 indicators (4
# hashes + 5 network + 10 file:name) and broke the downstream-
# tractability assertion. Applied by the STIX renderer with priority
# order: hashes (sha256 always) -> network IOCs -> file:name.
MAX_TOTAL_INDICATORS: int = 15


# How many hexadecimal characters a digest of each algorithm STIX names has.
# A literal of any other length is not that digest: a consumer matching on MD5
# will never match sixteen of the thirty-two characters of one, and the run
# that exported ``32066ff6369a7bd7`` offered a value nothing can act on. Here
# rather than beside either of its two callers — the grounding check and the
# export's own decline — so the two cannot come to disagree about what a hash
# is.
HASH_HEX_LENGTHS: dict[str, int] = {
    "MD5": 32,
    "SHA-1": 40,
    "SHA1": 40,
    "SHA-224": 56,
    "SHA-256": 64,
    "SHA256": 64,
    "SHA-384": 96,
    "SHA-512": 128,
    "SHA512": 128,
    "SHA3-256": 64,
    "SHA3-512": 128,
}

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# The algorithm a ``file:hashes`` comparison names, read off the object path the
# one reader gives back: ``hashes.'md5'`` quotes it as a key and ``hashes.md5``
# writes it plainly.
_HASH_ALGORITHM_RE = re.compile(r"^hashes\.(?:'(?P<quoted>.*)'|(?P<bare>[a-z0-9_-]+))$")

# The operators that assert a literal *is* a digest of the algorithm it is
# written under. ``IN`` is one of them: a judge with two candidate digests
# writes them as a list, and every member of that list is a value a consumer
# will try to match. The length question was asked of the ``=`` form alone, so
# the same truncated digest that is refused written one way was carried
# written the other.
_ASSERTING_OPERATORS = ("=", "in")


def hash_literal_is_wellformed(algorithm: object, value: object) -> bool:
    """Whether ``value`` is a digest of ``algorithm``, by length and alphabet.

    An algorithm this does not know is left alone: STIX allows a bundle to name
    a digest this table has never heard of, and refusing one would be code
    deciding a question it cannot answer.
    """
    expected = HASH_HEX_LENGTHS.get(str(algorithm or "").strip().upper())
    if expected is None:
        return True
    literal = str(value or "").strip()
    return len(literal) == expected and HEX_RE.match(literal) is not None


def _asserts_a_value(operator: str) -> bool:
    """Whether this comparison says a literal is the thing the path names.

    ``=`` and ``IN (…)``. A regular expression or a subset test says something
    about a shape rather than about a digest, and a digest question asked of
    one would refuse a pattern for a reason that is not true of it.
    """
    return operator.split("(")[0].strip() in _ASSERTING_OPERATORS


def malformed_hash_in(pattern: str) -> tuple[str, str] | None:
    """The first ``(algorithm, literal)`` in ``pattern`` that is not that digest.

    Read through :func:`~maljan.schemas.stix_pattern.read_comparisons`, which is
    the one reader of a pattern this repository has. A second regex over the
    same syntax is how two readers come to disagree about what a pattern says,
    and this one did not undo an escape either.
    """
    from maljan.schemas.stix_pattern import read_comparisons

    for comparison in read_comparisons(pattern or ""):
        if comparison.object_type != "file" or not _asserts_a_value(comparison.operator):
            continue
        named = _HASH_ALGORITHM_RE.match(comparison.prop)
        if named is None:
            continue
        algorithm = named.group("quoted") or named.group("bare") or ""
        if not hash_literal_is_wellformed(algorithm, comparison.literal):
            return (str(algorithm).strip().upper(), comparison.literal)
    return None


# What continues one label of a value: the characters a host name, a path
# segment, a mailbox, a digest or a registry key is written with.
_CONTINUES_A_LABEL_RE = re.compile(r"[A-Za-z0-9._\-@+%~]")

# The three characters that join the parts of a compound value rather than
# extend a part. They bound a part — but only for a value that has parts of its
# own; see the docstring below.
_JOINS_A_VALUE = "/\\:"
_CONTINUES_A_COMPONENT_RE = re.compile(r"[A-Za-z0-9._\-@+%~/\\:]")

# The one character that is a value's and a sentence's both. Which it is shows
# in what follows it: ``a@b.com.`` ends a sentence, ``a@b.com.tr`` is a longer
# name.
_TERMINAL_DOT = "."

# The letters a two-character escape is written with. Text a tool returned as
# JSON reaches the corpus with its escapes intact, so a value written straight
# after a newline is written straight after a backslash and an ``n``.
_ESCAPE_LETTERS = frozenset('nrt"\\/bf')

# What a path component is written with, for telling an escape from a
# separator below.
_ENDS_A_PATH_COMPONENT = "\\/ \t\"'"


def whole_value_in(literal: str, haystack: str) -> bool:
    """Whether ``literal`` appears in ``haystack`` as a value of its own.

    Containment by substring says a truncated MD5 is present whenever the whole
    digest is, and says a short mutex name is present whenever some longer
    token happens to spell it. Both are the same mistake: the run recorded
    something else that this value is a slice of. Both arguments are compared
    lowercased, because the corpus is.

    The boundary rule, once, because both ends read it. A value runs from one
    boundary to the next, and a boundary is anything that does not continue a
    label: a space, a bracket, a quote, and the newline a tool's JSON output
    writes as two characters.

    ``/``, ``\\`` and ``:`` join the parts of a compound value rather than
    extend a part, so they bound a part too — **but only for a value that has
    parts of its own.** A value that carries one of those three characters or a
    dot is a compound or distinctive thing — a path, a host, an address, a
    mailbox, a file name with an extension — and finding it between two of them
    is finding that thing: ``evil.exe`` is corroborated by
    ``c:\\tmp\\evil.exe`` and the host of ``http://evil.example/x`` is
    corroborated by the URL. A bare single component is not: ``system32``,
    ``8080``, ``temp`` and a one-word mutex name appear inside half the paths a
    sandbox writes down, and this function decides the second-source bar for
    the mutex, registry, path, e-mail and address kinds. One of those is found
    only as a free-standing token, which is the rule that held before the
    joining characters became boundaries.

    A ``.`` continues a label either way, so ``168.1.1`` is not found inside
    ``192.168.1.1`` and ``evil.com`` is not found inside ``notevil.com``,
    ``sub.evil.com`` or ``evil.com.br`` — except at the end of a value, where a
    ``.`` that nothing continues is the sentence's full stop.
    """
    lowered = str(literal or "").lower()
    if not lowered:
        return False
    continues = _continuation_for(lowered)
    start = haystack.find(lowered)
    while start != -1:
        if _opens_a_value(haystack, start, continues) and _closes_a_value(
            haystack, start + len(lowered), continues
        ):
            return True
        start = haystack.find(lowered, start + 1)
    return False


def _continuation_for(value: str) -> re.Pattern[str]:
    """Which characters continue the thing ``value`` is, rather than bound it."""
    if any(character in value for character in _JOINS_A_VALUE) or _TERMINAL_DOT in value:
        return _CONTINUES_A_LABEL_RE
    return _CONTINUES_A_COMPONENT_RE


def _opens_a_value(haystack: str, start: int, continues: re.Pattern[str]) -> bool:
    """Whether a value may begin at ``start`` rather than continue a longer one."""
    if start == 0 or not continues.match(haystack[start - 1]):
        return True
    return _after_an_escape(haystack, start)


def _closes_a_value(haystack: str, end: int, continues: re.Pattern[str]) -> bool:
    """Whether a value may end at ``end`` rather than run on into a longer one."""
    after = haystack[end : end + 1]
    if not after or not continues.match(after):
        return True
    if _before_an_escape(haystack, end):
        return True
    if after != _TERMINAL_DOT:
        return False
    following = haystack[end + 1 : end + 2]
    return not following or not continues.match(following)


def _after_an_escape(haystack: str, start: int) -> bool:
    """Whether the two characters before ``start`` are an escape, not a value's."""
    return start >= 2 and _is_an_escape(haystack, start - 2)


def _before_an_escape(haystack: str, end: int) -> bool:
    """Whether the two characters at ``end`` are an escape, not a value's."""
    return _is_an_escape(haystack, end)


def _is_an_escape(haystack: str, index: int) -> bool:
    """Whether a backslash at ``index`` opens a two-character escape.

    JSON writes a newline as ``\\`` and ``n``, and a path's own backslash as two
    backslashes, so inside JSON the two readings never collide. In text that is
    not JSON they can: ``c:\\new\\evil.com`` carries the same two characters and
    the backslash is a separator. What tells them apart is the component in
    front of it — a drive root, or another separator — so a backslash that
    separates two parts of a path is never read as an escape.
    """
    if (
        haystack[index : index + 1] != "\\"
        or haystack[index + 1 : index + 2] not in _ESCAPE_LETTERS
    ):
        return False
    return not _separates_a_path(haystack, index)


def _separates_a_path(haystack: str, index: int) -> bool:
    """Whether the backslash at ``index`` stands between two parts of a path."""
    cut = index
    while cut > 0 and haystack[cut - 1] not in _ENDS_A_PATH_COMPONENT:
        cut -= 1
    component = haystack[cut:index]
    return component.endswith(":") or (cut > 0 and haystack[cut - 1] in "\\/")
