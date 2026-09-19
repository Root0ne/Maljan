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

# ``file:hashes.'MD5' = '<literal>'`` and the unquoted spelling of the same.
_HASH_EQUALITY_RE = re.compile(
    r"file:hashes\.(?:'(?P<quoted>[^']+)'|(?P<bare>[A-Za-z0-9_-]+))\s*=\s*'(?P<value>[^']*)'",
    re.IGNORECASE,
)


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


def malformed_hash_in(pattern: str) -> tuple[str, str] | None:
    """The first ``(algorithm, literal)`` in ``pattern`` that is not that digest."""
    for match in _HASH_EQUALITY_RE.finditer(pattern or ""):
        algorithm = match.group("quoted") or match.group("bare") or ""
        literal = match.group("value") or ""
        if not hash_literal_is_wellformed(algorithm, literal):
            return (str(algorithm).strip().upper(), literal)
    return None


# What can be part of one indicator value: the characters a host name, a path,
# a mailbox, a digest or a registry key is written with. A value found in the
# evidence between two of anything else is that value; one flanked by these is
# a slice of a longer value and is not.
_VALUE_CHARACTER_RE = re.compile(r"[A-Za-z0-9._\-@:/\\+%~]")

# The punctuation a value is written with and a sentence ends with. Either
# reading is possible for the same character, and which one it is shows in what
# follows it: ``a@b.com.`` ends a sentence, ``a@b.com.tr`` is a longer name.
_TERMINAL_PUNCTUATION = (".", ":", ",")

# A URI scheme and the colon that closes it, at the end of the text before a
# value. ``mailto:`` introduces a mailbox and ``ssh://`` a host, and neither is
# part of the value it introduces — while the dot of ``192.168.`` is. Anchored
# to a boundary of its own so the tail of a longer token cannot pass as one.
_SCHEME_END_RE = re.compile(r"(?:^|[^A-Za-z0-9._\-@:/\\+%~])[A-Za-z][A-Za-z0-9+.\-]*:$")


def whole_value_in(literal: str, haystack: str) -> bool:
    """Whether ``literal`` appears in ``haystack`` as a value of its own.

    Containment by substring says a truncated MD5 is present whenever the whole
    digest is, and says a short mutex name is present whenever some longer
    token happens to spell it. Both are the same mistake: the run recorded
    something else that this value is a slice of. Both arguments are compared
    lowercased, because the corpus is.

    The boundary rule, in one place because both ends read it. A value ends
    where a character that cannot be part of one begins — and also at a ``.``,
    ``:`` or ``,`` that nothing continues, because that one is the sentence's
    and not the value's. A value begins where a character that cannot be part
    of one ends — and also after a URI scheme's colon, because ``mailto:`` and
    ``ssh://`` introduce a value rather than extend one. Everything else that
    could continue a value does: the ``.`` of ``192.168.1.1`` keeps ``168.1.1``
    from being found in it, which is the whole point of asking.
    """
    lowered = str(literal or "").lower()
    if not lowered:
        return False
    start = haystack.find(lowered)
    while start != -1:
        if _opens_a_value(haystack, start) and _closes_a_value(haystack, start + len(lowered)):
            return True
        start = haystack.find(lowered, start + 1)
    return False


def _opens_a_value(haystack: str, start: int) -> bool:
    """Whether a value may begin at ``start`` rather than continue a longer one."""
    if start == 0 or not _VALUE_CHARACTER_RE.match(haystack[start - 1]):
        return True
    return _SCHEME_END_RE.search(haystack[:start]) is not None


def _closes_a_value(haystack: str, end: int) -> bool:
    """Whether a value may end at ``end`` rather than run on into a longer one."""
    after = haystack[end : end + 1]
    if not after or not _VALUE_CHARACTER_RE.match(after):
        return True
    if after not in _TERMINAL_PUNCTUATION:
        return False
    following = haystack[end + 1 : end + 2]
    return not following or not _VALUE_CHARACTER_RE.match(following)
