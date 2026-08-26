"""Curated denylists / allowlists for indicator filtering (Wave 4).

A 2026-05-28 noise audit surfaced ~50 hallucinated indicator SDOs whose
pattern values were toolchain/build paths, bundled bytecode class refs,
or random extracted short strings (``/I FyD``, ``/urLU4b``, etc.) — all
substrings of the analyst report so J-02's corpus-presence check passed
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
# would otherwise pass J-02's corpus check (they ARE in the corpus, but
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

# Wave 9 (2026-05-29): hard cap on the total number of indicator SDOs in
# the STIX bundle. The 2026-05-29 Linux ELF audit hit 19 indicators (4
# hashes + 5 network + 10 file:name) and broke G-FP-4's downstream-
# tractability assertion. Applied by the STIX renderer with priority
# order: hashes (sha256 always) -> network IOCs -> file:name.
MAX_TOTAL_INDICATORS: int = 15
