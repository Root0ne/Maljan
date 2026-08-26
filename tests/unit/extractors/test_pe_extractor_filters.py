"""Unit tests for :func:`maljan.extractors.pe_extractor._looks_like_domain`.

The filter is what keeps APK / asset / source filenames from being labelled
``DOMAIN`` in the STATIC tab. Yesterday's E2E run on zararli.apk showed
``resources.arsc``, ``icon.png``, ``classes.dex``, ``AndroidManifest.xml``,
and ``message.cpp`` all surfacing as DOMAIN — this suite locks in the
expanded blacklist so regressions are caught at unit-test time.
"""

from __future__ import annotations

import pytest

from maljan.extractors.pe_extractor import _looks_like_domain

# Pairs of (text, expected) — True means "treat as domain candidate".
_NON_DOMAIN_CASES = [
    # Native binaries
    "kernel32.dll",
    "wininet.dll",
    "userspace.exe",
    "driver.sys",
    "libcrypto.so",
    "libfoo.dylib",
    # Source / scripts
    "script.py",
    "bundle.js",
    "main.c",
    "stdio.h",
    "vector.cpp",
    "string.hpp",
    "Main.java",
    # Android / mobile artefacts (the headline reason for the fix)
    "zararli.apk",
    "bundle.aab",
    "resources.arsc",
    "classes.dex",
    "Activity.smali",
    "module.kotlin_module",
    # Bundled assets
    "icon.png",
    "logo.jpg",
    "preview.webp",
    "icon.svg",
    "background.gif",
    "favicon.ico",
    # Config / markup
    "AndroidManifest.xml",
    "config.json",
    "policy.yaml",
    "settings.yml",
    "pyproject.toml",
    "app.ini",
    "main.cfg",
    "redis.conf",
    "index.html",
    "report.htm",
    "style.css",
    "notes.txt",
    "readme.md",
    "data.csv",
    # Office / Java / .NET packaging
    "lib.jar",
    "Main.class",
    "doc.pdf",
    "report.docx",
    "sheet.xlsx",
    "deck.pptx",
]

_REAL_DOMAIN_CASES = [
    "google.com",
    "evil.example.net",
    # Was "c2-server.malware.tld" until 2026-07-27. `.tld` is not a TLD — it is
    # documentation shorthand — and the filter now checks the last label against
    # a real list. Moved to a TLD that exists rather than loosened, since
    # loosening it to keep the fixture green would have re-admitted the .NET
    # namespaces the check was added to reject.
    "c2-server.malware.top",
    "api.example.io",
    "sub.deep.example.co.uk",
    "888kafa.com",
    "cdn.evil-host.ru",
]

# Dotted identifiers that are shaped exactly like hostnames. Every one of these
# was emitted as a `domain` IOC before the positive TLD check landed.
_NAMESPACE_CASES = [
    "System.Collections.Generic",
    "System.Net",
    "System.IO",
    "System.Runtime.InteropServices",
    "Microsoft.Win32",
    "System.Text.RegularExpressions",
]


@pytest.mark.parametrize("filename", _NON_DOMAIN_CASES)
def test_non_domain_filenames_are_rejected(filename: str) -> None:
    """File-like strings must never classify as a DOMAIN IOC."""
    assert _looks_like_domain(filename) is False, (
        f"{filename!r} was incorrectly accepted as a domain"
    )


@pytest.mark.parametrize("fqdn", _REAL_DOMAIN_CASES)
def test_real_domains_pass(fqdn: str) -> None:
    """Genuine FQDNs continue to pass the heuristic."""
    assert _looks_like_domain(fqdn) is True, f"{fqdn!r} was incorrectly rejected"


@pytest.mark.parametrize("identifier", _NAMESPACE_CASES)
def test_dotted_identifiers_are_not_domains(identifier: str) -> None:
    """A .NET namespace is dot-separated labels ending in something that can
    look like a TLD. Every one of these was reported as a C2 domain."""
    assert _looks_like_domain(identifier) is False, (
        f"{identifier!r} was incorrectly accepted as a domain"
    )


def test_trailing_dot_rejected() -> None:
    assert _looks_like_domain("evil.tld.") is False


def test_leading_dot_rejected() -> None:
    assert _looks_like_domain(".env") is False


def test_too_many_dots_rejected() -> None:
    assert _looks_like_domain("a.b.c.d.e.f.tld") is False


def test_too_short_rejected() -> None:
    assert _looks_like_domain("a.b") is False


def test_case_insensitive_suffix_match() -> None:
    """``.PNG`` and ``.png`` must both be filtered."""
    assert _looks_like_domain("ICON.PNG") is False
    assert _looks_like_domain("ICON.png") is False
