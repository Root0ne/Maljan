"""Every place a forge starts an autolink is defanged, at any depth, in one reading.

GFM starts an extended autolink at a scheme after any character that is not a
letter (its scanner walks back over letters only), at ``www.`` after a space,
``*``, ``_``, ``~`` or ``(``, and at a mailbox whose name may hold ``_``. A
reader whose word boundary treats ``_`` as a letter, or that peels one nested
URL per pass, leaves the next one live. The defanger reads every ``://``, every
``www.`` and every ``@`` of the text once, whatever stands before it and
however deep it is nested, and a value holding any characters at all (the
whole private-use block included) renders every section.
"""

from __future__ import annotations

import re
import time

import pytest

from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.markdown import (
    MarkdownRenderer,
    _defanged_text,
    _reference_spans,
)

# A scheme GFM links: http, https or ftp after anything but a letter.
_LIVE_SCHEME = re.compile(r"(?i)(?<![a-z])(?:https?|ftp)://")
# A "www." host with its first dot bare, after anything but a letter or digit.
_LIVE_WWW = re.compile(r"(?i)(?<![^\W_])www\.")
# A mailbox with a bare "@" and a bare dot in its domain.
_LIVE_MAIL = re.compile(r"[\w.+-]@[\w-]+\.[\w-]")
# A bare host under a TLD after "//", where a Markdown image or link would fetch it.
_LIVE_PROTOCOL_RELATIVE = re.compile(r"//[\w-]+\.[\w-]")


def _live(markdown: str) -> list[str]:
    found: list[str] = []
    for pattern in (_LIVE_SCHEME, _LIVE_WWW, _LIVE_MAIL, _LIVE_PROTOCOL_RELATIVE):
        found += [
            markdown[max(0, m.start() - 12) : m.end() + 12] for m in pattern.finditer(markdown)
        ]
    return found


def _nested(depth: int, joiner: str) -> str:
    return joiner.join(f"http://h{level}.example.com" for level in range(depth)) + (
        f"{joiner}https://evil.com/p"
    )


AUTOLINK_STARTS = (
    "x_www.evil.com",
    "x_http://evil.sh/p",
    "foo_http://c2.ps/x",
    "1http://evil.com/p",
    "a.http://evil.com/p",
    "x_op@evil.com",
    "op@evil_x.com",
    "(www.evil.com)",
    "~www.evil.com~",
    "*www.evil.com*",
    "/www.evil.com",
    "http://a.x*http://b.x*http://c.x*http://d.x*https://evil.com/p",
    "http://a.x~http://b.x~http://c.x~http://d.x~https://evil.com/p",
    "http://a.x/http://b.x/http://c.x/http://d.x/https://evil.com/p",
    "http://h0.com/http://h1.com/http://h2.com/http://h3.com/http://h4.com/http://h5.com",
    "![i](//evil.sh/p.png)",
    "[x](//c2.ps/a)",
    "http:///evil.sh/p",
    "x_https:////c2.ps/x",
    *(_nested(depth, joiner) for depth in (5, 8, 40) for joiner in "*~/_(-"),
)


def _report(text: str) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        technical_analysis=TechnicalAnalysis(
            command_and_control=TechnicalSubsection(title="Command and control", body=text)
        ),
        static=StaticAnalysis(
            interesting_strings=[StringIOC(value="/a C", kind="path", notes=text)]
        ),
    )


@pytest.mark.parametrize("payload", AUTOLINK_STARTS)
def test_no_autolink_start_survives_the_defanger(payload: str) -> None:
    assert _live(_defanged_text(f"Before {payload} after.")) == []


@pytest.mark.parametrize("payload", AUTOLINK_STARTS)
def test_no_autolink_start_survives_anywhere_in_the_markdown(payload: str) -> None:
    markdown = MarkdownRenderer().render(_report(f"Before {payload} after."))

    assert _live(markdown) == []


def test_a_kept_reference_link_stays_beside_a_nested_live_one() -> None:
    sha = "b" * 64
    text = f"see https://www.virustotal.com/gui/file/{sha} and x_{_nested(6, '*')}"
    written = _defanged_text(text)

    assert f"https://www.virustotal.com/gui/file/{sha}" in written
    assert _live(written.replace(f"https://www.virustotal.com/gui/file/{sha}", "")) == []


def test_a_reference_link_is_kept_as_it_was_checked() -> None:
    text = "at https://www.virustotal.com/gui/domain/evil.com/.. then"
    ((start, end),) = _reference_spans(text)

    assert text[start:end] == "https://www.virustotal.com/gui/domain/evil.com/"


def test_the_defanger_is_idempotent() -> None:
    text = "Before " + " ".join(AUTOLINK_STARTS) + " after."
    once = _defanged_text(text)

    assert _defanged_text(once) == once


_PRIVATE_USE = "".join(chr(cp) for cp in range(0xE000, 0xF900))


def test_a_value_holding_every_private_use_character_keeps_every_section() -> None:
    report = _report(_PRIVATE_USE + " http://evil.com/p")
    report.executive_summary = _PRIVATE_USE + " see www.evil.com"
    report.static.interesting_strings.append(
        StringIOC(value=_PRIVATE_USE + "x_www.evil.com", kind="path", notes=_PRIVATE_USE)
    )
    started = time.monotonic()
    markdown = MarkdownRenderer().render(report)
    elapsed = time.monotonic() - started

    assert "rendering failed" not in markdown
    assert re.search(r"^## 1\. ", markdown, re.M)
    assert re.search(r"^## 9\. ", markdown, re.M)
    assert _live(markdown) == []
    assert elapsed < 5


def _timed(text: str) -> float:
    started = time.perf_counter()
    _defanged_text(text)
    return time.perf_counter() - started


def test_long_text_is_read_in_linear_time() -> None:
    unit = (
        "It wrote x_www.evil.com, op@mail.example.org and 203.0.113.9 "
        + _nested(6, "*")
        + " beside ASP.NET and lib.rs "
        + _PRIVATE_USE[:40]
        + "\n"
    )
    small = unit * (50_000 // len(unit))
    large = unit * (200_000 // len(unit))
    _timed(small)
    small_time = min(_timed(small) for _ in range(2))
    large_time = _timed(large)

    assert _live(_defanged_text(large)) == []
    # Four times the text: linear is about four times the time, quadratic sixteen.
    assert large_time < 8 * small_time + 0.5


# Two-label names under a TLD that is also a file extension: files in free prose.
FILE_NAMES = (
    "The crate ships lib.rs.",
    "It drops install.sh and run.ps beside archive.zip.",
    "It records clip.mov and logo.ai.",
    "It runs app.py, tool.pl and Module.pm.",
    "It reads notes.md and libc.so.",
    "It installs oem1.cat and opens invoice.one.",
    "It is an ASP.NET page handler on .NET.",
    "FileVersion 10.0.0.1 is in its resources.",
)


@pytest.mark.parametrize("sentence", FILE_NAMES)
def test_a_file_name_under_a_file_extension_tld_prints_as_written(sentence: str) -> None:
    assert sentence in MarkdownRenderer().render(_report(sentence))


HOSTS_UNDER_NEW_TLDS = (
    ("It beacons to cdn.evil.sh.", "cdn.evil.sh"),
    ("It shortens through bit.ly first.", "bit.ly"),
    ("It posts to panel.evil.ai.", "panel.evil.ai"),
    ("It resolves update.example.is.", "update.example.is"),
    ("It calls home to x.ly.", "x.ly"),
    ("It fetches http://evil.sh/p.", "evil.sh/p"),
    ("Mail goes to op@evil.zip.", "op@evil.zip"),
    ("It reads www.evil.mov first.", "www.evil.mov"),
)


@pytest.mark.parametrize(("sentence", "live"), HOSTS_UNDER_NEW_TLDS)
def test_a_host_under_any_iana_tld_is_defanged(sentence: str, live: str) -> None:
    assert live not in MarkdownRenderer().render(_report(sentence))


def test_a_file_shaped_name_the_run_recorded_is_defanged() -> None:
    report = _report("It beacons to evil.sh and drops install.sh.")
    report.network = NetworkIOCs(domains=[NetworkDomain(fqdn="evil.sh", source="sandbox")])
    prose = MarkdownRenderer().render(report).split("Command and control", 1)[1]

    assert "evil.sh" not in prose.split("drops", 1)[0]
    assert "install.sh" in prose
