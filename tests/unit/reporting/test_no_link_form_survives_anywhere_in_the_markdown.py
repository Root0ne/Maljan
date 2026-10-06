"""No form a viewer links is left live anywhere in the Markdown, whatever its host.

A viewer makes a link of text only by its form: a scheme followed by ``//``, a
scheme a link or autolink syntax opens (``<…>``, ``[x](…)``, ``[r]: …``), a
``mailto:``-style scheme, a ``www.`` prefix or a mailbox. Every such form is
defanged whatever its top-level domain, length or shape; only a reference
service's own lookup stays a link. So the check is one regular expression over
the whole output, with the kept lookups taken out first, and no rule of any
viewer can differ from it: every probe payload the reviews used goes through a
report's prose and an indicator's context cell, and none leaves a live form.
"""

from __future__ import annotations

import json
import re

import pytest

from maljan.core.paths import resolve_data
from maljan.reporting.models import (
    FileHashes,
    MalwareReport,
    SampleIdentity,
    StaticAnalysis,
    StringIOC,
    TechnicalAnalysis,
    TechnicalSubsection,
)
from maljan.reporting.renderers.markdown import MarkdownRenderer, _defanged_text

# A reference service's own lookup, the one form that stays a link.
_KEPT = re.compile(
    r"(?i)https://(?:www\.virustotal\.com/gui/(?:file|url|domain|ip-address)/[A-Za-z0-9.:-]+/?"
    r"|bazaar\.abuse\.ch/sample/[0-9a-f]{64}/?"
    r"|attack\.mitre\.org/(?:techniques|tactics|software|matrices)/[A-Za-z0-9/]+)"
)
_AUTHORITY = r"[^\s/?#\\<>()\[\]{}\"'`|]*"
_DEFANGED = ("hxxp", "hxxps", "fxp")
# A scheme before "//", read whole from its first letter.
_SCHEME = re.compile(r"(?i)(?<![a-z0-9+.-])[0-9+.-]*([a-z][a-z0-9+.-]*)://")
_LIVE_FORMS = (
    # A defanged scheme whose host still holds a bare dot.
    re.compile(r"(?i)(?:hxxps?|fxp)://" + _AUTHORITY + r"(?<!\[)\.(?!\])"),
    # A scheme a link or autolink syntax opens.
    re.compile(r"(?i)(?:<|\]\(<?|(?<!\[[.:@])\]:[ \t]*)(?!(?:hxxps?|fxp):)[a-z][a-z0-9+.-]{1,31}:"),
    # A scheme a viewer links without "//".
    re.compile(r"(?i)(?<![a-z0-9+.-])(?:mailto|xmpp|javascript|vbscript|data):(?=[^\s:])"),
    # A "www." prefix with its dot bare.
    re.compile(r"(?i)(?<![^\W_])www\."),
    # A mailbox with its "@" bare and a dot in its domain.
    re.compile(r"[\w.+-]@[\w-]+\.[\w-]"),
    # A "//" target whose host holds a bare dot.
    re.compile(r"//[\w-]+\.[\w-]"),
)


def live_forms(markdown: str) -> list[str]:
    text = _KEPT.sub("KEPT", markdown)
    found_at = [
        found for found in _SCHEME.finditer(text) if found.group(1).lower() not in _DEFANGED
    ]
    found_at += [found for pattern in _LIVE_FORMS for found in pattern.finditer(text)]
    return [text[max(0, found.start() - 16) : found.end() + 16] for found in found_at]


FORMS = (
    "ws://2130706433/x",
    "sftp://10.0.0.1/in",
    "a1://evil.example",
    "WS://EVIL.EXAMPLE",
    "<irc:evil.example>",
    "<HTTP:evil.example>",
    "[x](irc:evil.example)",
    "[x](<irc:evil.example>)",
    "[r]: irc:evil.example",
    "mailto:evil.example",
    "javascript:alert(1)",
    "xmpp:op@evil.example",
    "hxxp://evil.example/a",
    "HXXPS://203.0.113.9/x",
    "fxp://files.example.org/a",
    "op@evil.sh and www.evil.zip and http://evil.rs/x",
)


def _payloads() -> list[str]:
    from tests.unit.reporting.test_every_autolink_start_is_defanged import AUTOLINK_STARTS

    fixture = json.loads(
        resolve_data("tests/fixtures/defang/earlier_defanger.json").read_text(encoding="utf-8")
    )
    payloads = [row["payload"] for row in fixture["rows"]]
    return list(dict.fromkeys([*payloads, *AUTOLINK_STARTS, *FORMS]))


PAYLOADS = _payloads()


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


@pytest.mark.parametrize("payload", FORMS)
def test_a_link_form_is_defanged_whatever_its_host(payload: str) -> None:
    assert live_forms(_defanged_text(f"Before {payload} after.")) == []


def test_no_probe_payload_leaves_a_live_form_anywhere_in_the_markdown() -> None:
    live: dict[str, list[str]] = {}
    for payload in PAYLOADS:
        found = live_forms(MarkdownRenderer().render(_report(f"Before {payload} after.")))
        if found:
            live[payload] = found
    assert live == {}


def test_all_probe_payloads_at_once_leave_no_live_form() -> None:
    assert live_forms(MarkdownRenderer().render(_report("\n\n".join(PAYLOADS)))) == []


AS_WRITTEN = (
    "Data::Data::Modulo [C0058] and Cryptography::Encrypt Data::RC4",
    "data: 5 bytes, mailto: none",
    "It is an ASP.NET page handler; the crate ships lib.rs.",
    "FileVersion 10.0.0.1 is in its resources.",
)


@pytest.mark.parametrize("sentence", AS_WRITTEN)
def test_a_text_that_is_no_link_form_prints_as_written(sentence: str) -> None:
    assert sentence in MarkdownRenderer().render(_report(sentence))
