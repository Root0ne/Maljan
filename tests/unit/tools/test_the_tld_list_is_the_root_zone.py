"""The string sweep's top-level domains are the root zone's own list, vendored with its version.

The list is ``data/tlds-alpha-by-domain.txt`` as the registry publishes it,
refreshed by ``scripts/knowledge/refresh_iana_tlds.py``; nothing here reads the
network. The list only adds hosts: everything the sweep extracted with the
shorter curated list (``tests/fixtures/strings/dev_extraction.json``, written
by that version) it still extracts, and a file-shaped host (``update.zip``,
``c2.sh``) is a candidate indicator. The report's file-name rule is a display
rule of the report alone.
"""

from __future__ import annotations

from maljan.core.paths import resolve_data
from maljan.tools.strings import _KNOWN_TLDS, iocs_from_text, read_tld_list


def test_the_data_file_parses_with_its_version_line() -> None:
    text = resolve_data("data/tlds-alpha-by-domain.txt").read_text(encoding="ascii")
    version, tlds = read_tld_list(text)

    assert version.startswith("# Version ")
    assert len(tlds) > 1000
    assert tlds == _KNOWN_TLDS


def test_the_list_holds_common_real_tlds() -> None:
    for tld in ("sh", "ps", "ac", "ly", "ai", "is", "zip", "mov", "com", "ru"):
        assert tld in _KNOWN_TLDS, tld


def test_a_list_without_its_version_line_is_refused() -> None:
    import pytest

    with pytest.raises(ValueError):
        read_tld_list("COM\nNET\n")


def _domains(text: str) -> list[str]:
    return [row["value"] for row in iocs_from_text(text, ["domain"])["iocs"]]


def test_the_sweep_reads_hosts_under_the_new_tlds() -> None:
    found = _domains("beacon cdn.evil.sh then bit.ly then panel.evil.ai then update.example.is")

    assert {"cdn.evil.sh", "bit.ly", "panel.evil.ai", "update.example.is"} <= set(found)


def test_the_sweep_reads_a_file_shaped_host_as_a_candidate() -> None:
    found = set(_domains("update.zip then cdn.mov then install.sh then panel.ai"))

    assert {"update.zip", "cdn.mov", "install.sh", "panel.ai"} <= found
    # A one- or two-letter name is read under a new TLD exactly as under an old one.
    assert ("c2.sh" in _domains("beacon c2.sh")) == ("c2.ru" in _domains("beacon c2.ru"))
    assert ("x.ai" in _domains("beacon x.ai")) == ("x.ru" in _domains("beacon x.ru"))


def test_the_sweep_still_reads_the_country_codes_it_always_read() -> None:
    assert set(_domains("evil.pl and evil.rs")) == {"evil.pl", "evil.rs"}


def test_the_sweep_extracts_everything_it_extracted_with_the_shorter_list() -> None:
    import json

    golden = json.loads(
        resolve_data("tests/fixtures/strings/dev_extraction.json").read_text(encoding="utf-8")
    )
    rows = iocs_from_text(golden["text"])["iocs"]
    found = {f"{row['kind']}\t{row['value']}" for row in rows}

    assert sorted(set(golden["expected"]) - found) == []
    assert len(found) > len(golden["expected"])


def test_the_mailbox_reader_finds_what_the_mailbox_regex_finds() -> None:
    import random

    from maljan.tools.strings import _EMAIL_RE, emails_in

    rng = random.Random(7)
    alphabet = b"ab.@-+_%c1 x"
    for _ in range(3000):
        data = bytes(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        assert emails_in(data) == _EMAIL_RE.findall(data), data
    for data in (b"a@b.comc@d.com", b"a@b.cc+x@d.com", b"op@mail.example.org", b"@x.com a@@b.co"):
        assert emails_in(data) == _EMAIL_RE.findall(data), data


def test_the_mailbox_reader_is_linear_on_a_long_run_with_no_at() -> None:
    import time

    from maljan.tools.strings import emails_in

    started = time.perf_counter()
    emails_in(b"a." * 200_000 + b"x")
    emails_in(b"a@" * 200_000)
    assert time.perf_counter() - started < 2
