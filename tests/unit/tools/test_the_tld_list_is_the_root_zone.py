"""The string sweep's top-level domains are the root zone's own list, vendored with its version.

The list is ``data/tlds-alpha-by-domain.txt`` as the registry publishes it,
refreshed by ``scripts/knowledge/refresh_iana_tlds.py``; nothing here reads the
network. A two-label name under a TLD that is also a file extension a binary
carries in bulk (``install.sh``, ``archive.zip``) is a file to the sweep; a
longer name under one is a host.
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


def test_the_sweep_reads_a_file_under_a_file_extension_tld_as_no_host() -> None:
    found = _domains("install.sh archive.zip clip.mov logo.ai invoice.one oem1.cat Module.pm")

    assert found == []


def test_the_sweep_still_reads_the_country_codes_it_always_read() -> None:
    assert set(_domains("evil.pl and evil.rs")) == {"evil.pl", "evil.rs"}


def test_a_detection_name_wearing_a_shouted_generic_tld_is_no_host() -> None:
    assert _domains("Latrodectus.CPA and Lactrodectus.CPA, authrootstl.cab") == []


def test_a_host_somebody_capitalised_is_still_a_host() -> None:
    assert set(_domains("Evil.COM and Relay.NET")) == {"Evil.COM", "Relay.NET"}
