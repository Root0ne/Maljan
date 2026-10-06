"""The readers changed for two-character labels and IPv6 still read everything dev read.

The two-character rule only adds values. Each row is an input and what dev's
string sweep, host reader, publish checks and defanger made of it, recorded
from dev's code: a host written after a kernel object's namespace, a host at
the end of an ordinary path, and a two-label name under a multipart second
level (``co.com``, ``in.com``) are read, asked about and defanged as before.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import (
    _unstated_values,
    network_values_in,
    recommendation_indicator_violations,
)
from maljan.reporting.renderers.markdown import _defanged_text
from maljan.tools.strings import iocs_from_text

# (input, sweep, host reader, values the publish check names, recommendation
# questions, defanged text): dev's output for each.
DEV = [
    (
        "The sample beacons to Global\\c2.example.com every 60 seconds.",
        ["c2.example.com"],
        [("domain", "c2.example.com")],
        ["c2.example.com"],
        1,
        "The sample beacons to Global\\c2[.]example[.]com every 60 seconds.",
    ),
    (
        "Block Local\\updates.badcdn.net at the proxy.",
        ["updates.badcdn.net"],
        [("domain", "updates.badcdn.net")],
        ["updates.badcdn.net"],
        1,
        "Block Local\\updates[.]badcdn[.]net at the proxy.",
    ),
    (
        "Block Session\\1\\evil.example.org/path at the proxy.",
        ["evil.example.org"],
        [("domain", "evil.example.org")],
        ["evil.example.org"],
        1,
        "Block Session\\1\\evil[.]example[.]org/path at the proxy.",
    ),
    (
        "Block the host AppData\\Local\\c2.example.com.",
        [],
        [("domain", "c2.example.com")],
        ["c2.example.com"],
        1,
        "Block the host AppData\\Local\\c2[.]example[.]com.",
    ),
    (
        "mutex Global\\mtx.app created",
        ["mtx.app"],
        [("domain", "mtx.app")],
        ["mtx.app"],
        1,
        "mutex Global\\mtx[.]app created",
    ),
    (
        "Local\\EVIL.COM",
        [],
        [],
        [],
        0,
        "Local\\EVIL[.]COM",
    ),
    (
        "\\Sessions\\1\\BaseNamedObjects\\c2.example.com",
        ["c2.example.com"],
        [("domain", "c2.example.com")],
        ["c2.example.com"],
        1,
        "\\Sessions\\1\\BaseNamedObjects\\c2[.]example[.]com",
    ),
    (
        "Block ac.com and ac.ru at the proxy.",
        ["ac.com"],
        [("domain", "ac.com")],
        ["ac.com"],
        1,
        "Block ac[.]com and ac.ru at the proxy.",
    ),
    (
        "Block co.com and co.ru at the proxy.",
        ["co.com"],
        [("domain", "co.com")],
        ["co.com"],
        1,
        "Block co[.]com and co.ru at the proxy.",
    ),
    (
        "Block in.com and in.ru at the proxy.",
        ["in.com"],
        [("domain", "in.com")],
        ["in.com"],
        1,
        "Block in[.]com and in.ru at the proxy.",
    ),
    (
        "Block ne.com and ne.ru at the proxy.",
        ["ne.com"],
        [("domain", "ne.com")],
        ["ne.com"],
        1,
        "Block ne[.]com and ne.ru at the proxy.",
    ),
    (
        "Block or.com and or.ru at the proxy.",
        ["or.com"],
        [("domain", "or.com")],
        ["or.com"],
        1,
        "Block or[.]com and or.ru at the proxy.",
    ),
]


def _no_row(kind: str, value: str) -> str:
    return ""


@pytest.mark.parametrize(("text", "sweep", "reader", "named", "asked", "defanged"), DEV)
def test_every_reader_reads_what_dev_read(
    text: str,
    sweep: list[str],
    reader: list[tuple[str, str]],
    named: list[str],
    asked: int,
    defanged: str,
) -> None:
    assert [row["value"] for row in iocs_from_text(text, ["domain"])["iocs"]] == sweep
    assert network_values_in(text) == reader
    assert [value for _kind, value, _state in _unstated_values(text, _no_row)] == named
    payload = {"defensive_recommendations": [{"action": text}]}
    assert len(recommendation_indicator_violations(payload, _no_row)) == asked
    assert _defanged_text(text) == defanged


def test_the_publish_checks_read_a_long_text_in_linear_time() -> None:
    import time

    hosts = " ".join(f"h{i}.example{i % 97}.com" for i in range(10_000))
    objects = " ".join(f"Global\\h{i}.example.com" for i in range(12_500))
    for text in (hosts, objects):
        started = time.perf_counter()
        _unstated_values(text, _no_row)
        assert time.perf_counter() - started < 10, len(text)
