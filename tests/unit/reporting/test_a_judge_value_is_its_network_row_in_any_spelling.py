"""A judge's indicator is asked as the network block's row for it, found by the one spelling.

``judge_value_answer`` compared an address and a URL with the row exactly, so a
judge writing ``http://EVIL-C2.top/gate.php`` or an IPv6 address in capitals
was told the value was "named only by the judge's indicator" while the sandbox
had recorded it. Every other lookup keys values by ``value_key``.
"""

from __future__ import annotations

import pytest

from maljan.reporting.models import (
    FileHashes,
    JudgeIndicator,
    MalwareReport,
    NetworkDomain,
    NetworkIOCs,
    NetworkIP,
    NetworkURL,
    SampleIdentity,
)
from maljan.reporting.renderers.stix_renderer import judge_value_answer, one_reading


def _report(kind: str, row: str, judged: str) -> MalwareReport:
    if kind == "url":
        network = NetworkIOCs(urls=[NetworkURL(url=row, source="sandbox")])
    elif kind == "ip":
        network = NetworkIOCs(
            ips=[NetworkIP(address=row, source="sandbox", sample_process_tree=True)]
        )
    else:
        network = NetworkIOCs(domains=[NetworkDomain(fqdn=row, source="sandbox")])
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        verdict="Malware",
        overall_confidence=0.9,
        network=network,
        judge_indicators=[JudgeIndicator(kind=kind, value=judged)],
    )


@pytest.mark.parametrize(
    ("kind", "row", "judged"),
    [
        ("url", "http://evil-c2.top/gate.php", "http://evil-c2.top/gate.php"),
        ("url", "http://evil-c2.top/gate.php", "http://EVIL-C2.top/gate.php"),
        ("ip", "2a00:1450:4001:82a::200e", "2a00:1450:4001:82a::200e"),
        ("ip", "2a00:1450:4001:82a::200e", "2A00:1450:4001:82A::200E"),
        ("ip", "2a00:1450:4001:82a::200e", "[2a00:1450:4001:82a::200e]"),
        ("domain", "evil-c2.top", "EVIL-C2.top."),
    ],
)
def test_the_judge_s_spelling_finds_the_sandbox_s_row(kind: str, row: str, judged: str) -> None:
    report = _report(kind, row, judged)
    with one_reading(report):
        answer = judge_value_answer(report, kind, judged, "")
        same = judge_value_answer(report, kind, row, "")
    assert answer == same
    assert answer.startswith("yes"), answer


def test_a_url_key_folds_its_scheme_and_host_and_keeps_its_path() -> None:
    from maljan.reporting.ledger_projection import value_key

    assert (
        value_key("url", "HTTP://Evil-C2.TOP./Gate.PHP?Id=A") == "http://evil-c2.top/Gate.PHP?Id=A"
    )
    assert value_key("url", "http://a.example/x.") == "http://a.example/x."
    assert value_key("url", "http://a.example/Gate") != value_key("url", "http://a.example/gate")
