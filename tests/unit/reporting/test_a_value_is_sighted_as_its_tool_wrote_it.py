"""A value's sightings are searched for as the tool wrote it, and indexed by its one key.

``value_key`` writes a path with one separator and keeps a URL's path case,
which no tool's text holds: searching the text for the key lost every POSIX
path and every forward-slash Windows path. The search reads the value's own
lowered spelling, as before; the key only indexes, and a report stored with
the old keys still resolves.
"""

from __future__ import annotations

import pytest

from maljan.agents._indicator_denylists import whole_value_in
from maljan.reporting.ledger_projection import tool_sightings, value_key
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.stix_renderer import listed_value_sightings, query_answers
from maljan.schemas.evidence import LedgerEntry

TEXT = (
    "found /tmp/evil.sh and http://x.com/Gate.php and C:/Users/x/evil.exe and "
    "C:\\Users\\y\\b.exe and C:\\Mixed/dir\\m.exe"
)
VALUES = [
    ("path", "/tmp/evil.sh"),
    ("url", "http://x.com/Gate.php"),
    ("path", "C:/Users/x/evil.exe"),
    ("path", "C:\\Users\\y\\b.exe"),
    ("path", "C:\\Mixed/dir\\m.exe"),
    ("path", "/tmp/absent"),
]


def _entry(eid: str, output: str, args: dict[str, str] | None = None) -> LedgerEntry:
    return LedgerEntry(
        id=eid, stage="static", agent="a", tool="strings", args=args or {}, ok=True, output=output
    )


def test_every_spelling_of_a_path_is_sighted() -> None:
    seen, _asked = tool_sightings([_entry("ev_1", TEXT)], VALUES)
    for kind, value in VALUES[:-1]:
        assert seen[value_key(kind, value)] == [("ev_1", "strings")], value
    assert seen[value_key("path", "/tmp/absent")] == []


@pytest.mark.parametrize(("kind", "value"), VALUES)
def test_every_value_the_old_search_saw_is_still_seen(kind: str, value: str) -> None:
    entries = [_entry("ev_1", TEXT), _entry("ev_2", "nothing"), _entry("ev_3", TEXT.upper())]
    old = [
        e.id for e in entries if whole_value_in(value.lower().rstrip("."), str(e.output).lower())
    ]
    seen, _asked = tool_sightings(entries, [(kind, value)])
    assert [eid for eid, _tool in seen[value_key(kind, value)]] == old


def test_two_spellings_of_one_path_hold_what_either_is_seen_in() -> None:
    entries = [_entry("ev_1", "wrote /tmp/x"), _entry("ev_2", "wrote \\tmp\\x")]
    seen, _asked = tool_sightings(entries, [("path", "/tmp/x"), ("path", "\\tmp\\x")])
    assert seen == {value_key("path", "/tmp/x"): [("ev_1", "strings"), ("ev_2", "strings")]}


def test_a_report_stored_with_the_old_keys_still_resolves() -> None:
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        tool_sightings={
            "/tmp/evil.sh": [("ev_1", "strings")],
            "http://x.com/gate.php": [("ev_2", "floss")],
        },
        tool_queries={"c:/users/x/evil.exe": [("ev_3", "lookup")]},
    )
    assert listed_value_sightings(report, "path", "/tmp/evil.sh")[0] == "ev_1 (strings)"
    assert listed_value_sightings(report, "url", "http://x.com/Gate.php")[0] == "ev_2 (floss)"
    assert query_answers(report, "path", "C:/Users/x/evil.exe") == "ev_3 lookup"
