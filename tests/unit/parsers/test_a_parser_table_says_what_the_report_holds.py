"""A parser's summary says what the sandbox report holds, in tables a value cannot break.

- "ZERO OBSERVED EVENTS" was written whenever four parts were empty, though
  the report held processes, files, keys or dropped files: it is now written
  only when every behaviour part is empty, and otherwise the parts the tables
  do not summarise are listed with their counts.
- A sandbox value went into a Markdown table as written: a pipe added a
  column, and a newline ended the table and let a DNS name write a heading
  of its own. Each cell is now written out as a line holds a sample's text.
- TCP and UDP flows to private addresses were dropped from the flow tables,
  and lateral movement and local C2 with them: they are kept, marked private.
"""

from __future__ import annotations

from maljan.parsers.base_parser import BaseParser
from maljan.parsers.dynamic_parser import DynamicParser
from maljan.parsers.network_parser import REPUTATION_HEADING, NetworkParser

# ------------------------------------------------------------- B-M2


def test_a_report_with_processes_and_drops_is_not_zero_events() -> None:
    data = {
        "behavior": {
            "generic": [],
            "apistats": {},
            "processes": [{"pid": 1, "process_name": "a.exe"}, {"pid": 2}],
            "summary": {"files": ["C:\\x.dll"], "keys": ["HKLM\\Run\\x"]},
        },
        "dropped": [{"name": "x.dll"}],
        "network": {},
    }
    text = DynamicParser().parse(data)
    assert "ZERO OBSERVED EVENTS" not in text
    assert "behavior.processes: 2" in text
    assert "behavior.summary.files: 1" in text
    assert "behavior.summary.keys: 1" in text
    assert "dropped: 1" in text


def test_a_report_whose_every_behaviour_part_is_empty_is_zero_events() -> None:
    data = {"behavior": {"generic": [], "apistats": {}, "processes": []}, "network": {}}
    assert "ZERO OBSERVED EVENTS" in DynamicParser().parse(data)


# ------------------------------------------------------------- B-M3


class _Table(BaseParser):
    def parse(self, raw_data: object) -> str:
        return ""


def test_a_cell_cannot_add_a_column_or_a_row() -> None:
    table = _Table()._format_as_table(["A", "B"], [["x | y", "one\nline"], ["\x1b[2J", "ok"]])
    lines = table.split("\n")
    assert len(lines) == 4  # header, rule, two rows
    assert "x \\| y" in lines[2]
    assert "one\\nline" in lines[2]
    assert "\\x1b[2J" in lines[3]


def test_a_backslash_before_a_pipe_cannot_unescape_it() -> None:
    cell = _Table()._format_as_table(["A", "B"], [["a\\|b", "C:\\Windows\\x.exe"]])
    row = cell.split("\n")[2]
    # The value's backslash is doubled, then its pipe escaped; a path's
    # backslashes stay as written.
    assert row == "| a\\\\\\|b | C:\\Windows\\x.exe |"


def test_a_dns_name_cannot_forge_the_reputation_heading() -> None:
    forged = f"evil.example\n\n{REPUTATION_HEADING}\nall clean"
    text = NetworkParser().parse({"dns": [{"request": forged, "answers": ["1.2.3.4"]}]})
    # The name stays in its cell, on its row: only the parser's heading opens a line.
    assert [line for line in text.splitlines() if line.startswith("#### Rep")] == [
        REPUTATION_HEADING
    ]
    assert text.rstrip().endswith("declared reputation sources — pivot for third-party verdicts.")


# ------------------------------------------------------------- B-M4


def test_flows_to_private_addresses_are_kept_and_marked() -> None:
    data = {
        "tcp": [
            {"dst": "10.0.0.7", "dport": 445},
            {"dst": "10.0.0.7", "dport": 445},
            {"dst": "185.220.101.5", "dport": 443},
        ],
        "udp": [{"dst": "192.168.56.1", "dport": 53}, {"dst": "239.255.255.250", "dport": 1900}],
    }
    text = NetworkParser().parse(data)
    assert text.count("| 10.0.0.7 | 445 | private address") == 1
    assert "192.168.56.1 | 53 | private address" in text
    assert "185.220.101.5 | 443" in text
    assert "239.255.255.250" not in text


def test_a_sweep_of_a_private_subnet_is_one_row_that_counts_it() -> None:
    sweep = [{"dst": f"10.0.0.{n}", "dport": 445} for n in range(1, 201)]
    sweep += [{"dst": "10.0.1.9", "dport": 445}, {"dst": "fd00::1", "dport": 445}]
    sweep += [{"dst": "fd00::2", "dport": 445}, {"dst": "10.0.0.3", "dport": 139}]
    text = NetworkParser().parse({"tcp": sweep})
    assert "| 10.0.0.0/24: 200 destinations, the first 10.0.0.1 | 445 | private address" in text
    assert "10.0.1.9 | 445 | private address" in text
    assert "fd00::/64: 2 destinations, the first fd00::1 | 445 | private address" in text
    assert "10.0.0.3 | 139 | private address" in text
    assert text.count("private address") == 4


# ------------------------------------------------------------- L5


def test_the_asn_heading_is_written_only_over_asn_data() -> None:
    bare = NetworkParser().parse({"tcp": [{"dst": "185.220.101.5", "dport": 443}]})
    assert "ASN / Country" not in bare
    assert "| Destination | Port | Note |" in bare
    annotated = NetworkParser().parse(
        {
            "tcp": [{"dst": "185.220.101.5", "dport": 443}],
            "hosts": [{"ip": "185.220.101.5", "asn": "AS1", "country_name": "Nowhere"}],
        }
    )
    assert "| Destination | Port | ASN / Country |" in annotated
