"""A TECHNIQUE line that writes its id with the catalogue's own name, or says none, is read.

An analyst wrote sixteen lines like "T1106 Native API": the id and the vendored
catalogue's name for it, with no bracket. The bracketed form was read; this one
was asked about, and kept unread after the retry, so sixteen claims carried no
technique. A name with no bracket runs to the next comma, semicolon or the
line's end, and is taken off only when all of it is the id's catalogue name.
A line that opens with "none" and holds no technique id and no catalogue
technique name claims none, whatever the words after it say. A qualifier
("candidate"), another name, or an id or a named candidate technique on a
"none" line ("None; Process Injection is likely") is still asked about.
"""

from __future__ import annotations

import time

import pytest

from maljan.agents.base_agent import read_technique_line


@pytest.mark.parametrize(
    ("line", "ids"),
    [
        ("T1106 Native API", ("T1106",)),
        ("T1071.001 Web Protocols", ("T1071.001",)),
        ("T1071.001 - Web Protocols", ("T1071.001",)),
        ("T1140 Deobfuscate/Decode Files or Information", ("T1140",)),
        (
            "T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
            ("T1547.001",),
        ),
        ("T1106 Native API, T1140 Deobfuscate/Decode Files or Information", ("T1106", "T1140")),
        ("none asserted", ()),
        ("none (capability only)", ()),
        ("None additional.", ()),
    ],
)
def test_it_is_read(line: str, ids: tuple[str, ...]) -> None:
    assert read_technique_line(line) == (ids, None)


@pytest.mark.parametrize(
    "line",
    [
        "T1071.001 (candidate)",
        "T1071.001 Web Protocols (candidate)",
        "T1106 Native calls",
        "T1218.011 Signed Binary Proxy Execution: Rundll32",
        "none (T1568 not supported)",
        "none asserted; T1041 would apply if transmission is shown",
        "nonexistent T1027",
        "T1027 or T1140",
        "None; Process Injection is likely",
        "none observed, though native api use is possible",
    ],
)
def test_it_is_asked_about(line: str) -> None:
    assert read_technique_line(line) == ((), line)


def test_a_long_none_line_is_read_in_linear_time() -> None:
    def cost(line: str) -> float:
        start = time.perf_counter()
        read_technique_line(line)
        return time.perf_counter() - start

    unit = "none of these words names anything "
    cost(unit * 60)
    small = cost(unit * 600)
    large = cost(unit * 6000)
    assert large <= max(small, 1e-3) * 30


def test_ten_times_the_line_costs_at_most_ten_times_the_time() -> None:
    def cost(line: str) -> float:
        start = time.perf_counter()
        for _ in range(20):
            read_technique_line(line)
        return time.perf_counter() - start

    unit = "T1106 Native API word, "
    cost(unit)
    small = cost(unit * 40)
    large = cost(unit * 400)
    assert large <= max(small, 1e-3) * 30
