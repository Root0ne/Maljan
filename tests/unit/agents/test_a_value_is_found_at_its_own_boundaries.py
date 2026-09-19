"""Where one indicator value ends in the evidence, and where it only seems to.

``whole_value_in`` is the corroboration question's reading of the run's own
evidence: does this value appear there as a value, rather than as a slice of
something longer the run recorded. It treated ``/``, ``\\`` and ``:`` as part of
a label, so a host written inside a URL, a host written before its port, a
mailbox after ``mailto:`` and an address at the end of a sentence were all
reported as appearing nowhere — and the row was withheld from the bundle with a
sentence saying nothing corroborates it.

Both directions are pinned here, because the widening is only worth having if
the slice it was protecting against is still refused.
"""

from __future__ import annotations

import pytest

from maljan.agents._indicator_denylists import whole_value_in

# Every haystack below is lowercased, because the corpus reaches this function
# lowercased and the function lowercases only the value it is asked about.
MAILBOX = "operator@example.org"
HOST = "gate.example.org"
ADDRESS = "185.220.101.1"
DIGEST = "a" * 32


FOUND: list[tuple[str, str]] = [
    # A boundary that is not a value character at all.
    (HOST, f"the sandbox reached {HOST} on port 443"),
    (HOST, f"({HOST})"),
    (HOST, f'"{HOST}"'),
    # A full stop, a colon or a comma that nothing continues.
    (MAILBOX, f"the dropper mailed {MAILBOX}."),
    (HOST, f"{HOST}: {ADDRESS}"),
    (HOST, f"{HOST}, a.example.org"),
    (ADDRESS, f"it called {ADDRESS}."),
    # A scheme's colon, and the slashes after it.
    (MAILBOX, f"the link was mailto:{MAILBOX}"),
    (HOST, f"ssh:{HOST}"),
    (HOST, f"http://{HOST}/gate"),
    (HOST, f"ssh://{HOST}"),
    (HOST, f"https://{HOST}"),
    # A port, and a colon between two values.
    (HOST, f"{HOST}:443"),
    (HOST, f"{ADDRESS}:{HOST}"),
    (ADDRESS, f"{ADDRESS}:8080 was reached"),
    # A separator inside a path, either way round, for a value with parts.
    ("x.exe", "the dropper wrote /tmp/x.exe"),
    ("x.exe", "the dropper wrote c:\\windows\\temp\\x.exe"),
    (HOST, f"http://{HOST}/a/b?q=1"),
    ("evil.exe", "the dropper wrote c:\\tmp\\evil.exe"),
    ("global\\zararli", "opened mutex global\\zararli now"),
    # A bare component, free-standing, is found the way it always was.
    ("system32", "the sample wrote system32 twice"),
    ("8080", "the port was 8080 all along"),
    ("temp", "it unpacked into temp, then ran"),
    # A value written straight after a two-character escape in a tool's JSON.
    (HOST, f'"a\\n{HOST}"'),
    (HOST, f'"a\\t{HOST}"'),
    ("system32", '"a\\nsystem32"'),
    (HOST, f'"{HOST}\\nb"'),
]

NOT_FOUND: list[tuple[str, str]] = [
    # A longer label the value is only the front, the back or the middle of.
    (HOST, f"not{HOST}"),
    (HOST, f"sub.{HOST}"),
    (HOST, f"{HOST}.tr"),
    (HOST, f"xn--{HOST}"),
    (HOST, f"{HOST}s"),
    # A longer address the value is a slice of.
    ("1.2.3.4", "the host was 11.2.3.45"),
    ("168.1.1", "the host was 192.168.1.1"),
    ("185.220.101.1", "the host was 185.220.101.11"),
    # A digest the value is the prefix of.
    (DIGEST[:16], f"md5 {DIGEST}"),
    # A mailbox inside a longer local part.
    (MAILBOX, f"x{MAILBOX}"),
    ("example.org", f"{MAILBOX}"),
    # A longer path the value is written inside.
    ("x.exe", "the dropper wrote /tmp/prefix-x.exe"),
    ("/tmp/x", "the dropper wrote /tmp/xyz"),
    # A bare single component between two parts of a compound value. Every one
    # of these appears in half the paths a sandbox writes down, and this
    # function is the second-source bar for the kinds that carry them.
    ("system32", "c:\\windows\\system32\\a.dll"),
    ("8080", "10.0.0.5:8080"),
    ("temp", "c:\\windows\\temp\\x"),
    ("zararlimutex", "c:\\zararlimutex\\x"),
    ("run", "hklm\\software\\microsoft\\windows\\currentversion\\run"),
    ("windows", "c:/windows/system32"),
    # A path separator is not a two-character escape, whatever letter follows.
    ("ew\\evil.com", "c:\\new\\evil.com"),
    ("ew\\evil.com", "\\\\server\\new\\evil.com"),
    ("emp\\x.exe", "c:\\temp\\x.exe"),
]


@pytest.mark.parametrize(("literal", "haystack"), FOUND)
def test_the_value_is_found(literal: str, haystack: str) -> None:
    assert whole_value_in(literal, haystack)


@pytest.mark.parametrize(("literal", "haystack"), NOT_FOUND)
def test_the_slice_is_not_found(literal: str, haystack: str) -> None:
    assert not whole_value_in(literal, haystack)


def test_nothing_is_found_for_an_empty_value() -> None:
    assert not whole_value_in("", "anything at all")


def test_a_second_occurrence_is_read_when_the_first_is_a_slice() -> None:
    """The scan does not stop at the first place the characters appear."""
    assert whole_value_in(HOST, f"not{HOST} and then {HOST}")
