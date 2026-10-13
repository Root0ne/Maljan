"""radare2's log envelope and open-first refusal are declared patterns that decide as the code did.

The adapter used to hold its ``<log>`` envelope rule and its open-first marker
as code; both are now patterns in radare2's declaration, held by the general
error rule and run by RE2. This holds the declared envelope to the rule it
replaced, the reference copy below, over the replies that tell them apart,
and holds it linear on a hostile reply.
"""

from __future__ import annotations

import random
import re
import time

import pytest

from maljan.providers.static import r2

_ENVELOPE = re.compile(r"<log>(?P<body>.*)</log>", re.DOTALL)
_LOG_LINE = re.compile(r"\[(?P<level>[A-Z]+)\]\s*\S.*")


def _the_rule_it_replaced(text: str) -> str | None:
    envelope = _ENVELOPE.fullmatch(text.strip())
    if envelope is None:
        return None
    lines = [line.strip() for line in envelope.group("body").splitlines() if line.strip()]
    matched = [_LOG_LINE.fullmatch(line) for line in lines]
    if not lines or not all(matched):
        return None
    if not any(m is not None and m.group("level") in {"ERROR", "FATAL"} for m in matched):
        return None
    return "\n".join(lines)


REPLIES = [
    "<log>[ERROR] Cannot find function at 0x401000</log>",
    "<log>\n[INFO] analysing\n  [ERROR] Cannot find function in 0x10  \n\n</log>",
    "  <log>[FATAL] no core</log>  ",
    "<log>[INFO] only info</log>",
    "<log>[ERROR] a\nnot a log line\n</log>",
    "<log>[ERROR]</log>",
    "<log>[ERROR]   </log>",
    "<log></log>",
    "<log>[ERROR] a</log> and an answer",
    "an answer <log>[ERROR] a</log>",
    "<log>[ERROR] a\rnot a log line</log>",
    "<log>[ERROR] a\r\n[WARN] b</log>",
    "<log>[ERROR] a </log> b\n[INFO] c</log>",
    "<log>[error] lower case</log>",
    "<log>[ERROR] a\x0bnot a log line</log>",
    "<log>[ERROR] a [INFO] b</log>",
]


REPLIES += [
    "<log>[WARN] relocs not applied; [ERROR] tags follow</log>",
    "<log>[INFO] ok [FATAL] x</log>",
    "<log>[WARN]x[ERROR]x\n</log>",
    "<log>[WARN][INFO][FATAL][WARN] </log>",
    "<log>[ERROR] a\n　\n\xa0  \n</log>",
    "<log>　[ERROR] a </log>",
    "<log>[ERROR]\xa0</log>",
]


@pytest.mark.parametrize("reply", REPLIES)
def test_the_declared_envelope_decides_as_the_rule_it_replaced(reply: str) -> None:
    assert r2._r2_logged_error(reply.strip()) == _the_rule_it_replaced(reply)


def test_a_level_tag_inside_a_line_is_that_lines_text() -> None:
    reply = "<log>[WARN] relocs not applied; [ERROR] tags follow</log>"
    assert r2._r2_logged_error(reply) is None
    assert r2.r2_error_reply("list_strings", reply) is None


# Every character ``str.splitlines`` ends a line at, every other character
# ``str.isspace`` holds, and the tokens an envelope is made of.
_BREAKS = ["\n", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", " ", " "]
_SPACES = [" ", "\t", "\x1f", "\xa0", " ", " ", " ", " ", " "]
_SPACES += [" ", "　"]
_TOKENS = ["[ERROR]", "[FATAL]", "[WARN]", "[INFO]", "[error]", "[E1]", "[]", "x", "ab", "é"]
_TOKENS += ["<log>", "</log>", "]", "["]


def _reply(rng: random.Random) -> str:
    parts = [rng.choice(_TOKENS + _BREAKS + _SPACES) for _ in range(rng.randint(0, 12))]
    body = "".join(parts)
    shape = rng.random()
    if shape < 0.85:
        return f"{rng.choice(['', ' ', chr(0x3000)])}<log>{body}</log>{rng.choice(['', '\n'])}"
    return body


def test_two_hundred_thousand_random_replies_are_decided_as_before() -> None:
    rng = random.Random(20261011)
    disagreements = []
    failures = 0
    for _ in range(200_000):
        reply = _reply(rng)
        before = _the_rule_it_replaced(reply)
        failures += before is not None
        if r2._r2_logged_error(reply.strip()) != before:
            disagreements.append(reply)
    assert disagreements == []
    assert failures > 1_000  # the replies reach both answers, not only "not an error"


def test_a_hostile_envelope_is_read_in_linear_time() -> None:
    def timed(n: int) -> float:
        reply = "<log>" + "[INFO] [ERROR] x\n" * n + "not a line"
        started = time.perf_counter()
        assert r2._r2_logged_error(reply) is None
        return time.perf_counter() - started

    timed(1_000)
    small, large = timed(5_000), timed(50_000)
    assert large < max(small, 0.002) * 30


def test_the_open_first_refusal_is_read_from_the_protocol_error() -> None:
    marker = {
        "error": {
            "code": "tool_failed",
            "message": "Use the open_file method before calling any other method",
        }
    }
    failure = r2.r2_error_reply("list_functions", marker, readable="/m/s.exe")
    assert failure is not None
    assert failure["error"]["remediation"] == (
        "call open_file with /m/s.exe, then call this tool again"
    )
    assert (
        r2.r2_error_reply(
            "list_functions", "Use the open_file method before calling any other method"
        )
        is None
    )
