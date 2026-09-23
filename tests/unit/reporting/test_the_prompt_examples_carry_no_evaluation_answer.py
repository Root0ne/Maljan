"""The examples shown to the report models describe nothing an evaluation scores.

A local model copies the shape it is shown, and sometimes the words. An example
that describes the behaviour a scoring key expects lets a model that copies it
"find" the key's items with no evidence behind them, which makes the score
meaningless and puts the platform's words in text the report labels as the
model's. So the examples describe an invented sample of a different class, and
this test holds them to it: no string value of any example may carry one of the
distinctive terms of the evaluation key below.

The list is data owned by this test, drawn from the behaviours, identifiers and
technique ids the key scores. A term is matched case-insensitively as a
substring of any example's string values; keys of the answer object are the
schema's own names and are not checked.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from maljan.reporting.composer import _EXAMPLES
from maljan.reporting.narrative_agent import EXAMPLE_OBJECT

# The distinctive terms of the evaluation key: how the scored sample resolves its
# APIs, checks its host, persists, configures itself, talks to its server and
# what its commands do, and the technique ids the key expects.
KEY_TERMS: tuple[str, ...] = (
    "crc32",
    "fnv",
    "rc4",
    "peb",
    "beingdebugged",
    "debugger",
    "wow64",
    "mac address",
    "process count",
    "running processes",
    "mutex",
    "single instance",
    "scheduled task",
    "logon",
    "rundll32",
    "appdata",
    "self-delet",
    "alternate data stream",
    "by hash",
    "hashing export",
    "export name",
    "api hash",
    "resolves its",
    "loader",
    "downloader",
    "64-bit dll",
    "volume serial",
    "bot id",
    "group id",
    "campaign",
    "https post",
    "post request",
    "beacon",
    "base64",
    "key=value",
    "user-agent",
    "sleep",
    "update_data",
    "c2 url",
    "xor",
    "string decryption",
    "run_exe",
    "download",
    "shellcode",
    "desktop",
    "process list",
    "ipconfig",
    "systeminfo",
    "nltest",
    "net view",
    "whoami",
    "domain trust",
    "antivirus",
    "t1053.005",
    "t1218.011",
    "t1071.001",
    "t1027",
    "t1055",
    "t1070.004",
    "t1059.003",
    "t1105",
    "t1622",
    "t1497",
)


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for item in value.values() for s in _strings(item)]
    if isinstance(value, list):
        return [s for item in value for s in _strings(item)]
    return []


EXAMPLES: dict[str, str] = {"narrative": EXAMPLE_OBJECT, **_EXAMPLES}


@pytest.mark.parametrize("name", sorted(EXAMPLES))
def test_no_example_carries_a_term_the_key_scores(name: str) -> None:
    text = " ".join(_strings(json.loads(EXAMPLES[name]))).lower()
    shared = [term for term in KEY_TERMS if term in text]
    assert not shared, f"the {name} example carries {shared}"


def test_the_guard_would_catch_one() -> None:
    leaked = {"steps": [{"action": "Creates a mutex and exits if it already exists"}]}
    text = " ".join(_strings(leaked)).lower()
    assert [term for term in KEY_TERMS if term in text] == ["mutex"]


def test_the_term_list_is_long_enough_to_mean_something() -> None:
    assert len(KEY_TERMS) >= 50
    assert len(set(KEY_TERMS)) == len(KEY_TERMS)
