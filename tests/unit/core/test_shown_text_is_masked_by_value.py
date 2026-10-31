"""Shown text is masked by every secret value the platform holds, in each encoded form (T-482).

The structural rules (``maljan.core.settings_masking``) guess a credential by
where it stands, and each patch to them opened a new edge (a Windows path, a
UNC share, a JSON escape before the password). A value the settings hold is
now masked wherever it stands and however it is encoded, beside those rules:
what they masked is masked as before, and the values only add masks.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import random
import re
import string
from pathlib import Path
from urllib.parse import quote, quote_plus

import pytest
from tests.credential_shapes import lowercase_body

from maljan.core import settings_masking as sm
from maljan.core import settings_overrides as ov
from maljan.core.config import MCPServerConfig
from maljan.core.settings_catalog import shown_secret_values

MASK = sm.SNAPSHOT_MASK


def _secret(variant: int = 0) -> str:
    """A value no structural rule could tell from a word: letters and digits, past the floor."""
    return "Vb" + lowercase_body(14 + variant)


def _awkward() -> str:
    """A value each encoding changes: a slash, a space, a quote, a backslash, a non-ASCII letter."""
    return _secret() + '/ &"\\é+'


def _remember(*values: str) -> None:
    sm.remember_values(values, scope="test")


def _forms(value: str) -> list[tuple[str, str]]:
    raw = value.encode()
    return [
        ("as written", value),
        ("quote", quote(value)),
        ("quote, nothing safe", quote(value, safe="")),
        ("quote_plus", quote_plus(value)),
        ("lower-case escapes", re.sub(r"%[0-9A-F]{2}", lambda m: m.group().lower(), quote(value))),
        ("JSON", json.dumps(value)[1:-1]),
        ("JSON, non-ASCII kept", json.dumps(value, ensure_ascii=False)[1:-1]),
        ("JSON in JSON", json.dumps(json.dumps(value)[1:-1])[1:-1]),
        ("base64", base64.b64encode(raw).decode()),
        ("base64 unpadded", base64.b64encode(raw).decode().rstrip("=")),
        ("base64 url-safe", base64.urlsafe_b64encode(raw).decode()),
        ("base64 url-safe unpadded", base64.urlsafe_b64encode(raw).decode().rstrip("=")),
    ]


@pytest.mark.parametrize("index", range(12))
def test_each_encoding_of_a_held_value_is_masked(index):
    value = _awkward()
    name, form = _forms(value)[index]
    _remember(value)

    shown = sm.masked_text(f"the tool said: <{form}> and stopped")

    assert form not in shown, name
    assert shown == f"the tool said: <{MASK}> and stopped", name


@pytest.mark.parametrize("before", ["", "u:", "ab:", "Basic xy:"])
@pytest.mark.parametrize("altchars", [None, b"-_"])
def test_a_value_inside_longer_base64_is_masked_at_any_offset(before, altchars):
    value = _secret()
    _remember(value)
    blob = base64.b64encode(f"{before}{value}".encode() + b"tail", altchars).decode()

    shown = sm.masked_text(f"Authorization: Basic {blob}")

    # Only the one or two characters the value shares with its neighbours are left.
    assert MASK in shown
    kept = shown.removeprefix("Authorization: Basic ").replace(MASK, "")
    assert len(kept) <= len(blob) - len(value)
    held = base64.b64encode(value.encode(), altchars).decode()[2:-2]
    assert held not in shown


def test_the_user_and_password_form_of_a_stored_address_is_a_value():
    password = _secret()
    settings = ov.build_settings({"llm.openai.base_url": f"https://ops:{password}@llm.example/v1"})

    held = shown_secret_values(settings)
    assert f"ops:{password}" in held
    sm.remember_values(held, scope="test")
    header = base64.b64encode(f"ops:{password}".encode()).decode()

    assert sm.masked_text(f"sent Basic {header}") == f"sent Basic {MASK}"


def test_overlapping_values_are_masked_as_one_run_and_the_longest_wins():
    long, short = _secret(6), _secret(0)
    assert long.startswith(short)
    _remember(short, long)

    assert sm.masked_text(f"[{long}]") == f"[{MASK}]"
    assert sm.masked_text(f"[{short}]") == f"[{MASK}]"
    # Two values that overlap without one holding the other: no part of either is left.
    first, second = "Qa" + lowercase_body(12), lowercase_body(12)[6:] + "Zz" + lowercase_body(8)
    _remember(first, second)
    joined = first + second[len(lowercase_body(12)[6:]) :]
    assert sm.masked_text(f"<{joined}>") == f"<{MASK}>"


def test_a_value_shorter_than_the_floor_is_masked_only_by_the_structural_rules():
    short = _secret()[: sm.VALUE_FLOOR - 1]
    _remember(short)

    assert sm.masked_text(f"the word {short} stays") == f"the word {short} stays"
    # Where it stands as a credential, the structural rules still mask it.
    assert sm.masked_text(f"https://u:{short}@h.example/") == f"https://{MASK}@h.example/"
    assert sm.masked_args(["--api-key", short]) == ["--api-key", MASK]
    assert sm.masked_server({"env": {"A": short}}) == {"env": {"A": MASK}}


@pytest.mark.parametrize(
    "written",
    [
        "C:\\Users\\{pw}\\x.txt",
        '{"path":"C:\\\\Users\\\\{pw}\\\\x"}',
        "\\\\srv\\{pw}\\share",
        "\\\\{pw}\\x@h:8080",
        '{"a":"{\\"u\\":\\"{pw}\\"}"}',
        "/home/{pw}/run",
    ],
)
def test_a_held_value_inside_a_path_json_or_a_unc_share_is_masked(written):
    value = _secret()
    _remember(value)

    shown = sm.masked_text(written.replace("{pw}", value))

    assert value not in shown
    # The rest of the path, the JSON or the share is kept where no rule masks it.
    assert _reveals_no_more(shown, written.replace("{pw}", MASK))


# The residual shapes of T-481 and the named residuals of T-471 / T-474: the
# structural rules keep each, and the value, once held, is masked in them.
_RESIDUALS = [
    "C:\\x=u:{pw}@h:8080",
    "C:\\x)u:{pw}@h:8080",
    "[C:\\x]u:{pw}@h:8080",
    "u:{pw}@h:8080,x",
    "C:\\x,u:{pw}@h:8080,C:\\z",
    '{"a":"C:\\\\x,\'{pw}@h:8080\'"}',
    "x;u:{pw}\\q@h",
    "u:p\\{pw}@h",
    "u:/{pw}\\x@h",
    "u:/{pw}\\x@h:8080",
    "\\\\{pw}@SSL\\x@h:8080",
    "\\\\{pw}@1234\\x@h",
    "\\\\{pw}$\\x@h/y",
    "\\\\{pw}\\x@h:8080",
]


@pytest.mark.parametrize("written", _RESIDUALS)
def test_every_residual_shape_is_masked_once_the_value_is_held(written):
    value = _secret()
    text = written.replace("{pw}", value)
    _remember(value)

    assert value not in sm.masked_text(text)
    assert value not in sm.masked_text(f"Error: cannot connect to {text}")
    assert value not in sm.masked_text(json.dumps({"detail": text}))
    assert value not in ov.redact_url(f"driver said: {text}")


def test_masking_by_value_costs_time_linear_in_the_text():
    from tests.linear_cost import assert_scales

    values = [_secret(variant) + str(index) for index, variant in enumerate(range(200))]
    _remember(*values)
    sm.masked_text("warm the pattern")
    word = f"C:\\x,u:{values[17]}@h:8080 {lowercase_body(30)} "

    assert_scales(lambda size: word * size, 400, sm.masked_text)


def test_a_pathological_value_set_still_masks_in_one_linear_pass():
    from tests.linear_cost import assert_scales

    # Each value one longer than the last: a branch point at every length,
    # deeper than the regex compiler nests, so the automaton reads them.
    values = ["a" * length for length in range(sm.VALUE_FLOOR, 1_500)]
    assert isinstance(sm._value_matcher(frozenset(values)), sm._Automaton)
    _remember(*values)

    assert sm.masked_text("x" + "a" * 2_000 + "y") == f"x{MASK}y"
    assert sm.masked_text("b" + "a" * 7 + "b") == "b" + "a" * 7 + "b"
    assert_scales(lambda size: ("a" * 40 + " ") * size, 200, sm.masked_text)


@pytest.mark.parametrize("seed", range(5))
def test_the_automaton_and_the_trie_pattern_mask_alike(seed):
    draw = random.Random(seed)
    values = frozenset(
        "".join(draw.choice("ab/=+%") for _ in range(draw.randint(sm.VALUE_FLOOR, 14)))
        for _ in range(30)
    )
    forms = sorted({form for value in values for form in sm.encoded_forms(value)})
    automaton, pattern = sm._Automaton(forms), re.compile(sm._trie_pattern(forms))
    for _ in range(50):
        text = "".join(draw.choice("ab/=+%xY") for _ in range(200))
        assert sm._value_spans(automaton, text) == sm._value_spans(pattern, text), text


def test_a_scope_registered_again_replaces_what_it_held():
    first, second = _secret(1), _secret(2)
    sm.remember_values([first], scope="job")
    sm.remember_values([second], scope="process")
    assert {first, second} <= sm.held_values()

    sm.remember_values([], scope="job")

    assert sm.masked_text(first) == first
    assert sm.masked_text(second) == MASK
    sm.forget_values()
    assert sm.held_values() == frozenset()


def test_reading_the_values_never_raises_and_never_names_one(monkeypatch, caplog):
    value = _secret()
    sm.remember_values([value], scope="store")

    def broken(*_sources):
        raise ValueError(f"cannot read {value}")

    monkeypatch.setattr("maljan.core.settings_catalog.shown_secret_values", broken)
    with caplog.at_level(logging.DEBUG, logger="maljan.core.settings_masking"):
        sm.remember_settings_values({"api_key": value}, scope="store")

    assert value not in caplog.text
    assert "ValueError" in caplog.text
    # The scope keeps what it held.
    assert value in sm.held_values()


def test_the_values_come_from_the_settings_and_the_store_by_kind_never_by_name():
    env_value, token, api_key, row = _secret(1), _secret(2), _secret(3), _secret(4)
    settings = ov.build_settings({})
    settings.mcp.servers["any"] = MCPServerConfig(
        command="tool", env={"PLAIN_NAME": env_value}, auth_token=token
    )
    stored = {
        "core.mcp.servers": {"other": {"env": {"MODE": env_value + "x"}}},
        "api.enrichment_sources": {"some_source": {"api_key": api_key, "url": "https://x"}},
        "secret": [row],
    }

    held = shown_secret_values(settings, stored)

    assert {env_value, token, api_key, row, env_value + "x"} <= held
    # A number or a switch is a setting whatever its key says.
    assert not {"true", "8080"} & shown_secret_values({"env": {"A": "true", "B": "8080"}})


def test_the_run_snapshot_masks_a_servers_env_value_wherever_it_stands():
    value = _secret()
    settings = ov.build_settings({})
    settings.mcp.servers["any"] = MCPServerConfig(
        command="tool",
        env={"UPSTREAM": value},
        args=["--name", value, f"--path=/srv/{value}/x"],
        label=f"reads {quote(value)}",
    )

    snap = ov.public_snapshot(settings, ())

    assert value not in json.dumps(snap)
    assert quote(value) not in json.dumps(snap)
    assert snap["mcp.servers.any.args"] == ["--name", MASK, f"--path=/srv/{MASK}/x"]


def test_a_tool_server_argument_and_a_console_value_are_masked_by_a_held_value():
    value = _secret()
    _remember(value)

    assert sm.masked_args(["--name", value, value]) == ["--name", MASK, MASK]
    assert sm.masked_value({"note": f"x{value}y"}) == {"note": f"x{MASK}y"}
    assert sm.masked_server({"cwd": f"/srv/{value}"}) == {"cwd": f"/srv/{MASK}"}


# --- never weaker: a differential over the masking corpus -------------------


def _corpus_module():
    path = Path(__file__).with_name("test_the_run_snapshot_carries_no_secret.py")
    spec = importlib.util.spec_from_file_location("_masking_corpus", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _reveals_no_more(now: str, before: str) -> bool:
    """Whether ``now`` is ``before`` with some of its text replaced by the mask.

    Every run ``now`` keeps stands in ``before`` in the same order, with
    anything (what a new mask covers) between them.
    """
    pieces = now.split(MASK)
    pattern = "(?:.*?)".join(re.escape(piece) for piece in pieces)
    return re.fullmatch(pattern, before, re.DOTALL) is not None


def _corpus_texts() -> list[str]:
    corpus = _corpus_module()
    written: list[str] = []
    for name in (
        "_SCHEMELESS",
        "_BACKSLASHED_PASSWORDS",
        "_PASSWORDS_AFTER_A_PATH",
        "_WORDS_A_READING_AFTER_A_PATH_MASKS",
    ):
        written.extend(row[0] for row in getattr(corpus, name))
    written.extend(corpus._fuzzed_words(3_000))
    written.extend(_RESIDUALS)
    return written


def test_masking_is_never_weaker_than_the_structural_rules_on_the_corpus():
    secret, other = _secret(), "Qx" + lowercase_body(20)
    draw = random.Random(482)
    weaker = []
    for written in _corpus_texts():
        text = written.replace("{pw}", secret)
        text = f"{text} {draw.choice(string.ascii_letters)}{other}"
        sm.forget_values()
        before = sm.masked_text(text)
        _remember(secret, other)
        now = sm.masked_text(text)
        if not _reveals_no_more(now, before) or secret in now or other in now:
            weaker.append(written)
    assert weaker == []
