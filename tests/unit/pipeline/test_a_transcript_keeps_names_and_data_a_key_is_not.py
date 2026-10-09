"""The event scrub masks credentials, not the names and data a tool or a model wrote.

A run's transcript printed ``***`` where the report printed a list of module
names, a function name abbreviated in a list, a list of addresses or process
ids, a decompiler's stack variable, a memory read's hex under its own ``hex``
field and the base64 alphabet a decoder is built from: the length rule read
each as a key. Each is kept by its exact form or by the vendored catalogue,
and every credential shape is still masked, alone and inside each such list.
"""

from __future__ import annotations

import json

import pytest

from maljan.pipeline import events as ev
from maljan.pipeline.events import scrub, scrub_keeping_layout
from tests.credential_shapes import lowercase_body, prefixed_key
from tests.unit.pipeline.test_live_event_schema import _every_key_shape

KEPT = (
    "imports kernel32/USER32/WinINet/Shell32/ADVAPI32/iphlpapi by hash",
    "NtQueryInformationProcess/Thread/SystemInformation are resolved",
    "FindFirstFileA/W+FindNextFileA/W walk the folder",
    "slots 0x1a20/0x1a28/0x1a30/0x1a38/0x1a40 hold the pointers",
    "flow pids 1111/2222/3333/4444/5555 are not the sample's",
    "undefined8 in_stack_ffffffffffffff10; ulonglong uStack_ffffffffffffff28;",
    '{"address": "0x401000", "hex": "00112233445566778899aabbccddeeff0011223344556677"}',
    'alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" decodes',
)


@pytest.fixture(autouse=True)
def _nothing_registered() -> None:
    ev.forget_secret_values()


@pytest.mark.parametrize("text", KEPT)
def test_the_text_is_kept_as_written(text: str) -> None:
    assert scrub(text) == text
    assert scrub_keeping_layout(text) == text


def test_with_values_registered_too() -> None:
    ev.remember_secret_values([prefixed_key("sk-")], scope="job")
    for text in KEPT:
        assert scrub(text) == text, text


def test_every_key_shape_inside_a_list_of_names_is_masked() -> None:
    for key in _every_key_shape():
        for text in (
            f"imports kernel32/{key}/user32 by hash",
            f"FindFirstFileA/{key}",
            f"slots 0x1a20/{key}/0x1a28",
            f"pids 1111/{key}",
        ):
            assert key not in scrub(text), (key, text)


def test_a_key_under_a_hex_field_is_masked_when_it_is_not_hex() -> None:
    for key in _every_key_shape():
        assert key not in scrub(f'{{"hex": "{key}"}}'), key


def _hex_run(length: int) -> str:
    """A hex run of ``length`` digits, built at call time."""
    return "".join("0123456789abcdef"[(index * 7 + 3) % 16] for index in range(length))


@pytest.mark.parametrize("length", [30, 48, 50])
def test_a_hex_run_after_a_label_or_a_credential_word_is_masked(length: int) -> None:
    run = _hex_run(length)
    for text in (
        f"secret hex = {run}",
        f"key hex: {run}",
        f"hex: {run}",
        f"hex={run}",
        f'{{"api key hex": "{run}"}}',
        f'{{"token": {{"hex": "{run}"}}}}',
        f'{{"secret": "x", "hex": "{run}"}}',
    ):
        assert run not in scrub(text), text
        assert run not in scrub_keeping_layout(text), text


@pytest.mark.parametrize("length", [30, 48, 50])
def test_a_credential_word_anywhere_in_the_object_or_its_keys_keeps_the_run_a_key(
    length: int,
) -> None:
    run = _hex_run(length)
    far = "x" * 120
    texts = [
        f'{{"hex": "{run}", "kind": "api_key"}}',
        f'{{"label": "signing", "{far}": 1, "hex": "{run}"}}',
        f'{{"api_token_{far}": {{"meta": 1, "hex": "{run}"}}}}',
        f'{{"outer": {{"session": {{"meta": {{"n": 1}}, "hex": "{run}"}}}}}}',
        f'{{"hex": "{run}", "meta": {{"note": "an iv"}}}}',
    ]
    texts += [
        f'{{"{name}": {{"hex": "{run}"}}}}'
        for name in ("hmac", "seed", "salt", "private", "nonce", "iv", "mnemonic")
    ]
    for text in texts:
        assert run not in scrub(text), text
        assert run not in scrub_keeping_layout(text), text


@pytest.mark.parametrize("length", [30, 48, 50])
def test_a_tool_s_hex_field_in_a_list_of_reads_is_kept(length: int) -> None:
    run = _hex_run(length)
    text = (
        f'{{"reads": [{{"address": "0x401000", "hex": "{run}"}}, '
        f'{{"address": "0x401100", "hex": "{run}"}}], "archive": "derived.bin"}}'
    )
    assert scrub(text) == text


@pytest.mark.parametrize("length", [30, 48, 50])
def test_a_tool_s_own_hex_field_is_kept(length: int) -> None:
    run = _hex_run(length)
    for text in (
        f'{{"address": "0x401000", "size": {length // 2}, "hex": "{run}"}}',
        json.dumps({"tool": "read_memory", "output": json.dumps({"hex": run})}),
    ):
        assert scrub(text) == text, text
        assert scrub_keeping_layout(text) == text, text


@pytest.mark.parametrize("length", [30, 48, 50])
def test_text_that_only_looks_like_a_hex_field_is_masked(length: int) -> None:
    """The exemption is granted by a JSON parse, never by a pattern over the text."""
    run = _hex_run(length)
    for text in (
        '{\\"hex\\": \\"' + run + '\\"}',
        f'the answer was {{"hex": "{run}"}} and more',
        f'{{"hex": "{run}"',
        f'{{"hex": "{run}", "hex": "00"}}',
        f'{{"hex": "{run}", "note": "copied {run}"}}',
        json.dumps({"note": '}{"hex": "' + run + '"', "kind": "x"}),
        json.dumps({"a": '"hex": "' + run + '"'}),
        json.dumps({"hex": [run]}),
        json.dumps({"kind": "api_key", "data": {"hex": run}}),
        json.dumps({"data": {"hex": run, "list": ["a signing pair"]}}),
        f'{{"hex": "{run}"}}\n{{"key": "{run}"}}',
    ):
        assert run not in scrub(text), text
        assert run not in scrub_keeping_layout(text), text


def test_a_configured_hex_value_under_a_hex_field_is_masked() -> None:
    run = _hex_run(48)
    ev.remember_secret_values([run], scope="job")
    assert run not in scrub(json.dumps({"hex": run}))
    assert run not in scrub_keeping_layout(json.dumps({"hex": run}))


def test_concurrent_scrubs_do_not_read_each_other_s_text() -> None:
    """No state of one call is read by another: each thread gets its own answer."""
    from concurrent.futures import ThreadPoolExecutor

    run = _hex_run(48)
    kept = json.dumps({"address": "0x401000", "hex": run})
    masked = f'{{"hex": "{run}", "note": "copied {run}"}}'
    texts = [kept, masked] * 400
    with ThreadPoolExecutor(max_workers=8) as pool:
        answers = list(pool.map(scrub, texts))
    for text, answer in zip(texts, answers, strict=True):
        assert (answer == text) is (text == kept), (text, answer)


def test_a_long_hex_run_with_no_hex_field_is_still_a_key() -> None:
    assert scrub("value " + "d" * 48) == "value ***"


def test_a_piece_that_completes_no_catalogue_name_is_no_name() -> None:
    assert scrub(f"value CreateFileA/{lowercase_body(14)}") == "value ***"


def test_short_stretches_of_the_alphabet_are_no_name() -> None:
    assert scrub("value ABCDEFGH/abcdefgh+0123456789") == "value ***"


def test_a_token_glued_behind_a_word_is_masked() -> None:
    from tests.credential_shapes import jwt

    for token in (jwt(), jwt(header=b'{ "alg":"HS256"}')):
        for text in (f"in_stack_{token}", f"x_{token}", f"name-{token} tail", f"0x1a20/v_{token}"):
            answer = scrub(text)
            for segment in token.split(".")[1:]:
                assert segment not in answer, (text, answer)


class TestHostileAnswersCostLinearWork:
    """The hex exemption reads an answer once per scrub, in linear work and memory.

    The ten-times rule: ten times the input costs at most about ten times the
    time and the traced memory (bounds 20 and 15 leave room for noise).
    """

    @staticmethod
    def _many_hex(count: int) -> str:
        return json.dumps(
            {"reads": [{"address": f"0x{i:x}", "hex": f"{i:08x}" * 6} for i in range(count)]}
        )

    @staticmethod
    def _control(count: int) -> str:
        return json.dumps(
            {"reads": [{"address": f"0x{i:x}", "bytes": f"{i:08x}" * 6} for i in range(count)]}
        )

    @staticmethod
    def _nested(depth: int) -> str:
        return "[" * depth + json.dumps({"hex": _hex_run(48)}) + "]" * depth

    @staticmethod
    def _near(count: int) -> str:
        return "".join(f'{{"hex": "{i:08x}{_hex_run(40)}", "x": [' for i in range(count))

    @staticmethod
    def _cost(text: str) -> tuple[float, int]:
        import time
        import tracemalloc

        started = time.perf_counter()
        scrub_keeping_layout(text)
        took = time.perf_counter() - started
        tracemalloc.start()
        scrub_keeping_layout(text)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        return took, peak

    @pytest.mark.parametrize(
        ("make", "small"), [("_many_hex", 300), ("_near", 300), ("_nested", 10_000)]
    )
    def test_ten_times_the_input_costs_about_ten_times(self, make: str, small: int) -> None:
        build = getattr(self, make)
        small_time, small_peak = self._cost(build(small))
        large_time, large_peak = self._cost(build(small * 10))
        assert large_time <= max(small_time, 0.01) * 20, (small_time, large_time)
        assert large_peak <= max(small_peak, 1 << 20) * 15, (small_peak, large_peak)

    def test_ten_megabytes_of_hex_fields_cost_no_more_than_the_same_without(self) -> None:
        import time

        hostile, plain = self._many_hex(120_000), self._control(120_000)
        assert len(hostile) > 9_000_000
        started = time.perf_counter()
        answer = scrub_keeping_layout(hostile)
        hostile_time = time.perf_counter() - started
        started = time.perf_counter()
        scrub_keeping_layout(plain)
        plain_time = time.perf_counter() - started
        assert answer == hostile
        assert hostile_time <= plain_time * 1.2, (hostile_time, plain_time)

    def test_deep_nesting_and_garbage_are_masked_and_finish(self) -> None:
        run = _hex_run(48)
        for text in (self._nested(100_000), self._near(1_000), '{"hex": "' + run + '"' * 1000):
            assert run not in scrub_keeping_layout(text)


# Each a run that drove one of the scrub's patterns to retry every start: a
# long stretch with no dot-separated token after it (the trailing-stretch
# search), dotted runs a token search reads (the token scans), and a long run
# of backslashes (the UNC path marker).
_REDOS_UNITS = {
    "stretch then a dot": "a" * 1000 + ".b ",
    "dot after every letter": "a.",
    "header-shaped runs with dots": "e" * 50 + ".aaaaaaaa.aaaaaaaa",
    "header heads with dots": "eyJ.",
    "backslashes": "\\\\",
    "hex keys": '{"hex":"00",',
}


@pytest.mark.parametrize("unit", list(_REDOS_UNITS.values()), ids=list(_REDOS_UNITS))
def test_a_megabyte_of_a_hostile_unit_costs_ten_times_a_tenth(unit: str) -> None:
    import time

    took = []
    for size in (100_000, 1_000_000):
        text = unit * (size // len(unit))
        started = time.perf_counter()
        scrub(text)
        scrub_keeping_layout(text)
        took.append(time.perf_counter() - started)
    assert took[1] <= max(took[0], 0.01) * 20, took
