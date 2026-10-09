"""The event scrub masks credentials, not the names a tool or a model wrote.

A run's transcript printed ``***`` where the report printed a list of module
names, a function name abbreviated in a list, a list of addresses or process
ids and the base64 alphabet a decoder is built from: the length rule read each
as a key. Each is kept by its exact form or by the vendored catalogue, and
every credential shape is still masked, alone and inside each such list.

Hex is masked as it always was: a run with eleven or more hex digits in a row
is never one of the kept forms, so a hex dump (a tool's ``"hex"`` field among
them), a digest inside a list and a name ending in long hex read as before.
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


def _hex_run(length: int) -> str:
    """A hex run of ``length`` digits, built at call time."""
    return "".join("0123456789abcdef"[(index * 7 + 3) % 16] for index in range(length))


@pytest.mark.parametrize("length", [24, 30, 48, 50, 96])
def test_a_hex_run_is_masked_wherever_it_stands(length: int) -> None:
    """No context keeps a hex run of a key's length: not a tool's hex field, a list,
    a module list, an address list or a decompiler's name."""
    run = _hex_run(length)
    for text in (
        run,
        f'{{"address": "0x401000", "hex": "{run}"}}',
        json.dumps({"tool": "read_memory", "output": json.dumps({"hex": run})}),
        f"imports kernel32/{run}/user32",
        f"slots 0x1a20/{run}/0x1a28",
        f"pids 1111/{run}",
        f"FindFirstFileA/{run}",
        f"undefined8 in_stack_{run};",
        f"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef/{run}",
    ):
        assert run not in scrub(text), text
        assert run not in scrub_keeping_layout(text), text


def test_a_digest_in_a_list_is_read_as_before() -> None:
    """A digest alone travels, as it always did; inside a module list it is masked as before."""
    digest = _hex_run(64)
    assert scrub(digest) == digest
    assert digest not in scrub(f"kernel32/{digest}/user32")
    assert digest not in scrub(f"0x1a20/{digest}")


def test_a_long_hex_run_alone_is_still_a_key() -> None:
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
    """A large answer with many hex fields, deep nesting or near-JSON costs linear work.

    The ten-times rule: ten times the input costs at most about ten times the
    time and the traced memory (bounds 20 and 15 leave room for noise).
    """

    @staticmethod
    def _many_hex(count: int) -> str:
        return json.dumps(
            {"reads": [{"address": f"0x{i:x}", "hex": f"{i:08x}" * 6} for i in range(count)]}
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
    "hex keys": '{"hex":"00112233445566778899aabbccdd",',
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


_NAME_FORMS = (
    "",
    "hello",
    "kernel32/USER32/WinINet",
    "FindFirstFileA/W",
    "NtQueryInformationProcess/Thread",
    "0x1a20/0x1a28",
    "1111/2222",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
)


@pytest.mark.parametrize("name", _NAME_FORMS)
@pytest.mark.parametrize("separator", ["", "/", ".", "@"])
def test_every_key_shape_after_every_kept_name_form_is_masked(name: str, separator: str) -> None:
    """A kept name in front of a key never covers it, and a dot or an ``@`` before a
    key does not hide it from the rules (``hello.<key>``)."""
    for key in _every_key_shape():
        text = f"{name}{separator}{key}"
        assert key not in scrub(text), text
        assert key not in scrub_keeping_layout(text), text


def test_a_dotted_name_is_not_read_as_a_token() -> None:
    """A head that decodes to ``{`` alone is no token: a token's header opens with a quoted key."""
    for text in (
        "telemetry_exporter.dataservice.internalzone",
        "pipeline.exporter_settings.retention_policy",
    ):
        assert scrub(text) == text


def test_long_number_lists_are_masked_as_before() -> None:
    """Number pieces are kept up to eight digits; longer ones are read as before."""
    for text in ("0x1234567890/0x2345678901/0x3456789012", "1234567890/2345678901/3456789012"):
        assert scrub(f"value {text}") == "value ***", text


def test_a_digest_named_file_and_a_hex_behind_an_escape_stay_as_before() -> None:
    digest = _hex_run(64)
    assert scrub(f"opened {digest}.exe") == f"opened {digest}.exe"
    # A cut digest behind a JSON escape's ``n``: hex and one letter, no key body.
    cut = _hex_run(30)
    assert cut in scrub(f"path\\\\n{cut}.exe")


_SPAN_UNITS = {
    "dotted header-shaped heads": "exexexexex.",
    "dotted token headers": "eyJhbGci.",
    "a token header glued behind a word": "x_eyJhbGciOiJIUzI1NiJ9.",
    "a word and a dot": "hello.",
}


@pytest.mark.parametrize("unit", list(_SPAN_UNITS.values()), ids=list(_SPAN_UNITS))
def test_dotted_runs_cost_ten_times_a_tenth(unit: str) -> None:
    import time

    took = []
    for size in (100_000, 1_000_000):
        text = unit * (size // len(unit))
        started = time.perf_counter()
        scrub(text)
        scrub_keeping_layout(text)
        took.append(time.perf_counter() - started)
    assert took[1] <= max(took[0], 0.01) * 12, took
