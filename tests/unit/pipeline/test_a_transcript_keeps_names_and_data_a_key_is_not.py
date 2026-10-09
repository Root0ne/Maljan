"""The event scrub masks credentials, not the names and data a tool or a model wrote.

A run's transcript printed ``***`` where the report printed a list of module
names, a function name abbreviated in a list, a list of addresses or process
ids, a decompiler's stack variable, a memory read's hex under its own ``hex``
field and the base64 alphabet a decoder is built from: the length rule read
each as a key. Each is kept by its exact form or by the vendored catalogue,
and every credential shape is still masked, alone and inside each such list.
"""

from __future__ import annotations

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


def test_a_long_hex_run_with_no_hex_field_is_still_a_key() -> None:
    assert scrub("value " + "d" * 48) == "value ***"


def test_a_piece_that_completes_no_catalogue_name_is_no_name() -> None:
    assert scrub(f"value CreateFileA/{lowercase_body(14)}") == "value ***"


def test_short_stretches_of_the_alphabet_are_no_name() -> None:
    assert scrub("value ABCDEFGH/abcdefgh+0123456789") == "value ***"
