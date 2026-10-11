"""A call's argument is chosen by the reader's name priority, never by the call's own order."""

from __future__ import annotations

import time

from maljan.providers.call_arguments import argument_table, pick_argument

NAMES = ("FullName", "SubKey", "Registry")


def test_the_reader_s_first_name_wins_over_the_call_s_first_argument() -> None:
    arguments = [
        {"name": "Registry", "value": "0x80000002"},
        {"name": "SubKey", "value": "SOFTWARE\\Example"},
        {"name": "FullName", "value": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Example"},
    ]
    assert pick_argument(arguments, NAMES) == "HKEY_LOCAL_MACHINE\\SOFTWARE\\Example"


def test_a_later_name_answers_when_the_earlier_ones_are_absent_or_blank() -> None:
    arguments = [
        {"name": "Registry", "value": "0x80000002"},
        {"name": "FullName", "value": "  "},
        {"name": "SubKey", "value": "SOFTWARE\\Example"},
    ]
    assert pick_argument(arguments, NAMES) == "SOFTWARE\\Example"
    assert pick_argument([{"name": "Registry", "value": "0x80000002"}], NAMES) == "0x80000002"
    assert pick_argument([{"name": "Other", "value": "x"}], NAMES) is None


def test_every_shape_a_sandbox_files_arguments_in_is_read() -> None:
    as_dict = {"Registry": "0x80000001", "FullName": "HKEY_CURRENT_USER\\Example"}
    as_rows_of_dicts = [{"Registry": "0x80000001"}, {"FullName": "HKEY_CURRENT_USER\\Example"}]
    as_name_value = [
        {"name": "Registry", "value": "0x80000001"},
        {"name": "FullName", "value": "HKEY_CURRENT_USER\\Example"},
    ]
    for arguments in (as_dict, as_rows_of_dicts, as_name_value):
        assert pick_argument(arguments, NAMES) == "HKEY_CURRENT_USER\\Example"
    assert pick_argument(None, NAMES) is None
    assert pick_argument("FullName", NAMES) is None


def test_the_first_value_filed_under_a_name_is_the_one_kept() -> None:
    arguments = [{"name": "SubKey", "value": "first"}, {"name": "SubKey", "value": "second"}]
    assert argument_table(arguments) == {"SubKey": "first"}


def test_a_caller_decides_which_values_count() -> None:
    arguments = [{"name": "FullName", "value": 7}, {"name": "SubKey", "value": "text"}]
    assert pick_argument(arguments, NAMES) == 7
    assert pick_argument(arguments, NAMES, accept=lambda v: isinstance(v, str)) == "text"


def _best_time(arguments: list[dict[str, str]], names: tuple[str, ...]) -> float:
    best = float("inf")
    for _ in range(3):
        began = time.perf_counter()
        pick_argument(arguments, names)
        best = min(best, time.perf_counter() - began)
    return best


def test_ten_times_the_arguments_and_names_costs_about_ten_times_as_long() -> None:
    def hostile(n: int) -> tuple[list[dict[str, str]], tuple[str, ...]]:
        arguments = [{"name": f"arg{i}", "value": "x" * 64} for i in range(n)]
        names = tuple(f"missing{i}" for i in range(n))
        return arguments, names

    small = _best_time(*hostile(5_000))
    large = _best_time(*hostile(50_000))
    assert large < small * 40 + 0.05
