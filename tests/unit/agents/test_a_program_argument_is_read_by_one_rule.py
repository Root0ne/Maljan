"""A program argument is read by one rule wherever two program names are compared.

The image range check (``agents.image_range``) and the redone-call reading
(``reporting.redone_calls``, T-542) both read a program argument with ``\\``
as ``/`` and a path by its last segment; one helper holds that rule so the two
cannot drift apart (T-545). The name it is compared with is read as given,
and case is kept.
"""

from __future__ import annotations

import pytest

from maljan.agents.image_range import program_name, same_program


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("sample.exe", "sample.exe"),
        ("C:\\work\\sample.exe", "sample.exe"),
        ("/tmp/work/sample.exe", "sample.exe"),
        ("  C:/work\\Sample.EXE \n", "Sample.EXE"),
        ("C:\\work\\", ""),
        ("", ""),
    ],
)
def test_the_program_a_value_names_is_its_last_path_segment(value: str, expected: str) -> None:
    assert program_name(value) == expected


@pytest.mark.parametrize(
    ("named", "name", "expected"),
    [
        ("sample.exe", "sample.exe", True),
        ("C:\\work\\sample.exe", "sample.exe", True),
        ("/tmp/work/sample.exe", "sample.exe", True),
        (" C:\\work\\sample.exe ", "C:/work/sample.exe", True),
        ("C:\\work\\Sample.exe", "sample.exe", False),
        ("C:\\work\\other.exe", "sample.exe", False),
        # The name compared with is read as given: a backslash path is not
        # read by its last segment on that side.
        ("sample.exe", "C:\\work\\sample.exe", False),
        # Known limit: two folders that hold the same file name are one program.
        ("a/sample.exe", "sample.exe", True),
    ],
)
def test_a_program_argument_names_a_program_by_path_or_last_segment(
    named: str, name: str, expected: bool
) -> None:
    assert same_program(named, name) is expected
