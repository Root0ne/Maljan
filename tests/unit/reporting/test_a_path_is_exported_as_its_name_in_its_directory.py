"""A path indicator is a file's name in its directory, as STIX writes a file.

The export wrote ``[file:name = 'C:\\\\Users\\\\a\\\\evil.exe']``: ``file:name`` is
the last component, so a consumer matching it on a whole path matches nothing.
The name is compared as ``file:name`` and the directory as
``file:parent_directory_ref.path``, and every reader of an exported pattern
reads the pair back as the path the IOC table holds, by ``value_key``.
"""

from __future__ import annotations

import pytest

from maljan.agents.judge_postprocess import enforce_bundle_integrity
from maljan.reporting.dedupe import pattern_fingerprint
from maljan.reporting.ledger_projection import value_key
from maljan.reporting.renderers.stix_renderer import (
    exported_indicator_values,
    indicator_pattern,
    joined_path,
    pattern_values,
    rule_values,
    split_path,
)
from maljan.schemas.stix_pattern import read_comparisons

# (path, directory, name, the path read back)
SPLITS = [
    ("C:\\Users\\a\\evil.exe", "C:\\Users\\a", "evil.exe", "C:\\Users\\a\\evil.exe"),
    ("C:\\evil.exe", "C:\\", "evil.exe", "C:\\evil.exe"),
    ("C:\\x", "C:\\", "x", "C:\\x"),
    ("/x", "/", "x", "/x"),
    ("/tmp/x", "/tmp", "x", "/tmp/x"),
    ("%TEMP%\\x.exe", "%TEMP%", "x.exe", "%TEMP%\\x.exe"),
    ("./x", ".", "x", "./x"),
    ("\\\\srv\\share\\it's.exe", "\\\\srv\\share", "it's.exe", "\\\\srv\\share\\it's.exe"),
    ("a//b", "a", "b", "a/b"),
    ("C:\\dir\\\\x.exe", "C:\\dir", "x.exe", "C:\\dir\\x.exe"),
    ("C:/a/b\\evil.exe", "C:/a/b", "evil.exe", "C:/a/b\\evil.exe"),
]


@pytest.mark.parametrize(("path", "directory", "name", "back"), SPLITS)
def test_the_pattern_names_the_file_and_its_directory(
    path: str, directory: str, name: str, back: str
) -> None:
    assert split_path(path) == (directory, name)
    assert joined_path(directory, name) == back
    compared = {
        (c.object_type, c.prop): c.literal
        for c in read_comparisons(indicator_pattern("path", path) or "")
    }
    assert compared == {("file", "name"): name, ("file", "parent_directory_ref.path"): directory}


@pytest.mark.parametrize(("path", "directory", "name", "back"), SPLITS)
def test_every_reader_reads_the_pair_back_as_the_same_path(
    path: str, directory: str, name: str, back: str
) -> None:
    pattern = indicator_pattern("path", path)
    assert pattern is not None
    bundle = {"objects": [{"type": "indicator", "pattern": pattern}]}
    for read in (pattern_values(pattern), rule_values(pattern), exported_indicator_values(bundle)):
        assert [(v.kind, v.value) for v in read] == [("path", back)]
    assert value_key("path", back) == value_key("path", path)


@pytest.mark.parametrize("value", ["evil.exe", "/", "C:\\dir\\", "C:evil.exe"])
def test_a_value_with_no_name_in_a_directory_stays_one_comparison(value: str) -> None:
    quoted = value.replace("\\", "\\\\")
    assert indicator_pattern("path", value) == f"[file:name = '{quoted}']"


def test_one_windows_file_in_two_cases_is_one_indicator() -> None:
    one = indicator_pattern("path", "C:\\Windows\\Evil.exe")
    two = indicator_pattern("path", "c:\\windows\\evil.exe")
    assert pattern_fingerprint("stix", one) == pattern_fingerprint("stix", two)
    posix = (indicator_pattern("path", "/tmp/Evil"), indicator_pattern("path", "/tmp/evil"))
    assert pattern_fingerprint("stix", posix[0]) != pattern_fingerprint("stix", posix[1])
    objects = [
        {"type": "indicator", "id": f"indicator--{n}", "pattern": p, "pattern_type": "stix"}
        for n, p in (("1", one), ("2", two))
    ]
    kept = enforce_bundle_integrity(objects)
    assert [o["id"] for o in kept if o["type"] == "indicator"] == ["indicator--1"]


def test_a_file_in_an_environment_variable_s_directory_folds_its_case() -> None:
    one = indicator_pattern("path", "%TEMP%\\A.exe")
    two = indicator_pattern("path", "%temp%\\a.exe")
    assert pattern_fingerprint("stix", one) == pattern_fingerprint("stix", two)


def test_the_fold_is_read_per_observation() -> None:
    windows = "[file:name = 'A.exe' AND file:parent_directory_ref.path = 'C:\\\\x']"
    posix = "[file:name = 'Evil' AND file:parent_directory_ref.path = '/tmp']"
    lowered = posix.replace("Evil", "evil")
    assert pattern_fingerprint("stix", f"{windows} AND {posix}") != pattern_fingerprint(
        "stix", f"{windows} AND {lowered}"
    )
    assert pattern_fingerprint("stix", f"{windows} AND {posix}") == pattern_fingerprint(
        "stix", f"{windows.replace('A.exe', 'a.exe')} AND {posix}"
    )


@pytest.mark.parametrize(
    "pattern",
    [
        "[file:name = 'a.exe' OR file:parent_directory_ref.path = 'C:\\\\x']",
        "[file:name = 'a.exe'] AND [file:parent_directory_ref.path = 'C:\\\\x']",
        "[file:name = 'a.exe' AND file:parent_directory_ref.path != 'C:\\\\x']",
        "[file:name = 'a.exe' AND NOT file:parent_directory_ref.path = 'C:\\\\x']",
        "[file:name = 'a.exe' AND file:parent_directory_ref.path = 'C:\\\\x'] WITHIN 5 SECONDS",
    ],
)
def test_a_name_and_a_directory_not_written_as_one_file_are_two_values(pattern: str) -> None:
    values = [(v.kind, v.value) for v in rule_values(pattern)]
    assert ("path", "C:\\x\\a.exe") not in values
    assert ("path", "a.exe") in values
    if "!=" not in pattern:
        assert ("path", "C:\\x") in values


def test_a_directory_written_as_a_shape_is_declined_by_the_export() -> None:
    from maljan.reporting.renderers.stix_renderer import shape_is_asked_the_rule

    pattern = "[file:name = 'a.exe' AND file:parent_directory_ref.path LIKE 'C:\\\\%']"
    assert [(v.kind, v.value) for v in rule_values(pattern)] == [("path", "a.exe")]
    folder = read_comparisons(pattern)[1]
    assert shape_is_asked_the_rule(folder)
