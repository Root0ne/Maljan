"""Every label the detector gives a sample is listed among the routed formats.

``routed_formats`` is what the settings schema serves the console as the
formats a triage pack step may name. It is read off the detector's tables plus
``_RULE_FILE_TYPES``, the labels the detector gives by a rule of its own.

The source guard reads the returns of the functions ``DETECTOR_FUNCTIONS``
names. Every label such a return spells out, or names by a module string
constant, must be listed, and every rule label listed must be one of them. So
a label written into a return of those functions, or a rule removed from them,
makes it fail. A label produced through a new helper function, or out of a new
table read through a loop variable, is seen neither by the guard nor by the
probes below, which walk the known tables and rules with bytes that reach them.
"""

from __future__ import annotations

import ast
import inspect
import io
import zipfile
from pathlib import Path

from maljan.extractors import sample_identity
from maljan.extractors.sample_identity import detect_file_type, routed_formats

FILLER = b"\x00" * 64

# The functions whose returns are the detector's labels.
DETECTOR_FUNCTIONS = ("_detect_file_type", "_zip_container_type", "_shebang_type")


def _zip(names: list[str]) -> bytes:
    held = io.BytesIO()
    with zipfile.ZipFile(held, "w") as archive:
        for name in names:
            archive.writestr(name, b"x")
    return held.getvalue()


def _given(tmp_path: Path, name: str, blob: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(blob)
    return detect_file_type(path, blob)


def _returned_labels() -> set[str]:
    """Every text a detector function's ``return`` spells out or names by a module constant."""
    tree = ast.parse(inspect.getsource(sample_identity))
    labels: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name not in DETECTOR_FUNCTIONS:
            continue
        for held in ast.walk(node):
            if not isinstance(held, ast.Return) or held.value is None:
                continue
            for part in ast.walk(held.value):
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    labels.add(part.value)
                elif isinstance(part, ast.Name):
                    named = getattr(sample_identity, part.id, None)
                    if isinstance(named, str):
                        labels.add(named)
    return labels


def test_the_list_is_sorted_and_names_each_format_once() -> None:
    listed = routed_formats()
    assert list(listed) == sorted(set(listed))
    assert "unknown" in listed


def test_every_label_a_detector_return_spells_out_is_listed() -> None:
    returned = _returned_labels()
    assert returned, "the guard found no return of the detector's functions"
    assert returned <= set(routed_formats()), returned - set(routed_formats())


def test_every_rule_label_listed_is_one_the_detector_returns() -> None:
    rules = set(sample_identity._RULE_FILE_TYPES)
    assert rules <= _returned_labels(), rules - _returned_labels()


def test_every_magic_prefix_gives_a_listed_format(tmp_path: Path) -> None:
    for prefix, label in sample_identity._MAGIC_PREFIXES:
        given = _given(tmp_path, "sample.bin", prefix + FILLER)
        assert given == label and given in routed_formats(), (prefix, given)


def test_every_zip_signature_and_a_plain_zip_give_listed_formats(tmp_path: Path) -> None:
    for entry, label in sample_identity._ZIP_SIGNATURE_ENTRIES:
        given = _given(tmp_path, "sample.zip", _zip([entry]))
        assert given == label and given in routed_formats(), (entry, given)
    for names in (["Payload/App.app/Info.plist"], ["readme.txt"]):
        assert _given(tmp_path, "sample.zip", _zip(names)) in routed_formats(), names


def test_every_shebang_and_extension_gives_a_listed_format(tmp_path: Path) -> None:
    for needle, label in sample_identity._SHEBANG_TYPES:
        blob = f"#!/usr/bin/{needle.strip('/')}\necho\n".encode()
        given = _given(tmp_path, "script", blob)
        assert given == label and given in routed_formats(), (needle, given)
    for extension, label in sample_identity._EXTENSION_TYPES.items():
        given = _given(tmp_path, f"sample{extension}", b"plain text, no magic\n")
        assert given == label and given in routed_formats(), (extension, given)


def test_the_rule_labels_are_listed(tmp_path: Path) -> None:
    thin = b"\xcf\xfa\xed\xfe" + FILLER
    fat = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big") + FILLER
    shortcut = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + FILLER
    disc = b"\x00" * 32769 + b"CD001" + FILLER
    for name, blob in (
        ("thin", thin),
        ("fat", fat),
        ("shortcut", shortcut),
        ("disc", disc),
        ("nothing.dat", b"\x01\x02\x03\x04" + FILLER),
    ):
        given = _given(tmp_path, name, blob)
        assert given in routed_formats(), (name, given)
    assert _given(tmp_path, "nothing.dat", b"\x01\x02\x03\x04" + FILLER) == "unknown"
