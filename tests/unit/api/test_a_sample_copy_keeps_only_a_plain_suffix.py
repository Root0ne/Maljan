"""Every copy of a sample the platform writes keeps the upload's suffix only when it is plain.

The copies (the download, each provider's mirror) are named by the SHA-256
plus the upload's suffix, so a sandbox can pick its profile from ``.elf`` or
``.exe``. The suffix is the uploader's text; one with a percent sign, a
backslash, a control character or anything else outside ``[A-Za-z0-9._-]`` is
dropped, so every path a tool is handed is plain. An uploader could otherwise
name a sample so that a tool reads its path another way.
"""

from __future__ import annotations

import pytest

from app.worker.sample_files import safe_suffix


@pytest.mark.parametrize(
    ("filename", "suffix"),
    [
        ("invoice.exe", ".exe"),
        ("loader.ELF", ".ELF"),
        ("a.b-c_d", ".b-c_d"),
        ("archive.tar.gz", ".gz"),
        ("no_suffix", ""),
    ],
)
def test_a_plain_suffix_is_kept(filename: str, suffix: str) -> None:
    assert safe_suffix(filename) == suffix


@pytest.mark.parametrize(
    "filename",
    [
        "invoice.e%78e",
        "report.%TEMP%",
        "payload.e\\xe",
        "payload.ex\x7fe",
        "payload.ex\x00e",
        "payload.ex e",
        "payload.exe‮",
        "payload.еxe",
    ],
)
def test_any_other_suffix_is_dropped(filename: str) -> None:
    assert safe_suffix(filename) == ""


def test_a_mirror_is_named_with_the_safe_suffix() -> None:
    from types import SimpleNamespace

    from app.worker.analysis_worker import mirror_target_for

    spec = SimpleNamespace(work_subdir=".work", container_prefix="/data/samples")
    provider = SimpleNamespace(
        capabilities=SimpleNamespace(needs_sample_mirror=True), mirror_spec=lambda: spec
    )
    target = mirror_target_for(provider, sha256="ab" * 32, extension=safe_suffix("x.e%78e"))
    assert target is not None
    assert target[1].endswith("/.work/" + "ab" * 32)
