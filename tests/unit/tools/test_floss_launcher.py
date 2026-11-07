"""The arm64 FLOSS launcher refuses an environment that is not the pinned one (T-573).

``scripts/floss/floss`` is copied with its prefix and environment digest
pointed at a virtual environment built here, holding a stand-in FLOSS and
binary2strings with RECORD files of their own, and run as the image runs it
(``-ISB``). Each way the environment can differ ends in exit 2 and the
launcher's reason, before anything of FLOSS is imported; the pinned
environment answers ``--version``.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import subprocess
import sys
import venv
from pathlib import Path

import pytest

LAUNCHER = Path(__file__).resolve().parents[3] / "scripts" / "floss" / "floss"
MAIN = b'def main():\n    print("floss 3.1.1")\n    return 0\n'


def _row(site: Path, relative: str) -> list[str]:
    data = (site / relative).read_bytes()
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return [relative, f"sha256={digest}", str(len(data))]


def _dist(
    site: Path, name: str, version: str, files: dict[str, bytes], extra: tuple[str, ...] = ()
) -> Path:
    """A dist-info for ``name`` whose RECORD lists ``files`` and ``extra`` (by hash)."""
    info = site / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n")
    for relative, data in files.items():
        (site / relative).parent.mkdir(parents=True, exist_ok=True)
        (site / relative).write_bytes(data)
    listed = [*files, *extra, f"{info.name}/METADATA"]
    rows = [_row(site, relative) for relative in listed]
    rows.append([f"{info.name}/RECORD", "", ""])
    buffer = io.StringIO()
    csv.writer(buffer).writerows(sorted(rows))
    (info / "RECORD").write_text(buffer.getvalue(), newline="")
    return info / "RECORD"


@pytest.fixture
def env(tmp_path: Path) -> tuple[Path, Path]:
    """A virtual environment holding a stand-in FLOSS 3.1.1 and binary2strings 0.1.13."""
    prefix = tmp_path / "floss-env"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(prefix)
    site = prefix / "lib" / f"python{sys.version_info[0]}.{sys.version_info[1]}" / "site-packages"
    _dist(site, "flare-floss", "3.1.1", {"floss/__init__.py": b"", "floss/main.py": MAIN})
    _dist(site, "binary2strings", "0.1.13", {"binary2strings.py": b""})
    return prefix, site


def _launcher(prefix: Path, digest: str) -> str:
    text = LAUNCHER.read_text(encoding="utf-8")
    text = text.replace('PREFIX = "/opt/floss"', f"PREFIX = {str(prefix)!r}", 1)
    pinned = re.search(r"^ENVIRONMENT = \{\n.*?^\}\n", text, re.MULTILINE | re.DOTALL)
    assert pinned
    return text.replace(
        pinned[0], f"ENVIRONMENT = {{__import__('platform').machine(): {digest!r}}}\n"
    )


def _run(prefix: Path, digest: str = "0" * 64) -> subprocess.CompletedProcess[str]:
    script = prefix.parent / "floss-launcher"
    script.write_text(_launcher(prefix, digest), encoding="utf-8")
    return subprocess.run(  # noqa: S603 - this test's own interpreter and file
        [str(prefix / "bin" / "python3"), "-ISB", str(script), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=prefix.parent,
    )


def _pinned_run(prefix: Path) -> subprocess.CompletedProcess[str]:
    """Run with the environment digest pinned to what this environment gives."""
    first = _run(prefix)
    found = re.search(r"image build installs \(([0-9a-f]{64})\)", first.stderr)
    if found is None:
        return first
    return _run(prefix, found[1])


def _refused(done: subprocess.CompletedProcess[str], words: str) -> None:
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert done.stdout == ""
    assert words in done.stderr
    assert done.stderr.rstrip().endswith("nothing was run")


def test_the_pinned_environment_answers(env: tuple[Path, Path]) -> None:
    done = _pinned_run(env[0])
    assert (done.returncode, done.stdout.strip()) == (0, "floss 3.1.1"), done.stderr


def test_another_environment_digest_is_refused(env: tuple[Path, Path]) -> None:
    _refused(_run(env[0]), "the installed packages are not the ones the image build installs")


def test_an_added_package_is_refused_even_with_a_valid_record(env: tuple[Path, Path]) -> None:
    prefix, site = env
    pinned = re.search(r"\(([0-9a-f]{64})\)", _run(prefix).stderr)
    assert pinned
    _dist(site, "helper", "1.0", {"helper.py": b""})
    _refused(_run(prefix, pinned[1]), "not the ones the image build installs")


def test_a_changed_file_is_refused(env: tuple[Path, Path]) -> None:
    prefix, site = env
    (site / "floss" / "main.py").write_bytes(MAIN + b"# changed\n")
    _refused(_pinned_run(prefix), "floss/main.py of flare-floss is not the file its RECORD lists")


def test_an_unlisted_pth_is_refused_and_never_runs(env: tuple[Path, Path]) -> None:
    prefix, site = env
    marker = prefix.parent / "pth-ran"
    (site / "added.pth").write_text(f"import pathlib; pathlib.Path({str(marker)!r}).touch()\n")
    _refused(_pinned_run(prefix), "added.pth is in site-packages but in no RECORD")
    assert not marker.exists()


def test_another_release_is_refused(tmp_path: Path) -> None:
    prefix = tmp_path / "floss-env"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(prefix)
    site = prefix / "lib" / f"python{sys.version_info[0]}.{sys.version_info[1]}" / "site-packages"
    _dist(site, "flare-floss", "3.1.2", {"floss/__init__.py": b"", "floss/main.py": MAIN})
    _dist(site, "binary2strings", "0.1.13", {"binary2strings.py": b""})
    _refused(_pinned_run(prefix), "flare-floss is 3.1.2, not 3.1.1")


def test_a_package_installed_twice_is_refused(env: tuple[Path, Path]) -> None:
    prefix, site = env
    _dist(site, "flare-floss", "3.1.0", {"floss_old.py": b""})
    _refused(_pinned_run(prefix), "flare-floss is installed twice")


def test_a_symlink_to_a_listed_file_is_refused(env: tuple[Path, Path]) -> None:
    prefix, site = env
    (site / "floss" / "alias.py").symlink_to(site / "floss" / "main.py")
    _refused(_pinned_run(prefix), "floss/alias.py is a symlink")


def test_compiled_bytecode_is_refused(env: tuple[Path, Path]) -> None:
    prefix, site = env
    cache = site / "floss" / "__pycache__"
    cache.mkdir()
    (cache / "main.cpython-313.pyc").write_bytes(b"not checked source")
    _refused(_pinned_run(prefix), "compiled bytecode is in the environment (main.cpython-313.pyc)")


def test_a_floss_package_flare_floss_does_not_list_is_refused(tmp_path: Path) -> None:
    prefix = tmp_path / "floss-env"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(prefix)
    site = prefix / "lib" / f"python{sys.version_info[0]}.{sys.version_info[1]}" / "site-packages"
    _dist(site, "flare-floss", "3.1.1", {"flare_floss_marker.py": b""})
    # Listed, and so hashed, by another package's RECORD instead.
    _dist(site, "binary2strings", "0.1.13", {"floss/__init__.py": b"", "floss/main.py": MAIN})
    _refused(_pinned_run(prefix), "the floss package found is not the one flare-floss's RECORD")


def test_a_row_without_a_hash_is_refused(env: tuple[Path, Path]) -> None:
    prefix, site = env
    (site / "floss" / "extra.py").write_bytes(b"")
    record = next(site.glob("flare_floss-*.dist-info")) / "RECORD"
    record.write_text(record.read_text() + "floss/extra.py,,\r\n", newline="")
    _refused(_pinned_run(prefix), "flare-floss records floss/extra.py without a hash")


def test_another_interpreter_is_refused(env: tuple[Path, Path]) -> None:
    prefix, _site = env
    script = prefix.parent / "floss-launcher"
    script.write_text(_launcher(prefix, "0" * 64), encoding="utf-8")
    done = subprocess.run(  # noqa: S603 - this test's own interpreter and file
        [sys.executable, "-ISB", str(script), "--version"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    _refused(done, "the interpreter is not")
