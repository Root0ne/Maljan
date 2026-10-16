"""capa's rules and signatures are fetched for the flare-capa version uv.lock pins.

The backend image's ``capa-data`` stage and ``scripts/dev/fetch_capa_data.sh``
(which ``fetch_external.sh`` runs) each write the version and two sha256
digests: the rules archive's, recorded when it was pinned, and flare-capa's
sdist's, which is the digest uv.lock records for it. They agree with uv.lock
and with each other, both leave the rules' CI folder out, both syncs of the
image install the ``capa`` extra, and the image puts the two directories where
the settings point by default, with a workstation's own copies kept out of it.
The script never touches a directory already there; it says whether that is
the pinned version.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tomllib
from pathlib import Path

import pytest

from maljan.core.config import StaticCapaConfig

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "Dockerfile.backend"
FETCH_SCRIPT = ROOT / "scripts" / "dev" / "fetch_capa_data.sh"
PINS = ("CAPA_VERSION", "CAPA_RULES_SHA256", "CAPA_SDIST_SHA256")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _image_pins() -> dict[str, str]:
    return dict(re.findall(r"^ARG (CAPA_[A-Z0-9_]+)=(\S+)$", _text(DOCKERFILE), re.M))


def _locked_capa() -> tuple[str, str]:
    lock = tomllib.loads(_text(ROOT / "uv.lock"))
    (package,) = [p for p in lock["package"] if p["name"] == "flare-capa"]
    return str(package["version"]), str(package["sdist"]["hash"]).removeprefix("sha256:")


def test_the_image_fetches_for_the_locked_capa() -> None:
    version, sdist_digest = _locked_capa()
    pins = _image_pins()

    assert sorted(pins) == sorted(PINS)
    assert pins["CAPA_VERSION"] == version
    assert pins["CAPA_SDIST_SHA256"] == sdist_digest
    assert re.fullmatch(r"[0-9a-f]{64}", pins["CAPA_RULES_SHA256"])


def test_the_fetch_script_pins_what_the_image_pins() -> None:
    names = "|".join(PINS)
    script = dict(re.findall(rf'^({names})="([^"]+)"$', _text(FETCH_SCRIPT), re.M))

    assert script == _image_pins()


def test_both_syncs_of_the_image_install_the_capa_extra() -> None:
    syncs = [line for line in _text(DOCKERFILE).splitlines() if line.startswith("RUN uv sync")]
    extras = [sorted(re.findall(r"--extra (\S+)", line)) for line in syncs]

    assert len(extras) == 2
    assert extras[0] == extras[1], "a second sync naming fewer extras prunes the others"
    assert "capa" in extras[0]


def test_the_image_puts_them_where_the_settings_point() -> None:
    defaults = StaticCapaConfig()
    copied = re.findall(r"^COPY --from=capa-data \S+ (\S+)$", _text(DOCKERFILE), re.M)
    kept_out = set(_text(ROOT / ".dockerignore").splitlines())
    untracked = set(_text(ROOT / ".gitignore").splitlines())

    assert copied == [defaults.rules_dir, defaults.signatures_dir]
    for directory in copied:
        assert f"{directory}/" in kept_out
        assert f"{directory}/" in untracked


def test_both_unpack_the_rules_without_their_ci_folder() -> None:
    """capa skips the rules' .github workflows; the provider's count would not."""
    for text in (_text(DOCKERFILE), _text(FETCH_SCRIPT)):
        (unpack,) = [
            line for line in text.splitlines() if "tar -xzf" in line and "rules.tar.gz" in line
        ]
        assert "--exclude=.github" in unpack


def test_setup_runs_the_capa_fetch() -> None:
    external = _text(ROOT / "scripts" / "dev" / "fetch_external.sh")

    assert 'bash "$REPO_ROOT/scripts/dev/fetch_capa_data.sh"' in external


def _run_in(tree: Path) -> list[str]:
    """The script copied into ``tree`` and run: both directories exist, so nothing is fetched."""
    assert (tree / "data" / "capa-rules").is_dir() and (tree / "data" / "capa-signatures").is_dir()
    script = tree / "scripts" / "dev" / FETCH_SCRIPT.name
    if not script.exists():
        script.parent.mkdir(parents=True)
        shutil.copy(FETCH_SCRIPT, script)
    done = subprocess.run(
        ["bash", str(script)], capture_output=True, text=True, check=True, timeout=60
    )
    return done.stdout.splitlines()


@pytest.mark.skipif(shutil.which("bash") is None, reason="the script is a bash script")
def test_a_directory_already_there_is_said_to_be_pinned_or_not_and_left_alone(
    tmp_path: Path,
) -> None:
    pins = _image_pins()
    version = pins["CAPA_VERSION"]
    rules = tmp_path / "data" / "capa-rules"
    signatures = tmp_path / "data" / "capa-signatures"
    rules.mkdir(parents=True)
    signatures.mkdir()
    (rules / "a.yml").write_text("rule:\n", encoding="utf-8")
    (signatures / "PINNED.txt").write_text(
        f"flare-capa {version} sigs sha256:{pins['CAPA_SDIST_SHA256']}\n", encoding="utf-8"
    )

    said = _run_in(tmp_path)

    assert said == [
        f"  present  capa rules in data/, but not the pinned v{version}: left as they are",
        f"  ok       capa signatures v{version}",
    ]
    assert sorted(p.name for p in rules.iterdir()) == ["a.yml"]
    (rules / "PINNED.txt").write_text(
        f"capa-rules v{version} sha256:{pins['CAPA_RULES_SHA256']}\n", encoding="utf-8"
    )
    assert _run_in(tmp_path)[0] == f"  ok       capa rules v{version}"
