"""capa's rules and signatures are fetched for the flare-capa version uv.lock pins.

The backend image's ``capa-data`` stage and ``scripts/dev/fetch_external.sh``
each write the version and two sha256 digests: the rules archive's, recorded
when it was pinned, and flare-capa's sdist's, which is the digest uv.lock
records for it. They agree with uv.lock and with each other, both syncs of the
image install the ``capa`` extra, and the image puts the two directories where
the settings point by default, with a workstation's own copies kept out of it.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from maljan.core.config import StaticCapaConfig

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "docker" / "Dockerfile.backend"
FETCH_SCRIPT = ROOT / "scripts" / "dev" / "fetch_external.sh"
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
