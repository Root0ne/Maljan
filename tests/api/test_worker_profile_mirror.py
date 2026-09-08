"""The sample is mirrored once per static provider that needs a copy.

Today the worker asks the one configured provider. A profile with two static
analysts on two providers needs two mirrors, or the second analyst opens a
path that is not there; a profile with none needs zero, and the existing
single-provider path must produce exactly the bytes and the state key it
always did (sub-project A's contract).
"""

from __future__ import annotations

from pathlib import Path

from app.worker.analysis_worker import (  # noqa: E402
    mirror_static_samples,
    mirror_target_for,
    profile_static_providers,
)
from maljan.core.config import Settings  # noqa: E402
from maljan.core.container import ServiceContainer  # noqa: E402


def _container(**agents) -> ServiceContainer:
    return ServiceContainer(Settings(_env_file=None, agents=agents), mock=True)


def test_the_default_profile_names_one_provider():
    assert profile_static_providers(_container()) == ["ghidra"]


def test_two_static_analysts_on_two_providers_name_both_global_first():
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    assert profile_static_providers(container) == ["ghidra", "r2"]


def test_two_static_analysts_on_the_same_provider_name_it_once():
    container = _container(
        definitions={"static_b": {"role": "static", "static_provider": "ghidra"}},
        profiles={"two": {"analysts": ["static", "static_b"]}},
        profile="two",
    )
    assert profile_static_providers(container) == ["ghidra"]


def test_a_profile_with_no_static_analyst_still_names_the_global_provider():
    """The global provider backs ``state['static_sample_path']``, which A froze."""
    container = _container(profiles={"lean": {"analysts": ["network"]}}, profile="lean")
    assert profile_static_providers(container) == ["ghidra"]


def test_a_provider_that_reads_in_place_produces_no_mirror_target():
    container = _container()
    assert (
        mirror_target_for(
            container.get_static_provider("capa_yara"), sha256="ab" * 32, extension=".exe"
        )
        is None
    )


def test_each_provider_gets_its_own_container_visible_path():
    container = _container()
    ghidra = mirror_target_for(
        container.get_static_provider("ghidra"), sha256="ab" * 32, extension=".exe"
    )
    r2 = mirror_target_for(container.get_static_provider("r2"), sha256="ab" * 32, extension=".exe")
    assert ghidra is not None and r2 is not None
    # Two answers about how a tool reaches the sample: Ghidra sees the container
    # mount, a co-located r2mcp sees the host path itself.
    assert ghidra[1] != r2[1]
    # And, since BUG 10, two host files. radare2 rejects a path with a `/.`
    # segment, so r2 cannot be given the hidden `.work` copy Ghidra reads.
    assert ghidra[0] != r2[0]
    assert ghidra[0].parent.name == ".work"
    assert not r2[0].parent.name.startswith(".")


def test_the_state_carries_a_path_per_provider_and_keeps_the_global_key():
    from maljan.pipeline.state import AnalysisState

    assert "static_sample_paths" in AnalysisState.__annotations__
    assert "static_sample_path" in AnalysisState.__annotations__


def test_each_distinct_host_path_is_copied_once_and_cleaned_up():
    """Ghidra and r2 need separate host copies since BUG 10 — r2 cannot read
    the hidden `.work` one — so the mirror step makes one copy per distinct
    host path, and every one of them is returned for cleanup."""
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    calls: list[tuple[Path, Path]] = []

    def fake_copy(src: Path, dst: Path) -> None:
        calls.append((src, dst))

    host_mirrors, static_sample_paths = mirror_static_samples(
        container,
        temp_path="/tmp/does-not-matter.exe",
        sha256="ab" * 32,
        extension=".exe",
        copy_fn=fake_copy,
    )

    assert profile_static_providers(container) == ["ghidra", "r2"]
    assert set(static_sample_paths) == {"ghidra", "r2"}
    ghidra_target = mirror_target_for(
        container.get_static_provider("ghidra"), sha256="ab" * 32, extension=".exe"
    )
    r2_target = mirror_target_for(
        container.get_static_provider("r2"), sha256="ab" * 32, extension=".exe"
    )
    assert ghidra_target is not None and r2_target is not None
    assert static_sample_paths["ghidra"] == ghidra_target[1]
    assert static_sample_paths["r2"] == r2_target[1]
    # Two distinct host paths, one copy each, and both handed back so the
    # cleanup removes them — a copy that is made and not returned outlives the
    # job in a directory that holds live malware.
    assert len(calls) == 2
    assert {dst for _src, dst in calls} == {ghidra_target[0], r2_target[0]}
    assert set(host_mirrors) == {ghidra_target[0], r2_target[0]}
    assert len(host_mirrors) == len(set(host_mirrors)), "no path may be listed twice"


def test_the_frozen_key_is_the_global_providers_mirror_not_the_first_one_made():
    """F5: ``static_sample_path`` means the globally configured provider.

    A global provider that reads in place (capa/YARA, r2) makes no mirror while
    a clone on Ghidra does; taking the first entry that appeared handed the
    clone's path to every reader that means the global one.
    """
    from app.worker.analysis_worker import global_mirror_path

    settings = Settings(_env_file=None).static
    assert settings.provider == "ghidra"

    assert global_mirror_path({"ghidra": "/g/abc.exe"}, settings) == "/g/abc.exe"
    assert global_mirror_path({"r2": "/host/abc.exe", "ghidra": "/g/abc.exe"}, settings) == (
        "/g/abc.exe"
    )
    assert global_mirror_path({"r2": "/host/abc.exe"}, settings) is None
    assert global_mirror_path({}, settings) is None
