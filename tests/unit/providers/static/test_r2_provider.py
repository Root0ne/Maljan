"""radare2 is the generic MCP provider with radare2's defaults."""

from __future__ import annotations

from pathlib import Path

from maljan.core.config import Settings
from maljan.providers.static.generic_mcp import GenericMCPStaticProvider
from maljan.providers.static.r2 import R2StaticProvider


def _cfg():
    cfg = Settings(_env_file=None)
    cfg.static.provider = "r2"
    cfg.static.r2.enabled = True
    return cfg


def test_it_is_the_generic_adapter_with_defaults():
    assert issubclass(R2StaticProvider, GenericMCPStaticProvider)


def test_capabilities():
    caps = R2StaticProvider.from_settings(_cfg()).capabilities
    assert caps.provides_tools and caps.needs_sample_mirror
    assert caps.degrade_on_failure is True
    assert caps.provides_function_hashes is False


def test_the_command_defaults_to_the_configured_binary():
    cfg = _cfg()
    cfg.static.r2.binary_path = "/opt/r2/bin/r2mcp"
    provider = R2StaticProvider.from_settings(cfg)
    assert provider.server_command() == "/opt/r2/bin/r2mcp"


def test_the_prompt_fragment_names_r2_tools_and_no_ghidra_tool():
    fragment = R2StaticProvider.from_settings(_cfg()).prompt_fragment()
    assert "cite a concrete artifact" in fragment
    assert "load_program" not in fragment and "Ghidra" not in fragment
    assert "open_file" in fragment and "decompile_function" in fragment


def test_the_mirror_spec_uses_the_configured_directory():
    cfg = _cfg()
    cfg.static.r2.work_dir = "r2-elsewhere"
    spec = R2StaticProvider.from_settings(cfg).mirror_spec()
    assert spec is not None and spec.work_subdir == "r2-elsewhere"


def test_the_mirror_spec_has_no_container_prefix():
    """A co-located r2mcp opens the sample by its host path; there is no
    container mount to translate the mirrored path into."""
    spec = R2StaticProvider.from_settings(_cfg()).mirror_spec()
    assert spec is not None and spec.container_prefix == ""


def test_opening_never_writes_the_resolved_command_back_into_the_config(monkeypatch):
    """Regression: ``open()`` must resolve ``binary_path`` into the launched
    command without mutating ``self._cfg`` — that object is the shared,
    user-editable ``Settings`` leaf ``settings_snapshot()`` later persists into
    the job's run summary, so a write here would show the operator a
    ``command`` they never set."""
    from maljan.agents import mcp_client
    from maljan.providers.base import StaticJobContext

    recorded: dict[str, object] = {}

    class _FakeToolkit:
        def __init__(self, server_params, **kwargs):
            recorded["command"] = server_params.command

        async def initialize(self) -> None:
            return None

        def get_tools(self):
            return []

    monkeypatch.setattr(mcp_client, "MCPLangChainToolkit", _FakeToolkit)
    from maljan.providers.static import r2

    monkeypatch.setattr(
        r2, "resolve_r2_binary", lambda configured, env=None: r2.R2Binary(configured, ())
    )

    cfg = _cfg()
    original_command = cfg.static.r2.command
    provider = R2StaticProvider.from_settings(cfg)

    provider.open(StaticJobContext())

    assert recorded["command"] == "r2mcp", "the fake toolkit must receive binary_path as command"
    assert cfg.static.r2.command == original_command, "open() must not mutate the shared config"


# ---------------------------------------------------------------------------
# BUG 10 (live 2026-09-07): every r2 `open_file` in the run reported
# "Failed to open file." radare2's own sandbox path check rejects a path with a
# `/.` segment, and the r2 mirror lived in `data/samples/.work`. Reproduced
# against a live r2mcp with one PE: it opens from `data/samples/<sha>.exe` and
# from `data/samples/r2work/<sha>.exe`, and fails from
# `data/samples/.work/<sha>.exe` — with `-g none` too, so it is not the
# sandbox profile. The mirror therefore has to live somewhere unhidden, and the
# setting has to refuse a directory that would put it back.
# ---------------------------------------------------------------------------


def _hidden_segments(path: str) -> list[str]:
    return [part for part in Path(path).parts if part.startswith(".") and part not in (".", "..")]


def test_the_r2_mirror_directory_is_not_hidden() -> None:
    """The default the operator inherits must be one r2 can actually open."""
    cfg = _cfg()
    assert _hidden_segments(cfg.static.r2.work_dir) == [], (
        f"r2 cannot open a sample under a hidden directory: {cfg.static.r2.work_dir!r}"
    )


def test_the_mirror_spec_carries_no_hidden_segment() -> None:
    provider = R2StaticProvider.from_settings(_cfg())
    subdir = provider.mirror_spec().work_subdir
    assert not subdir.startswith("."), f"r2 mirror subdirectory is hidden: {subdir!r}"


def test_a_hidden_work_directory_is_rejected_at_settings_validation() -> None:
    """An operator who points it back at `.work` is told why, not left with a
    provider that silently analyses nothing."""
    import pytest
    from pydantic import ValidationError

    from maljan.core.config import StaticR2Config

    with pytest.raises(ValidationError) as excinfo:
        StaticR2Config(work_dir=".hidden")
    message = str(excinfo.value)
    assert "hidden" in message.lower()
    assert "radare2" in message.lower() or "r2" in message.lower()


def test_an_ordinary_work_directory_is_accepted() -> None:
    from maljan.core.config import StaticR2Config

    assert StaticR2Config(work_dir="r2-work").work_dir == "r2-work"


def test_a_work_directory_that_is_a_path_is_rejected() -> None:
    """One name under the samples directory, as for every server: `..` and a
    path resolve outside it."""
    import pytest
    from pydantic import ValidationError

    from maljan.core.config import StaticR2Config

    for bad in ("data/samples/..", "..", ".", "data/samples/r2-work"):
        with pytest.raises(ValidationError):
            StaticR2Config(work_dir=bad)


def test_a_block_naming_no_directory_is_still_mirrored_somewhere_r2_can_open() -> None:
    """The shipped name, never the shared hidden default (BUG 10)."""
    cfg = _cfg()
    cfg.static.r2.work_dir = ""
    spec = R2StaticProvider.from_settings(cfg).mirror_spec()
    assert spec.work_subdir == "r2-work"


# ---------------------------------------------------------------------------
# The earlier release's `mirror_dir` is read as `work_dir`.
# ---------------------------------------------------------------------------


def test_a_stored_mirror_dir_is_read_as_the_work_dir() -> None:
    from maljan.core.config import StaticR2Config

    block = StaticR2Config(mirror_dir="data/samples/r2-elsewhere")
    assert block.work_dir == "r2-elsewhere"
    assert not hasattr(block, "mirror_dir")
    assert StaticR2Config(mirror_dir="./data/samples/r2-work/").work_dir == "r2-work"
    assert StaticR2Config(mirror_dir="data/samples/.").work_dir == "samples"


def test_a_stored_work_dir_wins_over_a_stored_mirror_dir() -> None:
    from maljan.core.config import StaticR2Config

    block = StaticR2Config(mirror_dir="data/samples/old", work_dir="new")
    assert block.work_dir == "new"


def test_a_stored_mirror_dir_reaches_the_mirror_spec_through_the_settings() -> None:
    from maljan.core.settings_overrides import build_settings

    cfg = build_settings(
        {
            "static.provider": "r2",
            "static.r2.enabled": True,
            "static.r2.mirror_dir": "data/samples/r2-elsewhere",
        }
    )
    assert cfg.static.r2.work_dir == "r2-elsewhere"
    assert R2StaticProvider.from_settings(cfg).mirror_spec().work_subdir == "r2-elsewhere"


def test_a_stored_mirror_dir_that_was_never_valid_is_still_refused() -> None:
    import pytest
    from pydantic import ValidationError

    from maljan.core.config import StaticR2Config

    for bad in ("data/samples/..", "..", "", ".", "data/samples/.hidden"):
        with pytest.raises(ValidationError):
            StaticR2Config(mirror_dir=bad)
