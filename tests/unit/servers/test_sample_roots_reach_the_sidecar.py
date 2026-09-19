"""The directories the worker puts a sample in reach the sidecar that reads it.

Confinement is only half a working tool call. A sidecar reads a path argument
only inside the roots it was given, and it learns them from one environment
variable that is copied into the child at spawn — so a deployment where
``MALJAN_SAMPLE_ROOTS`` does not survive that copy refuses every analyst tool
call on the very sample the run is about, with the same error a real escape
attempt gets.

The tests here are deliberately on the far side of the process boundary: a
sidecar started the way the registry starts one, asked for a file under an
exported root and for a file outside every root. An in-process import of the
same module proves the confinement logic and nothing about whether the roots
arrive.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]

_INTERPRETER_MISSING = not sys.executable or not shutil.which(sys.executable)

# A tool call through a live child, generously: the child imports the whole
# analysis tool stack before it answers ``initialize``.
LIVE_BUDGET_S = 120.0


def _path_taking_sidecars() -> list[str]:
    """The built-ins whose server module holds a path argument to the roots.

    Read off the servers themselves rather than written out here: a sidecar
    that starts confining paths has to start receiving the roots in the same
    change, and a list kept by hand is what lets the two drift.
    """
    from maljan.core.config import BUILTIN_SERVER_KEYS

    found = []
    for key in BUILTIN_SERVER_KEYS:
        server = ROOT / "services" / f"{key}-mcp" / "server.py"
        if server.is_file() and "resolve_under_roots" in server.read_text(encoding="utf-8"):
            found.append(key)
    return found


PATH_TAKING = _path_taking_sidecars()


def _builtin_keys() -> list[str]:
    from maljan.core.config import BUILTIN_SERVER_KEYS

    return list(BUILTIN_SERVER_KEYS)


BUILTIN_KEYS = _builtin_keys()


def _stale_server_map(settings_servers: dict[str, Any]) -> dict[str, Any]:
    """The stored map a deployment saved before the sample roots existed.

    This is what the settings store really holds: the server editor writes the
    whole map as one row, every entry dumped in full, so each saved copy pins
    the built-ins' launch parameters as they stood on the day it was saved.
    """
    out: dict[str, Any] = {}
    for key, server in settings_servers.items():
        entry = server.model_dump(mode="json")
        entry.pop("auth_token", None)
        entry["env_allow"] = [
            name for name in entry.get("env_allow", []) if name != "MALJAN_SAMPLE_ROOTS"
        ]
        out[key] = entry
    return out


def _cleared_server_map() -> dict[str, Any]:
    """The stored map of an admin who emptied every built-in's ``env_allow``.

    The narrowest thing the editor lets them do to that field, and the shape
    the policy is easiest to read off: whatever comes back is what a stored row
    is not allowed to take away.
    """
    from maljan.core.config import Settings

    out: dict[str, Any] = {}
    for key, server in Settings(_env_file=None).mcp.servers.items():
        entry = server.model_dump(mode="json")
        entry.pop("auth_token", None)
        entry["env_allow"] = []
        out[key] = entry
    return out


def _no_roots_yet(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start from no roots, and leave this process's environment as it was.

    An empty value rather than a deletion: a root exported during the test
    then belongs to the value ``monkeypatch`` puts back, instead of outliving
    the test in the environment every later one reads.
    """
    from maljan.tools.roots import SAMPLE_ROOTS_ENV

    monkeypatch.setenv(SAMPLE_ROOTS_ENV, "")


def _sample(target: Path) -> str:
    target.write_bytes(b"MZ" + b"\x00" * 128 + b"a readable string" * 4)
    return str(target)


async def _answers(config: Any, calls: list[dict[str, Any]], job_id: str) -> list[Any]:
    """Spawn the sidecar the registry's way and make each call against it."""
    from maljan.providers.servers import ServerHandle

    handle = ServerHandle("analysis", config)
    await handle.aopen(job_id)
    try:
        tools = {str(getattr(tool, "name", "")): tool for tool in handle.tools()}
        return [await tools["strings"].ainvoke(call) for call in calls]
    finally:
        await handle.aclose()


def _live(config: Any, calls: list[dict[str, Any]], job_id: str = "roots-test") -> list[Any]:
    return asyncio.run(asyncio.wait_for(_answers(config, calls, job_id), timeout=LIVE_BUDGET_S))


def _error(answer: Any) -> dict[str, Any]:
    parsed = json.loads(answer) if isinstance(answer, str) else answer
    assert isinstance(parsed, dict), parsed
    return parsed.get("error") or {}


class TestEveryPathTakingSidecarMayReadTheRoots:
    def test_at_least_the_two_file_reading_sidecars_are_covered(self) -> None:
        assert set(PATH_TAKING) >= {"analysis", "network"}

    @pytest.mark.parametrize("name", PATH_TAKING)
    def test_the_child_environment_carries_the_roots(
        self, name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents.subprocess_env import child_env
        from maljan.core.config import Settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        monkeypatch.setenv(SAMPLE_ROOTS_ENV, str(tmp_path))
        config = Settings(_env_file=None).mcp.servers[name]

        env = child_env(config.env, allow=tuple(config.env_allow))

        assert env[SAMPLE_ROOTS_ENV] == str(tmp_path)

    def test_a_sidecar_that_takes_no_path_is_told_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents.subprocess_env import child_env
        from maljan.core.config import BUILTIN_SERVER_KEYS, Settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        monkeypatch.setenv(SAMPLE_ROOTS_ENV, str(tmp_path))
        servers = Settings(_env_file=None).mcp.servers

        for name in BUILTIN_SERVER_KEYS:
            if name in PATH_TAKING:
                continue
            config = servers[name]
            env = child_env(config.env, allow=tuple(config.env_allow))
            assert SAMPLE_ROOTS_ENV not in env, name

    def test_the_variable_is_named_per_server_and_not_given_to_every_child(self) -> None:
        """A name in ``BASE_KEYS`` would reach every subprocess the app starts."""
        from maljan.agents.subprocess_env import BASE_KEYS
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        assert SAMPLE_ROOTS_ENV not in BASE_KEYS


class TestAServerAnOperatorAddedSeesTheRootsOnlyWhenAsked:
    def test_a_custom_server_is_told_nothing_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents.subprocess_env import child_env
        from maljan.core.config import Settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        monkeypatch.setenv(SAMPLE_ROOTS_ENV, str(tmp_path))
        settings = Settings(
            _env_file=None,
            mcp={"servers": {"mine": {"transport": "stdio", "command": sys.executable}}},
        )
        config = settings.mcp.servers["mine"]

        assert config.env_allow == []
        assert SAMPLE_ROOTS_ENV not in child_env(config.env, allow=tuple(config.env_allow))

    def test_a_custom_server_that_lists_it_receives_it(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.agents.subprocess_env import child_env
        from maljan.core.config import Settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        monkeypatch.setenv(SAMPLE_ROOTS_ENV, str(tmp_path))
        settings = Settings(
            _env_file=None,
            mcp={
                "servers": {
                    "mine": {
                        "transport": "stdio",
                        "command": sys.executable,
                        "env_allow": [SAMPLE_ROOTS_ENV],
                    }
                }
            },
        )
        config = settings.mcp.servers["mine"]

        env = child_env(config.env, allow=tuple(config.env_allow))

        assert env[SAMPLE_ROOTS_ENV] == str(tmp_path)


class TestAStoredServerMapCannotWithholdWhatTheSidecarNeeds:
    """What a built-in's child may read is code, not a value an old row pins.

    The registry is one stored row holding every server, written whole every
    time an operator saves anything in it — a token, a custom server, a
    disabled built-in. Re-seeding only the *missing* built-ins therefore left
    every deployment that had ever saved the map running yesterday's launch
    parameters, so a variable a sidecar gained afterwards reached a fresh
    install and nothing else.
    """

    def _from_stale_store(self) -> Any:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import build_settings

        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)
        return build_settings({"mcp.servers": stale})

    @pytest.mark.parametrize("name", PATH_TAKING)
    def test_a_map_saved_before_the_variable_existed_still_carries_it(self, name: str) -> None:
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        settings = self._from_stale_store()

        assert SAMPLE_ROOTS_ENV in settings.mcp.servers[name].env_allow

    def test_the_operator_s_own_names_are_kept(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import build_settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)
        stale["analysis"]["env_allow"] = [*stale["analysis"]["env_allow"], "MY_OWN_VARIABLE"]

        env_allow = build_settings({"mcp.servers": stale}).mcp.servers["analysis"].env_allow

        assert SAMPLE_ROOTS_ENV in env_allow
        assert env_allow[-1] == "MY_OWN_VARIABLE"
        assert len(env_allow) == len(set(env_allow))

    def test_a_server_the_operator_added_is_left_exactly_as_stored(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import build_settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)
        stale["mine"] = {"transport": "stdio", "command": sys.executable, "env_allow": ["MY_TOKEN"]}

        settings = build_settings({"mcp.servers": stale})

        assert settings.mcp.servers["mine"].env_allow == ["MY_TOKEN"]
        assert SAMPLE_ROOTS_ENV not in settings.mcp.servers["mine"].env_allow

    def test_everything_else_the_operator_stored_is_untouched(self) -> None:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import build_settings

        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)
        stale["threatintel"]["enabled"] = False

        settings = build_settings({"mcp.servers": stale})

        assert settings.mcp.servers["threatintel"].enabled is False

    def test_a_map_the_editor_validates_is_stored_with_the_required_names(self) -> None:
        """The row an operator saves is normalised on the way in as well."""
        from app.services.server_map import validate_server_map
        from maljan.core.config import Settings
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)

        cleaned = validate_server_map(stale)

        for name in PATH_TAKING:
            assert SAMPLE_ROOTS_ENV in cleaned[name]["env_allow"], name

    def test_a_name_an_admin_added_survives_the_save(self) -> None:
        """The save repairs the row without spending the admin's own names."""
        from app.services.server_map import validate_server_map
        from maljan.core.config import REQUIRED_ENV_ALLOW, Settings

        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)
        stale["analysis"]["env_allow"] = ["MY_OWN_VARIABLE"]

        cleaned = validate_server_map(stale)

        assert cleaned["analysis"]["env_allow"] == [
            *REQUIRED_ENV_ALLOW["analysis"],
            "MY_OWN_VARIABLE",
        ]


class TestWhatAStoredRowMayTakeAwayAndWhatItMayNot:
    """A built-in keeps what it cannot run without, and loses what it can.

    The floor is not the shipped list. ``MALJAN_SAMPLE_ROOTS``,
    ``MALJAN_STAGING_DIR`` and ``MALJAN_STAGING_TTL_HOURS`` are facts a sidecar
    cannot work out for itself — which directories it may read, where a
    delivered sample lands and how long it is kept — so a stored row that has
    lost one gets it back. Every other shipped name is a default: the
    threat-intel keys are the deployment's credentials, and an admin who
    clears that list to stop a sample being looked up finds it still clear on
    the next run, the next save, the next look at the editor and the next
    connection test.
    """

    def test_every_required_name_is_one_the_server_ships_with(self) -> None:
        from maljan.core.config import REQUIRED_ENV_ALLOW, Settings

        servers = Settings(_env_file=None).mcp.servers

        for key, required in REQUIRED_ENV_ALLOW.items():
            assert set(required) <= set(servers[key].env_allow), key

    def test_nothing_but_the_roots_the_staging_names_and_the_retry_is_required(self) -> None:
        """A credential is never a name a stored row is made to carry."""
        from maljan.core.config import REQUIRED_ENV_ALLOW
        from maljan.tools.knowledge import INDEX_RETRY_ENV
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        named = {name for required in REQUIRED_ENV_ALLOW.values() for name in required}

        assert named == {
            SAMPLE_ROOTS_ENV,
            "MALJAN_STAGING_DIR",
            "MALJAN_STAGING_TTL_HOURS",
            INDEX_RETRY_ENV,
        }

    @pytest.mark.parametrize("name", PATH_TAKING)
    def test_a_sidecar_that_confines_paths_may_not_lose_the_roots(self, name: str) -> None:
        from maljan.core.config import REQUIRED_ENV_ALLOW
        from maljan.tools.roots import SAMPLE_ROOTS_ENV

        assert SAMPLE_ROOTS_ENV in REQUIRED_ENV_ALLOW.get(name, ())

    @pytest.mark.parametrize("name", BUILTIN_KEYS)
    def test_a_cleared_list_comes_back_as_the_required_names_alone(self, name: str) -> None:
        from maljan.core.config import REQUIRED_ENV_ALLOW
        from maljan.core.settings_overrides import build_settings

        settings = build_settings({"mcp.servers": _cleared_server_map()})

        assert settings.mcp.servers[name].env_allow == list(REQUIRED_ENV_ALLOW.get(name, ()))

    @pytest.mark.parametrize("name", BUILTIN_KEYS)
    def test_a_save_stores_the_required_names_alone(self, name: str) -> None:
        from app.services.server_map import validate_server_map
        from maljan.core.config import REQUIRED_ENV_ALLOW

        cleaned = validate_server_map(_cleared_server_map())

        assert cleaned[name]["env_allow"] == list(REQUIRED_ENV_ALLOW.get(name, ()))

    def test_a_fresh_deployment_is_given_the_whole_shipped_list(self) -> None:
        """Nothing here narrows what a deployment nobody has configured gets."""
        from maljan.core.settings_overrides import build_settings

        servers = build_settings({}).mcp.servers

        assert servers["threatintel"].env_allow == ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]
        assert servers["analysis"].env_allow == [
            "MALJAN_STAGING_DIR",
            "MALJAN_STAGING_TTL_HOURS",
            "MALJAN_SAMPLE_ROOTS",
        ]

    def test_a_cleared_intel_list_keeps_the_keys_out_of_the_child(self) -> None:
        """The removal is worth nothing unless the child really loses them."""
        from maljan.agents.subprocess_env import child_env
        from maljan.core.settings_overrides import build_settings

        config = build_settings({"mcp.servers": _cleared_server_map()}).mcp.servers["threatintel"]

        env = child_env(
            config.env,
            allow=tuple(config.env_allow),
            source={"VIRUSTOTAL_API_KEY": "vt", "ABUSEIPDB_API_KEY": "abuse", "PATH": "/usr/bin"},
        )

        assert "VIRUSTOTAL_API_KEY" not in env
        assert "ABUSEIPDB_API_KEY" not in env


@pytest.mark.skipif(
    _INTERPRETER_MISSING, reason="no python interpreter available to launch the sidecar"
)
class TestTheLiveSidecarReadsTheSampleAndNothingElse:
    def test_a_file_under_an_exported_root_is_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.settings_overrides import build_settings
        from maljan.tools.roots import add_sample_root

        _no_roots_yet(monkeypatch)
        add_sample_root(tmp_path)
        config = build_settings({}).mcp.servers["analysis"]

        answer, refused = _live(
            config,
            [{"path": _sample(tmp_path / "sample.bin")}, {"path": "/etc/hostname"}],
        )

        assert _error(answer) == {}, answer
        error = _error(refused)
        assert error.get("code") == "path_outside_roots", refused
        assert error.get("remediation")
        assert "/etc/hostname" not in json.dumps(refused, default=str)

    def test_a_sidecar_started_from_a_stored_map_reads_it_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from maljan.core.config import Settings
        from maljan.core.settings_overrides import build_settings
        from maljan.tools.roots import add_sample_root

        _no_roots_yet(monkeypatch)
        add_sample_root(tmp_path)
        stale = _stale_server_map(Settings(_env_file=None).mcp.servers)
        config = build_settings({"mcp.servers": stale}).mcp.servers["analysis"]

        (answer,) = _live(config, [{"path": _sample(tmp_path / "sample.bin")}])

        assert _error(answer) == {}, answer

    def test_a_root_named_after_one_job_reaches_the_next_one_s_sidecar(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The roots are a snapshot taken at spawn, and a job re-attaches.

        Which is why nothing has to respawn mid-job: every caller that names a
        root — the worker at startup, the mirror step, the sandbox capture
        fetch, a run that was handed a sample path — runs before that job's
        registry attaches anything, and a handle held over from an earlier job
        is closed and started again for the new job id.
        """
        from maljan.core.settings_overrides import build_settings
        from maljan.providers.servers import ServerHandle
        from maljan.tools.roots import add_sample_root

        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        _no_roots_yet(monkeypatch)
        add_sample_root(first)
        config = build_settings({}).mcp.servers["analysis"]

        async def two_jobs() -> Any:
            handle = ServerHandle("analysis", config)
            await handle.aopen("job-one")
            try:
                add_sample_root(second)
                await handle.aopen("job-two")
                tools = {str(getattr(tool, "name", "")): tool for tool in handle.tools()}
                return await tools["strings"].ainvoke({"path": _sample(second / "sample.bin")})
            finally:
                await handle.aclose()

        answer = asyncio.run(asyncio.wait_for(two_jobs(), timeout=LIVE_BUDGET_S))

        assert _error(answer) == {}, answer


class TestTheWorkerNamesItsOwnDirectoriesBeforeAnySidecarStarts:
    def test_the_environment_handed_to_a_spawn_carries_the_mirror_base(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.worker import sample_files
        from maljan.agents.subprocess_env import child_env
        from maljan.core.settings_overrides import build_settings
        from maljan.tools.roots import ROOT_SEPARATOR, SAMPLE_ROOTS_ENV

        _no_roots_yet(monkeypatch)
        monkeypatch.setattr(sample_files.settings, "samples_dir", str(tmp_path / "samples"))
        monkeypatch.setattr(sample_files.settings, "upload_temp_dir", str(tmp_path / "uploads"))

        sample_files.export_sample_roots()

        config = build_settings({}).mcp.servers["analysis"]
        env = child_env(config.env, allow=tuple(config.env_allow))
        roots = env[SAMPLE_ROOTS_ENV].split(ROOT_SEPARATOR)
        assert str(tmp_path / "uploads") in roots
        assert str(tmp_path / "samples" / sample_files.WORK_SUBDIR) in roots

    def test_the_separator_is_the_platform_s_own(self) -> None:
        from maljan.tools.roots import ROOT_SEPARATOR

        assert ROOT_SEPARATOR == os.pathsep
