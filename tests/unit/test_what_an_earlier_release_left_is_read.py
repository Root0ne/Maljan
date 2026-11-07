"""What an earlier release, another store or an installed component left under the
previous name is read, never dropped (T-576).

A server that declares its tools under the previous ``_meta`` key, a stored
server map naming environment variables by the previous prefix, a stored
bundle the run diff reads, a plugin declared in a previous entry-point group,
the staging base an earlier release swept, and an environment variable still
set under the previous prefix: each is read through a fallback built from
``malspark.core.previous_name``, or named in the log.
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from malspark.core.previous_name import CURRENT_NAME, PREVIOUS_NAME

ROOT = Path(__file__).resolve().parents[2]
OLD_ENV = f"{PREVIOUS_NAME.upper()}_"
NEW_ENV = f"{CURRENT_NAME.upper()}_"


# ---- the tool facts a server declares under the previous key ---------------


def test_a_tool_declared_under_the_previous_meta_key_is_read_as_declared() -> None:
    from malspark.core.derived_declarations import _declares_itself
    from malspark.core.served_declarations import served_facts_of
    from malspark.tools.declared_facts import FACTS_META_KEY, PREVIOUS_FACTS_META_KEY

    assert PREVIOUS_FACTS_META_KEY == f"{PREVIOUS_NAME}/tool_facts"
    facts = {"category": "strings", "read_only": True}
    old = {"name": "t", "_meta": {PREVIOUS_FACTS_META_KEY: facts}}
    new = {"name": "t", "_meta": {FACTS_META_KEY: facts}}
    assert served_facts_of(old) is not None
    assert served_facts_of(old) == served_facts_of(new)
    assert _declares_itself(old) and _declares_itself(new)
    assert not _declares_itself({"name": "t", "_meta": {}})


def test_the_current_meta_key_wins_over_the_previous_one() -> None:
    from malspark.tools.declared_facts import (
        FACTS_META_KEY,
        PREVIOUS_FACTS_META_KEY,
        facts_in_meta,
    )

    meta = {FACTS_META_KEY: {"category": "a"}, PREVIOUS_FACTS_META_KEY: {"category": "b"}}
    assert facts_in_meta(meta) == {"category": "a"}
    assert facts_in_meta({PREVIOUS_FACTS_META_KEY: {"category": "b"}}) == {"category": "b"}
    assert facts_in_meta(None) is None


# ---- a stored server map's environment names --------------------------------

MIGRATION = (
    ROOT / "apps/api/alembic/versions/20261107000000_server_env_names_take_the_new_prefix.py"
)
EARLIER = ROOT / "apps/api/alembic/versions/20260915000000_drop_judgement_layer_settings.py"


def _module(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _connect() -> Any:
    import sqlalchemy as sa

    conn = sa.create_engine("sqlite://").connect()
    conn.execute(
        sa.text(
            "CREATE TABLE runtime_settings ("
            "key TEXT PRIMARY KEY, value TEXT, is_secret BOOLEAN NOT NULL DEFAULT 0)"
        )
    )
    return conn


def _insert(conn: Any, key: str, value: Any, secret: bool = False) -> None:
    import sqlalchemy as sa

    conn.execute(
        sa.text("INSERT INTO runtime_settings (key, value, is_secret) VALUES (:k, :v, :s)"),
        {"k": key, "v": json.dumps(value), "s": secret},
    )


def _rows(conn: Any) -> dict[str, Any]:
    import sqlalchemy as sa

    result = conn.execute(sa.text("SELECT key, value FROM runtime_settings")).fetchall()
    return {k: json.loads(v) for k, v in result}


def _run(mod: Any, conn: Any, direction: str = "upgrade") -> None:
    from alembic.operations import Operations
    from alembic.runtime.migration import MigrationContext

    with Operations.context(MigrationContext.configure(conn)):
        getattr(mod, direction)()


STORED_MAP = {
    "analysis": {
        "env": {f"{OLD_ENV}SIGMA_RULES_DIR": "/rules/sigma", "OTHER": "x"},
        "env_allow": [f"{OLD_ENV}STAGING_DIR", f"{NEW_ENV}STAGING_DIR", "PATH"],
    },
    "mine": {
        "env": {f"{OLD_ENV}YARA_RULES_DIR": "/old", f"{NEW_ENV}YARA_RULES_DIR": "/new"},
    },
    "plain": {"command": "x"},
}


def test_the_revision_renames_every_block_s_environment_names(caplog: Any) -> None:
    mod = _module(MIGRATION)
    assert mod.PREVIOUS_PREFIX == OLD_ENV and mod.CURRENT_PREFIX == NEW_ENV
    conn = _connect()
    _insert(conn, "core.mcp.servers", STORED_MAP)
    _insert(conn, "core.mcp.servers.analysis.env", "ciphertext-not-json-safe", secret=True)
    with caplog.at_level(logging.INFO):
        _run(mod, conn)
    servers = _rows(conn)["core.mcp.servers"]
    assert servers["analysis"]["env"] == {f"{NEW_ENV}SIGMA_RULES_DIR": "/rules/sigma", "OTHER": "x"}
    assert servers["analysis"]["env_allow"] == [f"{NEW_ENV}STAGING_DIR", "PATH"]
    # A name the block already sets under the new prefix keeps its own value.
    assert servers["mine"]["env"] == {f"{NEW_ENV}YARA_RULES_DIR": "/new"}
    assert servers["plain"] == {"command": "x"}
    # The secret row is never read or written; values never reach the log.
    assert _rows(conn)["core.mcp.servers.analysis.env"] == "ciphertext-not-json-safe"
    assert "/rules/sigma" not in caplog.text and "/old" not in caplog.text
    before = _rows(conn)
    _run(mod, conn)
    assert _rows(conn) == before, "a second run writes nothing"


def test_the_revision_s_downgrade_restores_the_previous_prefix() -> None:
    mod = _module(MIGRATION)
    conn = _connect()
    _insert(conn, "core.mcp.servers", {"analysis": {"env": {f"{NEW_ENV}SIGMA_RULES_DIR": "/s"}}})
    _run(mod, conn, "downgrade")
    assert _rows(conn)["core.mcp.servers"] == {
        "analysis": {"env": {f"{OLD_ENV}SIGMA_RULES_DIR": "/s"}}
    }


@pytest.mark.parametrize("prefix", [OLD_ENV, NEW_ENV])
def test_the_earlier_revision_s_downgrade_reads_either_name(prefix: str) -> None:
    mod = _module(EARLIER)
    conn = _connect()
    _insert(conn, "core.mcp.servers", {"analysis": {"env": {f"{prefix}SIGMA_RULES_DIR": "/s"}}})
    _run(mod, conn, "downgrade")
    rows = _rows(conn)
    assert rows[mod.LEGACY_SIGMA_KEY] == "/s"
    assert rows["core.mcp.servers"]["analysis"]["env"] == {}


def test_an_encrypted_env_row_is_read_under_the_current_names() -> None:
    from app.services.server_map import merge_server_secrets

    merged = merge_server_secrets(
        {
            "core.mcp.servers": {"analysis": {"command": "x"}},
            "core.mcp.servers.analysis.env": json.dumps(
                {f"{OLD_ENV}SIGMA_RULES_DIR": "/s", f"{OLD_ENV}KEY": "a", f"{NEW_ENV}KEY": "b"}
            ),
        }
    )
    assert merged["core.mcp.servers"]["analysis"]["env"] == {
        f"{NEW_ENV}SIGMA_RULES_DIR": "/s",
        f"{NEW_ENV}KEY": "b",
    }


# ---- a stored bundle the run diff reads ------------------------------------


def test_the_run_diff_reads_a_draft_stored_before_the_rename_as_a_draft() -> None:
    from app.services.report_service import run_record
    from malspark.reporting.run_diff import _stix_is_draft

    report = SimpleNamespace(
        id="r1",
        job_id="j1",
        created_at=None,
        verdict="Malware",
        overall_confidence=0.9,
        malware_category="loader",
        malware_report={},
        run_summary={},
        stix_bundle={
            "type": "bundle",
            f"x_{PREVIOUS_NAME}_published": False,
            "objects": [{"type": "malware", f"x_{PREVIOUS_NAME}_evidence_refs": ["ev_0001"]}],
        },
        agent_findings=[],
        job=None,
    )
    record = run_record(report)  # type: ignore[arg-type]
    assert _stix_is_draft(record)
    assert record.stix_bundle is not None
    assert record.stix_bundle["objects"][0] == {
        "type": "malware",
        f"x_{CURRENT_NAME}_evidence_refs": ["ev_0001"],
    }


# ---- a plugin declared in a previous entry-point group ----------------------


def test_a_plugin_in_the_previous_group_is_found_and_named(monkeypatch: Any, caplog: Any) -> None:
    from malspark.core import plugins

    new_group = plugins.PLUGIN_GROUPS["memory"]
    old_group = f"{PREVIOUS_NAME}.{new_group.split('.', 1)[1]}"
    current = SimpleNamespace(name="now", value="pkg.now:Backend", dist=None)
    earlier = SimpleNamespace(
        name="old", value="pkg.old:Backend", dist=SimpleNamespace(name="old-plugin")
    )
    twin = SimpleNamespace(name="now", value="pkg.now:Backend", dist=None)
    groups = {new_group: [current], old_group: [earlier, twin]}
    monkeypatch.setattr(plugins, "entry_points", lambda group: groups.get(group, []))
    monkeypatch.setattr(plugins, "_WARNED_PREVIOUS_GROUP", set())
    with caplog.at_level(logging.WARNING):
        found = plugins._entry_points(new_group)
        plugins._entry_points(new_group)
    assert [p.name for p in found] == ["now", "old"]
    named = [r.getMessage() for r in caplog.records if "'old'" in r.getMessage()]
    assert len(named) == 1, "named once"
    assert "old-plugin" in named[0] and old_group in named[0] and new_group in named[0]


def test_a_sandbox_reader_in_the_previous_group_is_registered(monkeypatch: Any) -> None:
    import importlib.metadata

    from malspark.providers.sandbox import readers

    old_group = f"{PREVIOUS_NAME}.{readers.ENTRY_POINT_GROUP.split('.', 1)[1]}"
    loaded: list[Any] = []
    earlier = SimpleNamespace(name="old_reader", load=lambda: "READER")
    monkeypatch.setattr(
        importlib.metadata,
        "entry_points",
        lambda group: [earlier] if group == old_group else [],
    )
    monkeypatch.setattr(readers, "_ENTRY_POINTS_READ", [])
    monkeypatch.setattr(readers, "register_report_reader", loaded.append)
    readers._read_entry_points()
    assert loaded == ["READER"]


# ---- the staging base an earlier release used --------------------------------


def _analysis_server() -> Any:
    spec = importlib.util.spec_from_file_location(
        "analysis_mcp_server_previous_base", ROOT / "services" / "analysis-mcp" / "server.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _aged(path: Path, seconds_ago: float) -> None:
    when = time.time() - seconds_ago
    os.utime(path, (when, when))


def test_the_previous_default_base_is_swept_with_the_same_ttl(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from malspark.tools import staging

    server = _analysis_server()
    monkeypatch.setattr(server.tempfile, "gettempdir", lambda: str(tmp_path))
    assert staging.LEGACY_BASE_NAME == f"{PREVIOUS_NAME}-analysis-mcp"
    base = tmp_path / "current"
    base.mkdir()
    monkeypatch.setenv(staging.STAGING_DIR_ENV, str(base))
    monkeypatch.setenv(staging.STAGING_TTL_ENV, "1")
    legacy = tmp_path / staging.LEGACY_BASE_NAME
    job = staging.job_staging_dir(legacy, "old")
    job.mkdir(parents=True)
    stale = job / "aaaaaaaaaaaaaaaa_old.exe"
    stale.write_bytes(b"MZ-OLD")
    flat = legacy / "bbbbbbbbbbbbbbbb_flat.exe"
    flat.write_bytes(b"MZ-FLAT")
    fresh = legacy / "cccccccccccccccc_new.exe"
    fresh.write_bytes(b"MZ-NEW")
    for entry in (stale, job, flat):
        _aged(entry, 7200)

    removed = server._prune_staging(base)

    assert removed == 2
    assert not job.exists() and not flat.exists()
    assert fresh.exists() and legacy.is_dir(), "a file inside its TTL stays, and its base"
    _aged(fresh, 7200)
    server._prune_staging(base)
    assert not legacy.exists(), "the empty base goes"


# ---- a variable still set under the previous prefix ------------------------


def test_a_previous_prefix_variable_is_named_never_its_value(caplog: Any) -> None:
    from malspark.core.previous_name import warn_previous_environment

    environ = {f"{OLD_ENV}TOKEN": "secret-value", f"{OLD_ENV}UID": "1", "PATH": "/bin"}
    log = logging.getLogger("t576-test")
    with caplog.at_level(logging.WARNING, logger="t576-test"):
        names = warn_previous_environment(log, environ)
    assert names == [f"{OLD_ENV}TOKEN", f"{OLD_ENV}UID"]
    assert f"{OLD_ENV}TOKEN" in caplog.text and f"{OLD_ENV}UID" in caplog.text
    assert "secret-value" not in caplog.text
    caplog.clear()
    assert warn_previous_environment(log, {"PATH": "/bin"}) == []
    assert caplog.text == ""


@pytest.mark.parametrize(
    "path",
    [
        "apps/api/app/main.py",
        "apps/api/app/worker/analysis_worker.py",
        "services/analysis-mcp/server.py",
        "services/network-mcp/server.py",
        "services/knowledge-mcp/server.py",
        "services/threatintel-mcp/server.py",
    ],
)
def test_every_process_that_imports_the_platform_warns_at_start(path: str) -> None:
    assert "warn_previous_environment(" in (ROOT / path).read_text(encoding="utf-8")


# ---- an encrypted env row shown and sent back under the current names -------


def test_an_encrypted_env_row_round_trips_through_the_editor(monkeypatch: Any) -> None:
    from app.services import settings_service
    from app.services.server_map import TOKEN_MASK, _keep_masked_env

    row = SimpleNamespace(value="sealed")
    stored_env = {f"{OLD_ENV}SIGMA_RULES_DIR": "/rules", "API_KEY": "k"}
    monkeypatch.setattr(settings_service.box, "decrypt", lambda _v: json.dumps(stored_env))
    shown = settings_service._with_env_names(
        {"analysis": {"command": "x"}}, {"core.mcp.servers.analysis.env": row}
    )
    assert shown["analysis"]["env"] == {f"{NEW_ENV}SIGMA_RULES_DIR": "/rules", "API_KEY": "k"}

    sent_back = {"analysis": {"command": "x", "env": {f"{NEW_ENV}SIGMA_RULES_DIR": TOKEN_MASK}}}
    kept = _keep_masked_env(sent_back, {"analysis": {"command": "x", "env": stored_env}})
    assert kept["analysis"]["env"] == {f"{NEW_ENV}SIGMA_RULES_DIR": "/rules"}, "never dropped"


# ---- the MinIO bucket a deployment held before the rename -------------------


class _Store:
    def __init__(self, buckets: set[str]) -> None:
        self.buckets = set(buckets)
        self.made: list[str] = []

    def bucket_exists(self, name: str) -> bool:
        return name in self.buckets

    def make_bucket(self, name: str) -> None:
        self.made.append(name)
        self.buckets.add(name)


@pytest.fixture
def unsettled(monkeypatch: Any) -> Any:
    from app.services import object_store

    monkeypatch.setattr(object_store, "_SETTLED", {})
    return object_store


def _settings_from_env(monkeypatch: Any, value: str | None) -> Any:
    """The API's settings built as a process started with ``MINIO_BUCKET=value`` builds them
    (``None``: unset), and handed to every reader of ``app.config``."""
    import app.config

    if value is None:
        monkeypatch.delenv("MINIO_BUCKET", raising=False)
    else:
        monkeypatch.setenv("MINIO_BUCKET", value)
    built = app.config.APISettings()
    monkeypatch.setattr(app.config, "get_settings", lambda: built)
    return built


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty-as-compose-passes-it"])
def test_an_unconfigured_bucket_uses_the_previous_one_and_creates_no_twin(
    unsettled: Any, monkeypatch: Any, caplog: Any, value: str | None
) -> None:
    built = _settings_from_env(monkeypatch, value)
    assert "minio_bucket" not in built.model_fields_set
    assert built.minio_bucket == f"{CURRENT_NAME}-samples"
    previous = f"{PREVIOUS_NAME}-samples"
    assert unsettled.PREVIOUS_BUCKET == previous
    store = _Store({previous})
    with caplog.at_level(logging.WARNING):
        assert unsettled.bucket(store) == previous
        unsettled.ensure_bucket(store)
        unsettled.bucket(store)
    assert store.made == [], "no empty bucket beside the old one"
    named = [r.getMessage() for r in caplog.records if "MINIO_BUCKET" in r.getMessage()]
    assert len(named) == 1 and previous in named[0]


def test_compose_passes_the_bucket_empty_when_it_is_unset() -> None:
    compose = (ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("MINIO_BUCKET: ${MINIO_BUCKET:-}") == 3
    assert "MINIO_BUCKET: ${MINIO_BUCKET:-malspark" not in compose


def test_a_fresh_deployment_creates_the_default_bucket(unsettled: Any, monkeypatch: Any) -> None:
    _settings_from_env(monkeypatch, "")
    store = _Store(set())
    unsettled.ensure_bucket(store)
    assert store.made == [f"{CURRENT_NAME}-samples"]


def test_a_store_that_cannot_answer_settles_nothing(unsettled: Any, monkeypatch: Any) -> None:
    _settings_from_env(monkeypatch, None)

    class _Down:
        def bucket_exists(self, name: str) -> bool:
            raise OSError("down")

    assert unsettled.bucket(_Down()) == f"{CURRENT_NAME}-samples"
    assert unsettled._SETTLED == {}


@pytest.mark.parametrize("value", ["mine", f"{CURRENT_NAME}-samples"])
def test_a_configured_bucket_is_used_as_configured(
    unsettled: Any, monkeypatch: Any, value: str
) -> None:
    """Named explicitly, even as the default name, it is the operator's: no fallback."""
    built = _settings_from_env(monkeypatch, value)
    assert "minio_bucket" in built.model_fields_set
    store = _Store({f"{PREVIOUS_NAME}-samples"})
    unsettled.ensure_bucket(store)
    assert store.made == [value]


# ---- the upgrade script, against a stub docker ------------------------------


SCRIPT = ROOT / "scripts" / "upgrade" / "rename-volumes-and-env.sh"
STUB_DOCKER = """#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
case "$1 $2" in
  "volume ls") printf '%s_minio_data\\nother\\n' "$OLD" ;;
  "volume inspect") exit 1 ;;
  "ps -q") : ;;
esac
exit 0
"""


def _script(tmp_path: Path, env_text: str, *args: str) -> tuple[str, str, str]:
    import subprocess

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(STUB_DOCKER, encoding="utf-8")
    docker.chmod(0o755)
    env_file = tmp_path / "env"
    if not env_file.exists():
        env_file.write_text(env_text, encoding="utf-8")
    log = tmp_path / "log"
    done = subprocess.run(
        ["bash", str(SCRIPT), "--env-file", str(env_file), *args],
        capture_output=True,
        text=True,
        check=True,
        env={
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "STUB_LOG": str(log),
            "OLD": PREVIOUS_NAME,
        },
        timeout=60,
    )
    return done.stdout, env_file.read_text(encoding="utf-8"), log.read_text(encoding="utf-8")


@pytest.mark.parametrize("ending", ["\n", ""])
def test_the_script_pins_the_old_bucket_on_its_own_line(tmp_path: Path, ending: str) -> None:
    out, env, log = _script(tmp_path, f"{OLD_ENV}UID=1{ending}", "--apply")
    previous = f"{PREVIOUS_NAME}-samples"
    assert f"test -d /data/{previous}" in log, "the copied MinIO data is checked for the bucket"
    assert env.splitlines() == [f"{NEW_ENV}UID=1", f"MINIO_BUCKET={previous}"]
    assert "set MINIO_BUCKET" in out


def test_the_script_s_plan_writes_nothing(tmp_path: Path) -> None:
    out, env, _log = _script(tmp_path, f"{OLD_ENV}UID=1\n")
    assert env == f"{OLD_ENV}UID=1\n"
    assert "set MINIO_BUCKET" in out


def test_the_script_keeps_a_set_bucket_and_never_overwrites_a_backup(tmp_path: Path) -> None:
    (tmp_path / "env.before-malspark").write_text("EARLIER\n", encoding="utf-8")
    out, env, _log = _script(tmp_path, f"{OLD_ENV}UID=1\nMINIO_BUCKET=mine\n", "--apply")
    assert "MINIO_BUCKET=mine" in env.splitlines()
    assert env.count("MINIO_BUCKET=") == 1
    assert (tmp_path / "env.before-malspark").read_text(encoding="utf-8") == "EARLIER\n"
    backups = sorted(p.name for p in tmp_path.glob("env.before-malspark.*"))
    assert len(backups) == 1
    assert "keep MINIO_BUCKET" in out


def test_the_script_without_an_env_file_still_runs_with_a_qdrant_url(tmp_path: Path) -> None:
    import subprocess

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "curl").write_text("#!/bin/sh\ncat >/dev/null\necho '{}'\n", encoding="utf-8")
    (bin_dir / "curl").chmod(0o755)
    done = subprocess.run(
        ["bash", str(SCRIPT), "--env-file", str(tmp_path / "absent"), "--qdrant-url", "http://q"],
        capture_output=True,
        text=True,
        env={"PATH": f"{bin_dir}:/usr/bin:/bin"},
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    assert "Qdrant:" in done.stdout and "MinIO:" in done.stdout


def test_a_mask_sent_back_under_the_previous_name_keeps_the_stored_value() -> None:
    from app.services.server_map import TOKEN_MASK, _keep_masked_env

    stored = {"analysis": {"env": {f"{OLD_ENV}X": "secret1", f"{OLD_ENV}Y": "secret2"}}}
    sent = {"analysis": {"env": {f"{OLD_ENV}X": TOKEN_MASK, f"{NEW_ENV}Y": TOKEN_MASK}}}
    kept = _keep_masked_env(sent, stored)
    assert kept["analysis"]["env"] == {f"{NEW_ENV}X": "secret1", f"{NEW_ENV}Y": "secret2"}
    both = {"analysis": {"env": {f"{OLD_ENV}X": "old", f"{NEW_ENV}X": TOKEN_MASK}}}
    assert _keep_masked_env(both, stored)["analysis"]["env"] == {f"{NEW_ENV}X": "secret1"}
