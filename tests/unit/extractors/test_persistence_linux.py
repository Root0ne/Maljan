"""Wave 9 (2026-05-29) Linux persistence extractor tests.

The 2026-05-29 Mirai ELF audit found the PERSISTENCE tab empty even
though Mirai is well-known to drop systemd units and tamper with cron.
``build_persistence_list`` now scans Linux signals — these tests pin the
five kinds (systemd_service, cron_job, init_d, rc_local, ld_preload) to
specific path / command-line / API patterns so future regressions
surface immediately.
"""

from __future__ import annotations

import pytest

from maljan.extractors.persistence_extractor import build_persistence_list


def _sandbox_with_path(path: str) -> dict:
    return {
        "behavior": {
            "summary": {
                "files": [path],
            }
        }
    }


def _sandbox_with_process(cmd: str) -> dict:
    return {
        "behavior": {
            "processes": [{"command_line": cmd, "pid": 100, "ppid": 1, "name": "sh"}],
        }
    }


def _sandbox_with_notable_api(api: str, arguments: str = "") -> dict:
    return {
        "behavior": {
            "notable_apis": [{"api": api, "arguments": arguments}],
        }
    }


# ---------------------------------------------------------------------------
# systemd_service
# ---------------------------------------------------------------------------


class TestSystemdService:
    @pytest.mark.parametrize(
        "path",
        [
            "/etc/systemd/system/mirai.service",
            "/lib/systemd/system/foo.service",
            "/usr/lib/systemd/system/bar.service",
        ],
    )
    def test_systemd_write_path(self, path: str) -> None:
        out = build_persistence_list(_sandbox_with_path(path))
        kinds = [m.kind for m in out]
        assert "systemd_service" in kinds

    def test_systemctl_enable_command(self) -> None:
        out = build_persistence_list(_sandbox_with_process("systemctl enable mirai"))
        assert any(m.kind == "systemd_service" for m in out)


# ---------------------------------------------------------------------------
# cron_job
# ---------------------------------------------------------------------------


class TestCronJob:
    @pytest.mark.parametrize(
        "path",
        [
            "/etc/cron.d/mal",
            "/etc/cron.daily/mal",
            "/etc/cron.hourly/mal",
            "/var/spool/cron/root",
        ],
    )
    def test_cron_path(self, path: str) -> None:
        out = build_persistence_list(_sandbox_with_path(path))
        assert any(m.kind == "cron_job" for m in out)

    def test_crontab_edit_command_requires_corroboration(self) -> None:
        # Signal-quality §2.4: a bare ``crontab -e`` (interactive, no confirmed
        # write) is read-only-ish noise and must NOT be flagged on its own.
        out = build_persistence_list(_sandbox_with_process("crontab -e"))
        assert not any(m.kind == "cron_job" for m in out)

    def test_crontab_edit_command_with_cron_write_is_flagged(self) -> None:
        # When a cron-path write corroborates the ``crontab -e`` command, it is
        # genuine persistence.
        report = {
            "behavior": {
                "summary": {"files": ["/var/spool/cron/root"]},
                "processes": [{"command_line": "crontab -e", "pid": 100, "ppid": 1, "name": "sh"}],
            }
        }
        out = build_persistence_list(report)
        assert any(m.kind == "cron_job" for m in out)


# ---------------------------------------------------------------------------
# init_d
# ---------------------------------------------------------------------------


class TestXdgAndTimer:
    def test_xdg_autostart_path(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/home/u/.config/autostart/mal.desktop"))
        assert any(m.kind == "xdg_autostart" for m in out)

    def test_etc_xdg_autostart_path(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/xdg/autostart/mal.desktop"))
        assert any(m.kind == "xdg_autostart" for m in out)

    def test_systemd_timer_classified_separately(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/systemd/system/mal.timer"))
        kinds = [m.kind for m in out]
        assert "systemd_timer" in kinds
        assert "systemd_service" not in kinds


class TestInitD:
    def test_init_d_path(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/init.d/mirai"))
        assert any(m.kind == "init_d" for m in out)

    def test_rc_d_path(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/rc3.d/S99mirai"))
        assert any(m.kind == "init_d" for m in out)

    def test_update_rc_d_command(self) -> None:
        out = build_persistence_list(_sandbox_with_process("update-rc.d mirai defaults"))
        assert any(m.kind == "init_d" for m in out)


# ---------------------------------------------------------------------------
# rc_local
# ---------------------------------------------------------------------------


class TestRcLocal:
    def test_rc_local_write(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/rc.local"))
        assert any(m.kind == "rc_local" for m in out)


# ---------------------------------------------------------------------------
# ld_preload
# ---------------------------------------------------------------------------


class TestLdPreload:
    def test_ld_so_preload_write(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/ld.so.preload"))
        assert any(m.kind == "ld_preload" for m in out)

    def test_ld_preload_env_via_notable_api(self) -> None:
        sandbox = _sandbox_with_notable_api("setenv", arguments="LD_PRELOAD=/tmp/m.so")
        out = build_persistence_list(sandbox)
        assert any(m.kind == "ld_preload" for m in out)


# ---------------------------------------------------------------------------
# Deduplication + technique IDs
# ---------------------------------------------------------------------------


class TestLinuxTechniqueIDs:
    def test_systemd_technique_id(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/systemd/system/m.service"))
        sys_items = [m for m in out if m.kind == "systemd_service"]
        assert sys_items and sys_items[0].technique_id == "T1543.002"

    def test_cron_technique_id(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/cron.d/m"))
        cron_items = [m for m in out if m.kind == "cron_job"]
        assert cron_items and cron_items[0].technique_id == "T1053.003"

    def test_ld_preload_technique_id(self) -> None:
        out = build_persistence_list(_sandbox_with_path("/etc/ld.so.preload"))
        items = [m for m in out if m.kind == "ld_preload"]
        assert items and items[0].technique_id == "T1574.006"
