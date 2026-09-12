"""What a non-Windows guest reports had nowhere to land.

``SandboxReport.registry`` is the one platform-specific channel this project
grew, and it is Windows'. A Linux package's strace, an Android package's
permissions and receivers, a macOS launchd job: every one of them was parsed
away. ``channels`` keeps them, namespaced by platform so two sandboxes cannot
collide on a bare word.
"""

from __future__ import annotations

from typing import Any

from maljan.core.config import RestMappingConfig
from maljan.providers.cape_view import to_cape_shaped_dict
from maljan.providers.sandbox.rest_mapping import apply_mapping, compile_mapping
from maljan.schemas.sandbox_report import SandboxReport, cape_report_to_sandbox_report


def _cape(**blocks: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "info": {"id": 1},
        "target": {"file": {"sha256": "a" * 64, "name": "sample"}},
        "behavior": {"processes": [], "summary": {}},
    }
    base.update(blocks)
    return base


class TestCapeChannels:
    def test_a_linux_package_keeps_its_syscall_stream(self) -> None:
        report = cape_report_to_sandbox_report(
            _cape(strace=[{"syscall": "execve", "args": "/bin/sh"}]),
            provider="cape2",
            source_format="cape2",
        )
        assert report.channels["linux.strace"] == [{"syscall": "execve", "args": "/bin/sh"}]

    def test_an_android_package_keeps_its_permissions(self) -> None:
        raw = _cape()
        raw["behavior"]["permissions"] = ["android.permission.SEND_SMS"]
        report = cape_report_to_sandbox_report(raw, provider="cape2", source_format="cape2")
        assert report.channels["android.permissions"] == [{"value": "android.permission.SEND_SMS"}]

    def test_a_windows_report_grows_no_channels(self) -> None:
        report = cape_report_to_sandbox_report(_cape(), provider="cape2", source_format="cape2")
        assert report.channels == {}

    def test_a_sandbox_that_namespaced_its_own_channels_is_taken_as_it_is(self) -> None:
        report = cape_report_to_sandbox_report(
            _cape(channels={"macos.launchd": [{"label": "com.evil.agent"}]}),
            provider="cape2",
            source_format="cape2",
        )
        assert report.channels["macos.launchd"] == [{"label": "com.evil.agent"}]

    def test_the_shared_process_list_is_not_duplicated_into_a_channel(self) -> None:
        raw = _cape()
        raw["behavior"]["processes"] = [{"pid": 1, "process_name": "sh"}]
        report = cape_report_to_sandbox_report(raw, provider="cape2", source_format="cape2")
        assert report.processes
        assert "linux.processes" not in report.channels

    def test_raw_and_the_ignored_extras_survive(self) -> None:
        raw = _cape(strace=[{"syscall": "open"}], something_new={"x": 1})
        report = cape_report_to_sandbox_report(raw, provider="cape2", source_format="cape2")
        assert report.raw is raw
        assert report.channels["linux.strace"]


class TestTheCapeView:
    def test_channels_ride_through_the_rendered_view(self) -> None:
        report = SandboxReport(
            provider="rest",
            source_format="generic",
            channels={"android.receivers": [{"name": "BootReceiver"}]},
        )
        assert to_cape_shaped_dict(report)["channels"] == {
            "android.receivers": [{"name": "BootReceiver"}]
        }

    def test_a_report_with_no_channels_grows_no_key(self) -> None:
        report = SandboxReport(provider="rest", source_format="generic")
        assert "channels" not in to_cape_shaped_dict(report)


class TestTheRestDsl:
    def _mapped(self, payload: dict[str, Any], channels: dict[str, str]) -> SandboxReport:
        mapping = RestMappingConfig(target_sha256="", channels=channels)
        return apply_mapping(compile_mapping(mapping), payload, provider="rest", task_id="1").report

    def test_an_operator_named_channel_lands_under_its_name(self) -> None:
        report = self._mapped(
            {"apk": {"permissions": [{"name": "SEND_SMS"}, {"name": "READ_SMS"}]}},
            {"android.permissions": "$.apk.permissions[*]"},
        )
        assert report.channels == {
            "android.permissions": [{"name": "SEND_SMS"}, {"name": "READ_SMS"}]
        }

    def test_bare_values_are_wrapped_so_every_row_is_a_mapping(self) -> None:
        report = self._mapped(
            {"units": ["evil.service", "evil.timer"]},
            {"linux.systemd": "$.units[*]"},
        )
        assert report.channels == {
            "linux.systemd": [{"value": "evil.service"}, {"value": "evil.timer"}]
        }

    def test_a_path_that_selects_nothing_leaves_no_channel(self) -> None:
        report = self._mapped({"apk": {}}, {"android.permissions": "$.apk.permissions[*]"})
        assert report.channels == {}

    def test_the_selection_is_reported_in_the_stats(self) -> None:
        mapping = RestMappingConfig(target_sha256="", channels={"macos.launchd": "$.jobs[*]"})
        result = apply_mapping(
            compile_mapping(mapping),
            {"jobs": [{"label": "com.evil.agent"}]},
            provider="rest",
            task_id="1",
        )
        stats = result.stats["channels.macos.launchd"]
        assert (stats.matched, stats.kept, stats.dropped) == (1, 1, 0)

    def test_a_channel_round_trips_out_through_the_cape_view(self) -> None:
        report = self._mapped(
            {"apk": {"permissions": [{"name": "SEND_SMS"}]}},
            {"android.permissions": "$.apk.permissions[*]"},
        )
        assert to_cape_shaped_dict(report)["channels"]["android.permissions"] == [
            {"name": "SEND_SMS"}
        ]
