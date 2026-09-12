"""A scanner runs for the platform it was written against, and no other.

The gate used to be negative: the Windows registry, service and scheduled-task
scanners ran unless the platform was literally "linux". Every other platform —
macOS, Android, iOS, a cross-platform JAR — therefore got the full Windows
sweep, and an Android sample could be reported with registry-run persistence it
has no registry to hold.
"""

from __future__ import annotations

import pytest

from maljan.extractors.persistence_extractor import build_persistence_list


def _windows_signals() -> dict:
    return {
        "behavior": {
            "calls": [
                {
                    "api": "RegSetValueExA",
                    "arguments": [
                        {
                            "FullName": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                            "Buffer": "C:\\Users\\x\\evil.exe",
                        }
                    ],
                }
            ]
        }
    }


def _linux_signals() -> dict:
    return {"behavior": {"summary": {"files": ["/etc/systemd/system/evil.service"]}}}


def _kinds(report: dict, platform: str | None) -> set[str]:
    return {m.kind for m in build_persistence_list(report, platform)}


class TestWindowsScanners:
    @pytest.mark.parametrize("platform", ["windows", "WINDOWS", " windows "])
    def test_they_run_for_a_windows_sample(self, platform: str) -> None:
        assert "registry_run" in _kinds(_windows_signals(), platform)

    @pytest.mark.parametrize("platform", [None, "", "unknown", "multi"])
    def test_they_run_when_the_platform_is_undetermined(self, platform: str | None) -> None:
        """``multi`` counts as undetermined: a macro document, a JAR or a Python
        script binds to no OS by format, but it was detonated on one, and those
        are among the commonest Windows carriers."""
        assert "registry_run" in _kinds(_windows_signals(), platform)

    @pytest.mark.parametrize("platform", ["linux", "macos", "android", "ios"])
    def test_they_do_not_run_for_a_platform_that_has_no_registry(self, platform: str) -> None:
        assert _kinds(_windows_signals(), platform) == set()


class TestLinuxScanner:
    def test_it_runs_for_a_linux_sample(self) -> None:
        assert "systemd_service" in _kinds(_linux_signals(), "linux")

    @pytest.mark.parametrize("platform", [None, "", "unknown", "multi"])
    def test_it_runs_when_the_platform_is_undetermined(self, platform: str | None) -> None:
        assert "systemd_service" in _kinds(_linux_signals(), platform)

    @pytest.mark.parametrize("platform", ["windows", "macos", "android", "ios"])
    def test_it_does_not_run_for_a_platform_without_systemd(self, platform: str) -> None:
        assert _kinds(_linux_signals(), platform) == set()


def test_signature_detection_is_platform_agnostic() -> None:
    """A sandbox signature names the behaviour itself; no scanner has to run."""
    report = {"signatures": [{"name": "autostart_registry", "description": "installs autorun"}]}
    for platform in ("windows", "linux", "macos", "android", None):
        assert _kinds(report, platform)
