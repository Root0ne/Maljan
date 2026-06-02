"""Windows persistence extraction + platform gating (signal-quality §2.4).

The persistence extractor previously ran Windows registry/service/scheduled-task
scanners on every sample regardless of platform, flagging a Linux/Android ELF
with spurious registry-run persistence. ``build_persistence_list`` now gates the
Windows scanners on ``sample_platform``.
"""

from __future__ import annotations

from maljan.extractors.persistence_extractor import build_persistence_list


def _windows_registry_run_report() -> dict:
    return {
        "behavior": {
            "calls": [
                {
                    "api": "RegSetValueExA",
                    "arguments": [
                        {
                            "FullName": ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
                            "Buffer": "C:\\Users\\x\\evil.exe",
                        }
                    ],
                }
            ]
        }
    }


def test_registry_run_detected_on_windows() -> None:
    out = build_persistence_list(_windows_registry_run_report(), sample_platform="windows")
    assert any(m.kind == "registry_run" for m in out)


def test_registry_run_detected_when_platform_unknown() -> None:
    # Backward-compatible: unknown/None platform runs all scanners.
    out = build_persistence_list(_windows_registry_run_report(), sample_platform=None)
    assert any(m.kind == "registry_run" for m in out)


def test_registry_run_suppressed_on_linux() -> None:
    out = build_persistence_list(_windows_registry_run_report(), sample_platform="linux")
    assert not any(m.kind == "registry_run" for m in out)


def test_linux_path_suppressed_on_windows() -> None:
    # Symmetric gate: Linux persistence scanner skipped on a Windows sample.
    report = {"behavior": {"summary": {"files": ["/etc/systemd/system/mal.service"]}}}
    out = build_persistence_list(report, sample_platform="windows")
    assert out == []
