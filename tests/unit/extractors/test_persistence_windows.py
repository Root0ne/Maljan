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


# ---------------------------------------------------------------------------
# COM hijacking (T1546.015)
# ---------------------------------------------------------------------------


def _com_hijack_report(subkey: str) -> dict:
    return {
        "behavior": {
            "calls": [
                {
                    "api": "RegSetValueExW",
                    "arguments": [
                        {
                            "FullName": (
                                "HKCU\\Software\\Classes\\CLSID\\"
                                "{ab8902b4-09ca-4bb6-b78d-a8f59079a8d5}" + subkey
                            ),
                            "Buffer": "C:\\Users\\x\\AppData\\Roaming\\evil.dll",
                        }
                    ],
                }
            ]
        }
    }


class TestCOMHijacking:
    def test_inprocserver32_detected_on_windows(self) -> None:
        out = build_persistence_list(
            _com_hijack_report("\\InprocServer32"), sample_platform="windows"
        )
        mechs = [m for m in out if m.kind == "com_hijacking"]
        assert len(mechs) == 1
        assert mechs[0].technique_id == "T1546.015"
        assert mechs[0].payload.endswith("evil.dll")

    def test_localserver32_and_treatas_detected(self) -> None:
        for subkey in ("\\LocalServer32", "\\TreatAs"):
            out = build_persistence_list(_com_hijack_report(subkey), sample_platform="windows")
            assert any(m.kind == "com_hijacking" for m in out), subkey

    def test_com_hijack_detected_when_platform_unknown(self) -> None:
        out = build_persistence_list(_com_hijack_report("\\InprocServer32"), sample_platform=None)
        assert any(m.kind == "com_hijacking" for m in out)

    def test_com_hijack_suppressed_on_linux(self) -> None:
        out = build_persistence_list(
            _com_hijack_report("\\InprocServer32"), sample_platform="linux"
        )
        assert not any(m.kind == "com_hijacking" for m in out)

    def test_non_clsid_registry_write_not_com_hijack(self) -> None:
        # A normal Run-key write must not be mislabelled as COM hijacking.
        out = build_persistence_list(_windows_registry_run_report(), sample_platform="windows")
        assert not any(m.kind == "com_hijacking" for m in out)
        assert any(m.kind == "registry_run" for m in out)
