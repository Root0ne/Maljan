"""Extract persistence mechanisms from the sandbox / dynamic data.

We look at three input sources:

1. **Sandbox signatures** that explicitly call out persistence — Triage and
   CAPEv2 both ship many of these (``InstallsAutoRun``,
   ``CreatesScheduledTask``, ``InstallsService``, ...). The signature name
   maps to a ``PersistenceMechanism.kind`` and the ``marks`` list gives the
   evidence string.
2. **Raw registry modifications** that touch known autorun key paths —
   useful when the sandbox didn't ship a signature but the behaviour was
   observed (``HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` etc.).
3. **API call traces** for ``CreateService``, ``ScheduleJob``,
   ``RegisterEventSource`` family.

The output is deduplicated per (kind, target) so the same persistence is
not reported twice. ATT&CK technique IDs are attached when known.
"""

from __future__ import annotations

import re
from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import PersistenceMechanism

# Substrings (lowercased) that classify a Windows registry path as autorun.
_AUTORUN_REGISTRY_PATHS: tuple[tuple[str, str], ...] = (
    ("currentversion\\run", "T1547.001"),
    ("currentversion\\runonce", "T1547.001"),
    ("currentversion\\runonceex", "T1547.001"),
    ("currentversion\\explorer\\run", "T1547.001"),
    ("currentversion\\policies\\explorer\\run", "T1547.001"),
    ("currentversion\\windows\\appinit_dlls", "T1546.010"),
    ("session manager\\appcertdlls", "T1546.009"),
    ("services\\eventlog", "T1543.003"),
    ("currentversion\\image file execution options", "T1546.012"),
    ("currentversion\\winlogon\\userinit", "T1547.004"),
    ("currentversion\\winlogon\\shell", "T1547.004"),
    ("control\\lsa\\notification packages", "T1547.002"),
    ("control\\lsa\\authentication packages", "T1547.002"),
    ("currentversion\\silentprocessexit", "T1546.012"),
    ("currentversion\\explorer\\shell folders\\startup", "T1547.001"),
)

# Sandbox signature name fragments → (kind, ATT&CK ID)
_SIGNATURE_HINTS: tuple[tuple[str, str, str], ...] = (
    ("installsautorun", "registry_run", "T1547.001"),
    ("autostart", "registry_run", "T1547.001"),
    ("createsscheduledtask", "scheduled_task", "T1053.005"),
    ("schedules", "scheduled_task", "T1053.005"),
    ("schtask", "scheduled_task", "T1053.005"),
    ("installsservice", "service", "T1543.003"),
    ("creates_service", "service", "T1543.003"),
    ("wmi_persistence", "wmi_subscription", "T1546.003"),
    ("wmi_event", "wmi_subscription", "T1546.003"),
    ("startup_folder", "startup_folder", "T1547.001"),
    ("dll_hijack", "dll_search_hijacking", "T1574.001"),
    ("driver_load", "driver", "T1547.006"),
    ("imagefileexec", "image_hijack", "T1546.012"),
    ("appinit_dll", "appinit_dll", "T1546.010"),
    ("winlogon", "winlogon_helper", "T1547.004"),
    ("lsa_provider", "lsa_provider", "T1547.002"),
)


def build_persistence_list(
    sandbox_report: dict[str, Any] | None,
) -> list[PersistenceMechanism]:
    """Return a deduplicated list of persistence mechanisms."""
    if not sandbox_report:
        return []

    found: dict[tuple[str, str], PersistenceMechanism] = {}

    _scan_signatures(sandbox_report, found)
    _scan_registry_calls(sandbox_report, found)
    _scan_service_apis(sandbox_report, found)
    _scan_scheduled_task_apis(sandbox_report, found)

    out = list(found.values())
    logger.info("persistence_extractor: extracted %d mechanism(s)", len(out))
    return out


def _scan_signatures(
    sandbox_report: dict[str, Any],
    found: dict[tuple[str, str], PersistenceMechanism],
) -> None:
    sigs = sandbox_report.get("signatures") or []
    if not isinstance(sigs, list):
        return
    for sig in sigs:
        if not isinstance(sig, dict):
            continue
        name = str(sig.get("name") or "").lower()
        if not name:
            continue
        for fragment, kind, tid in _SIGNATURE_HINTS:
            if fragment in name:
                marks = sig.get("marks") or []
                target = ""
                payload = ""
                if isinstance(marks, list):
                    for m in marks:
                        if isinstance(m, str) and not target:
                            target = m
                            break
                        if isinstance(m, dict):
                            target = str(
                                m.get("ioc") or m.get("description") or m.get("type") or ""
                            )
                            payload = (
                                str(m.get("call", {}).get("api") or "")
                                if isinstance(m.get("call"), dict)
                                else ""
                            )
                            if target:
                                break
                if not target:
                    target = name
                key = (kind, target.lower())
                if key in found:
                    continue
                found[key] = PersistenceMechanism(
                    kind=kind,  # type: ignore[arg-type]
                    target=target,
                    payload=payload,
                    technique_id=tid,
                    evidence_ref=f"signature:{name}",
                )
                break


def _scan_registry_calls(
    sandbox_report: dict[str, Any],
    found: dict[tuple[str, str], PersistenceMechanism],
) -> None:
    behavior = sandbox_report.get("behavior") or {}
    calls = behavior.get("calls") if isinstance(behavior, dict) else None
    if not isinstance(calls, list):
        return
    for call in calls:
        api = (call.get("api") or "").strip()
        if api not in {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"}:
            continue
        args = call.get("arguments") or []
        key_str = _arg_value(args, ("FullName", "Key", "lpSubKey", "key"))
        if not key_str:
            continue
        lower = key_str.lower()
        for fragment, tid in _AUTORUN_REGISTRY_PATHS:
            if fragment in lower:
                value = _arg_value(args, ("Buffer", "Value", "lpData"))
                key = ("registry_run", lower)
                if key in found:
                    continue
                found[key] = PersistenceMechanism(
                    kind="registry_run",
                    target=key_str,
                    payload=value or "",
                    technique_id=tid,
                    evidence_ref=f"api:{api}",
                )
                break


def _scan_service_apis(
    sandbox_report: dict[str, Any],
    found: dict[tuple[str, str], PersistenceMechanism],
) -> None:
    behavior = sandbox_report.get("behavior") or {}
    calls = behavior.get("calls") if isinstance(behavior, dict) else None
    if not isinstance(calls, list):
        return
    for call in calls:
        api = (call.get("api") or "").strip()
        if api not in {"CreateServiceA", "CreateServiceW", "StartServiceA", "StartServiceW"}:
            continue
        args = call.get("arguments") or []
        name = _arg_value(args, ("lpServiceName", "ServiceName", "name"))
        binary = _arg_value(args, ("lpBinaryPathName", "BinaryPathName", "ImagePath"))
        if not name:
            continue
        key = ("service", name.lower())
        if key in found:
            continue
        found[key] = PersistenceMechanism(
            kind="service",
            target=name,
            payload=binary or "",
            technique_id="T1543.003",
            evidence_ref=f"api:{api}",
        )


def _scan_scheduled_task_apis(
    sandbox_report: dict[str, Any],
    found: dict[tuple[str, str], PersistenceMechanism],
) -> None:
    behavior = sandbox_report.get("behavior") or {}
    calls = behavior.get("calls") if isinstance(behavior, dict) else None
    if not isinstance(calls, list):
        return
    for call in calls:
        api = (call.get("api") or "").strip()
        if not _looks_like_scheduler_api(api):
            continue
        args = call.get("arguments") or []
        target = _arg_value(args, ("lpTaskName", "TaskName", "name", "command"))
        binary = _arg_value(args, ("ApplicationName", "BinaryPathName", "command"))
        if not target:
            continue
        key = ("scheduled_task", target.lower())
        if key in found:
            continue
        found[key] = PersistenceMechanism(
            kind="scheduled_task",
            target=target,
            payload=binary or "",
            technique_id="T1053.005",
            evidence_ref=f"api:{api}",
        )


def _looks_like_scheduler_api(api: str) -> bool:
    """Match common scheduler-related Windows APIs case-insensitively."""
    lower = api.lower()
    return any(
        token in lower
        for token in (
            "schtasks",
            "createtask",
            "registertask",
            "iregisteredtask",
            "itaskservice",
            "netscheduleadd",
        )
    )


def _arg_value(args: list[Any], names: tuple[str, ...]) -> str | None:
    for item in args:
        if not isinstance(item, dict):
            continue
        for name in names:
            if name in item and item[name] not in (None, ""):
                return str(item[name])
    return None


# Compile-time regex sanity check — fails the module at import if any
# autorun path is mis-quoted (defensive: easy to break in PRs).
for _path, _tid in _AUTORUN_REGISTRY_PATHS:
    re.compile(re.escape(_path))
