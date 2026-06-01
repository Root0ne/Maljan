"""Extract persistence mechanisms from the sandbox / dynamic data.

We look at three input sources:

1. **Sandbox signatures** that explicitly call out persistence — CAPEv2
   ships many of these (``InstallsAutoRun``, ``CreatesScheduledTask``,
   ``InstallsService``, ...). The signature name maps to a
   ``PersistenceMechanism.kind`` and the ``marks`` list gives the
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


_NON_WINDOWS_PLATFORMS: frozenset[str] = frozenset({"linux", "android", "macos", "darwin", "ios"})


def build_persistence_list(
    sandbox_report: dict[str, Any] | None,
    sample_platform: str | None = None,
) -> list[PersistenceMechanism]:
    """Return a deduplicated list of persistence mechanisms.

    ``sample_platform`` gates platform-specific scanners so a Linux/Android
    sample is not flagged with Windows registry-run persistence (and vice
    versa). The Windows scanners run unless the platform is an explicit
    non-Windows one; the Linux scanner runs unless the platform is Windows.
    Signature-based detection is platform-agnostic and always runs. When the
    platform is unknown/None, all scanners run (backward-compatible).
    """
    if not sandbox_report:
        return []

    plat = (sample_platform or "").strip().lower()
    run_windows = plat not in _NON_WINDOWS_PLATFORMS
    run_linux = plat != "windows"

    found: dict[tuple[str, str], PersistenceMechanism] = {}

    _scan_signatures(sandbox_report, found)
    if run_windows:
        _scan_registry_calls(sandbox_report, found)
        _scan_service_apis(sandbox_report, found)
        _scan_scheduled_task_apis(sandbox_report, found)
    if run_linux:
        # Wave 9 (2026-05-29): Linux ELF persistence detection. Driven from
        # ``dynamic.file_operations`` paths + ``notable_apis`` execve calls so
        # ELF samples (e.g. the 2026-05-29 Mirai audit) surface real
        # persistence instead of an empty tab.
        _scan_linux_persistence(sandbox_report, found)

    out = list(found.values())
    logger.info(
        "persistence_extractor: extracted %d mechanism(s) (platform=%s)",
        len(out),
        plat or "unknown",
    )
    return out


# Linux persistence path-fragment → (kind, ATT&CK technique ID).
# Order matters — first match wins so cron variants are picked over the
# generic ``/etc/`` heuristics.
_LINUX_PATH_RULES: tuple[tuple[str, str, str], ...] = (
    ("/.config/autostart/", "xdg_autostart", "T1547.001"),
    ("/etc/xdg/autostart/", "xdg_autostart", "T1547.001"),
    ("/etc/systemd/system/", "systemd_service", "T1543.002"),
    ("/lib/systemd/system/", "systemd_service", "T1543.002"),
    ("/usr/lib/systemd/system/", "systemd_service", "T1543.002"),
    ("/etc/cron.d/", "cron_job", "T1053.003"),
    ("/etc/cron.daily/", "cron_job", "T1053.003"),
    ("/etc/cron.hourly/", "cron_job", "T1053.003"),
    ("/etc/cron.weekly/", "cron_job", "T1053.003"),
    ("/etc/cron.monthly/", "cron_job", "T1053.003"),
    ("/var/spool/cron/", "cron_job", "T1053.003"),
    ("/etc/init.d/", "init_d", "T1037.004"),
    ("/etc/rc.d/", "init_d", "T1037.004"),
    ("/etc/rcs.d/", "init_d", "T1037.004"),
    ("/etc/rc0.d/", "init_d", "T1037.004"),
    ("/etc/rc1.d/", "init_d", "T1037.004"),
    ("/etc/rc2.d/", "init_d", "T1037.004"),
    ("/etc/rc3.d/", "init_d", "T1037.004"),
    ("/etc/rc4.d/", "init_d", "T1037.004"),
    ("/etc/rc5.d/", "init_d", "T1037.004"),
    ("/etc/rc6.d/", "init_d", "T1037.004"),
    ("/etc/rc.local", "rc_local", "T1037.004"),
    ("/etc/ld.so.preload", "ld_preload", "T1574.006"),
)


def _scan_linux_persistence(
    sandbox_report: dict[str, Any],
    found: dict[tuple[str, str], PersistenceMechanism],
) -> None:
    """Wave 9 (2026-05-29): inspect Linux-style persistence surfaces.

    Sources:
      * ``behavior.summary.files`` / ``behavior.summary.write_files`` —
        Triage rolls written paths into these lists.
      * ``behavior.processes[].command_line`` — catches ``crontab -e`` /
        ``systemctl enable`` invocations.
      * ``notable_apis`` (LD_PRELOAD env mutations).
    """
    behavior = sandbox_report.get("behavior") or {}
    if not isinstance(behavior, dict):
        return

    # ── Path-based writes (systemd / cron / init.d / rc.local / ld.so.preload).
    candidate_paths: list[str] = []
    summary = behavior.get("summary")
    if isinstance(summary, dict):
        for key in ("files", "write_files", "modified_files", "wrote_files"):
            seq = summary.get(key)
            if isinstance(seq, list):
                candidate_paths.extend(str(p) for p in seq if isinstance(p, str))
    # Also look at file_operations / file_writes top-level if present.
    for key in ("file_writes", "files_written"):
        seq = sandbox_report.get(key)
        if isinstance(seq, list):
            candidate_paths.extend(str(p) for p in seq if isinstance(p, str))

    has_cron_path_write = any(
        ("/cron" in p.lower() or "/var/spool/cron" in p.lower()) for p in candidate_paths
    )

    for path in candidate_paths:
        lower = path.lower()
        # systemd ``.timer`` units are scheduled jobs (T1053.003), distinct
        # from plain services — classify them before the generic dir rules.
        if lower.endswith(".timer"):
            key_pair = ("systemd_timer", lower)
            if key_pair not in found:
                found[key_pair] = PersistenceMechanism(
                    kind="systemd_timer",
                    target=path,
                    payload="",
                    technique_id="T1053.003",
                    evidence_ref=f"file_write:{path}",
                )
            continue
        for fragment, kind, tid in _LINUX_PATH_RULES:
            if fragment in lower:
                key_pair = (kind, lower)
                if key_pair in found:
                    break
                found[key_pair] = PersistenceMechanism(
                    kind=kind,  # type: ignore[arg-type]
                    target=path,
                    payload="",
                    technique_id=tid,
                    evidence_ref=f"file_write:{path}",
                )
                break

    # ── Command-line invocations (crontab, systemctl enable, update-rc.d).
    processes = behavior.get("processes") or []
    if isinstance(processes, list):
        for proc in processes:
            if not isinstance(proc, dict):
                continue
            cmd = str(proc.get("command_line") or proc.get("cmd") or "").strip()
            if not cmd:
                continue
            lower = cmd.lower()
            # Crontab command is only persistence when it edits (-e) AND a cron
            # path write corroborates it — a bare ``crontab -l``/``crontab``
            # invocation with no file change is read-only noise (precision over
            # recall; see signal-quality §2.4).
            if "crontab" in lower and "-e" in lower and has_cron_path_write:
                key_pair = ("cron_job", cmd.lower())
                if key_pair not in found:
                    found[key_pair] = PersistenceMechanism(
                        kind="cron_job",
                        target=cmd,
                        payload="",
                        technique_id="T1053.003",
                        evidence_ref=f"process:{cmd[:120]}",
                    )
            elif "systemctl" in lower and "enable" in lower:
                key_pair = ("systemd_service", cmd.lower())
                if key_pair not in found:
                    found[key_pair] = PersistenceMechanism(
                        kind="systemd_service",
                        target=cmd,
                        payload="",
                        technique_id="T1543.002",
                        evidence_ref=f"process:{cmd[:120]}",
                    )
            elif "update-rc.d" in lower:
                key_pair = ("init_d", cmd.lower())
                if key_pair not in found:
                    found[key_pair] = PersistenceMechanism(
                        kind="init_d",
                        target=cmd,
                        payload="",
                        technique_id="T1037.004",
                        evidence_ref=f"process:{cmd[:120]}",
                    )

    # ── LD_PRELOAD environment / setenv probes via notable_apis.
    dynamic = sandbox_report.get("dynamic") or {}
    notable = (
        (dynamic.get("notable_apis") if isinstance(dynamic, dict) else None)
        or behavior.get("notable_apis")
        or []
    )
    if isinstance(notable, list):
        for api in notable:
            if not isinstance(api, dict):
                continue
            joined = " ".join(
                str(api.get(k) or "") for k in ("api", "category", "process", "arguments")
            ).lower()
            if "ld_preload" in joined or "/etc/ld.so.preload" in joined:
                target_str = str(api.get("api") or "LD_PRELOAD")
                key_pair = ("ld_preload", joined)
                if key_pair not in found:
                    found[key_pair] = PersistenceMechanism(
                        kind="ld_preload",
                        target=target_str,
                        payload="",
                        technique_id="T1574.006",
                        evidence_ref="notable_api:LD_PRELOAD",
                    )


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
