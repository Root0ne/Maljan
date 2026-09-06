"""Extract the DynamicBehavior section from a normalised sandbox report.

The CAPEv2 sandbox report exposes ``behavior.processes`` (with ``pid``,
``ppid``, ``command_line``, ``calls``), ``behavior.apistats``
(``{proc_name: {api: count}}``), ``signatures`` (with optional ``marks``)
and ``network`` blocks. This module re-shapes that data into typed report
objects.

Failure mode: every accessor uses ``.get(...)`` with safe defaults so a
malformed sandbox report cannot crash the pipeline. Missing data means
an empty list / ``None``, never an exception.
"""

from __future__ import annotations

from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import (
    DynamicBehavior,
    ProcessNode,
    RegistryMod,
    SandboxSignature,
)

# Categories surfaced by ``MalwareReport.dynamic.notable_apis``.
_NOTABLE_APIS: dict[str, str] = {
    "RegSetValueExA": "registry_write",
    "RegSetValueExW": "registry_write",
    "RegCreateKeyExA": "registry_write",
    "RegCreateKeyExW": "registry_write",
    "CreateRemoteThread": "process_injection",
    "NtCreateThreadEx": "process_injection",
    "WriteProcessMemory": "process_injection",
    "VirtualAllocEx": "process_injection",
    "HttpSendRequestA": "network",
    "HttpSendRequestW": "network",
    "InternetOpenUrlA": "network",
    "InternetOpenUrlW": "network",
    "CryptAcquireContextA": "crypto",
    "BCryptEncrypt": "crypto",
    "CreateProcessA": "execution",
    "CreateProcessW": "execution",
    "ShellExecuteA": "execution",
    "ShellExecuteW": "execution",
    "WinExec": "execution",
    "LoadLibraryA": "library_load",
    "LoadLibraryW": "library_load",
    "GetProcAddress": "library_load",
    "AdjustTokenPrivileges": "privilege",
    "OpenProcessToken": "privilege",
    "SetFileAttributesA": "filesystem",
    "DeleteFileA": "filesystem",
    "WriteFile": "filesystem",
}


def build_dynamic_behavior(
    sandbox_report: dict[str, Any] | None,
) -> DynamicBehavior | None:
    """Return DynamicBehavior or None when no sandbox data is available."""
    if not sandbox_report:
        return None

    behavior = sandbox_report.get("behavior") or {}
    raw_procs = behavior.get("processes") if isinstance(behavior, dict) else None
    raw_apistats = behavior.get("apistats") if isinstance(behavior, dict) else None
    raw_calls = behavior.get("calls") if isinstance(behavior, dict) else None
    raw_sigs = sandbox_report.get("signatures") or []

    process_tree = _build_process_tree(raw_procs if isinstance(raw_procs, list) else [])
    registry_mods = _extract_registry_mods(raw_calls if isinstance(raw_calls, list) else [])
    file_ops = _extract_file_operations(raw_calls if isinstance(raw_calls, list) else [])
    notable = _extract_notable_apis(
        raw_apistats if isinstance(raw_apistats, dict) else {},
        raw_calls if isinstance(raw_calls, list) else [],
    )
    signatures = _extract_signatures(raw_sigs)

    if not (process_tree or registry_mods or file_ops or notable or signatures):
        return None

    raw_unavailable = sandbox_report.get("unavailable")
    unavailable = (
        [item for item in raw_unavailable if isinstance(item, str)]
        if isinstance(raw_unavailable, list)
        else []
    )

    logger.info(
        "dynamic_extractor: processes=%d registry=%d file_ops=%d apis=%d sigs=%d",
        len(process_tree),
        len(registry_mods),
        len(file_ops),
        len(notable),
        len(signatures),
    )
    return DynamicBehavior(
        process_tree=process_tree,
        registry_mods=registry_mods,
        file_operations=file_ops,
        notable_apis=notable,
        sandbox_signatures=signatures,
        unavailable=unavailable,
    )


# ---------------------------------------------------------------------------
# Process tree
# ---------------------------------------------------------------------------


# OS-normal processes that legitimately call the "injection" APIs
# (CreateRemoteThread / WriteProcessMemory / VirtualAllocEx). Matched on the
# basename so a real injector isn't drowned by benign system noise.
_BENIGN_INJECTORS: frozenset[str] = frozenset(
    {
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "conhost.exe",
        "explorer.exe",
        "searchindexer.exe",
        "taskhostw.exe",
        "dllhost.exe",
        "sihost.exe",
        "runtimebroker.exe",
        "ctfmon.exe",
    }
)

_MAX_TREE_DEPTH = 64


def _proc_basename(name: str) -> str:
    return name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def _would_cycle(child_pid: int, parent_pid: int, parent_of: dict[int, int]) -> bool:
    """True if making ``parent_pid`` the parent of ``child_pid`` forms a cycle."""
    seen: set[int] = set()
    cur: int | None = parent_pid
    while cur is not None and cur not in seen:
        if cur == child_pid:
            return True
        seen.add(cur)
        cur = parent_of.get(cur)
    return False


def _prune_depth(roots: list[ProcessNode], max_depth: int = _MAX_TREE_DEPTH) -> None:
    """Drop children beyond ``max_depth`` to bound renderer recursion (defensive)."""
    stack: list[tuple[ProcessNode, int]] = [(r, 1) for r in roots]
    while stack:
        node, depth = stack.pop()
        if depth >= max_depth:
            node.children = []
            continue
        for child in node.children:
            stack.append((child, depth + 1))


def _build_process_tree(processes: list[dict[str, Any]]) -> list[ProcessNode]:
    """Reconstruct parent→children relationships from a flat process list."""
    if not processes:
        return []

    nodes: dict[int, ProcessNode] = {}
    parent_of: dict[int, int] = {}
    for p in processes:
        try:
            pid = int(p.get("pid") or 0)
        except (TypeError, ValueError):
            pid = 0
        try:
            ppid = int(p.get("ppid") or 0)
        except (TypeError, ValueError):
            ppid = 0
        name = str(p.get("process_name") or p.get("name") or "")
        cmd = str(p.get("command_line") or p.get("cmd") or "")
        if pid == 0 or pid in nodes:
            # Skip pid 0 and keep the FIRST entry for a duplicate PID rather
            # than overwriting (which would lose its command line / calls).
            continue
        nodes[pid] = ProcessNode(pid=pid, ppid=ppid, name=name, command_line=cmd)
        if ppid:
            parent_of[pid] = ppid

    roots: list[ProcessNode] = []
    for pid, node in nodes.items():
        parent_pid = parent_of.get(pid)
        if (
            parent_pid
            and parent_pid in nodes
            and parent_pid != pid
            and not _would_cycle(pid, parent_pid, parent_of)
        ):
            nodes[parent_pid].children.append(node)
        else:
            roots.append(node)

    _prune_depth(roots)

    # Detect CreateRemoteThread / VirtualAllocEx targets as injection — but skip
    # OS-normal processes that legitimately use these APIs (FP reduction).
    for p in processes:
        if _proc_basename(str(p.get("process_name") or p.get("name") or "")) in _BENIGN_INJECTORS:
            continue
        for call in p.get("calls") or []:
            api = (call.get("api") or "").strip()
            if api in {"CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx"}:
                target = _extract_pid_from_args(call.get("arguments") or [])
                if target and target in nodes:
                    src_pid = int(p.get("pid") or 0)
                    if src_pid in nodes and target not in nodes[src_pid].injected_into:
                        nodes[src_pid].injected_into.append(target)

    return roots


def _extract_pid_from_args(args: Any) -> int | None:
    """Heuristic: look for a ``ProcessHandle`` / pid-like int in API arguments."""
    if not isinstance(args, list):
        return None
    for item in args:
        if isinstance(item, dict):
            for key in ("ProcessId", "TargetPid", "pid", "process_id"):
                if key in item:
                    try:
                        return int(item[key])
                    except (TypeError, ValueError):
                        continue
    return None


# ---------------------------------------------------------------------------
# Registry / file / API extraction
# ---------------------------------------------------------------------------


def _extract_registry_mods(calls: list[dict[str, Any]]) -> list[RegistryMod]:
    if not calls:
        return []
    mods: list[RegistryMod] = []
    seen: set[tuple[str, str, str]] = set()
    for call in calls:
        api = (call.get("api") or "").strip()
        if api not in {
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegDeleteKeyA",
            "RegDeleteKeyW",
            "RegDeleteValueA",
            "RegDeleteValueW",
            "RegQueryValueExA",
            "RegQueryValueExW",
        }:
            continue
        args = call.get("arguments") or []
        key_str = _arg_value(args, ("FullName", "Key", "lpSubKey", "key"))
        if not key_str:
            continue
        value_name = _arg_value(args, ("ValueName", "lpValueName", "name"))
        new_value = _arg_value(args, ("Buffer", "Value", "lpData", "data"))
        op = (
            "delete"
            if "Delete" in api
            else "query"
            if "Query" in api
            else "create"
            if "Create" in api
            else "modify"
        )
        # Read-only queries are not modifications — they are pure noise in a
        # "registry modifications" list (every tool constantly reads the
        # registry). Keep only create/modify/delete signal.
        if op == "query":
            continue
        hive = _classify_hive(key_str)
        dedup_key = (hive, key_str.lower(), op)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        mods.append(
            RegistryMod(
                hive=hive,  # type: ignore[arg-type]
                key=key_str,
                value_name=value_name,
                operation=op,  # type: ignore[arg-type]
                new_value=new_value,
            )
        )
    return mods


_HIVE_PREFIXES: dict[str, str] = {
    "HKLM": "HKLM",
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKCU": "HKCU",
    "HKEY_CURRENT_USER": "HKCU",
    "HKCR": "HKCR",
    "HKEY_CLASSES_ROOT": "HKCR",
    "HKU": "HKU",
    "HKEY_USERS": "HKU",
    "HKCC": "HKCC",
    "HKEY_CURRENT_CONFIG": "HKCC",
}


def _classify_hive(key: str) -> str:
    upper = key.upper().lstrip("\\")
    for prefix, mapped in _HIVE_PREFIXES.items():
        if upper.startswith(prefix):
            return mapped
    return "UNKNOWN"


def _arg_value(args: list[Any], names: tuple[str, ...]) -> str | None:
    for item in args:
        if not isinstance(item, dict):
            continue
        for name in names:
            if name in item and item[name] not in (None, ""):
                return str(item[name])
    return None


def _extract_file_operations(calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return a small dict per file op (path/op/api)."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    file_apis = {
        "CreateFileA": "create",
        "CreateFileW": "create",
        "WriteFile": "write",
        "DeleteFileA": "delete",
        "DeleteFileW": "delete",
        "MoveFileA": "move",
        "MoveFileW": "move",
        "MoveFileExA": "move",
        "MoveFileExW": "move",
        "CopyFileA": "copy",
        "CopyFileW": "copy",
        "SetFileAttributesA": "attribute",
        "SetFileAttributesW": "attribute",
    }
    for call in calls:
        api = (call.get("api") or "").strip()
        op = file_apis.get(api)
        if not op:
            continue
        args = call.get("arguments") or []
        path = _arg_value(args, ("FileName", "lpFileName", "path", "Path"))
        if not path:
            continue
        key = (path.lower(), op)
        if key in seen:
            continue
        seen.add(key)
        out.append({"path": path, "operation": op, "api": api})
        if len(out) >= 200:
            break
    return out


def _extract_notable_apis(
    apistats: dict[str, dict[str, int]],
    _calls: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return notable API call counts (suspicious ones), descending by count."""
    out: list[dict[str, Any]] = []
    for proc_name, api_map in apistats.items():
        if not isinstance(api_map, dict):
            continue
        for api_name, count in api_map.items():
            category = _NOTABLE_APIS.get(api_name)
            if not category:
                continue
            try:
                count_int = int(count)
            except (TypeError, ValueError):
                count_int = 0
            out.append(
                {
                    "api": api_name,
                    "category": category,
                    "process": proc_name,
                    "count": count_int,
                }
            )
    out.sort(key=lambda row: row.get("count", 0), reverse=True)
    return out[:50]


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


def _extract_signatures(raw: list[Any]) -> list[SandboxSignature]:
    out: list[SandboxSignature] = []
    if not isinstance(raw, list):
        return out
    for sig in raw:
        if not isinstance(sig, dict):
            continue
        name = str(sig.get("name") or "")
        if not name:
            continue
        try:
            severity = int(sig.get("severity") or sig.get("score") or 0)
        except (TypeError, ValueError):
            severity = 0
        marks_raw = sig.get("marks") or []
        marks: list[str] = []
        if isinstance(marks_raw, list):
            for m in marks_raw:
                if isinstance(m, dict):
                    marks.append(_stringify_mark(m))
                else:
                    marks.append(str(m))
        techniques_raw = sig.get("ttp_tags") or sig.get("attck_id") or []
        techniques: list[str] = []
        if isinstance(techniques_raw, list):
            techniques = [str(t) for t in techniques_raw if t]
        elif isinstance(techniques_raw, str):
            techniques = [techniques_raw]
        out.append(
            SandboxSignature(
                name=name,
                description=str(sig.get("description") or name),
                severity=severity,
                technique_ids=techniques,
                marks=marks[:10],
            )
        )
    out.sort(key=lambda s: s.severity, reverse=True)
    return out


def _stringify_mark(mark: dict[str, Any]) -> str:
    """Render a sandbox signature ``mark`` dict into a single-line string."""
    if "ioc" in mark:
        return f"ioc: {mark['ioc']}"
    if "call" in mark:
        call = mark["call"]
        if isinstance(call, dict):
            return f"call: {call.get('api', '?')}"
    if "type" in mark:
        return f"{mark['type']}: {mark.get('description') or mark.get('value') or ''}"
    return str(mark)
