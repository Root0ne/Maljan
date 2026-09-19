#!/usr/bin/env python3
"""Build the Windows API behaviour map and the API→ATT&CK map.

Offline, operator-run, never imported by the pipeline — the same contract as
``build_family_feature_kb.py`` and ``build_attck_case_kb.py``.

Why the curated lists live here rather than in the JSON: the JSON is the
artifact, this is the source. Keeping the vocabulary in reviewable Python means
a reader can see *why* ``NtUnmapViewOfSection`` is process-injection and
``RegOpenKeyExA`` is not suspicious, and a contributor can extend a list without
hand-editing a 600-entry JSON literal and getting the commas wrong.

**Provenance.** Every name below is a public Win32/NT API symbol and every
technique ID is from the public MITRE ATT&CK catalog. Nothing here is copied
from another tool's data files; the *architecture* (one resolved-import set
projected onto two taxonomies, behind a reverse index) is the idea worth
borrowing, the bytes are not.

Usage::

    uv run python scripts/knowledge/build_api_capability_db.py
    make prepare-api-db
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
_BEHAVIOUR_OUT = _ROOT / "data" / "api_behaviour_map_v1.json"
_ATTCK_OUT = _ROOT / "data" / "api_attck_map_v1.json"
_VALID_IDS = _ROOT / "data" / "attck_valid_ids.json"
_RETIRED_IDS = _ROOT / "data" / "attck_retired_ids.json"
_TECHNIQUES = _ROOT / "data" / "attck_techniques.json"

# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------
# ``high``/``medium`` set ImportRow.is_suspicious; ``informational`` does not.
#
# The split is the whole point of this file. Categorising RegOpenKeyExA is
# useful — it tells the prompt and the ATT&CK mapper what the binary touches.
# Calling it *suspicious* is not: every Windows program opens registry keys, and
# a "suspicious imports" table that lists all of them tells a reader nothing.
#
# Rule of thumb applied below: a category is high/medium when its presence in an
# import table is itself unusual for ordinary software, and informational when
# the API is ubiquitous and only the *pattern* of use carries signal.

HIGH = "high"
MEDIUM = "medium"
INFO = "informational"


# What a category needs beside it to mean something. A category that is
# informational on its own says nothing about a sample, and saying only that
# leaves the reader to guess what would change the answer; these names travel
# in the manifest as ``corroborated_by`` and ``api_capability`` puts them on
# the row. Only categories that need it are listed.
WINDOWS_CORROBORATORS: dict[str, list[str]] = {
    "screen_capture": [
        "AttachThreadInput",
        "GetAsyncKeyState",
        "GetClipboardData",
        "GetKeyboardState",
        "GetRawInputData",
        "GetRawInputDeviceList",
        "RegisterRawInputDevices",
        "SetWinEventHook",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
    ],
    "message_loop": [
        "AttachThreadInput",
        "GetAsyncKeyState",
        "GetClipboardData",
        "GetKeyboardState",
        "GetRawInputData",
        "GetRawInputDeviceList",
        "RegisterRawInputDevices",
        "SetWinEventHook",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
    ],
}


# ---------------------------------------------------------------------------
# Windows behaviour categories
# ---------------------------------------------------------------------------
# The eight existing category names are frozen and must not be renamed: they are
# consumed by capability_matrix.py, import_capability_layer.py, and — invisibly — by the vendored
# data/family_fingerprints_v1.json, whose description text embeds this exact
# vocabulary. A rename desynchronises the family-RAG query from its catalog
# inside one embedding space, with no exception and no test failure.

WINDOWS_CATEGORIES: dict[str, tuple[str, list[str]]] = {
    # ---------------------------------------------------------------- frozen 8
    "process_injection": (
        HIGH,
        [
            "VirtualAlloc",
            "VirtualAllocEx",
            "VirtualProtect",
            "VirtualProtectEx",
            "WriteProcessMemory",
            "ReadProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtQueueApcThread",
            "SetWindowsHookEx",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "NtMapViewOfSection",
            "ZwMapViewOfSection",
            "NtWriteVirtualMemory",
            "ZwWriteVirtualMemory",
            "NtReadVirtualMemory",
            "NtAllocateVirtualMemory",
            "ZwAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "OpenProcess",
            "OpenThread",
            "SuspendThread",
            "ResumeThread",
            "SetThreadContext",
            "GetThreadContext",
            "Wow64SetThreadContext",
            "Wow64GetThreadContext",
            "CreateFileMapping",
            "CreateFileMappingA",
            "CreateFileMappingW",
            "MapViewOfFile",
            "MapViewOfFileEx",
            "UnmapViewOfFile",
            "NtCreateSection",
            "ZwCreateSection",
            "RtlMoveMemory",
            "SetPropA",
            "SetPropW",
            "EnumChildWindows",
        ],
    ),
    "anti_debug": (
        HIGH,
        [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "NtSetInformationThread",
            "ZwSetInformationThread",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "DebugActiveProcess",
            "DebugBreak",
            "NtQuerySystemInformation",
            "ZwQuerySystemInformation",
            "GetTickCount",
            "GetTickCount64",
            "QueryPerformanceCounter",
            "QueryPerformanceFrequency",
            "NtQueryPerformanceCounter",
            "GetSystemTimeAsFileTime",
            "timeGetTime",
            "RtlGetVersion",
            "NtClose",
            "GetThreadInformation",
            "SetHandleInformation",
            "NtYieldExecution",
            "SwitchToThread",
        ],
    ),
    "network": (
        MEDIUM,
        [
            "WSAStartup",
            "WSACleanup",
            "WSASocketA",
            "WSASocketW",
            "WSAConnect",
            "WSASend",
            "WSARecv",
            "WSAIoctl",
            "WSAGetLastError",
            "WSAAsyncSelect",
            "socket",
            "connect",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "bind",
            "listen",
            "ntohs",
            "accept",
            "closesocket",
            "shutdown",
            "select",
            "ioctlsocket",
            "gethostbyname",
            "gethostname",
            "htons",
            "getaddrinfo",
            "GetAddrInfoW",
            "freeaddrinfo",
            "inet_addr",
            "inet_ntoa",
            "inet_pton",
            "InternetOpenA",
            "InternetOpenW",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetConnectA",
            "InternetConnectW",
            "InternetReadFile",
            "InternetWriteFile",
            "InternetCloseHandle",
            "InternetSetOptionA",
            "InternetQueryOptionA",
            "InternetCrackUrlA",
            "InternetGetConnectedState",
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "HttpSendRequestExA",
            "HttpQueryInfoA",
            "HttpAddRequestHeadersA",
            "HttpEndRequestA",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "URLDownloadToCacheFileA",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WinHttpReadData",
            "WinHttpWriteData",
            "WinHttpQueryHeaders",
            "WinHttpSetOption",
            "WinHttpCloseHandle",
            "WinHttpCrackUrl",
            "WinHttpQueryDataAvailable",
            "WinHttpSetTimeouts",
            "DnsQuery_A",
            "DnsQuery_W",
            "DnsQueryEx",
            "DnsFree",
            "FtpPutFileA",
            "FtpGetFileA",
            "FtpOpenFileA",
            "IcmpSendEcho",
            "IcmpCreateFile",
            "NetShareEnum",
            "NetUseAdd",
            "NetServerEnum",
            "WNetAddConnection2A",
            "WNetOpenEnumA",
            "WNetEnumResourceA",
            "SendARP",
            "GetAdaptersInfo",
            "GetAdaptersAddresses",
            "GetNetworkParams",
            "GetIfTable",
            "GetTcpTable",
            "GetExtendedTcpTable",
            "GetUdpTable",
            "CoInternetSetFeatureEnabled",
            "ObtainUserAgentString",
        ],
    ),
    "crypto": (
        MEDIUM,
        [
            "CryptAcquireContextA",
            "CryptAcquireContextW",
            "CryptReleaseContext",
            "CryptCreateHash",
            "CryptHashData",
            "CryptGetHashParam",
            "CryptDestroyHash",
            "CryptDeriveKey",
            "CryptGenKey",
            "CryptImportKey",
            "CryptExportKey",
            "CryptDestroyKey",
            "CryptSetKeyParam",
            "CryptGetKeyParam",
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptGenRandom",
            "CryptProtectData",
            "CryptUnprotectData",
            "CryptProtectMemory",
            "CryptUnprotectMemory",
            "CryptStringToBinaryA",
            "CryptBinaryToStringA",
            "BCryptOpenAlgorithmProvider",
            "BCryptCloseAlgorithmProvider",
            "BCryptGenerateSymmetricKey",
            "BCryptGenerateKeyPair",
            "BCryptImportKey",
            "BCryptImportKeyPair",
            "BCryptExportKey",
            "BCryptDestroyKey",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "BCryptHashData",
            "BCryptCreateHash",
            "BCryptFinishHash",
            "BCryptGenRandom",
            "BCryptSetProperty",
            "BCryptDeriveKeyPBKDF2",
            "BCryptSignHash",
            "BCryptVerifySignature",
            "NCryptOpenStorageProvider",
            "NCryptOpenKey",
            "NCryptDecrypt",
            "NCryptEncrypt",
            "NCryptExportKey",
            "NCryptImportKey",
            "SystemFunction036",
            "RtlEncryptMemory",
            "RtlDecryptMemory",
            "CertOpenSystemStoreA",
            "CertOpenStore",
            "CertFindCertificateInStore",
            "CertEnumCertificatesInStore",
            "PFXImportCertStore",
            # Authenticode / catalog verification. Added 2026-07-28 after a real
            # sample showed 14 of these imported and none of them recognised.
            # Malware reads trust state as often as it forges it: checking its
            # own signature is a standard "am I being tampered with" probe, and
            # the catalog APIs are how a loader decides whether a DLL it is
            # about to sideload will trip WDAC. Kept in `crypto` rather than a
            # new category on purpose — the cert-store APIs above already live
            # here, and every new category name dilutes the family-RAG
            # vocabulary described at the top of this file.
            "WinVerifyTrust",
            "WinVerifyTrustEx",
            "CryptCATAdminAcquireContext",
            "CryptCATAdminAcquireContext2",
            "CryptCATAdminCalcHashFromFileHandle",
            "CryptCATAdminCalcHashFromFileHandle2",
            "CryptCATAdminEnumCatalogFromHash",
            "CryptCATAdminReleaseCatalogContext",
            "CryptCATAdminReleaseContext",
            "CryptCATCatalogInfoFromContext",
            "CryptQueryObject",
            "CryptMsgOpenToDecode",
            "CryptMsgGetParam",
            "CryptMsgClose",
            "CertGetNameStringA",
            "CertGetNameStringW",
            "CertGetCertificateChain",
            "CertVerifyCertificateChainPolicy",
            "CertFreeCertificateChain",
            "CertDuplicateCertificateContext",
            "CertFreeCertificateContext",
            "CertFreeCRLContext",
            "CertFreeCTLContext",
            "CertCloseStore",
            "CertNameToStrA",
            "CertNameToStrW",
        ],
    ),
    "filesystem": (
        INFO,
        [
            "CreateFileA",
            "CreateFileW",
            "CreateFile2",
            "ReadFile",
            "ReadFileEx",
            "WriteFile",
            "WriteFileEx",
            "CloseHandle",
            "SetFilePointer",
            "SetFilePointerEx",
            "GetFileSize",
            "GetFileSizeEx",
            "FlushFileBuffers",
            "DeleteFileA",
            "DeleteFileW",
            "MoveFileA",
            "MoveFileW",
            "MoveFileExA",
            "MoveFileExW",
            "CopyFileA",
            "CopyFileW",
            "CopyFileExA",
            "ReplaceFileA",
            "CreateDirectoryA",
            "CreateDirectoryW",
            "RemoveDirectoryA",
            "RemoveDirectoryW",
            "SetCurrentDirectoryA",
            "GetCurrentDirectoryA",
            "FindFirstFileA",
            "FindFirstFileW",
            "FindNextFileA",
            "FindNextFileW",
            "FindClose",
            "GetFileAttributesA",
            "GetFileAttributesW",
            "SetFileAttributesA",
            "GetFileAttributesExA",
            "SetFileTime",
            "GetFileTime",
            "SetEndOfFile",
            "GetTempPathA",
            "GetTempPathW",
            "GetTempFileNameA",
            "GetTempFileNameW",
            "GetWindowsDirectoryA",
            "GetSystemDirectoryA",
            "GetSystemWow64DirectoryA",
            "SHGetFolderPathA",
            "SHGetFolderPathW",
            "SHGetSpecialFolderPathA",
            "SHGetKnownFolderPath",
            "PathAppendA",
            "PathCombineA",
            "PathFileExistsA",
            "GetModuleFileNameA",
            "GetModuleFileNameW",
            "GetFullPathNameA",
            "GetLongPathNameA",
            "GetShortPathNameA",
            "GetVolumeInformationA",
            "GetLogicalDrives",
            "GetLogicalDriveStringsA",
            "GetDriveTypeA",
            "GetDiskFreeSpaceExA",
            "CreateHardLinkA",
            "DeviceIoControl",
            "SetFileInformationByHandle",
            "NtCreateFile",
            "NtWriteFile",
            "NtReadFile",
            "NtDeleteFile",
            "NtSetInformationFile",
            "NtQueryInformationFile",
            "SHFileOperationA",
            "SHFileOperationW",
            "CreateIoCompletionPort",
            # The Ex/By-handle spellings. `FindFirstFileW` was already here but
            # `FindFirstFileExW` was not, so a binary that enumerates
            # directories through the newer call looked like it touched no
            # files at all — the same one-letter blindness the A/W folding fixed
            # on the lookup side.
            "FindFirstFileExA",
            "FindFirstFileExW",
            "FindFirstFileNameW",
            "GetFinalPathNameByHandleA",
            "GetFinalPathNameByHandleW",
            "GetFileInformationByHandle",
            "GetFileInformationByHandleEx",
            "LockFile",
            "LockFileEx",
            "UnlockFile",
            "UnlockFileEx",
        ],
    ),
    "registry": (
        INFO,
        [
            "RegOpenKeyA",
            "RegOpenKeyW",
            "RegOpenKeyExA",
            "RegOpenKeyExW",
            "RegCreateKeyA",
            "RegCreateKeyW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegCloseKey",
            "RegDeleteKeyA",
            "RegDeleteKeyW",
            "RegDeleteKeyExA",
            "RegDeleteValueA",
            "RegDeleteValueW",
            "RegDeleteTreeA",
            "RegSetValueA",
            "RegSetValueW",
            "RegSetValueExA",
            "RegSetValueExW",
            "RegQueryValueA",
            "RegQueryValueW",
            "RegQueryValueExA",
            "RegQueryValueExW",
            "RegQueryInfoKeyA",
            "RegQueryInfoKeyW",
            "RegEnumKeyA",
            "RegEnumKeyExA",
            "RegEnumKeyExW",
            "RegEnumValueA",
            "RegEnumValueW",
            "RegFlushKey",
            "RegSaveKeyA",
            "RegRestoreKeyA",
            "RegLoadKeyA",
            "RegUnLoadKeyA",
            "RegConnectRegistryA",
            "RegNotifyChangeKeyValue",
            "RegGetValueA",
            "RegOverridePredefKey",
            "SHGetValueA",
            "SHSetValueA",
            "SHDeleteKeyA",
            "NtOpenKey",
            "NtSetValueKey",
            "NtQueryValueKey",
            "NtDeleteKey",
            "NtEnumerateKey",
            "NtEnumerateValueKey",
            "ZwOpenKey",
            "ZwSetValueKey",
        ],
    ),
    "privilege": (
        HIGH,
        [
            "AdjustTokenPrivileges",
            "OpenProcessToken",
            "OpenThreadToken",
            "LookupPrivilegeValueA",
            "LookupPrivilegeValueW",
            "LookupPrivilegeNameA",
            "PrivilegeCheck",
            "ImpersonateLoggedOnUser",
            "ImpersonateNamedPipeClient",
            "ImpersonateSelf",
            "RevertToSelf",
            "SetThreadToken",
            "DuplicateToken",
            "DuplicateTokenEx",
            "CreateProcessAsUserA",
            "CreateProcessAsUserW",
            "CreateProcessWithTokenW",
            "CreateProcessWithLogonW",
            "LogonUserA",
            "LogonUserW",
            "SetTokenInformation",
            "GetTokenInformation",
            "CheckTokenMembership",
            "AllocateAndInitializeSid",
            "InitializeSecurityDescriptor",
            "SetSecurityDescriptorDacl",
            "SetSecurityInfo",
            "SetNamedSecurityInfoA",
            "ConvertStringSecurityDescriptorToSecurityDescriptorA",
            "NtAdjustPrivilegesToken",
            "RtlAdjustPrivilege",
            "SeDebugPrivilege",
            "CoImpersonateClient",
            "OpenSCManagerA",
            "OpenSCManagerW",
            # ACL *modification*. Only `SetNamedSecurityInfoA` was here — not
            # even its own W spelling — which left T1222 with no import-side
            # evidence at all. Writing a DACL is genuinely unusual for ordinary
            # software; the read-side spellings are deliberately filed under
            # `discovery` at informational tier instead, because inspecting
            # permissions is something every security-aware program does.
            "SetNamedSecurityInfoW",
            "SetFileSecurityA",
            "SetFileSecurityW",
            "SetKernelObjectSecurity",
            "SetUserObjectSecurity",
            "SetSecurityDescriptorOwner",
            "SetEntriesInAclA",
            "SetEntriesInAclW",
            "AddAccessAllowedAce",
            "AddAccessAllowedAceEx",
            "AddAccessDeniedAce",
            "AddAce",
            "DeleteAce",
            "MakeAbsoluteSD",
            "MakeSelfRelativeSD",
        ],
    ),
    "execution": (
        MEDIUM,
        [
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
            "CreateProcessA",
            "CreateProcessW",
            "CreateProcessInternalW",
            "NtCreateUserProcess",
            "RtlCreateProcessParameters",
            "system",
            "_wsystem",
            "_popen",
            "_execv",
            "_spawnl",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "GetProcAddress",
            "GetModuleHandleA",
            "GetModuleHandleW",
            "GetModuleHandleExA",
            "FreeLibrary",
            "LdrLoadDll",
            "LdrGetProcedureAddress",
            "LdrGetDllHandle",
            "DisableThreadLibraryCalls",
            "CreateThread",
            "ExitThread",
            "TerminateThread",
            "ExitProcess",
            "TerminateProcess",
            "NtTerminateProcess",
            "WaitForSingleObject",
            "WaitForMultipleObjects",
            "CreateJobObjectA",
            "AssignProcessToJobObject",
            "CoCreateInstance",
            "CoCreateInstanceEx",
            "CoInitialize",
            "CoInitializeEx",
            "CoGetObject",
            "CLSIDFromProgID",
            "OleRun",
            "IDispatch",
            "WScriptShell",
            "ScriptControl",
            # Module search-path control. These are the DLL search-order
            # hijacking primitives (T1574.001) — and also exactly how hardened
            # software removes the CWD from its own search path. An import
            # table cannot tell `SetDllDirectoryW(L"")` from
            # `SetDllDirectoryW(attacker_path)`, so they are categorised here
            # for the histogram and the prompt but deliberately given NO
            # entry in WINDOWS_ATTCK below. Claiming T1574.001 from a call that
            # is at least as often defensive would be the same firehose that
            # got T1129 and T1218 dropped.
            "SetDllDirectoryA",
            "SetDllDirectoryW",
            "AddDllDirectory",
            "RemoveDllDirectory",
            "SetDefaultDllDirectories",
            "SetSearchPathMode",
        ],
    ),
    # --------------------------------------------------------------- new four
    "discovery": (
        INFO,
        [
            "GetComputerNameA",
            "GetComputerNameW",
            "GetComputerNameExA",
            "GetUserNameA",
            "GetUserNameW",
            "GetUserNameExA",
            "GetSystemInfo",
            "GetNativeSystemInfo",
            "GetVersionExA",
            "GetVersionExW",
            "GetSystemMetrics",
            "GetSystemDefaultLangID",
            "GetUserDefaultLangID",
            "GetUserDefaultUILanguage",
            "GetSystemDefaultUILanguage",
            "GetLocaleInfoA",
            "GetLocaleInfoW",
            "GetTimeZoneInformation",
            "GetKeyboardLayout",
            "GetKeyboardLayoutList",
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32FirstW",
            "Process32Next",
            "Process32NextW",
            "Module32First",
            "Module32Next",
            "Thread32First",
            "Thread32Next",
            "Heap32First",
            "Heap32ListFirst",
            "EnumProcesses",
            "EnumProcessModules",
            "EnumProcessModulesEx",
            "GetModuleBaseNameA",
            "GetProcessImageFileNameA",
            "QueryFullProcessImageNameA",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "GetProcessId",
            "EnumWindows",
            "FindWindowA",
            "FindWindowW",
            "FindWindowExA",
            "GetWindowTextA",
            "GetWindowTextW",
            "GetForegroundWindow",
            "GetWindowThreadProcessId",
            "GetClassNameA",
            "IsWindowVisible",
            "EnumDesktopWindows",
            "EnumDesktopsA",
            "GetDesktopWindow",
            "GlobalMemoryStatusEx",
            "GetPhysicallyInstalledSystemMemory",
            "GetDiskFreeSpaceA",
            "EnumServicesStatusA",
            "EnumServicesStatusExA",
            "QueryServiceConfigA",
            "EnumDependentServicesA",
            "NetUserGetInfo",
            "NetUserEnum",
            "NetLocalGroupGetMembers",
            "NetWkstaGetInfo",
            "NetGetJoinInformation",
            "DsGetDcNameA",
            "LookupAccountSidA",
            "LookupAccountNameA",
            "GetCurrentHwProfileA",
            "EnumSystemLocalesA",
            "IsProcessorFeaturePresent",
            "GetProductInfo",
            "WTSEnumerateSessionsA",
            "WTSQuerySessionInformationA",
            "GetLastInputInfo",
            "GetCursorPos",
            # SID and ACL *inspection*. `GetSidSubAuthority` + friends is the
            # canonical "am I SYSTEM / am I elevated" probe, and
            # `LookupAccountSid` is account discovery by another name. Kept at
            # informational tier: reading permissions is ubiquitous, only the
            # pattern carries signal. The write-side spellings live in
            # `privilege` at high tier.
            "GetFileSecurityA",
            "GetFileSecurityW",
            "GetNamedSecurityInfoA",
            "GetNamedSecurityInfoW",
            "GetSecurityInfo",
            "GetKernelObjectSecurity",
            "GetSecurityDescriptorDacl",
            "GetSecurityDescriptorOwner",
            "GetSecurityDescriptorGroup",
            "GetAclInformation",
            "GetAce",
            "GetSidIdentifierAuthority",
            "GetSidSubAuthority",
            "GetSidSubAuthorityCount",
            "GetLengthSid",
            "FreeSid",
            "EqualSid",
            "IsValidSid",
            "CopySid",
            "ConvertSidToStringSidA",
            "ConvertSidToStringSidW",
            "ConvertStringSidToSidA",
            "ConvertStringSidToSidW",
            # Host and device enumeration. `QueryDosDevice` doubles as an
            # anti-VM probe (\\.\VBoxGuest and friends) but is filed here
            # rather than in anti_debug, which is high tier — the call alone
            # does not prove the intent.
            "QueryDosDeviceA",
            "QueryDosDeviceW",
            "ExpandEnvironmentStringsA",
            "ExpandEnvironmentStringsW",
            "GetFileVersionInfoA",
            "GetFileVersionInfoW",
            "GetFileVersionInfoSizeA",
            "GetFileVersionInfoSizeW",
            "VerQueryValueA",
            "VerQueryValueW",
            "ProcessIdToSessionId",
            "WTSGetActiveConsoleSessionId",
            "GetMappedFileNameA",
            "GetMappedFileNameW",
            "K32GetMappedFileNameW",
            "K32GetModuleFileNameExW",
        ],
    ),
    "persistence": (
        HIGH,
        [
            "CreateServiceA",
            "CreateServiceW",
            "OpenServiceA",
            "OpenServiceW",
            "StartServiceA",
            "StartServiceW",
            "StartServiceCtrlDispatcherA",
            "ControlService",
            "DeleteService",
            "ChangeServiceConfigA",
            "ChangeServiceConfig2A",
            "RegisterServiceCtrlHandlerA",
            "SetServiceStatus",
            "QueryServiceStatusEx",
            "CloseServiceHandle",
            "NetScheduleJobAdd",
            "NetScheduleJobEnum",
            "ITaskScheduler",
            "ITaskService",
            "IRegisteredTask",
            "ITaskFolder",
            "CoTaskMemAlloc",
            "SHSetValueW",
            "RegisterEventSourceA",
            "ReportEventA",
            "WriteProfileStringA",
            "GetPrivateProfileStringA",
            "CreateMutexA",
            "CreateMutexW",
            "CreateMutexExA",
            "OpenMutexA",
            "OpenMutexW",
            "CreateEventA",
            "CreateEventW",
            "OpenEventA",
            "CreateSemaphoreA",
            "ReleaseMutex",
            "SHGetSpecialFolderLocation",
            "SHChangeNotify",
            "IWbemLocator",
            "IWbemServices",
            "IWbemClassObject",
            "CoSetProxyBlanket",
            "CoInitializeSecurity",
        ],
    ),
    "keylogging": (
        HIGH,
        [
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "SetKeyboardState",
            "GetKeyNameTextA",
            "MapVirtualKeyA",
            "ToAscii",
            "ToUnicode",
            "ToUnicodeEx",
            "RegisterRawInputDevices",
            "GetRawInputData",
            "GetRawInputDeviceList",
            "AttachThreadInput",
            "BlockInput",
            "keybd_event",
            "mouse_event",
            "SendInput",
            "SetWinEventHook",
            "RegisterHotKey",
            "GetClipboardData",
            "SetClipboardData",
            "OpenClipboard",
            "CloseClipboard",
            "EmptyClipboard",
            "IsClipboardFormatAvailable",
            "AddClipboardFormatListener",
            "waveInOpen",
            "waveInStart",
            "capCreateCaptureWindowA",
        ],
    ),
    # The GDI calls that copy pixels out of a device context. They are what a
    # screenshot is made of, and they are also what every program that draws
    # its own window calls: filed under keylogging at tier high, they made a
    # signed SSH client read as a keylogger to the one analyst that spoke.
    # Informational, with the company they would need to mean something.
    "screen_capture": (
        INFO,
        [
            "BitBlt",
            "StretchBlt",
            "CreateCompatibleBitmap",
            "CreateCompatibleDC",
            "GetDC",
            "GetWindowDC",
            "GetDIBits",
            "SelectObject",
            "PrintWindow",
        ],
    ),
    # The Win32 message pump. Every windowed program has one; a keylogger is
    # told apart by the hook or the raw-input registration beside it.
    "message_loop": (
        INFO,
        [
            "GetMessageA",
            "GetMessageW",
            "PeekMessageA",
            "TranslateMessage",
            "DispatchMessageA",
        ],
    ),
    "evasion": (
        HIGH,
        [
            "NtSetInformationProcess",
            "ZwSetInformationProcess",
            "RtlSetProcessIsCritical",
            "NtRaiseHardError",
            "SetProcessMitigationPolicy",
            "SetProcessValidCallTargets",
            "AddVectoredExceptionHandler",
            "RemoveVectoredExceptionHandler",
            "SetUnhandledExceptionFilter",
            "UnhandledExceptionFilter",
            "RtlAddVectoredExceptionHandler",
            "RaiseException",
            "IsWow64Process",
            "IsWow64Process2",
            "Wow64DisableWow64FsRedirection",
            "Wow64RevertWow64FsRedirection",
            "Wow64EnableWow64FsRedirection",
            "GetProcessHeap",
            "HeapCreate",
            "HeapAlloc",
            "HeapFree",
            "HeapWalk",
            "GlobalAlloc",
            "GlobalLock",
            "LocalAlloc",
            "VirtualQuery",
            "VirtualQueryEx",
            "FlushInstructionCache",
            "GetWriteWatch",
            "ResetWriteWatch",
            "SetFileAttributesW",
            "DeleteFileTransactedA",
            "CreateTransaction",
            "CommitTransaction",
            "RollbackTransaction",
            "NtCreateTransaction",
            "SetProcessDEPPolicy",
            "GetEnvironmentVariableA",
            "GetEnvironmentVariableW",
            "SetEnvironmentVariableA",
            "GetEnvironmentStringsA",
            "CreateDesktopA",
            "SwitchDesktop",
            "SetThreadDesktop",
            "OpenDesktopA",
            "SetErrorMode",
            "SetThreadErrorMode",
            "EventWrite",
            "EtwEventWrite",
            "EtwEventRegister",
            "EtwEventUnregister",
            "AmsiScanBuffer",
            "AmsiInitialize",
            "AmsiOpenSession",
            "SaferComputeTokenFromLevel",
            "SaferCreateLevel",
            "GetModuleHandleExW",
            "EnumSystemFirmwareTables",
            "GetSystemFirmwareTable",
            "SetupDiGetClassDevsA",
            "SetupDiEnumDeviceInfo",
            "RtlDecompressBuffer",
            "RtlCompressBuffer",
        ],
    ),
    "credential": (
        HIGH,
        [
            "CredEnumerateA",
            "CredEnumerateW",
            "CredReadA",
            "CredReadW",
            "CredWriteA",
            "CredFree",
            "CredDeleteA",
            "LsaOpenPolicy",
            "LsaRetrievePrivateData",
            "LsaEnumerateLogonSessions",
            "LsaGetLogonSessionData",
            "LsaCallAuthenticationPackage",
            "SamConnect",
            "SamEnumerateDomainsInSamServer",
            "SamLookupDomainInSamServer",
            "MsvpPasswordValidate",
            "SspiPromptForCredentialsA",
            "CredUIPromptForCredentialsA",
            "CredUIPromptForWindowsCredentialsA",
            "NetUserChangePassword",
            "WNetGetUserA",
            "SqliteOpen",
            "sqlite3_open",
            "sqlite3_prepare_v2",
            "sqlite3_step",
        ],
    ),
}


# ---------------------------------------------------------------------------
# API → ATT&CK
# ---------------------------------------------------------------------------
# ``min_apis`` is the field the equivalent public tables lack, and it is what
# separates a usable layer from a firehose. A rule of "any match counts" turns a
# lone GetUserNameA into an Account Discovery finding; requiring two distinct
# imports means the claim describes a capability, not a coincidence.
#
# ``confidence_max`` never exceeds 0.65 — below the YARA floor of 0.70 — so a
# deterministic import signal corroborates other layers without solo-driving a
# verdict. That ceiling is enforced again in the loader.

# ---------------------------------------------------------------------------
# Linux / ELF behaviour categories
# ---------------------------------------------------------------------------
# The same discipline as the Windows block above, and the same sentence a
# reader should keep in mind: a row is an association, not a verdict. An ELF's
# dynamic symbol table is much smaller and much more ordinary than a PE's
# import table — every C program in existence calls ``read`` and ``malloc`` —
# so the bar for a name to appear here at all is that its presence says
# something a reader could not have assumed, and the bar for a high or medium
# tier is that the name is unusual in ordinary software.
#
# What is deliberately absent, rather than guessed at:
#   - ``registry``, which has no Linux counterpart;
#   - ``persistence``, because Linux persistence is a path — a unit file, a
#     crontab, a shell profile — and not a libc call, so any symbol list here
#     would be a guess dressed as data;
#   - ``keylogging``, ``screen_capture`` and ``credential``, whose honest
#     vocabularies are X11, /dev/input and file paths rather than libc;
#   - ``evasion``, which on Linux is overwhelmingly about what a process does
#     with ordinary calls rather than which calls it imports.
# The mapping is deliberately smaller than Windows's, and a category that would
# fire on every coreutils binary is worse than no category.
#
# Tiers here were measured, not judged. Every group was run against the 1894
# ELF binaries with a dynamic symbol table under this machine's own /usr/bin,
# /usr/sbin and systemd directories, and a group whose bare presence labels
# more than one in a hundred of them is an informational association with
# ``corroborated_by`` rather than a tier the catalogue calls suspicious. Only
# reading or writing another process's memory survived that bar, and even it
# carries ``flags_with``: the flag appears when the symbol set actually reaches
# into another process, not when a program merely creates an anonymous file.

LINUX_CATEGORIES: dict[str, tuple[str, list[str]]] = {
    # Reading or writing another process's memory, and running code that was
    # never a file. ``ptrace`` is the obvious omission here: it is a debugger
    # call before it is an injection call, so it sits under anti_debug and the
    # injection technique rule names it there.
    "process_injection": (
        HIGH,
        [
            "process_vm_readv",
            "process_vm_writev",
            "memfd_create",
            "fexecve",
        ],
    ),
    # ``personality`` is how a process turns ASLR off for itself and ``ptrace``
    # is how it attaches to another. A debugger, ``strace`` and ``setarch`` are
    # the ordinary users of both, so the group says what it is and names what
    # would give it weight instead of carrying a tier of its own.
    "anti_debug": (
        INFO,
        [
            "ptrace",
            "personality",
        ],
    ),
    "network": (
        INFO,
        [
            "accept",
            "accept4",
            "bind",
            "connect",
            "curl_easy_cleanup",
            "curl_easy_init",
            "curl_easy_perform",
            "curl_easy_setopt",
            "curl_global_init",
            "freeaddrinfo",
            "getaddrinfo",
            "gethostbyname",
            "getnameinfo",
            "getpeername",
            "getsockname",
            "getsockopt",
            "inet_addr",
            "inet_ntoa",
            "inet_ntop",
            "inet_pton",
            "listen",
            "recv",
            "recvfrom",
            "recvmsg",
            "res_query",
            "res_search",
            "send",
            "sendmsg",
            "sendto",
            "setsockopt",
            "shutdown",
            "socket",
        ],
    ),
    "crypto": (
        INFO,
        [
            "AES_cbc_encrypt",
            "AES_set_encrypt_key",
            "EVP_CIPHER_CTX_free",
            "EVP_CIPHER_CTX_new",
            "EVP_DecryptFinal_ex",
            "EVP_DecryptInit_ex",
            "EVP_DecryptUpdate",
            "EVP_DigestFinal_ex",
            "EVP_DigestInit_ex",
            "EVP_DigestUpdate",
            "EVP_EncryptFinal_ex",
            "EVP_EncryptInit_ex",
            "EVP_EncryptUpdate",
            "EVP_aes_128_cbc",
            "EVP_aes_256_cbc",
            "EVP_aes_256_gcm",
            "EVP_sha256",
            "MD5_Final",
            "MD5_Init",
            "MD5_Update",
            "RAND_bytes",
            "RSA_private_decrypt",
            "RSA_public_encrypt",
            "SHA256_Final",
            "SHA256_Init",
            "SHA256_Update",
            "SSL_CTX_new",
            "SSL_connect",
            "SSL_new",
            "SSL_read",
            "SSL_write",
            "gcry_cipher_decrypt",
            "gcry_cipher_encrypt",
            "gcry_cipher_open",
            "gcry_cipher_setkey",
        ],
    ),
    "filesystem": (
        INFO,
        [
            "access",
            "chdir",
            "chmod",
            "chown",
            "close",
            "closedir",
            "creat",
            "faccessat",
            "fchmod",
            "fchown",
            "fclose",
            "fopen",
            "fopen64",
            "fread",
            "fseek",
            "fstat",
            "ftell",
            "ftruncate",
            "fwrite",
            "getcwd",
            "link",
            "lstat",
            "mkdir",
            "mkdirat",
            "open",
            "open64",
            "openat",
            "opendir",
            "pread",
            "pwrite",
            "read",
            "readdir",
            "readdir64",
            "readlink",
            "realpath",
            "remove",
            "rename",
            "renameat",
            "rmdir",
            "stat",
            "stat64",
            "symlink",
            "truncate",
            "unlink",
            "unlinkat",
            "utimes",
            "write",
        ],
    ),
    "discovery": (
        INFO,
        [
            "get_nprocs",
            "getegid",
            "getenv",
            "geteuid",
            "getgid",
            "getgrgid",
            "getgrnam",
            "getifaddrs",
            "getuid",
            "getlogin",
            "getpgid",
            "getpid",
            "getppid",
            "getpwnam",
            "getpwuid",
            "gethostname",
            "isatty",
            "sched_getaffinity",
            "secure_getenv",
            "sysconf",
            "sysinfo",
            "ttyname",
            "uname",
        ],
    ),
    # Dropping or assuming another identity. The setuid family is what every
    # daemon and every legitimate privileged helper uses to *drop* privilege —
    # 7.8% of the measured binaries import one — so the group is an
    # association with corroborators and the catalogue says nothing about it
    # on its own.
    "privilege": (
        INFO,
        [
            "cap_set_flag",
            "cap_set_proc",
            "capset",
            "chroot",
            "initgroups",
            "setegid",
            "seteuid",
            "setfsgid",
            "setfsuid",
            "setgid",
            "setgroups",
            "setregid",
            "setresgid",
            "setresuid",
            "setreuid",
            "setuid",
        ],
    ),
    # Handing a string to a shell, replacing the process image, or resolving a
    # symbol at run time. Ordinary in 22% of the measured binaries, which is
    # what an association looks like rather than a finding.
    "execution": (
        INFO,
        [
            "dlopen",
            "dlsym",
            "execl",
            "execle",
            "execlp",
            "execv",
            "execve",
            "execvp",
            "execvpe",
            "popen",
            "posix_spawn",
            "posix_spawnp",
            "system",
        ],
    ),
    # Making, reaping and detaching processes: the vocabulary of a daemon as
    # much as of a dropper, which is why it is informational.
    "process": (
        INFO,
        [
            "clone",
            "daemon",
            "fork",
            "kill",
            "nice",
            "setpgid",
            "setsid",
            "vfork",
            "wait4",
            "waitpid",
        ],
    ),
}


CATEGORIES_BY_PLATFORM: dict[str, dict[str, tuple[str, list[str]]]] = {
    "windows": WINDOWS_CATEGORIES,
    "linux": LINUX_CATEGORIES,
}

# The Linux counterpart of ``WINDOWS_CORROBORATORS``, and the reason the block
# tiers almost nothing: an ELF's dynamic symbol table is small and ordinary,
# and a group that means little alone should say what would give it weight
# rather than carry a label a reader cannot act on.
LINUX_CORROBORATORS: dict[str, list[str]] = {
    "anti_debug": ["memfd_create", "process_vm_readv", "process_vm_writev"],
    "privilege": ["chroot", "memfd_create", "process_vm_writev", "ptrace"],
    "network": ["EVP_EncryptInit_ex", "SSL_connect", "curl_easy_perform", "popen", "system"],
    "execution": ["connect", "memfd_create", "ptrace", "socket"],
    "crypto": ["connect", "readdir", "rename", "socket", "unlink"],
    "process": ["memfd_create", "ptrace", "setsid", "system"],
}

# Per category, the names whose presence beside it turns the catalogue's own
# ``suspicious`` label on. A category with no entry here is labelled by its
# tier alone, which is every Windows category and how the flag has always
# worked. ``process_injection`` has one because ``memfd_create`` by itself is
# ordinary in the graphics and service stacks, while the same symbol beside a
# call that reaches into another process is not.
LINUX_FLAG_GATES: dict[str, list[str]] = {
    "process_injection": ["process_vm_readv", "process_vm_writev", "ptrace"],
}

CORROBORATORS_BY_PLATFORM: dict[str, dict[str, list[str]]] = {
    "windows": WINDOWS_CORROBORATORS,
    "linux": LINUX_CORROBORATORS,
}

FLAG_GATES_BY_PLATFORM: dict[str, dict[str, list[str]]] = {
    "windows": {},
    "linux": LINUX_FLAG_GATES,
}


ATTCK_TECHNIQUES: list[dict[str, Any]] = [
    # ---------------------------------------------------------------- Discovery
    {
        "technique_id": "T1057",
        "name": "Process Discovery",
        "min_apis": 2,
        "confidence_base": 0.42,
        "confidence_max": 0.62,
        "apis": [
            "CreateToolhelp32Snapshot",
            "Process32First",
            "Process32FirstW",
            "Process32Next",
            "Process32NextW",
            "EnumProcesses",
            "EnumProcessModules",
            "GetProcessImageFileNameA",
            "QueryFullProcessImageNameA",
        ],
    },
    {
        "technique_id": "T1082",
        "name": "System Information Discovery",
        "min_apis": 3,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": [
            "GetSystemInfo",
            "GetNativeSystemInfo",
            "GetVersionExA",
            "GetVersionExW",
            "GetComputerNameA",
            "GetComputerNameW",
            "GlobalMemoryStatusEx",
            "GetSystemMetrics",
            "GetProductInfo",
            "GetCurrentHwProfileA",
            "GetSystemFirmwareTable",
            "GetLogicalDrives",
            "GetVolumeInformationA",
        ],
    },
    {
        "technique_id": "T1033",
        "name": "System Owner/User Discovery",
        "min_apis": 2,
        "confidence_base": 0.42,
        "confidence_max": 0.60,
        "apis": [
            "GetUserNameA",
            "GetUserNameW",
            "GetUserNameExA",
            "LookupAccountSidA",
            "LookupAccountNameA",
            "NetUserGetInfo",
            "WTSQuerySessionInformationA",
        ],
    },
    {
        "technique_id": "T1087",
        "name": "Account Discovery",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.62,
        "apis": [
            "NetUserEnum",
            "NetLocalGroupGetMembers",
            "NetUserGetInfo",
            "LookupAccountNameA",
            "CheckTokenMembership",
            "DsGetDcNameA",
        ],
    },
    {
        "technique_id": "T1012",
        "name": "Query Registry",
        "min_apis": 2,
        "confidence_base": 0.38,
        "confidence_max": 0.55,
        "apis": [
            "RegQueryValueExA",
            "RegQueryValueExW",
            "RegQueryInfoKeyA",
            "RegEnumKeyExA",
            "RegEnumValueA",
            "RegGetValueA",
            "SHGetValueA",
            "NtQueryValueKey",
            "NtEnumerateKey",
        ],
    },
    {
        "technique_id": "T1083",
        "name": "File and Directory Discovery",
        "min_apis": 3,
        "confidence_base": 0.38,
        "confidence_max": 0.55,
        "apis": [
            "FindFirstFileA",
            "FindFirstFileW",
            "FindNextFileA",
            "FindNextFileW",
            "GetFileAttributesA",
            "GetLogicalDriveStringsA",
            "GetDriveTypeA",
            "PathFileExistsA",
            "SHGetFolderPathA",
        ],
    },
    {
        "technique_id": "T1010",
        "name": "Application Window Discovery",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.60,
        "apis": [
            "EnumWindows",
            "FindWindowA",
            "FindWindowW",
            "GetWindowTextA",
            "GetWindowTextW",
            "GetForegroundWindow",
            "GetClassNameA",
            "EnumDesktopWindows",
        ],
    },
    {
        "technique_id": "T1016",
        "name": "System Network Configuration Discovery",
        "min_apis": 2,
        "confidence_base": 0.42,
        "confidence_max": 0.58,
        "apis": [
            "GetAdaptersInfo",
            "GetAdaptersAddresses",
            "GetIfTable",
            "gethostname",
            "GetNetworkParams",
            "SendARP",
            "NetWkstaGetInfo",
        ],
    },
    {
        "technique_id": "T1049",
        "name": "System Network Connections Discovery",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.60,
        "apis": [
            "GetTcpTable",
            "GetExtendedTcpTable",
            "GetUdpTable",
            "NetShareEnum",
            "WNetOpenEnumA",
            "WNetEnumResourceA",
            "NetServerEnum",
        ],
    },
    {
        "technique_id": "T1007",
        "name": "System Service Discovery",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.60,
        "apis": [
            "EnumServicesStatusA",
            "EnumServicesStatusExA",
            "QueryServiceConfigA",
            "EnumDependentServicesA",
            "OpenSCManagerA",
        ],
    },
    {
        "technique_id": "T1614",
        "name": "System Location Discovery",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.58,
        "apis": [
            "GetLocaleInfoA",
            "GetLocaleInfoW",
            "GetSystemDefaultLangID",
            "GetUserDefaultLangID",
            "GetUserDefaultUILanguage",
            "GetTimeZoneInformation",
            "GetKeyboardLayout",
            "EnumSystemLocalesA",
        ],
    },
    # ------------------------------------------------------------- Persistence
    {
        "technique_id": "T1543.003",
        "name": "Create or Modify System Process: Windows Service",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "CreateServiceA",
            "CreateServiceW",
            "OpenSCManagerA",
            "OpenSCManagerW",
            "StartServiceA",
            "ChangeServiceConfigA",
            "ChangeServiceConfig2A",
            "DeleteService",
            "ControlService",
        ],
    },
    {
        "technique_id": "T1547.001",
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "min_apis": 2,
        "confidence_base": 0.42,
        "confidence_max": 0.60,
        "apis": [
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegSetValueExA",
            "RegSetValueExW",
            "SHSetValueA",
            "NtSetValueKey",
        ],
    },
    {
        "technique_id": "T1053.005",
        "name": "Scheduled Task/Job: Scheduled Task",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "NetScheduleJobAdd",
            "NetScheduleJobEnum",
            "ITaskScheduler",
            "ITaskService",
            "IRegisteredTask",
            "ITaskFolder",
        ],
    },
    {
        "technique_id": "T1546.003",
        "name": "Event Triggered Execution: WMI Event Subscription",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": ["IWbemLocator", "IWbemServices", "IWbemClassObject", "CoSetProxyBlanket"],
    },
    # --------------------------------------------------------- Privilege Esc.
    {
        "technique_id": "T1134",
        "name": "Access Token Manipulation",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "OpenProcessToken",
            "OpenThreadToken",
            "AdjustTokenPrivileges",
            "DuplicateTokenEx",
            "DuplicateToken",
            "SetThreadToken",
            "ImpersonateLoggedOnUser",
            "CreateProcessWithTokenW",
            "CreateProcessAsUserA",
            "SetTokenInformation",
            "RtlAdjustPrivilege",
            "NtAdjustPrivilegesToken",
            "ImpersonateNamedPipeClient",
        ],
    },
    {
        "technique_id": "T1548.002",
        "name": "Abuse Elevation Control Mechanism: Bypass UAC",
        "min_apis": 2,
        "confidence_base": 0.45,
        "confidence_max": 0.62,
        "apis": [
            "ShellExecuteExA",
            "ShellExecuteExW",
            "CoGetObject",
            "CLSIDFromProgID",
            "CheckTokenMembership",
            "GetTokenInformation",
        ],
    },
    # ------------------------------------------------------- Defense Evasion
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "WriteProcessMemory",
            "VirtualAllocEx",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtQueueApcThread",
            "SetWindowsHookEx",
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
            "OpenProcess",
        ],
    },
    {
        "technique_id": "T1055.012",
        "name": "Process Injection: Process Hollowing",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "SetThreadContext",
            "GetThreadContext",
            "ResumeThread",
            "WriteProcessMemory",
            "CreateProcessInternalW",
        ],
    },
    {
        "technique_id": "T1620",
        "name": "Reflective Code Loading",
        "min_apis": 2,
        "confidence_base": 0.45,
        "confidence_max": 0.62,
        "apis": [
            "NtCreateSection",
            "ZwCreateSection",
            "NtMapViewOfSection",
            "MapViewOfFile",
            "CreateFileMappingA",
            "LdrLoadDll",
            "LdrGetProcedureAddress",
        ],
    },
    {
        "technique_id": "T1622",
        "name": "Debugger Evasion",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "OutputDebugStringA",
            "DebugActiveProcess",
            "NtClose",
        ],
    },
    {
        "technique_id": "T1497",
        "name": "Virtualization/Sandbox Evasion",
        "min_apis": 2,
        "confidence_base": 0.42,
        "confidence_max": 0.60,
        "apis": [
            "GetSystemFirmwareTable",
            "EnumSystemFirmwareTables",
            "SetupDiGetClassDevsA",
            "SetupDiEnumDeviceInfo",
            "GetLastInputInfo",
            "GetCursorPos",
            "IsProcessorFeaturePresent",
        ],
    },
    {
        "technique_id": "T1497.003",
        "name": "Virtualization/Sandbox Evasion: Time Based Evasion",
        "min_apis": 3,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": [
            "GetTickCount",
            "GetTickCount64",
            "QueryPerformanceCounter",
            "QueryPerformanceFrequency",
            "GetSystemTimeAsFileTime",
            "timeGetTime",
            "NtQueryPerformanceCounter",
            "NtYieldExecution",
        ],
    },
    {
        "technique_id": "T1112",
        "name": "Modify Registry",
        "min_apis": 2,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": [
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegDeleteValueA",
            "RegDeleteKeyA",
            "RegDeleteTreeA",
            "NtSetValueKey",
            "NtDeleteKey",
            "RegRestoreKeyA",
            "RegLoadKeyA",
        ],
    },
    {
        # Only the write-side APIs appear here. The read-side spellings
        # (GetFileSecurity, GetAclInformation, GetAce) are categorised under
        # `discovery` and deliberately excluded: reading a DACL is what every
        # security-aware program does, and mapping it to T1222 would fire on
        # most signed software in the corpus.
        "technique_id": "T1222",
        "name": "File and Directory Permissions Modification",
        "min_apis": 2,
        "confidence_base": 0.42,
        "confidence_max": 0.60,
        "apis": [
            "SetFileSecurityA",
            "SetFileSecurityW",
            "SetNamedSecurityInfoA",
            "SetNamedSecurityInfoW",
            "SetSecurityInfo",
            "SetEntriesInAclA",
            "SetEntriesInAclW",
            "SetSecurityDescriptorDacl",
            "AddAccessAllowedAce",
            "AddAccessDeniedAce",
            "DeleteAce",
        ],
    },
    {
        # ATT&CK 19.2 folded this and Indicator Blocking below into T1685, and
        # the builder follows the vendored set's revoked-by to it. The id here
        # is the one the rule was curated against; ``name`` is the catalogue's
        # own name for the id it ends up on, and ``rule`` is what distinguishes
        # two rules that evidence the same technique from different imports. A
        # surface printing the id beside the name must print a name the
        # catalogue agrees with.
        "technique_id": "T1562.001",
        "name": "Disable or Modify Tools",
        "rule": "scanning and tracing provider calls",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "AmsiScanBuffer",
            "AmsiInitialize",
            "AmsiOpenSession",
            "EtwEventWrite",
            "EtwEventRegister",
            "EtwEventUnregister",
            "EventWrite",
        ],
    },
    {
        "technique_id": "T1562.006",
        "name": "Disable or Modify Tools",
        "rule": "tracing provider calls and the event log",
        "min_apis": 2,
        "confidence_base": 0.46,
        "confidence_max": 0.62,
        "apis": ["EtwEventUnregister", "EtwEventRegister", "EventWrite", "ReportEventA"],
    },
    {
        "technique_id": "T1070.004",
        "name": "Indicator Removal: File Deletion",
        "min_apis": 2,
        "confidence_base": 0.38,
        "confidence_max": 0.55,
        "apis": [
            "DeleteFileA",
            "DeleteFileW",
            "SHFileOperationA",
            "MoveFileExA",
            "DeleteFileTransactedA",
            "NtDeleteFile",
        ],
    },
    {
        "technique_id": "T1070.006",
        "name": "Indicator Removal: Timestomp",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["SetFileTime", "GetFileTime", "NtSetInformationFile"],
    },
    {
        # VirtualProtect deliberately absent. It is in every packer *and* in
        # every JIT, every hot-patcher and much of the CRT, so including it
        # would make this rule fire on ordinary software — and this particular
        # technique is one the local model already over-claims, which is why
        # capability_matrix caps it. Feeding that cap a noisy signal would be
        # worse than leaving the rule out.
        "technique_id": "T1027",
        "name": "Obfuscated Files or Information",
        "min_apis": 2,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": [
            "CryptStringToBinaryA",
            "CryptBinaryToStringA",
            "RtlDecompressBuffer",
            "RtlCompressBuffer",
        ],
    },
    {
        "technique_id": "T1140",
        "name": "Deobfuscate/Decode Files or Information",
        "min_apis": 2,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": [
            "CryptStringToBinaryA",
            "CryptUnprotectData",
            "RtlDecompressBuffer",
            "CryptDecrypt",
            "BCryptDecrypt",
            "SystemFunction036",
        ],
    },
    # T1036 (Masquerading) and T1218 (System Binary Proxy Execution) are
    # deliberately absent. Masquerading is a property of a file's *name and
    # appearance*, which an import table cannot see — SetFileAttributes and
    # CopyFile are the wrong evidence for it. Proxy execution needs the command
    # line, which the LOLBin layer already reads from sandbox telemetry;
    # inferring it from "this binary can start a process" would fire on nearly
    # everything and add nothing the LOLBin layer does not do properly.
    {
        "technique_id": "T1564.003",
        "name": "Hide Artifacts: Hidden Window",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.60,
        "apis": [
            "CreateDesktopA",
            "SwitchDesktop",
            "SetThreadDesktop",
            "OpenDesktopA",
            "IsWindowVisible",
        ],
    },
    # ----------------------------------------------------- Credential Access
    {
        "technique_id": "T1056.001",
        "name": "Input Capture: Keylogging",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "RegisterRawInputDevices",
            "GetRawInputData",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "AttachThreadInput",
            "MapVirtualKeyA",
            "ToUnicodeEx",
            "GetKeyNameTextA",
            "SetWinEventHook",
        ],
    },
    {
        "technique_id": "T1555",
        "name": "Credentials from Password Stores",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "CryptUnprotectData",
            "CredEnumerateA",
            "CredEnumerateW",
            "CredReadA",
            "CredReadW",
            "CredFree",
            "CertOpenSystemStoreA",
            "PFXImportCertStore",
            "SystemFunction036",
            "sqlite3_open",
            "sqlite3_prepare_v2",
        ],
    },
    {
        "technique_id": "T1003",
        "name": "OS Credential Dumping",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "LsaOpenPolicy",
            "LsaRetrievePrivateData",
            "LsaEnumerateLogonSessions",
            "LsaGetLogonSessionData",
            "LsaCallAuthenticationPackage",
            "SamConnect",
            "SamEnumerateDomainsInSamServer",
            "MsvpPasswordValidate",
        ],
    },
    {
        "technique_id": "T1040",
        "name": "Network Sniffing",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": ["WSAIoctl", "ioctlsocket", "bind", "WSASocketA", "recvfrom"],
    },
    # --------------------------------------------------------------- Collection
    {
        "technique_id": "T1113",
        "name": "Screen Capture",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "BitBlt",
            "StretchBlt",
            "CreateCompatibleBitmap",
            "CreateCompatibleDC",
            "GetDC",
            "GetWindowDC",
            "GetDIBits",
            "PrintWindow",
        ],
    },
    {
        "technique_id": "T1115",
        "name": "Clipboard Data",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "OpenClipboard",
            "GetClipboardData",
            "SetClipboardData",
            "CloseClipboard",
            "IsClipboardFormatAvailable",
            "AddClipboardFormatListener",
        ],
    },
    {
        "technique_id": "T1123",
        "name": "Audio Capture",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["waveInOpen", "waveInStart", "capCreateCaptureWindowA"],
    },
    # ------------------------------------------------------- Command & Control
    {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.62,
        "apis": [
            "InternetOpenA",
            "InternetOpenW",
            "InternetConnectA",
            "InternetOpenUrlA",
            "InternetReadFile",
            "HttpOpenRequestA",
            "HttpSendRequestA",
            "HttpQueryInfoA",
            "WinHttpOpen",
            "WinHttpConnect",
            "WinHttpOpenRequest",
            "WinHttpSendRequest",
            "WinHttpReceiveResponse",
            "WinHttpReadData",
            "URLDownloadToFileA",
            "URLDownloadToFileW",
        ],
    },
    {
        "technique_id": "T1071.004",
        "name": "Application Layer Protocol: DNS",
        "min_apis": 2,
        "confidence_base": 0.46,
        "confidence_max": 0.62,
        "apis": ["DnsQuery_A", "DnsQuery_W", "DnsQueryEx", "DnsFree", "getaddrinfo"],
    },
    {
        "technique_id": "T1095",
        "name": "Non-Application Layer Protocol",
        "min_apis": 3,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": [
            "socket",
            "connect",
            "send",
            "recv",
            "WSASocketA",
            "WSAConnect",
            "WSASend",
            "WSARecv",
            "sendto",
            "recvfrom",
            "IcmpSendEcho",
        ],
    },
    {
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "min_apis": 2,
        "confidence_base": 0.46,
        "confidence_max": 0.62,
        "apis": [
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "URLDownloadToCacheFileA",
            "InternetReadFile",
            "WinHttpReadData",
            "FtpGetFileA",
        ],
    },
    # ------------------------------------------------------------------ Impact
    {
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "CryptEncrypt",
            "BCryptEncrypt",
            "CryptGenKey",
            "CryptDeriveKey",
            "BCryptGenerateSymmetricKey",
            "CryptAcquireContextA",
            "NCryptEncrypt",
            "BCryptDeriveKeyPBKDF2",
        ],
    },
    {
        "technique_id": "T1490",
        "name": "Inhibit System Recovery",
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["DeleteFileA", "SHFileOperationA", "ControlService", "DeleteService"],
    },
    {
        "technique_id": "T1489",
        "name": "Service Stop",
        "min_apis": 2,
        "confidence_base": 0.46,
        "confidence_max": 0.62,
        "apis": ["ControlService", "OpenServiceA", "DeleteService", "TerminateProcess"],
    },
    # ---------------------------------------------------------------- Execution
    {
        "technique_id": "T1106",
        "name": "Native API",
        "min_apis": 3,
        "confidence_base": 0.38,
        "confidence_max": 0.55,
        "apis": [
            "NtCreateUserProcess",
            "NtCreateFile",
            "NtWriteFile",
            "NtOpenKey",
            "NtSetValueKey",
            "NtQuerySystemInformation",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "LdrLoadDll",
            "RtlCreateProcessParameters",
        ],
    },
    # T1129 (Shared Modules) is deliberately absent for the same reason, only
    # more so: LoadLibrary + GetProcAddress appear in essentially every PE ever
    # compiled, so a rule keyed on them fires always and therefore carries zero
    # information. What *is* suspicious is that pair in a binary with almost no
    # other imports — dynamic API resolution — and that is already detected, as
    # an obfuscation indicator, by ``_pe_obfuscation_indicators``.
    # ------------------------------------------------------------------ Linux
    # Only where the mapping is uncontroversial: the symbols are the technique's
    # own mechanism rather than one plausible use of them. Every id here is
    # valid in the vendored catalogue and declares Linux, which a test checks,
    # and every one was measured against this machine's own ELF binaries before
    # it was kept — a rule that fires on more than one in a hundred ordinary
    # programs is not evidence of anything and was dropped.
    #
    # Four rules were written and removed on that measurement, and the reasons
    # are worth keeping so they are not written again:
    #   - Setuid and Setgid on the ``setuid``/``setgid`` family. The technique
    #     is abuse of the setuid *bit on a file*; calling ``setuid`` is how
    #     every daemon and every legitimate setuid helper drops privilege, and
    #     a symbol table cannot tell the two apart. It cleared on 6.3% of them,
    #     ``su`` and ``bash`` included, and the direction of the error is the
    #     dangerous one: a privilege drop published as an escalation.
    #   - Non-Application Layer Protocol on the BSD socket calls. Those calls
    #     evidence "it talks over a network" and nothing narrower; 5.8%,
    #     ``ping`` included.
    #   - System Owner/User Discovery (``getuid`` and friends) at 12.9% and
    #     System Information Discovery (``uname`` and friends) at 4.6%. Every
    #     program that prints a prompt asks who it is running as.
    #   - Web Protocols on the libcurl session calls and Encrypted Channel on
    #     the OpenSSL client session. Both are one plausible use of a library
    #     among many: linking libcurl evidences "it makes HTTP requests" and
    #     linking libssl "it speaks TLS", and the techniques are about a
    #     command channel. ``curl`` and ``openssl`` themselves cleared them.
    #
    # What is left is three rules whose symbols are the technique's own
    # mechanism and nothing else, the worst of which appears on 0.2% of the
    # measured binaries.
    {
        "technique_id": "T1055.008",
        "name": "Ptrace System Calls",
        "platforms": ["linux"],
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["ptrace", "process_vm_readv", "process_vm_writev"],
    },
    {
        "technique_id": "T1620",
        "name": "Reflective Code Loading",
        "platforms": ["linux"],
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["memfd_create", "fexecve"],
    },
    {
        "technique_id": "T1622",
        "name": "Debugger Evasion",
        "platforms": ["linux"],
        "min_apis": 2,
        "confidence_base": 0.46,
        "confidence_max": 0.62,
        "apis": ["ptrace", "personality"],
    },
]

_CONFIDENCE_CEILING = 0.65


def _vendored_ids() -> set[str]:
    """Every active technique id the vendored catalogue carries."""
    try:
        raw = json.loads(_VALID_IDS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(raw, list):
        return {str(tid) for tid in raw}
    if "technique_ids" in raw:
        return {str(tid) for tid in raw["technique_ids"]}
    # One id list per ATT&CK domain.
    return {str(tid) for ids in raw.values() if isinstance(ids, list) for tid in ids}


def _vendored_replacements() -> dict[str, str]:
    """``{retired id: the id ATT&CK says replaced it}`` from the vendored set.

    The bundle's own ``revoked-by`` relationship is the only authority. A
    retired id it names no successor for is not in this map, and the entry
    keyed on it is dropped rather than pointed somewhere plausible.
    """
    try:
        raw = json.loads(_RETIRED_IDS.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {
        str(tid): str(row["revoked_by"])
        for tid, row in raw.items()
        if isinstance(row, dict) and not str(tid).startswith("_") and row.get("revoked_by")
    }


def _vendored_platforms(technique_id: str) -> tuple[str, ...]:
    """The platforms the vendored table declares for an id, lowercased."""
    try:
        raw = json.loads(_TECHNIQUES.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    row = raw.get(technique_id)
    return tuple(str(p).lower() for p in (row or {}).get("platforms") or ())


def _retargeted(
    techniques: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[tuple[str, str]], list[str]]:
    """The technique rules against the current release, plus what moved and what went.

    A curated id the release retired is followed to its replacement where the
    vendored set names one; where it does not, the rule is dropped. Neither is
    a judgement call this file gets to make, which is the point: the source
    keeps the id it was written against and the catalogue decides what that id
    is called now.
    """
    valid = _vendored_ids()
    replacements = _vendored_replacements()
    kept: list[dict[str, Any]] = []
    moved: list[tuple[str, str]] = []
    dropped: list[str] = []
    for tech in techniques:
        tid = str(tech["technique_id"])
        if not valid or tid in valid:
            kept.append(tech)
            continue
        replacement = replacements.get(tid)
        if replacement and replacement in valid:
            kept.append({**tech, "technique_id": replacement})
            moved.append((tid, replacement))
        else:
            dropped.append(tid)
    return kept, moved, dropped


def _validate(techniques: list[dict[str, Any]]) -> list[str]:
    """Return a list of problems; empty means the tables are internally sound."""
    problems: list[str] = []

    # Every ATT&CK id must exist in the vendored catalog.
    valid_ids = _vendored_ids()
    if not valid_ids:
        problems.append(f"cannot read {_VALID_IDS}")

    known_apis = {
        platform: {api for _tier, apis in categories.values() for api in apis}
        for platform, categories in CATEGORIES_BY_PLATFORM.items()
    }

    for tech in techniques:
        tid = tech["technique_id"]
        platforms = [str(p) for p in tech.get("platforms") or ["windows"]]
        if valid_ids and tid not in valid_ids:
            problems.append(f"{tid} is not in attck_valid_ids.json")
        if tech["confidence_max"] > _CONFIDENCE_CEILING:
            problems.append(f"{tid} confidence_max {tech['confidence_max']} exceeds ceiling")
        if tech["confidence_base"] > tech["confidence_max"]:
            problems.append(f"{tid} confidence_base above confidence_max")
        if tech["min_apis"] > len(tech["apis"]):
            problems.append(f"{tid} min_apis exceeds its own api list")
        # An ATT&CK entry naming an API the behaviour table has never heard of is
        # almost always a typo, and a typo here is silent: the technique simply
        # never fires.
        for platform in platforms:
            if platform not in known_apis:
                problems.append(f"{tid} names the platform {platform!r}, which has no categories")
                continue
            for api in tech["apis"]:
                if api not in known_apis[platform]:
                    problems.append(f"{tid} references unknown {platform} API {api!r}")
        # A technique rule must apply to the platform it is filed under: the
        # id's own platforms in the vendored table say where it can.
        declared = _vendored_platforms(tid)
        for platform in platforms:
            if declared and platform not in {p.lower() for p in declared}:
                problems.append(
                    f"{tid} is filed under {platform} and the catalogue does not list it"
                )

    # Two rules on one id are allowed and one rule twice is not: a release that
    # folds two sub-techniques into one technique — 19.2 folded Disable or
    # Modify Tools and Indicator Blocking into T1685 — leaves two distinct
    # evidence rules pointing at the same id, and each keeps its own APIs, its
    # own min_apis, its own confidence and its own ``rule`` label. The same
    # technique evidenced on two platforms is two rules as well, from two
    # vocabularies. A repeated (platform, id, name, rule) is the copy the
    # duplicate check exists to catch.
    seen: set[tuple[str, str, str, str]] = set()
    for tech in techniques:
        for platform in (str(p) for p in tech.get("platforms") or ["windows"]):
            rule = (
                platform,
                str(tech["technique_id"]),
                str(tech["name"]),
                str(tech.get("rule") or ""),
            )
            if rule in seen:
                label = f" {rule[3]!r}" if rule[3] else ""
                problems.append(f"duplicate {rule[0]} technique {rule[1]} {rule[2]!r}{label}")
            seen.add(rule)

    # An API in two categories has no defined tier. The consumer is a reverse
    # index — one dict, one entry per name — so whichever category is built last
    # silently wins, and the two categories rarely share a tier: on 2026-07-28
    # CheckTokenMembership sat in both `privilege` (high, therefore suspicious)
    # and `discovery` (informational, therefore not), which meant the import's
    # suspicion depended on dict ordering rather than on anything about the
    # import. Ambiguity here is not a style problem, it is nondeterminism.
    for platform, categories in CATEGORIES_BY_PLATFORM.items():
        owners: dict[str, list[str]] = {}
        for category, (_tier, apis) in categories.items():
            for api in apis:
                owners.setdefault(api.lower(), []).append(category)
        for api, cats in sorted(owners.items()):
            if len(cats) > 1:
                problems.append(
                    f"{platform} {api!r} claimed by more than one category: {sorted(cats)}"
                )

    return problems


def _block(platform: str, category: str) -> dict[str, object]:
    """One category as the catalog carries it, corroborators included."""
    tier, apis = CATEGORIES_BY_PLATFORM[platform][category]
    block: dict[str, object] = {"tier": tier}
    corroborators = CORROBORATORS_BY_PLATFORM.get(platform, {}).get(category)
    if corroborators:
        block["corroborated_by"] = sorted(set(corroborators))
    gate = FLAG_GATES_BY_PLATFORM.get(platform, {}).get(category)
    if gate:
        block["flags_with"] = sorted(set(gate))
    block["apis"] = sorted(set(apis))
    return block


def main() -> int:
    techniques, moved, dropped = _retargeted(ATTCK_TECHNIQUES)
    for old, new in moved:
        print(f"retargeted {old} -> {new} (the vendored set names it as the replacement)")
    for old in dropped:
        print(f"dropped {old}: the release retired it and names no replacement")
    problems = _validate(techniques)
    if problems:
        for p in problems:
            print(f"ERROR: {p}", file=sys.stderr)
        return 1

    behaviour = {
        "schema": "maljan-api-behaviour/v1",
        "version": "1.0",
        "platforms": {
            platform: {cat: _block(platform, cat) for cat in categories}
            for platform, categories in CATEGORIES_BY_PLATFORM.items()
        },
    }
    attck = {
        "schema": "maljan-api-attck/v1",
        "version": "1.0",
        "techniques": [
            {**t, "platforms": t.get("platforms") or ["windows"], "apis": sorted(set(t["apis"]))}
            for t in techniques
        ],
    }

    _BEHAVIOUR_OUT.write_text(json.dumps(behaviour, indent=2) + "\n", encoding="utf-8")
    _ATTCK_OUT.write_text(json.dumps(attck, indent=2) + "\n", encoding="utf-8")

    for platform, categories in CATEGORIES_BY_PLATFORM.items():
        total_apis = sum(len(set(apis)) for _tier, apis in categories.values())
        print(
            f"wrote {_BEHAVIOUR_OUT.relative_to(_ROOT)}: "
            f"{platform}, {len(categories)} categories, {total_apis} APIs"
        )
    print(f"wrote {_ATTCK_OUT.relative_to(_ROOT)}: {len(techniques)} techniques")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
