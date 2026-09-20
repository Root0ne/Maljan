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
# The rule of thumb is now a measurement, on both platforms. A category is
# labelled only when its own measured rate separates software that is a sample
# from software that is not, and only behind the combination its ``flags_with``
# names. Measured over the two Windows corpora described in ``MEASURED``, the
# nine Windows categories that carried a bare ``high`` or ``medium`` appeared on
# 97.73% of ordinary Windows software against 93.50% of malware — the label was
# very slightly more common on the benign side, which is no signal at all. Every
# one of them is informational here and says what would give it weight;
# ``keylogging`` is the one that keeps a label, behind the input hook or
# raw-input device that is the capture.

HIGH = "high"
MEDIUM = "medium"
INFO = "informational"


# What a category needs beside it to mean something. A category that is
# informational on its own says nothing about a sample, and saying only that
# leaves the reader to guess what would change the answer; these names travel
# in the manifest as ``corroborated_by`` and ``api_capability`` puts them on
# the row. Only categories that need it are listed.
WINDOWS_CORROBORATORS: dict[str, list[str]] = {
    # Allocating and protecting memory is what a just-in-time compiler and a
    # trampoline do; what makes it injection is a thread started elsewhere.
    "process_injection": [
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "QueueUserAPC",
        "RtlCreateUserThread",
    ],
    # A handle read and an exception filter are a C runtime starting up; the
    # evasion is the scanner or the tracing provider turned off beside them.
    "evasion": [
        "AmsiScanBuffer",
        "EtwEventWrite",
        "NtSetInformationProcess",
        "RtlSetProcessIsCritical",
        "Wow64DisableWow64FsRedirection",
    ],
    # Loading a library and resolving an export is every program on the
    # platform; what gives it weight is code fetched over the network or
    # started inside another process.
    "execution": [
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "WriteProcessMemory",
    ],
    # Reading the clock and asking about the program's own debug state is a
    # runtime routing its diagnostics; the question about another process's
    # debug port, or a thread hidden from the debugger, is not.
    "anti_debug": [
        "CheckRemoteDebuggerPresent",
        "DebugActiveProcess",
        "NtQueryInformationProcess",
        "NtSetInformationThread",
    ],
    # A socket is a socket. What the traffic is for shows in what the same
    # binary does with the clipboard, the screen or a shell.
    "network": [
        "CryptEncrypt",
        "GetClipboardData",
        "URLDownloadToFileA",
        "URLDownloadToFileW",
        "WinExec",
    ],
    # Encryption beside a directory walk and a rename is the shape of
    # ransomware; encryption on its own is how a program stores a secret.
    "crypto": [
        "DeleteFileA",
        "FindFirstFileA",
        "MoveFileExA",
        "connect",
        "socket",
    ],
    # Reading your own token is how a program finds out whether it is elevated.
    "privilege": [
        "CreateRemoteThread",
        "DuplicateTokenEx",
        "ImpersonateLoggedOnUser",
        "WriteProcessMemory",
    ],
    # A mutex and an event are how a program keeps one copy of itself running;
    # persistence is arranging to be started again by something else.
    "persistence": [
        "CreateServiceA",
        "CreateServiceW",
        "RegSetValueExA",
        "RegSetValueExW",
        "SHSetValueA",
    ],
    # Reading a credential store is what a password manager and a mail client
    # do; what gives it weight is the same binary capturing input or sending
    # what it found somewhere.
    "credential": [
        "CryptUnprotectData",
        "GetClipboardData",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "WinHttpSendRequest",
    ],
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
        INFO,
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
        INFO,
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
        INFO,
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
        INFO,
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
        INFO,
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
        INFO,
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
        INFO,
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
        INFO,
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
        INFO,
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
# ``suspicious`` label on. A category with no entry here is informational and
# is never labelled. ``process_injection`` has one because ``memfd_create`` by
# itself is ordinary in the graphics and service stacks, while the same symbol
# beside a call that reaches into another process is not.
LINUX_FLAG_GATES: dict[str, list[str]] = {
    "process_injection": ["process_vm_readv", "process_vm_writev", "ptrace"],
}

# The Windows counterpart, and the only Windows category that carries a label.
# Asking for the state of one key, naming a key for a key-binding screen, or
# closing the clipboard is what an editor, a game and a hotkey manager do every
# frame. The capture is the channel: an input hook, a raw-input device, or a
# read of the whole keyboard at once, which delivers keystrokes the program was
# never sent.
WINDOWS_FLAG_GATES: dict[str, list[str]] = {
    "keylogging": [
        "AttachThreadInput",
        "GetAsyncKeyState",
        "GetKeyboardState",
        "GetRawInputData",
        "RegisterRawInputDevices",
        "SetWinEventHook",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
    ],
}

CORROBORATORS_BY_PLATFORM: dict[str, dict[str, list[str]]] = {
    "windows": WINDOWS_CORROBORATORS,
    "linux": LINUX_CORROBORATORS,
}

FLAG_GATES_BY_PLATFORM: dict[str, dict[str, list[str]]] = {
    "windows": WINDOWS_FLAG_GATES,
    "linux": LINUX_FLAG_GATES,
}


# ---------------------------------------------------------------------------
# What each association was measured on
# ---------------------------------------------------------------------------
# The number a surviving association carries is the share of *benign* software
# it fires on, measured through the production loader over a named corpus, and
# it travels with the association to the model, to the report and to the
# console. It is the fact the platform states; the model weighs it.
#
# What it is not. There is no technique-level ground truth for either malware
# corpus: what was measured is discrimination between binaries already known to
# be bad and binaries already known to be good, never that a sample performs
# the technique a rule names. 29.2% of the Windows malware corpus imports
# nothing an import rule can see — packed, .NET, or resolving everything
# through ``GetProcAddress`` — so neither the recall nor the gates generalise
# beyond this pair of corpora. Every gate below was chosen from a written
# sentence about behaviour and then measured, not searched for.

BENIGN_CORPORA: dict[str, str] = {
    "windows": "2730 freely distributed Windows binaries from 25 independent vendors",
    "linux": "1842 ELF binaries with a dynamic symbol table under /usr/bin and /usr/sbin",
}

# The malware side, where there is one. A profile is a distinct import set, not
# a file: 201 parsed Windows samples collapse to 123 sets, and the held-out part
# is the half of them the combinations were not chosen on. There is no Linux
# malware corpus, so a Linux row carries a benign rate and says nothing about
# recall rather than implying one.
HELD_OUT_CORPORA: dict[str, str] = {
    "windows": "46 distinct import profiles the combinations were not chosen on",
}

# Per platform and category, how much of that corpus the category appears on,
# and — where the category is labelled — how much of it the gate labels.
MEASURED_CATEGORIES: dict[str, dict[str, dict[str, Any]]] = {
    "windows": {
        "process_injection": {"benign_percent": 65.6, "benign_files": 1790},
        "anti_debug": {"benign_percent": 36.6, "benign_files": 1000},
        "network": {"benign_percent": 14.4, "benign_files": 392},
        "crypto": {"benign_percent": 19.0, "benign_files": 520},
        "filesystem": {"benign_percent": 35.6, "benign_files": 972},
        "registry": {"benign_percent": 13.2, "benign_files": 359},
        "privilege": {"benign_percent": 9.8, "benign_files": 267},
        "execution": {"benign_percent": 93.5, "benign_files": 2552},
        "discovery": {"benign_percent": 56.4, "benign_files": 1541},
        "persistence": {"benign_percent": 16.8, "benign_files": 460},
        "keylogging": {
            "benign_percent": 4.0,
            "benign_files": 110,
            "labelled_percent": 2.0,
            "labelled_files": 55,
            "held_out_malware_profiles": 7,
        },
        "screen_capture": {"benign_percent": 5.2, "benign_files": 143},
        "message_loop": {"benign_percent": 5.7, "benign_files": 155},
        "evasion": {"benign_percent": 79.6, "benign_files": 2174},
        "credential": {"benign_percent": 1.2, "benign_files": 33},
    },
    "linux": {
        "process_injection": {
            "benign_percent": 0.9,
            "benign_files": 17,
            "labelled_percent": 0.3,
            "labelled_files": 5,
        },
        "anti_debug": {"benign_percent": 1.2, "benign_files": 22},
        "network": {"benign_percent": 15.6, "benign_files": 287},
        "crypto": {"benign_percent": 2.4, "benign_files": 44},
        "filesystem": {"benign_percent": 79.3, "benign_files": 1461},
        "discovery": {"benign_percent": 47.8, "benign_files": 881},
        "privilege": {"benign_percent": 7.9, "benign_files": 146},
        "execution": {"benign_percent": 22.7, "benign_files": 418},
        "process": {"benign_percent": 18.6, "benign_files": 342},
    },
}


ATTCK_TECHNIQUES: list[dict[str, Any]] = [
    # Every Windows rule below was measured in its shipped form over both
    # corpora, and fifteen of the forty-seven are gone because that measurement
    # found nothing in them: within the size-matched band their names fired no
    # more often on malware than on ordinary software. Those fifteen are named
    # where they used to stand, so the same rule is not written twice.
    #
    # Of the thirty-two left, fourteen carry a narrower combination than they
    # shipped with. A name was taken out of a rule only where the act it names
    # is not the act the technique describes — ``TerminateProcess`` ends a
    # process and not a service, ``MoveFileEx`` renames a file and does not
    # delete it, ``IsProcessorFeaturePresent`` is the C runtime asking about the
    # processor at startup. A name was never taken out for being common: a
    # combination chosen because it happened to separate these two corpora best
    # is a number, not a reason, and eight such combinations were written,
    # measured and then not applied.
    #
    # Every row states what it is: ``rule`` is the combination in words,
    # ``ordinary_use`` names the software that is not a sample and imports the
    # same names, and ``measured`` is how much of the benign corpus the rule
    # fires on. A technique association is a reference association — never a
    # finding, never a verdict, never a label of its own.
    # ---------------------------------------------------------------- Discovery
    {
        "technique_id": "T1057",
        "name": "Process Discovery",
        "rule": "walking the process list and naming the executables behind it",
        "ordinary_use": (
            "a task manager, an installer looking for a copy of itself already "
            "running, and every updater walk the same snapshot"
        ),
        "measured": {"benign_percent": 1.5, "benign_files": 42, "held_out_malware_profiles": 6},
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
        # ``GetSystemMetrics`` was taken out and put back. It returns the screen
        # geometry, which is how a window lays itself out — but it is also a
        # system metric, and this technique is reading system information. The
        # only argument for removing it was that it is common.
        "technique_id": "T1082",
        "name": "System Information Discovery",
        "rule": "reading the host's version, hardware and volume identity",
        "ordinary_use": (
            "a crash reporter, an installer and a licence check collect the same "
            "facts about the machine they are on"
        ),
        "measured": {"benign_percent": 4.1, "benign_files": 111, "held_out_malware_profiles": 9},
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
        "rule": "asking which account the program is running as",
        "ordinary_use": (
            "an installer, a licence check and any program writing into a user "
            "profile ask the same question"
        ),
        "measured": {"benign_percent": 1.6, "benign_files": 45, "held_out_malware_profiles": 3},
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
    # T1087 Account Discovery stood here and is gone: it fired on no malware
    # profile in the corpus at all, at any import-table size.
    {
        # The native spellings could have been kept alone, which would have put
        # the rule under a tenth of a percent of ordinary software. Reading a
        # key through ntdll rather than advapi32 is a different route to the
        # same act, and the route is not the technique.
        "technique_id": "T1012",
        "name": "Query Registry",
        "rule": "reading values out of the registry",
        "ordinary_use": (
            "every program that remembers a setting reads it back with these "
            "calls, and an import table does not carry which key was read"
        ),
        "measured": {"benign_percent": 4.4, "benign_files": 119, "held_out_malware_profiles": 12},
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
        # Narrowing this to the enumeration calls alone — dropping the ones that
        # ask about a single named file — was written and not applied: looking
        # in a specific location is inside this technique's own description, so
        # the only thing the narrower list had going for it was its rate.
        "technique_id": "T1083",
        "name": "File and Directory Discovery",
        "rule": "walking directories and reading the attributes of what is in them",
        "ordinary_use": (
            "a search tool, a backup agent, an installer and every archiver walk "
            "a tree the same way"
        ),
        "measured": {"benign_percent": 6.4, "benign_files": 175, "held_out_malware_profiles": 14},
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
        "rule": "enumerating the windows on the desktop and reading their titles and classes",
        "ordinary_use": (
            "an accessibility tool, a window manager and a program looking for "
            "its own running copy walk the same list"
        ),
        "measured": {"benign_percent": 2.6, "benign_files": 70, "held_out_malware_profiles": 7},
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
    # T1016 System Network Configuration Discovery and T1049 System Network
    # Connections Discovery stood here and are gone: neither fired on a single
    # malware profile.
    {
        "technique_id": "T1007",
        "name": "System Service Discovery",
        "rule": "opening the service manager and listing the services on the host",
        "ordinary_use": (
            "an installer, a monitoring agent and every service-control panel "
            "enumerate services the same way"
        ),
        "measured": {"benign_percent": 0.8, "benign_files": 23, "held_out_malware_profiles": 1},
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
        "rule": "reading the locale, the keyboard layout and the time zone",
        "ordinary_use": "every program that formats a date or a number reads the same settings",
        "measured": {"benign_percent": 6.8, "benign_files": 185, "held_out_malware_profiles": 8},
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
        # Opening the service manager, starting a service, sending it a control
        # code and removing it are administration, which is not what this
        # technique names. Creating a service and rewriting an existing one's
        # configuration is.
        "technique_id": "T1543.003",
        "name": "Create or Modify System Process: Windows Service",
        "rule": "creating a service, or rewriting an existing service's configuration",
        "ordinary_use": (
            "an installer and a management agent create and reconfigure their "
            "own services the same way"
        ),
        "measured": {"benign_percent": 0.3, "benign_files": 7, "held_out_malware_profiles": 0},
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "CreateServiceA",
            "CreateServiceW",
            "ChangeServiceConfigA",
            "ChangeServiceConfig2A",
        ],
    },
    {
        # No narrower combination was applied, because there is none to write:
        # every name here is the act of writing the registry, and the Run key
        # that makes the write persistence is a path.
        "technique_id": "T1547.001",
        "name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "rule": "creating a registry key and writing a value into it",
        "ordinary_use": (
            "every program that saves a setting writes a value, and the key that "
            "would make this persistence is a path an import table does not carry"
        ),
        "measured": {"benign_percent": 4.0, "benign_files": 108, "held_out_malware_profiles": 12},
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
    # T1053.005 Scheduled Task and T1546.003 WMI Event Subscription stood here
    # and are gone. Most of what they keyed on were COM interface names, which
    # are never in an import table — a GUID passed to CoCreateInstance is not a
    # symbol — so each had one or two real exports behind a floor of two and
    # neither could fire on anything, benign or otherwise. That evidence belongs
    # to a layer that reads strings.
    # --------------------------------------------------------- Privilege Esc.
    {
        # Opening a token and enabling a privilege the account already holds is
        # what a backup tool, a service and an installer do; and setting a
        # token's integrity level is how a launcher sandboxes its own child.
        # Manipulation in the sense this technique names is duplicating a token
        # and running or impersonating with it.
        "technique_id": "T1134",
        "name": "Access Token Manipulation",
        "rule": "duplicating an access token and running or impersonating with it",
        "ordinary_use": (
            "a service running work as the logged-on user, a named-pipe server "
            "and a task launcher duplicate tokens the same way"
        ),
        "measured": {"benign_percent": 0.4, "benign_files": 11, "held_out_malware_profiles": 4},
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": [
            "DuplicateTokenEx",
            "DuplicateToken",
            "SetThreadToken",
            "ImpersonateLoggedOnUser",
            "CreateProcessWithTokenW",
            "CreateProcessAsUserA",
            "ImpersonateNamedPipeClient",
        ],
    },
    {
        # Checking whether you are already an administrator and asking the shell
        # to run something elevated is how a program *requests* elevation, with
        # the consent prompt the user sees. The bypass is binding to an object
        # that is already elevated, through its moniker.
        "technique_id": "T1548.002",
        "name": "Abuse Elevation Control Mechanism: Bypass UAC",
        "rule": "binding to an already elevated COM object through its moniker",
        "ordinary_use": (
            "a setup program and a management console bind to an elevated COM "
            "object to do one privileged step"
        ),
        "measured": {"benign_percent": 0.0, "benign_files": 0, "held_out_malware_profiles": 2},
        "min_apis": 2,
        "confidence_base": 0.45,
        "confidence_max": 0.62,
        "apis": ["CoGetObject", "CLSIDFromProgID"],
    },
    # ------------------------------------------------------- Defense Evasion
    {
        # Opening a handle to another process is what a task manager, a debugger
        # and an updater do. Installing a global input hook is input capture's
        # own mechanism and is counted there; whether the hook's module lands in
        # another process is a runtime fact.
        "technique_id": "T1055",
        "name": "Process Injection",
        "rule": "allocating or writing memory in another process and starting a thread in it",
        "ordinary_use": (
            "a debugger, a profiler, an anti-cheat and an accessibility shim "
            "reach into another process with the same calls"
        ),
        "measured": {"benign_percent": 0.5, "benign_files": 13, "held_out_malware_profiles": 5},
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
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
        ],
    },
    {
        # Reading a thread's context is what a crash reporter does and resuming
        # a suspended child is how every launcher starts one. Writing the
        # context is redirecting execution, and unmapping the image is replacing
        # it.
        "technique_id": "T1055.012",
        "name": "Process Injection: Process Hollowing",
        "rule": (
            "unmapping a new process's image, or writing over it and pointing "
            "its thread at the replacement"
        ),
        "ordinary_use": (
            "a launcher that patches a child before it runs and an emulator that "
            "loads its own image use the same calls"
        ),
        "measured": {"benign_percent": 0.4, "benign_files": 10, "held_out_malware_profiles": 3},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "NtUnmapViewOfSection",
            "ZwUnmapViewOfSection",
            "SetThreadContext",
            "WriteProcessMemory",
            "CreateProcessInternalW",
        ],
    },
    # T1620 Reflective Code Loading stood here on the section and file-mapping
    # calls and is gone: mapping a section is how a program reads a large file,
    # and the rule appeared on ordinary software and on malware at the same
    # rate. The Linux rule of the same id survives on ``memfd_create``, which
    # names the act rather than a means to it.
    {
        # Narrowing this to the questions asked about *another* process's debug
        # port was written and not applied: this technique's own description
        # names ``IsDebuggerPresent`` and the output-debug trick, so removing
        # them would have been a statement about how common they are.
        "technique_id": "T1622",
        "name": "Debugger Evasion",
        "rule": "asking whether a debugger is attached and taking the debug path",
        "ordinary_use": (
            "a C runtime routes an assertion this way, and a crash reporter, a "
            "profiler and a debugger itself call the same functions"
        ),
        "measured": {"benign_percent": 7.5, "benign_files": 205, "held_out_malware_profiles": 6},
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
        # ``IsProcessorFeaturePresent`` is the C runtime asking whether the
        # processor has an instruction set, at startup, in two out of five
        # binaries ever compiled. It is not a question about a virtual machine.
        "technique_id": "T1497",
        "name": "Virtualization/Sandbox Evasion",
        "rule": (
            "reading the firmware tables, enumerating device instances, or "
            "checking whether a person is at the machine"
        ),
        "ordinary_use": (
            "a hardware inventory tool, a driver installer, a screensaver and a "
            "presentation program ask the same questions"
        ),
        "measured": {"benign_percent": 0.5, "benign_files": 13, "held_out_malware_profiles": 1},
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
        ],
    },
    {
        # Nothing was taken out and nothing could be: all eight are ordinary
        # timing calls and all eight are equally this technique's, because the
        # evasion is the *duration* a program waits, which no import carries.
        # This is the highest benign rate in the catalogue and it is stated
        # rather than tuned away.
        "technique_id": "T1497.003",
        "name": "Virtualization/Sandbox Evasion: Time Based Evasion",
        "rule": "reading the clock and the performance counters",
        "ordinary_use": (
            "every program that measures how long something took reads the same "
            "counters, and the evasion is a duration an import table cannot show"
        ),
        "measured": {"benign_percent": 9.6, "benign_files": 261, "held_out_malware_profiles": 14},
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
        # Keeping only the hive calls was written and not applied. Writing a
        # value *is* modifying the registry; loading a hive is a rarer sibling,
        # not a purer form of the same act.
        "technique_id": "T1112",
        "name": "Modify Registry",
        "rule": "writing or deleting registry keys and values",
        "ordinary_use": (
            "every program that saves a setting writes the registry, and an "
            "import table does not carry which key was written"
        ),
        "measured": {"benign_percent": 4.9, "benign_files": 135, "held_out_malware_profiles": 13},
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
    # T1222 File and Directory Permissions Modification stood here and is gone:
    # it appeared on ordinary software twice as often as on malware.
    #
    # Two rules on the scanning and tracing provider calls — the pair ATT&CK
    # 19.2 folded into T1685 — stood here and are gone. Neither fired on a
    # malware profile; between them they appeared on three benign binaries.
    {
        # ``MoveFileEx`` renames a file. It is in this rule for the flag that
        # defers the move until reboot, and the flag is an argument, not an
        # import.
        "technique_id": "T1070.004",
        "name": "Indicator Removal: File Deletion",
        "rule": "deleting a file through more than one of the deletion calls",
        "ordinary_use": (
            "an uninstaller, a cache cleaner and a build tool delete their own files the same way"
        ),
        "measured": {"benign_percent": 0.5, "benign_files": 13, "held_out_malware_profiles": 9},
        "min_apis": 2,
        "confidence_base": 0.38,
        "confidence_max": 0.55,
        "apis": [
            "DeleteFileA",
            "DeleteFileW",
            "SHFileOperationA",
            "DeleteFileTransactedA",
            "NtDeleteFile",
        ],
    },
    {
        "technique_id": "T1070.006",
        "name": "Indicator Removal: Timestomp",
        "rule": "reading a file's timestamps and writing them onto another",
        "ordinary_use": (
            "an archiver, a copy tool and a build system restore the original "
            "timestamps with exactly this pair"
        ),
        "measured": {"benign_percent": 0.5, "benign_files": 14, "held_out_malware_profiles": 3},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["SetFileTime", "GetFileTime", "NtSetInformationFile"],
    },
    # T1027 Obfuscated Files or Information and T1140 Deobfuscate/Decode stood
    # here and are gone: between them they appeared on nine benign binaries and
    # on no malware profile at all.
    #
    # T1036 (Masquerading) and T1218 (System Binary Proxy Execution) are
    # deliberately absent. Masquerading is a property of a file's *name and
    # appearance*, which an import table cannot see — SetFileAttributes and
    # CopyFile are the wrong evidence for it. Proxy execution needs the command
    # line, which the LOLBin layer already reads from sandbox telemetry;
    # inferring it from "this binary can start a process" would fire on nearly
    # everything and add nothing the LOLBin layer does not do properly.
    {
        # Asking whether a window is visible is not hiding one. What is left is
        # the second desktop, which the user never sees.
        "technique_id": "T1564.003",
        "name": "Hide Artifacts: Hidden Window",
        "rule": "creating a second desktop, or moving a thread onto one",
        "ordinary_use": (
            "a login screen, a screensaver host and an automation harness run "
            "their work on a desktop of their own"
        ),
        "measured": {"benign_percent": 0.1, "benign_files": 4, "held_out_malware_profiles": 0},
        "min_apis": 2,
        "confidence_base": 0.44,
        "confidence_max": 0.60,
        "apis": [
            "CreateDesktopA",
            "SwitchDesktop",
            "SetThreadDesktop",
            "OpenDesktopA",
        ],
    },
    # ----------------------------------------------------- Credential Access
    {
        # Asking for the state of one key is reading input the thread was
        # already sent, and naming a key or mapping its scan code is what a
        # key-binding screen does. The capture is the channel: a hook, a
        # raw-input device, or a read of the whole keyboard at once.
        "technique_id": "T1056.001",
        "name": "Input Capture: Keylogging",
        "rule": "an input hook, a raw-input device or a read of the whole keyboard's state",
        "ordinary_use": (
            "a hotkey manager, an on-screen keyboard, a game and a "
            "remote-desktop client install the same hooks"
        ),
        "measured": {"benign_percent": 1.2, "benign_files": 34, "held_out_malware_profiles": 5},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": [
            "GetAsyncKeyState",
            "GetKeyboardState",
            "RegisterRawInputDevices",
            "GetRawInputData",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "AttachThreadInput",
            "ToUnicodeEx",
            "SetWinEventHook",
        ],
    },
    # T1555 Credentials from Password Stores and T1003 OS Credential Dumping
    # stood here and are gone. Both read as the sharpest rules in the block and
    # neither fired on one malware profile: the credential theft in this corpus
    # is done by code that resolves those names at runtime, or by a .NET
    # assembly with no import table to read.
    {
        # Binding a socket and receiving a datagram is every UDP program, and
        # ``ioctlsocket`` is how a socket is put into non-blocking mode. The
        # sniff is the adapter itself, reconfigured through WSAIoctl on a socket
        # made by WSASocket.
        "technique_id": "T1040",
        "name": "Network Sniffing",
        "rule": "a socket created through WSASocket and reconfigured through WSAIoctl",
        "ordinary_use": (
            "a packet-capture library, a network monitor and a VPN client create "
            "and reconfigure sockets this way"
        ),
        "measured": {"benign_percent": 1.0, "benign_files": 26, "held_out_malware_profiles": 0},
        "min_apis": 2,
        "confidence_base": 0.48,
        "confidence_max": 0.65,
        "apis": ["WSAIoctl", "WSASocketA"],
    },
    # --------------------------------------------------------------- Collection
    {
        # A blit between two device contexts is how every program with a window
        # draws, and which context it reads from is an argument. The capture is
        # the readback: the pixels copied into the program's own memory, another
        # window's device context taken, or a window asked to render itself.
        "technique_id": "T1113",
        "name": "Screen Capture",
        "rule": "pulling the pixels back out of a window or screen device context",
        "ordinary_use": (
            "a screenshot tool, a remote-desktop server and a screen recorder "
            "read a device context the same way"
        ),
        "measured": {"benign_percent": 0.3, "benign_files": 8, "held_out_malware_profiles": 6},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["GetDIBits", "GetWindowDC", "PrintWindow"],
    },
    {
        # Opening and closing the clipboard brackets every copy and every paste,
        # and putting something on it is not taking something off it.
        "technique_id": "T1115",
        "name": "Clipboard Data",
        "rule": "reading what is on the clipboard, or asking to be told each time it changes",
        "ordinary_use": (
            "a clipboard manager, a password manager and an editor's paste path "
            "read the clipboard the same way"
        ),
        "measured": {"benign_percent": 0.6, "benign_files": 17, "held_out_malware_profiles": 4},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["GetClipboardData", "IsClipboardFormatAvailable", "AddClipboardFormatListener"],
    },
    {
        "technique_id": "T1123",
        "name": "Audio Capture",
        "rule": "opening a wave input device and starting it",
        "ordinary_use": (
            "a voice-chat client, a dictation tool and a recorder open the microphone the same way"
        ),
        "measured": {"benign_percent": 0.2, "benign_files": 5, "held_out_malware_profiles": 1},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["waveInOpen", "waveInStart", "capCreateCaptureWindowA"],
    },
    # ------------------------------------------------------- Command & Control
    {
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "rule": "speaking HTTP through the WinINet or WinHTTP stack",
        "ordinary_use": (
            "an updater, a licence check, a telemetry client and every "
            "downloader use the same stack"
        ),
        "measured": {"benign_percent": 0.7, "benign_files": 19, "held_out_malware_profiles": 7},
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
    # T1071.004 Application Layer Protocol: DNS stood here and is gone: it fired
    # on no malware profile.
    {
        # The ten Berkeley and Winsock names this rule shipped with are gone.
        # They label one benign binary in twenty and more than a third of
        # everything that touches a network, and a raw socket and a TCP socket
        # are the same import — the protocol is an argument to ``socket``. One
        # name is left and it is the only one that names the act: an echo
        # request is ICMP by construction. It fires on one benign binary in a
        # thousand and needs no second name to say so, so the floor is one.
        "technique_id": "T1095",
        "name": "Non-Application Layer Protocol",
        "rule": "sending an ICMP echo request",
        "ordinary_use": (
            "ping, a network diagnostic tool and a reachability check send the same echo request"
        ),
        "measured": {"benign_percent": 0.1, "benign_files": 2, "held_out_malware_profiles": 2},
        "min_apis": 1,
        "confidence_base": 0.40,
        "confidence_max": 0.58,
        "apis": ["IcmpSendEcho"],
    },
    {
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "rule": "fetching a file over HTTP or FTP straight to disk",
        "ordinary_use": "an updater and an installer download their payload with the same calls",
        "measured": {"benign_percent": 0.0, "benign_files": 0, "held_out_malware_profiles": 0},
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
        # Dropping ``CryptAcquireContextA`` was written and not applied. The
        # floor of two already stops the provider handle firing on its own, and
        # acquiring it is part of the same chain as the key and the encryption.
        "technique_id": "T1486",
        "name": "Data Encrypted for Impact",
        "rule": "deriving or generating a symmetric key and encrypting with it",
        "ordinary_use": (
            "a backup tool, a password manager and any program storing a secret "
            "at rest encrypt the same way"
        ),
        "measured": {"benign_percent": 0.4, "benign_files": 12, "held_out_malware_profiles": 1},
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
        # This rule's four names are the union of file deletion and service
        # stop, and no subset of them is shadow-copy destruction — that is a
        # command line. The row says what it keys on so a reader is not left
        # with the technique's name alone.
        "technique_id": "T1490",
        "name": "Inhibit System Recovery",
        "rule": "deleting a file and stopping or removing a service",
        "ordinary_use": (
            "an uninstaller removes its service and deletes its files with the "
            "same pair, and the recovery data this technique destroys is reached "
            "through a command line rather than an import"
        ),
        "measured": {"benign_percent": 1.8, "benign_files": 50, "held_out_malware_profiles": 9},
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["DeleteFileA", "SHFileOperationA", "ControlService", "DeleteService"],
    },
    {
        # ``TerminateProcess`` ends a process, and which process it ends is an
        # argument; overwhelmingly it is a child the program started itself. A
        # service is stopped through the service manager.
        "technique_id": "T1489",
        "name": "Service Stop",
        "rule": "opening a service and stopping or removing it",
        "ordinary_use": (
            "an installer, an uninstaller and every service-control panel stop "
            "services the same way"
        ),
        "measured": {"benign_percent": 1.7, "benign_files": 46, "held_out_malware_profiles": 1},
        "min_apis": 2,
        "confidence_base": 0.46,
        "confidence_max": 0.62,
        "apis": ["ControlService", "OpenServiceA", "DeleteService"],
    },
    # ---------------------------------------------------------------- Execution
    # T1106 Native API stood here and is gone: it fired on one benign binary and
    # on no malware profile. Malware that goes straight to ntdll resolves those
    # names at runtime, which is the one thing an import rule cannot see.
    #
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
    # and every one was measured against a host's own ELF binaries before it was
    # kept — a rule that fires on more than one in a hundred ordinary programs
    # is not evidence of anything and was dropped.
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
    #     ``ping`` included. The Windows block reached the same place from the
    #     other direction and is down to the one ICMP name.
    #   - System Owner/User Discovery (``getuid`` and friends) at 12.9% and
    #     System Information Discovery (``uname`` and friends) at 4.6%. Every
    #     program that prints a prompt asks who it is running as.
    #   - Web Protocols on the libcurl session calls and Encrypted Channel on
    #     the OpenSSL client session. Both are one plausible use of a library
    #     among many: linking libcurl evidences "it makes HTTP requests" and
    #     linking libssl "it speaks TLS", and the techniques are about a
    #     command channel. ``curl`` and ``openssl`` themselves cleared them.
    #
    # What is left is two rules whose symbols are the technique's own mechanism
    # and nothing else, the worse of which appears on 0.2% of the measured
    # binaries.
    #
    # Each carries the sentence a reader needs beside it, and the rate it was
    # measured at. The rule states a mechanism, and the same mechanism is the
    # ordinary working of software that is not a sample; a row that does not say
    # so reads as an accusation, which is not what a reference lookup may be.
    {
        "technique_id": "T1055.008",
        "name": "Ptrace System Calls",
        "rule": "attaching to another process and reading or writing its memory",
        "ordinary_use": (
            "a debugger, a tracer and a crash reporter reach into another process "
            "with exactly this pair"
        ),
        "measured": {"benign_percent": 0.2, "benign_files": 3},
        "platforms": ["linux"],
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["ptrace", "process_vm_readv", "process_vm_writev"],
    },
    {
        "technique_id": "T1620",
        "name": "Reflective Code Loading",
        "rule": "executing an anonymous file that was never written to disk",
        "ordinary_use": (
            "a language runtime, a just-in-time compiler and a sandbox launcher "
            "execute anonymous memory the same way"
        ),
        "measured": {"benign_percent": 0.1, "benign_files": 1},
        "platforms": ["linux"],
        "min_apis": 2,
        "confidence_base": 0.50,
        "confidence_max": 0.65,
        "apis": ["memfd_create", "fexecve"],
    },
    # Debugger Evasion was written here on ``ptrace`` and ``personality`` and
    # is gone. The technique is a process tracing *itself* so that no debugger
    # can attach, and turning address randomisation off for its own image; an
    # import list shows that a program can call ptrace and cannot show what it
    # calls it on. Measured, the rule named four binaries and every one was a
    # debugger — the population whose ordinary working the symbols are, rather
    # than the one the technique describes. A deterministic fact the platform
    # states is right or absent, and this one could not be made right.
]

_CONFIDENCE_CEILING = 0.65

# How many held-out malware profiles a combination needs behind it before the
# catalogue is willing to label on it. Below this the association still ships,
# informational, carrying the count so a reader knows how thin it is.
_HELD_OUT_FLOOR = 3


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
        # A rule states a mechanism, and every mechanism here is also the
        # ordinary working of software that is not a sample. A rule with no
        # label and no sentence naming that software reads as an accusation,
        # and one with no measured rate states a technique association without
        # saying how often it fires on software that is not a sample.
        if not str(tech.get("rule") or "").strip():
            problems.append(f"{tid} has no rule label")
        if not str(tech.get("ordinary_use") or "").strip():
            problems.append(f"{tid} names no ordinary user of the same symbols")
        problems += _measurement_problems(f"{tid}", tech.get("measured"))

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

    # A category is labelled only behind a named combination, and only where the
    # combination was measured against enough held-out malware to be worth a
    # label; three profiles is the floor, below which the row is informational
    # and says how many profiles it has. Everything else the block carries is a
    # reference association.
    for platform, categories in CATEGORIES_BY_PLATFORM.items():
        gates = FLAG_GATES_BY_PLATFORM.get(platform, {})
        measured = MEASURED_CATEGORIES.get(platform, {})
        for category, (tier, _apis) in categories.items():
            problems += _measurement_problems(f"{platform} {category}", measured.get(category))
            if tier == INFO:
                continue
            if not gates.get(category):
                problems.append(f"{platform} {category} is tiered {tier} with no flags_with gate")
            if platform not in HELD_OUT_CORPORA:
                continue
            support = (measured.get(category) or {}).get("held_out_malware_profiles")
            if not isinstance(support, int) or support < _HELD_OUT_FLOOR:
                problems.append(
                    f"{platform} {category} is tiered {tier} on {support} held-out profiles"
                )

    return problems


def _measurement_problems(what: str, measured: Any) -> list[str]:
    """Whether one association's measured rate is complete, or absent and silent.

    An absent block is allowed and means the association has not been measured;
    the surfaces then say so. A present one has to carry both the share and the
    count behind it, because a share rounded to one decimal place reads as zero
    for a rule that fires on one file in three thousand.
    """
    if measured is None:
        return []
    if not isinstance(measured, dict):
        return [f"{what} has a measured block that is not an object"]
    problems = []
    if not isinstance(measured.get("benign_percent"), int | float):
        problems.append(f"{what} has no measured benign share")
    if not isinstance(measured.get("benign_files"), int):
        problems.append(f"{what} has no measured benign count")
    return problems


def _block(platform: str, category: str) -> dict[str, object]:
    """One category as the catalog carries it, corroborators and rate included."""
    tier, apis = CATEGORIES_BY_PLATFORM[platform][category]
    block: dict[str, object] = {"tier": tier}
    corroborators = CORROBORATORS_BY_PLATFORM.get(platform, {}).get(category)
    if corroborators:
        block["corroborated_by"] = sorted(set(corroborators))
    gate = FLAG_GATES_BY_PLATFORM.get(platform, {}).get(category)
    if gate:
        block["flags_with"] = sorted(set(gate))
    measured = MEASURED_CATEGORIES.get(platform, {}).get(category)
    if measured:
        block["measured"] = _with_corpora(platform, measured)
    block["apis"] = sorted(set(apis))
    return block


def _with_corpora(platform: str, measured: dict[str, Any]) -> dict[str, Any]:
    """A measured block with the corpora its numbers are shares of named beside them.

    The corpus is written beside the rate rather than once at the top of the
    file, because the rate travels: it reaches the model in the
    ``api_capability`` answer, the report's import-technique table and the
    console's cell, and in each of those the number is useless without what it
    is a share of.
    """
    out = {**measured, "benign_corpus": BENIGN_CORPORA[platform]}
    if "held_out_malware_profiles" in out and platform in HELD_OUT_CORPORA:
        out["held_out_malware_corpus"] = HELD_OUT_CORPORA[platform]
    return out


def _emitted(tech: dict[str, Any]) -> dict[str, Any]:
    """One technique rule as the catalog carries it, its corpora named."""
    platforms = [str(p) for p in tech.get("platforms") or ["windows"]]
    row = {**tech, "platforms": platforms, "apis": sorted(set(tech["apis"]))}
    measured = tech.get("measured")
    if measured:
        row["measured"] = _with_corpora(platforms[0], measured)
    return row


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
        "techniques": [_emitted(t) for t in techniques],
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
