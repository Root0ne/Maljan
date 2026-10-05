# Latrodectus score: all-tools team, hosted DeepSeek

The reference sample run under the importable all-tools team with a real
sandbox, on a hosted model. `dev` @ `ceb4244a`, team `all_tools` (three static
analysts, a Ghidra reverser, then the dynamic and network stages; see [An
all-tools team](../../configuration.md#an-all-tools-team)), model
DeepSeek-V4.1-Flash through the OpenAI-compatible provider with
`compat = deepseek`, thinking on and `reasoning_effort = max`, a 1,048,576-token
window, output caps of 393,216 tokens for every analyst, the judge and the
report model, and a spend ceiling of 2.00 USD. **Sandbox: Hatching Triage, a
600 s run.** The job completed in 7,603 s and was charged 1.36 USD.

The method and the scoring surface are the same as for the [local
run](latrodectus-all-tools-local6.md) and are described in [the all-tools
series](../index.md#the-all-tools-series).

## Totals

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 4 | 1 | 0 | 0 | 0 |
| K2 execution flow | 6 | 5 | 1 | 0 | 0 | 0 |
| K3 anti-analysis | 7 | 6 | 0 | 0 | 1 | 0 |
| K4 identifiers | 3 | 2 | 1 | 0 | 0 | 0 |
| K5 persistence | 3 | 2 | 1 | 0 | 0 | 0 |
| K6 C2 | 7 | 6 | 1 | 0 | 0 | 0 |
| K9 IOCs | 8 | 7 | 1 | 0 | 0 | 0 |
| **Main (K1–K6, K9)** | **39** | **32** | **6** | **0** | **1** | **0** |
| K7 commands | 11 | 7 | 2 | 0 | 1 | 1 |
| K8 discovery | 1 | 1 | 0 | 0 | 0 | 0 |
| K10 ATT&CK | 6 | 5 | 1 | 0 | 0 | 0 |
| **Depth (K7, K8, K10)** | **18** | **13** | **3** | **0** | **1** | **1** |
| **All core** | **57** | **45** | **9** | **0** | **2** | **1** |

**45 found / 9 partly / 2 missed / 1 wrong**, and **19 facts beyond the human
reports** (below).

- **The best report of the benchmark.** 32 of the 39 main items found, and no
  item left in the appendix alone.
- **One item is wrong.** Command 0xf is labelled "uninstall"; B, E and P give
  it as update.
- **The new deterministic tools paid off.** `resolve_api_hashes` named
  `IsWow64Process` (K3.3, the first time in any run) and the volume APIs behind
  the bot id; `decode_string_blobs` joined the RC4 key, the group, the
  self-delete rename token, the install folder and `update_data.dat` to the
  functions that use them. With names in hand, the reverser decompiled every
  command handler.

## What the claims held and the report did not

Two losses happened between the analysts and the report:

- **A revision answer replaced 38 claims with 3.** The reverser's revision
  began 18 claims and only 3 were read: 15 ended their confidence line with a
  full stop, which the claim reader did not parse, and the loss was recorded
  nowhere. Had those claims been read, K7.12, K7.17 and K5.2 with its IOC would
  have been found.
- **The report dropped one claim that was read.** The MAC-address check (K3.4)
  was in three analysts' final claims and is not in the body.

**The spend ceiling latched early.** One refused debate turn marked the whole
ceiling exhausted at 0.98 USD of 2.00, so the second revision round and the
mediator's tool loop did not run, and the report opens with a degraded-run
banner. No scored item was lost to it directly.

## Item by item

| # | Score | Report (quoted or condensed) |
|---|---|---|
| K1.1a family | found | "Family: Latrodectus (moderate-to-high confidence, 0.80, stated by the judge)" |
| K1.1b loader | found | "Category: loader"; judge "a fully implemented loader whose next stages were never fetched" |
| K1.2 IcedID link | partly (body) | "47 distinct labels clustering as Latrodectus-, IcedId/Banker- and Ulise-named" (labels only) |
| K1.4 x64 DLL; arch check | found | "pe, x86-64, DLL"; "IsWow64Process must be 0" |
| K1.5 four exports, one address | found | "All 4 exports share one address, 0x3ce4." |
| K2.1 APIs by hash | found | "Resolves its API surface at start-up from CRC32 name hashes … 90 {hash, module, slot} triples" |
| K2.2 abort on failed check | found | "anti-analysis gates before operational work: … BeingDebugged check that aborts, a process-count threshold …, the mutex … aborts" |
| K2.3 mutex | found | "runnung (CreateMutexW; GetLastError 0xB7 ERROR_ALREADY_EXISTS aborts init)" |
| K2.4 install, then persist | found | Copy to `%APPDATA%\Custom_update\Update_<hex>` → COM task with LogonTrigger → "Launches the registered task and exits the parent with ExitProcess(0)" |
| K2.5 register, then loop | partly (body) | The full loop with its 180 s wait; "type = 2 on a fresh install and 1 thereafter". No counter-0 registration |
| K2.6 `update_data.dat` read first | found | "Keeps the URL list RC4-encrypted at %APPDATA%\Custom_update\update_data.dat, read at start-up" |
| K3.1 PEB BeingDebugged | found | The BeingDebugged gate; T1622 published |
| K3.2 process count 75/50 | found | "a process-count threshold (75 or 50 depending on the OS id)" |
| K3.3 architecture / WOW64 | found | "IsWow64Process must be 0" |
| K3.4 MAC check | missed | In three final claims, not in the body |
| K3.5 PEB walk + CRC32 names | found | "FUN_0x6aa4 builds the 256-entry table for … 0xEDB88320, FUN_0x869c walks IMAGE_EXPORT_DIRECTORY …, PEB access at 0x8690" |
| K3.6 string encryption | found | "4-byte seed 0x33629d40, 2-byte length XOR the seed's low 16 bits, … keystream byte i = (seed + i + 1) & 0xFF" |
| K3.7 self-deletion | found | `CreateFileW(path, 0x10000 /*DELETE*/ …)`, `FILE_RENAME_INFO` around the decoded `:wtfbbq`, then delete-on-close |
| K4.1 bot ID | partly (body) | Volume information through FindFirstVolumeW / GetVolumeInformationW formatted with `%04X%04X%04X%04X%08X%04X`. No 0x19660D |
| K4.2 group → FNV-1a | found | "Beacon group identifier: Littlehw (FNV-1a hashed; the result fills group=%lu)" |
| K4.4 two encrypted C2s | found | "FUN_0x6988 decodes both and writes them into the candidate slot array at 0x10568" |
| K5.1 `Custom_update\Update_%x.dll` | found | "%APPDATA%\Custom_update\Update_%x.dll or Update_%x.exe" |
| K5.2 task `Updater`, COM, logon | partly (body) | COM class and interface, LogonTrigger and flag 6 right; the task is named "LogonTrigger" (wrong) |
| K5.3 `update_data.dat` holds C2s | found | "RC4-encrypted URL list, re-written as URLS\|%d\|%s\r\n" |
| K6.1 HTTPS POST `/live/` | found | "POST it to a /live/ endpoint" |
| K6.2 User-Agent | found | stated in the body and the IOC section |
| K6.3 RC4 then base64 | found | "RC4("12345") then base64 with the standard alphabet before POST; replies decrypted the same way" |
| K6.4 beacon interval | found | "450-599 s … 1500-2099 s after C2 command 0x13" |
| K6.5 beacon format | found | The template with `&computername=%s`, `&domain=%s`, `&mac=` |
| K6.6 beacon types 1–5 | partly (body) | "type 2 at install, 1 otherwise"; types 3–5 missing |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | found | "URLS\|id\|url → 0xccbc, CLEARURL → 0xce20, COMMAND → 0x3cf4, ERROR ignored" |
| K9 own hashes | found | published |
| K9 `/live/` | found | both URLs published |
| K9 UA | found | body and IOC section; not published |
| K9 mutex `runnung` | found | published |
| K9 `Custom_update\` | found | "Install directory %APPDATA%\Custom_update\" |
| K9 `Update_<hex>.dll` | found | The pattern, with a hunting regex for it |
| K9 `update_data.dat` | found | "%APPDATA%\Custom_update\update_data.dat" with its role |
| K9 task `Updater` | partly (body) | `Updater` printed as a string decoded before the task-registration chain; the name given as LogonTrigger |
| K7 2 desktop links | found | "handler FUN_0x1a08 fills the `&desklinks=[` upload field from shell folders" |
| K7 3 process list | found | "FUN_0x1c38 enumerates processes via CreateToolhelp32Snapshot/Process32FirstW/Process32NextW into the `&proclist=[` field" |
| K7 4 sysinfo | found | The full cmd.exe set with its upload keys and the pipe-capture routine |
| K7 12 download + run EXE | partly (body) | The download to `<tick>.exe` stated; the execution not |
| K7 13 DLL via rundll32 | found | "the fetched DLL is started as `rundll32 <dll>,<token>` … through CreateProcessW at 0xb63d" |
| K7 14 shellcode | found | "fcn.0x7170 downloads a payload, allocates RWX memory (VirtualAlloc(0,n,0x1000,0x40)) and starts thread FUN_0xb398 on it" |
| K7 15 update | **wrong** | "0xf \| uninstall \| … deletes the installed file and the installed module, and calls ExitProcess(0)" |
| K7 17 uninstall | missed | The 0x11 row is blank |
| K7 18 `bp.dat` | partly (body) | Download and `rundll32` execution; `files/bp.dat` only as a template; no IcedID |
| K7 19 longer interval | found | "Switches the beacon cycle … to the 1500-2099 s long-sleep interval" |
| K7 20 reset counter | found | "Resets the beacon's counter." |
| K8 discovery | found | All twelve cmd and wmic lines with their fields |
| K10 T1027 | found | published |
| K10 T1218.011 | found | published, corroborated |
| K10 T1055 | partly (body) | Published, but on "Injection primitives resolved but never invoked"; command 0xe goes to T1620 |
| K10 T1053.005 | found | published, corroborated |
| K10 T1070.004 | found | published ("FUN_0x3a24 opens the module path … with DELETE") |
| K10 T1059.003 | found | published, corroborated |

**Build and later items** (consistency checks, not scored): the RC4 key
`12345`, the beacon version 1.2 and the group `Littlehw` are stated, and both C2
domains are on B's list of 47. The group's numeric id and `up` are not stated.

## Beyond the human reports

Each fact below is stated in the report body and is held by no item of the
human reports' key (K1–K11), and none of B, E or P states it for this hash. The
run's own evidence proves each one; the evidence id and the tool follow each
line.

1. Compile TimeDateStamp **2024-03-25 15:54:25 UTC** — `ev_0004` `pe_info`.
2. Export-directory name **`UpdaterTag.dll`** — `ev_0004` `pe_info`.
3. Section layout: five sections, highest entropy `.data` 6.48, no packer signature — `ev_0004` `pe_info`.
4. The static import table is exactly five imports from KERNEL32.dll and USER32.dll (`PeekNamedPipe`, `GetLastError`, `CreateMutexW`, `MessageBeep`, `MessageBoxA`) — `ev_0004` `pe_info`.
5. No Authenticode signature — `ev_0003` `signing_info`.
6. The string decoder is the routine at **0xae78** — `ev_0019` `floss`; `ev_0089` r2 `decompile_function`; `ev_0168` Ghidra `batch_decompile`.
7. The export-table resolver is at **0x869c** — `ev_0008` `capa`.
8. The CRC32 table routine is at **0x6aa4** and the FNV routine at **0xc99c** — `ev_0008` `capa`.
9. RC4 PRGA at **0xcaac** — `ev_0008` `capa`.
10. The runtime API surface: 164 embedded values resolve to Windows functions and modules across about ten DLLs — `ev_0020` `resolve_api_hashes`.
11. **This hash's C2 pair**, both on `/live/`, decoded from `.data` and referenced at 0x69b3 and 0x6a1f inside 0x6988 — `ev_0019` `floss`; `ev_0021` `decode_string_blobs`.
12. VirusTotal: 52 of 75 engines — `ev_0018` `get_file_report`.
13. The sandbox record: the load as `rundll32.exe <sample>.dll,#1`, an ordinal-1 call, and no dropped file — `ev_0012` `sandbox_processes`; `ev_0015` `sandbox_dropped_files`.
14. The ntdll resolution block at **0xa59c**: 37 {hash, module, slot} triples against one module-name pointer, resolved through 0x869c — `ev_0204` Ghidra `decompile_function`; the names from `ev_0020` `resolve_api_hashes`.
15. The decoded C2 URLs are written into a candidate slot array at **0x10568** by 0x6988 — `ev_0090` r2 `decompile_function`; `ev_0182` Ghidra `batch_decompile`.
16. The C2 reply handlers: `URLS` → **0xccbc**, `CLEARURL` → **0xce20**, `COMMAND` → **0x3cf4** — `ev_0195` and `ev_0171` Ghidra `batch_decompile`.
17. The command handlers' addresses: the desktop-link collector **0x1a08**, the process-list collector **0x1c38**, the in-memory loader **0x7170** and the self-delete routine **0x3a24** — `ev_0185`, `ev_0193` and `ev_0184` Ghidra `batch_decompile`.
18. The request routine 0x5030 calls `InternetSetOptionA(hRequest, 0x1f, &0x4380, 4)`; 0x4380 is the combination of the flags that ignore revocation, an unknown CA, wrong usage and a redirect to HTTPS — `ev_0129` r2 `decompile_function` (the flag names are the constant's arithmetic).
19. A 180 s wait (0x708 × 100 ms) before first contact, in the beacon thread 0x5750 — `ev_0169` Ghidra `batch_decompile`.

**19 facts beyond the human reports.** An earlier checklist count over the same
report put it at about 22; this list counts only the facts whose evidence entry
was checked again for this page.

**Not counted: wrong, or not proven by the evidence.**

- The task named "LogonTrigger": `LogonTrigger` is the trigger string; the name
  `Updater` is passed to the registration call.
- Command 0xf as "uninstall" (B, E and P: update), and 0x15 as a download to
  disk (B: an in-memory plugin).
- The copy's extension "chosen opposite to its own type", and T1036.008
  published on it: probably wrong; under rundll32 the copy is a `.dll`.
- Hash-resolved API names described as "imports" in the T1055 and T1071.001
  rows.
- "Mozilla/IE and curl user agents" for the C2 channel: the `curl` string is
  used only in the desktop-link handler.
- The key reused for the `update_data.dat` file: no decompile of its source is
  cited.
- "GET" as the context of the URL indicators: the beacon is POST.
- The statement that the two collectors were not decompiled: they were.

## Reverse direction: claims no human report supports

| Claim | Ruling |
|---|---|
| "Task registration name: LogonTrigger" | wrong |
| "0xf uninstall" | wrong (B, E, P: 15 is update) |
| "0x15 payload download … to %LOCALAPPDATA%/%APPDATA%" | wrong: an in-memory plugin |
| Extension chosen opposite to its own type; T1036.008 published | probably wrong |
| T1055 and T1071.001 rows calling resolved names "imports" | wrong wording |
| 15 techniques "stated by the judge and claimed by no analyst" | wrong for most: the corroboration record lists analysts |
| "the routines that build them (0x1c38 and 0x1a08) were not decompiled" | wrong |
| Mozilla/IE and curl user agents for the C2 channel | unsupported |
| "GET" on the URL indicators | wrong |
| T1547.001 and T1012 not published; Startup rejected with reasons; the CDN address not attributed to the sample; the packer false positive dismissed | correct |
| Every sandbox address published `no:` with a reason | correct |

## The run

| | |
|---|---|
| Duration | 7,603 s |
| Cost | 1.36 USD charged |
| Debate | 2 rounds (agreement 0.79 → 0.82); round-1 revision ran, round 2 cut by the spend ceiling |
| Published techniques | 26 |
| Published network indicators | 2 domains, 2 URLs |
| Model calls | 145; 11.79 M input tokens (9.10 M cached), 1.61 M output (1.39 M reasoning) |
| Tool calls | 307 (14 failed): pipeline 21, triage 47, static 11, static_r2 60, qu1cksc0pe 18, reverser 110, dynamic 20, network 20 |

The sample stayed inert in the sandbox: its own gates stopped it on a
four-process guest, so no C2 contact, drop or task registration was observed,
and the report says why. This is a single run.
