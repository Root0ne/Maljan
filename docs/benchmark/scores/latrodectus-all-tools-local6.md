# Latrodectus score: all-tools team, local Qwen3.6-35B

The reference sample run under the importable all-tools team with a real
sandbox, on a local model. `dev` @ `4d80c62e`, team `all_tools` (three static
analysts, a Ghidra reverser, then the dynamic and network stages; see [An
all-tools team](../../configuration.md#an-all-tools-team)), model
Qwen3.6-35B-A3B on ik_llama.cpp with thinking off, a 131,072-token window
probed from the server, output caps of 32,768 tokens for every analyst, the
judge and the report model, no spend ceiling. The server had one slot, so the
analysts ran one after another. **Sandbox: Hatching Triage, a 600 s run.** The
job completed in 8,373 s.

The method is the [benchmark's](../index.md#method), with the
[all-tools series' scoring surface](../index.md#the-all-tools-series): the 57
core items of K1–K10 (K1.1 split into family and loader), scored on the report
body, the STIX bundle and the `/iocs` feed.

- **partly (body)**: the body states part of the item, or states it with the
  wrong purpose.
- **partly (appendix)**: the value is printed only in the report's appendix.
- A behaviour that a string only hints at counts as **missed**.
- **wrong**: the body states something the human reports contradict.

Human sources: **B** Bitsight (names this hash), **E** Elastic, **P**
Proofpoint.

## Totals

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 3 | 2 | 0 | 0 | 0 |
| K2 execution flow | 6 | 1 | 2 | 0 | 3 | 0 |
| K3 anti-analysis | 7 | 3 | 0 | 0 | 4 | 0 |
| K4 identifiers | 3 | 0 | 2 | 1 | 0 | 0 |
| K5 persistence | 3 | 0 | 1 | 1 | 1 | 0 |
| K6 C2 | 7 | 2 | 2 | 0 | 3 | 0 |
| K9 IOCs | 8 | 2 | 1 | 5 | 0 | 0 |
| **Main (K1–K6, K9)** | **39** | **11** | **10** | **7** | **11** | **0** |
| K7 commands | 11 | 0 | 3 | 0 | 8 | 0 |
| K8 discovery | 1 | 1 | 0 | 0 | 0 | 0 |
| K10 ATT&CK | 6 | 3 | 1 | 0 | 2 | 0 |
| **Depth (K7, K8, K10)** | **18** | **4** | **4** | **0** | **10** | **0** |
| **All core** | **57** | **15** | **14** | **7** | **21** | **0** |

**15 found / 21 partly (14 body, 7 appendix) / 21 missed / 0 wrong**, and
**12 facts beyond the human reports** (below).

- **The best local found count of the all-tools series, still with nothing
  wrong**, and far below the [hosted run](latrodectus-all-tools-run4.md)'s 45.
- **The gains are the C2 channel and the task.** The `POST` to `/live/`, the
  fixed User-Agent, and T1053.005, published from the sandbox's "Uses Task
  Scheduler COM API" signature.
- **The losses are strings the report did not repeat.** `Custom_update`,
  `Update_%x` and `Updater` are in the appendix only, because no claim named
  them.
- **The analysis is not deeper.** The reverser decompiled 42 distinct
  functions, including every function the decoded strings of the key items are
  used in, and described none of them in a claim, even when asked once.

## What the evidence had and the report did not

The triage pack gave every analyst FLOSS, `resolve_api_hashes` and
`decode_string_blobs`, which ties each decoded string to the function that uses
it. The reverser decompiled each of these functions; no claim describes any of
them, so these key items stayed missed or appendix-only:

| Key item | Decoded string | Function | Decompiled | In a claim |
|---|---|---|---|---|
| K2.3 / K9 mutex | `runnung` | 0x3868 | yes | no |
| K3.7 self-deletion | `:wtfbbq` | 0x3a24 | yes | no |
| K5.2 / K9 task | `Updater` | 0x33ac | yes | no |
| K5.1 / K9 install folder | `Custom_update` | 0x30d0 | yes | no |
| K4.2 / K4.3 group | `Littlehw` | 0x463c | yes | no |
| K6.7 response tags | `URLS` | 0x541c, 0xcf14 | yes | no |
| K4.5 RC4 key | `12345` | 0x5750, 0xb670 | yes | no |
| K7.18 `bp.dat` | `files/bp.dat` | 0x4110 | yes | no |
| K2.6 / K5.3 | `\update_data.dat` | 0xcea4 | no | no |

The platform asked once about the decompiled functions no claim described; the
kept answer still named 41 of 42 in no claim, and the report says so.

## Item by item

| # | Score | Report (quoted or condensed) |
|---|---|---|
| K1.1a family | found | "Family: Latrodectus (high confidence, 0.98, stated by the judge)" |
| K1.1b loader | found | "Category: loader"; "Latrodectus/IcedId loader DLL" |
| K1.2 IcedID link | partly (body) | "Latrodectus/IcedId/Ulise family" (labels only) |
| K1.4 x64 DLL; arch check | partly (body) | "pe, x86-64, DLL". No architecture check |
| K1.5 four exports, one address | found | "All 4 exports share one address, 0x3ce4." |
| K2.1 APIs by hash | found | "resolves 164 API names … using CRC32"; "parses the PE export table … at offset 0x869c" |
| K2.2 abort on failed check | partly (body) | "Performs sandbox evasion checks including process enumeration and hook installation". Checks stated, from sandbox signatures; no abort |
| K2.3 mutex | missed | Only `CreateMutexW` in the measured import table |
| K2.4 install, then persist | missed | Persistence given as Active Setup and the Startup folder |
| K2.5 register, then loop | partly (body) | The beacon template as "Exfiltration Format"; host data sent by POST. No loop, no command reception |
| K2.6 `update_data.dat` read first | missed | String only in the appendix |
| K3.1 PEB BeingDebugged | found | "accesses the Process Environment Block (PEB) for anti-debugging", with capa's Debugger Detection |
| K3.2 process count 75/50 | missed | — |
| K3.3 architecture / WOW64 | missed | — |
| K3.4 MAC check | missed | `GetAdaptersInfo` only as "network interface enumeration" |
| K3.5 PEB walk + CRC32 names | found | Export parsing at 0x869c; CRC32; 164 names; the library list |
| K3.6 string encryption | found | "XOR-based string obfuscation … decoded at runtime by the routine at 0xae78" |
| K3.7 self-deletion | missed | Only an unpublished rule-match row for T1070.004 |
| K4.1 bot ID | partly (appendix) | `guid=%s` in the template; the format string in the appendix only |
| K4.2 group → FNV-1a | partly (body) | "FNV hashing for integrity checks"; `group=%lu` in the template. Not joined |
| K4.4 two encrypted C2s | partly (body) | Both URLs in the IOC section, decoded by 0xae78 inside 0x6988; the prose names only the first as C2 |
| K5.1 `Custom_update\Update_%x.dll` | partly (appendix) | Appendix only |
| K5.2 task `Updater`, COM, logon | partly (body) | T1053.005 published: "uses Task Scheduler COM API to schedule tasks for persistence or delayed execution". No name, no logon trigger |
| K5.3 `update_data.dat` holds C2s | missed | Appendix only |
| K6.1 HTTPS POST `/live/` | found | "constructs HTTP POST requests to the domain `skinny…[.]com` (specifically the path `/live/`)" |
| K6.2 User-Agent | found | "a custom User-Agent string (Mozilla/4.0 compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)" (opening parenthesis misplaced) |
| K6.3 RC4 then base64 | partly (body) | "communication channel is encrypted using RC4 PRGA"; no base64, no key |
| K6.4 beacon interval | missed | "Exfiltration Interval · 1000 · decrypted" — the value is in no cited evidence entry |
| K6.5 beacon format | partly (body) | Base template exact; no `&mac`, `&domain` |
| K6.6 beacon types 1–5 | missed | — |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | missed | — |
| K9 own hashes | found | published |
| K9 `/live/` | found | both URLs published with provenance |
| K9 UA | partly (body) | In the body once, inside a statement, not as an indicator |
| K9 mutex `runnung` | partly (appendix) | Appendix only |
| K9 `Custom_update\` | partly (appendix) | Appendix only |
| K9 `Update_<hex>.dll` | partly (appendix) | `Update_%x` in the appendix only |
| K9 `update_data.dat` | partly (appendix) | Appendix only |
| K9 task `Updater` | partly (appendix) | Appendix only; the body names a task, not its name |
| K7 2 desktop links | missed | Desktop appears only as a persistence folder |
| K7 3 process list | partly (body) | Toolhelp32 enumeration; "exfiltrates … process lists". No command |
| K7 4 sysinfo | partly (body) | The reconnaissance set, exfiltrated; no command id |
| K7 12 download + run EXE | partly (body) | "Downloads additional payloads using URLDownloadToFile". No execution, no command |
| K7 13 DLL via rundll32 | missed | — |
| K7 14 shellcode | missed | — |
| K7 15 update | missed | — |
| K7 17 uninstall | missed | — |
| K7 18 `bp.dat` | missed | Appendix only |
| K7 19 longer interval | missed | — |
| K7 20 reset counter | missed | — |
| K8 discovery | found | `ipconfig /all`, `systeminfo`, `nltest /domain_trusts /all_trusts`, `net group "Domain Admins" /domain`, `net view /all [/domain]`, `whoami /groups`, `net config workstation`, the SecurityCenter2 AntiVirusProduct query |
| K10 T1027 | found | published (capa RC4) |
| K10 T1218.011 | found | published, corroborated |
| K10 T1055 | partly (body) | Published on remote injection from resolved names and a sandbox signature; not command 14 |
| K10 T1053.005 | found | published, kept by the judge when asked |
| K10 T1070.004 | missed | Rule match only, not published |
| K10 T1059.003 | missed | Parent T1059 claimed and dropped by the judge |

**Build and later items** (consistency checks, not scored): the first C2
domain, stated as C2, is on B's list of 47; the second is published but never
called a C2. The RC4 key `12345`, the group `Littlehw` and the stealer field
`&stiller=` are in the appendix only.

## Beyond the human reports

Each fact below is stated in the report body and is held by no item of the
human reports' key (K1–K11), and none of B, E or P states it for this hash. The
run's own evidence proves each one; the evidence id and the tool follow each
line.

1. Compile TimeDateStamp **2024-03-25 15:54:25 UTC** — `ev_0004` `pe_info`.
2. Export-directory name **`UpdaterTag.dll`** — `ev_0004` `pe_info`; `ev_0035` r2 `list_exports`.
3. Section layout: five sections, highest entropy `.data` 6.48, no packer signatures — `ev_0004` `pe_info`.
4. The static import table is exactly five imports (`PeekNamedPipe`, `GetLastError`, `CreateMutexW`, `MessageBeep`, `MessageBoxA`) — `ev_0004` `pe_info`; `ev_0034` r2 `list_imports`.
5. No Authenticode signature — `ev_0003` `signing_info`.
6. The string decoder is the routine at **0xae78** — `ev_0019` `floss` (every decoded string names it); `ev_0073` Ghidra `decompile_function`.
7. The export-table resolver is at **0x869c** — `ev_0008` `capa` ("resolve function by parsing PE exports" at 0x869c); `ev_0086` Ghidra `decompile_function`.
8. The runtime API surface: 164 names resolved from CRC32 hashes across kernel32, user32, wininet, shell32, advapi32, urlmon, shlwapi and iphlpapi, with the WinINet, URLDownloadToFileW, Toolhelp32 and SHGetFolderPathW names stated — `ev_0020` `resolve_api_hashes`.
9. **This hash's C2 pair**, both on `/live/`, decoded by 0xae78 inside 0x6988 at 0x69b3 and 0x6a1f from file offsets 0xe050 and 0xe078 — `ev_0019` `floss`; `ev_0021` `decode_string_blobs`.
10. Where each decoded C2 URL goes next: the decoder's output slot `[rsp+0x40]` becomes argument 1 of the call to **0xbc1c**, at 0x6a4e for the first URL and 0x69e2 for the second — `ev_0021` `decode_string_blobs`.
11. VirusTotal: 52 of 75 engines, analysis of 2026-08-23 — `ev_0018` `get_file_report`.
12. The sandbox record: two `rundll32.exe <sample>.dll,#1` processes, i.e. the load is by ordinal 1 — `ev_0012` `sandbox_processes`.

**12 facts beyond the human reports.**

**Not counted: wrong, or not proven by the evidence.**

- Persistence by Active Setup and the Startup folder (T1547.001 and T1547.014
  published): contradicted by B and E, whose only persistence is the
  `Updater` task; it rests on a sandbox signature.
- 63 "host identifier" rows naming registry keys that no evidence entry holds.
- A sandbox address (`104[.]18[.]…`) stated as the C2's infrastructure: the
  sandbox attributes no flow to the sample, and the IOC feed does not publish it.
- Remote-process injection, privilege escalation, Volume Shadow Copy deletion
  and IE-settings changes: generic sandbox signatures with no call site.
- "Exfiltration Interval 1000": not in the cited evidence entry.
- "Six dropped files": sandbox memory dumps, not the sample's drops.
- The sandbox's SCSI-registry signature as the sample's own check: its process
  is not stated, so it is not counted, though it may be right.
- T1000 and T1042 (not valid ATT&CK ids), T1048, T1134, T1490, T1112 and T1083
  as stated.

## Reverse direction: claims no human report supports

| Claim | Ruling |
|---|---|
| Persistence by Active Setup registry keys and the Startup folder | contradicted (B, E) |
| 63 host-identifier rows built by joining PE strings, string fragments and a tool's answer onto a registry path | wrong; in no evidence entry; not published |
| The sample connects to a CDN address on port 443 that "corresponds to" the first C2 domain | unsupported: the sandbox attributes no flow to the sample |
| Process injection via `VirtualAllocEx` / `WriteProcessMemory` (T1055) | unsupported: resolved names and a generic sandbox signature, no call site |
| T1134, T1490, T1112, T1048 | unsupported or wrong ids, from generic sandbox signatures |
| "Installer Name · UpdaterTag.dll"; "Exfiltration Interval · 1000"; "Payload Extension · .dat" | wrong purpose, or not in the cited evidence |
| "The sample dropped six files" | sandbox capture artefacts, not the sample's drops |
| Family, loader, four exports at 0x3ce4, CRC32 resolution with 164 names at 0x869c, the decoder 0xae78, the reconnaissance set, RC4 PRGA, the beacon template, `POST` to `/live/`, the User-Agent, both C2 URLs, T1218.011, T1027, T1053.005 | correct |

## The run

| | |
|---|---|
| Duration | 8,373 s |
| Debate | 1 round; no dissent, no revision |
| Published techniques | 21 |
| Published network indicators | 2 domains, 2 URLs, no IP address |
| Model calls | 149; 7.60 M input tokens (5.71 M cached), 0.146 M output; 39.2 tokens/s generation, 499 tokens/s prompt |
| Tool calls | 112 (1 failed): pipeline 22, triage 6, static 0, static_r2 30, qu1cksc0pe 1, reverser 53, dynamic 0, network 0 |

Three analysts — static, dynamic and network — answered from the triage pack
without calling a tool even after being asked to. One analyst's answer ran to
its 32,768-token cap repeating claims, which the platform caught after the
answer and asked about once. This is a single run.
