# Latrodectus score: iteration 2, default model

Default model (Qwen3.6-35B-A3B on ik_llama.cpp, with a 1 GiB prompt cache; iteration 1 used the 8 GiB default),
`dev` @ `39b07c65`, default profile, **mock sandbox (nothing executed)**. The method is exactly as in the
[benchmark page](../index.md#method) and the [iteration-1 score](latrodectus-iteration1-default.md): 57 core items of
K1–K10 (K1.1 split), build items as consistency checks only, chain and later items not scored. **partly (body)** = the
body states part of the item or states it with the wrong purpose; **partly (appendix)** = the value is printed only in
Appendix A › Floss: strings. A behaviour that a string in the appendix only hints at is **missed**. Human sources: **B** Bitsight (names this hash), **E** Elastic,
**P** Proofpoint.

## Totals (iteration 1 in brackets)

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 3 (3) | 1 (1) | 0 (0) | 1 (1) | 0 (0) |
| K2 execution flow | 6 | 0 (0) | 4 (4) | 0 (0) | 2 (2) | 0 (0) |
| K3 anti-analysis | 7 | 0 (0) | 3 (3) | 0 (0) | 4 (4) | 0 (0) |
| K4 identifiers | 3 | 1 (1) | 1 (1) | 1 (1) | 0 (0) | 0 (0) |
| K5 persistence | 3 | 0 (0) | 3 (2) | 0 (1) | 0 (0) | 0 (0) |
| K6 C2 | 7 | **3** (2) | 1 (1) | 1 (2) | 2 (2) | 0 (0) |
| K9 IOCs | 8 | **3** (2) | 2 (1) | 3 (5) | 0 (0) | 0 (0) |
| **Main (K1–K6, K9)** | **39** | **10** (8) | **15** (13) | **5** (9) | **9** (9) | **0** (0) |
| K7 commands | 11 | 0 (0) | 4 (6) | 0 (0) | 7 (5) | 0 (0) |
| K8 discovery | 1 | 1 (1) | 0 (0) | 0 (0) | 0 (0) | 0 (0) |
| K10 ATT&CK | 6 | 1 (3) | 1 (1) | 0 (0) | 4 (2) | 0 (0) |
| **Depth (K7, K8, K10)** | **18** | **2** (4) | **5** (7) | **0** (0) | **11** (7) | **0** (0) |
| **All core** | **57** | **12** (12) | **20** (20) | **5** (9) | **20** (16) | **0** (0) |

In the baseline's four columns: **12 found / 25 partly / 20 missed / 0 wrong** (iteration 1: 12 / 29 / 16 / 0; baseline
3 / 7 / 46 / 1). Discounting appendix-only items: 12 / 20 / 25 / 0 (iteration 1: 12 / 20 / 25 / 0).

## Item by item

### K1
| # | Score | Maljan (quoted) | Human source |
|---|---|---|---|
| K1.1a family | found | "**Family:** Latrodectus (high confidence, 0.90, stated by the judge) [ev_0011]" | B intro |
| K1.1b loader | found | "a malicious DLL loader identified as part of the Latrodectus family"; "Category: Trojan/Loader" | B intro |
| K1.2 IcedID link | missed | `files/bp.dat` named in §5.8 only as a `.dat` filename | B intro; P, E |
| K1.4 x64 DLL; arch check | partly (body) | §2 "Type · pe, x86-64, DLL". No architecture check | B *System architecture check* |
| K1.5 four exports, one address | found | §7 "All 4 exports share one address, 0x3ce4." | E |

### K2
| # | Score | Maljan | Source |
|---|---|---|---|
| K2.1 APIs by hash | partly (body) | §5.2 capa rows "resolve function by parsing PE exports", "hash data with CRC32"; §5.1 "imports only `kernel32.dll` and `user32.dll` …, limiting its direct API surface". "By hash" never said | B *Windows API resolution* |
| K2.2 abort on failed check | missed | — | B *Anti analysis* |
| K2.3 mutex | missed | `CreateMutexW` only in §7 imports; `runnung` only in the appendix | B *Mutex* |
| K2.4 install, then persist | partly (body) | §4 step 2 "establishes persistence by creating scheduled tasks (LogonTrigger) and modifying registry Run keys". No copy step | B *Persistence* |
| K2.5 register, then command loop | partly (body) | §4 step 3 "communicates with command-and-control servers via HTTP POST requests, sending collected system data". No loop | B *Communications protocol* |
| K2.6 `update_data.dat` for new C2s | partly (body) | §5.8 "\"\\update_data.dat\" … suggesting it may drop or execute additional payloads" — named, purpose wrong | B *The update data .dat file* |

### K3
| # | Score | Maljan | Source |
|---|---|---|---|
| K3.1 PEB BeingDebugged | partly (body) | §5.2 capa row "PEB access · B0001.019"; §7 "Debugger Detection::Process Environment Block" | B *Debugger check* |
| K3.2 process count | missed | — | B |
| K3.3 architecture / WOW64 | missed | — | B, E |
| K3.4 MAC check | missed | — | B |
| K3.5 PEB walk + CRC32 names | partly (body) | §5.2 "capa identifies capabilities including PEB access, RC4 encryption, CRC32 hashing"; §4 step 4 reads CRC32 as obfuscation | B |
| K3.6 string encryption | partly (body) | §5.1 "Despite the absence of a traditional packer, the binary employs significant obfuscation … Emulated decoding routines recovered 81 strings". Scheme given as stackstrings/RC4, not a rolling XOR | B *Strings decryption*; E |
| K3.7 self-deletion via ADS | missed | `:wtfbbq` only in the appendix | E *Self-deletion* |

### K4–K6
| # | Score | Maljan | Source |
|---|---|---|---|
| K4.1 bot ID | partly (appendix) | `%04X%04X%04X%04X%08X%04X` only in Appendix A | B *Bot ID* |
| K4.2 group → FNV-1a | partly (body) | §5.2 capa row "hash data using fnv"; `Littlehw` only in the appendix | B *Group and Group ID* |
| K4.4 two encrypted C2s | found | §5.7 "The sample contains strings indicating communication with two C2 endpoints: `https://skinnyjeanso.com/live/` and `https://titnovacrion.top/live/`"; §5.1 "Emulated decoding routines recovered 81 strings, including URLs for command-and-control" | B *C2 decryption* |
| K5.1 `Custom_update\Update_%x.dll` | partly (body) | §5.8 "references a \"Custom_update\" routine" — the folder named, as a routine; `Update_%x` only in the appendix | B *Persistence* |
| K5.2 task `Updater`, COM, at logon | partly (body) | §4 "creating scheduled tasks (LogonTrigger)"; §5.3 "Scheduled Tasks (LogonTrigger)". `Updater` only in the appendix; COM not said; T1053.005 no longer published | B *Persistence* |
| K5.3 `update_data.dat` holds new C2 URLs | partly (body) | named in §5.6/§5.8, purpose "drop or execute additional payloads" | B |
| K6.1 HTTPS POST `/live/` | found | §5.2 "C2 communication is structured around HTTP POST requests to URLs such as `https://skinnyjeanso.com/live/`"; §5.7 channel table | B |
| K6.2 User-Agent | **found** (iteration 1: appendix) | §5.3 "User-Agent · Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)"; §5.7 "spoofs the User-Agent as `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)`" | B |
| K6.3 RC4 then base64 | partly (body) | §1 "obfuscating data with RC4 encryption"; §5.3 "Encryption · RC4 PRGA"; but the §5.7 channel table says "Encryption · None". Base64 not stated; key `12345` only in the appendix | B |
| K6.4 beacon interval | missed | — | B |
| K6.5 beacon format | found | §5.7 channel table quotes `counter=%d&type=%d&guid=%s&os=%d&arch=%d&username=%s&group=%lu&ver=%d.%d&up=%d&direction=%s`; registration additions only in the appendix | B *Beacon data* |
| K6.6 beacon types 1–5 | missed | — | B |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | partly (appendix) | only in the appendix; §5.6 says only "a 'stiller' parameter and a 'net_config_ws' parameter, likely for configuration or specific command execution" | B |

### K7–K10
- **K7 commands.** partly (body): **4** (the recon set in §5.5/§5.6, not tied to a C2 command), **12** and **13**
  (§5.6 "references … '.exe' and '.dll' files, suggesting it may drop or execute additional payloads"; §1 rundll32),
  **18** (`files/bp.dat` named as a `.dat` file). missed: **2**, **3** (no process list in the body this time), **14**,
  **15** (no self-update sentence this time), **17**, **19**, **20**.
- **K8 discovery: found.** §5.5 lists `net group "Domain Admins" /domain`, `nltest /domain_trusts` and `/all_trusts`,
  `net view /all /domain` and `/all`, `ipconfig /all`, `whoami /groups`, the SecurityCenter2 WMI query and `net config
  workstation`. `systeminfo` is in §1; the `ifconfig.me` lookup is missing.
- **K9 IOCs.** found: own hashes; `/live/`; **the User-Agent** (§5.3, §5.7). partly (body): `Custom_update` (as a
  "routine"), `update_data.dat`. partly (appendix): mutex `runnung`, `Update_%x`, task `Updater`.
- **K10 ATT&CK.** found: T1027 (published; RC4/stackstrings). partly: T1218.011 (T1218 only in §10.3 and §11 for
  rundll32, not published). missed: T1055, **T1053.005** and **T1059.003** (both found in iteration 1; the static
  analyst claimed T1082, T1071, T1027, T1014 and T1059.004 instead), T1070.004.
- **Build consistency.** `skinnyjeanso.com`, `titnovacrion.top` on B's list of 47 (now in §9 and `/iocs`); `Littlehw` and
  `12345` still only in the appendix — consistent.
- **K11.** The drafts are the hash/imphash YARA with the two C2 domains as strings (`2 of them`) and two Suricata DNS
  alerts for the domains. None of the decoded host strings (UA, `runnung`, `Custom_update`) is a draft string.

## IOC recall (K9, 8 core values)
- Published (`/iocs` and §9): 1 of 8 (the sample's hashes). `/iocs` and §9 now also publish the two C2 domains (source
  `judge`), which iteration 1 exported in STIX only.
- Stated in the body: **5 of 8** (hashes, `/live/`, UA, `Custom_update`, `update_data.dat`) — iteration 1: 3.
- Present anywhere including the appendix: 8 of 8.
- The host-identifier section that iteration 2 added for exactly these values is **missing**: "report section
  'host_identifiers' is missing: its answer reached the output cap of 8192 tokens and was cut off" (§13).

## Reverse direction: claims no human report supports

| Claim (quoted) | Assessment | How we know |
|---|---|---|
| "establishes persistence by loading a secondary DLL via rundll32.exe, a technique consistent with DLL side-loading" (§1, summary) | **contradicted** | B, E: persistence is the `Updater` task; rundll32 is how the DLL and command 13's payloads run |
| "modifying registry Run keys, targeting Startup and Personal shell folders"; "to place shortcuts or executables in the user's Startup directory"; judge "registry run keys" | **contradicted** | B, E: the task only; the Shell Folders values are E's configurable install location (K5.5) |
| **T1014 Rootkit** published ("checking for the presence of specific security products and potentially loading DLLs from non-standard locations") | **contradicted** | no report describes rootkit behaviour; the AV query is discovery (command 4) |
| T1059.004 Unix Shell claimed at 0.90 (not published; `attck.platform_mismatch` caught it) | wrong, caught | Windows DLL |
| §5.9 "Ransomware behaviour" — encryption scheme "RC4 · stream · per-file key no" | **unsupported** | nothing encrypts files; RC4 is the C2 traffic (B) |
| §5.7 channel "Encryption · None" | **contradicted** | B: RC4-encrypted, base64-encoded body; the report's own §1 and §5.3 say RC4 |
| "exfiltrates collected data" (§5.6, §12.3); "prevent further compromise and data exfiltration" | unsupported as framed | B: the recon results answer command 4; a loader |
| "attempts to evade detection by checking for security products" | contradicted (purpose) | B: discovery |
| judge "The presence of obfuscation and packing" | contradicted (packing) | the report's own §5.1: "no packer signatures", `.data` 6.48 |
| §5.1 "The sample does not exhibit persistence mechanisms in this run [ev_0009]" | self-contradiction | §4 and §5.4 state persistence |
| T1012 for the `Shell Folders` registry read (§10.3, §11) | correct but new | reading `Shell Folders` is a registry query |
| `Content-Type: application/x-www-form-urlencoded`; "does not import WinHTTP or WinINet" | correct but new | decoded strings; K3.5 |
| Severity Critical | new (judgement) | — |

Nine contradicted or unsupported (iteration 1: eight), one wrong technique caught by the platform.
