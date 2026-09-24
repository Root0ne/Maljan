# Latrodectus score: iteration 1, default model

Default model (Qwen3.6-35B-A3B on ik_llama.cpp), `dev` @ `9019db82`, default profile, **mock sandbox (nothing
executed)**. The method is described on the [benchmark page](../index.md#method): every core item of K1–K10 (K1.1 split
into family and class), 57 items; build items only as consistency checks; chain and later items not scored. Human
sources: **B** Bitsight (names this hash), **E** Elastic, **P** Proofpoint.

**Grading rule for "partly", stated because this report has an 81-row FLOSS string list in Appendix A.** The baseline
gave "partly" when a deterministic tool put the raw fact in the report and no model turned it into the finding. It is
kept unchanged and split into two kinds so the reader can discount them:
- **partly (body)** — the report body states part of the item, or states it with the wrong purpose;
- **partly (appendix)** — the item's own value (the IOC, the format string, the command keyword) is printed only in
  Appendix A › Floss: strings, with no sentence about it. A behaviour that a string in the appendix only hints at (e.g.
  `:wtfbbq` for self-deletion) is **missed**, not partly.

## Totals

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 3 | 1 | 0 | 1 | 0 |
| K2 execution flow | 6 | 0 | 4 | 0 | 2 | 0 |
| K3 anti-analysis | 7 | 0 | 3 | 0 | 4 | 0 |
| K4 identifiers | 3 | 1 | 1 | 1 | 0 | 0 |
| K5 persistence | 3 | 0 | 2 | 1 | 0 | 0 |
| K6 C2 | 7 | 2 | 1 | 2 | 2 | 0 |
| K9 IOCs | 8 | 2 | 1 | 5 | 0 | 0 |
| **Main (K1–K6, K9)** | **39** | **8** | **13** | **9** | **9** | **0** |
| K7 commands | 11 | 0 | 6 | 0 | 5 | 0 |
| K8 discovery | 1 | 1 | 0 | 0 | 0 | 0 |
| K10 ATT&CK | 6 | 3 | 1 | 0 | 2 | 0 |
| **Depth (K7, K8, K10)** | **18** | **4** | **7** | **0** | **7** | **0** |
| **All core** | **57** | **12** | **20** | **9** | **16** | **0** |

In the baseline's four columns: **12 found / 29 partly / 16 missed / 0 wrong** (baseline 3/7/46/1).

## Item by item

### K1
| # | Score | Maljan (quoted) | Human source |
|---|---|---|---|
| K1.1a family | found | "**Family:** Latrodectus (moderate-to-high confidence, 0.85) [ev_0011]"; title "Latrodectus loader analysis" | B intro |
| K1.1b loader | found | "**Category:** loader"; "potential secondary payload delivery" | B intro |
| K1.2 IcedID link | missed | no mention of IcedID (`files/bp.dat` is quoted as a payload string only) | B intro; P, E |
| K1.4 x64 DLL; host-arch check | partly (body) | §2 "Type · pe, x86-64, DLL". No architecture check | B *System architecture check* |
| K1.5 four exports, one address | found | §7 "All 4 exports share one address, 0x3ce4." | E *LATRODECTUS analysis* |

### K2
| # | Score | Maljan | Source |
|---|---|---|---|
| K2.1 APIs by hash | partly (body) | §5.2 capa rows "resolve function by parsing PE exports", "hash data with CRC32"; §5.7 "the network functionality is obfuscated or dynamically resolved". "By hash" is never said; CRC32 is read as "data integrity or identification" | B *Windows API resolution* |
| K2.2 abort on failed check | missed | — | B *Anti analysis* |
| K2.3 mutex single instance | missed | `CreateMutexW` only in the import table; `runnung` only in the appendix, never tied to it | B *Mutex* |
| K2.4 copy to AppData, then persist | partly (body) | "Establishes persistence by creating scheduled tasks …" (§4 step 4). No copy step; `AppData` only in the appendix | B *Persistence* |
| K2.5 register, then command loop | partly (body) | "Constructs a POST request payload containing the collected system information and executes it to a remote server" (§4 step 3). No loop, no instruction handling | B *Communications protocol* |
| K2.6 `update_data.dat` read for new C2s | partly (body) | "strings related to file operations (`%d.dat`, `\update_data.dat`, `files/bp.dat`) … drops additional payloads or updates itself" — named, purpose wrong | B *The update data .dat file* |

### K3
| # | Score | Maljan | Source |
|---|---|---|---|
| K3.1 PEB BeingDebugged | partly (body) | §5.2 capa row "PEB access · B0001.019"; §7 "Debugger Detection::Process Environment Block". Never stated as a debugger check | B *Debugger check* |
| K3.2 process count | missed | — | B |
| K3.3 architecture / WOW64 | missed | — | B, E |
| K3.4 MAC check | missed | — | B |
| K3.5 PEB walk + CRC32 names | partly (body) | capa PEB/CRC32/export rows in §5.2; prose "CRC32 hashing for data integrity or identification" | B *Windows API resolution* |
| K3.6 string encryption | partly (body) | "Emulation recovered 81 strings [ev_0012]"; "Additional encoded strings reference …". That the strings are encoded is stated; the scheme is attributed to "stackstrings and RC4 encryption", not a rolling XOR | B *Strings decryption*; E |
| K3.7 self-deletion via ADS | missed | `:wtfbbq` only in the appendix (a hint, not the behaviour) | E *Self-deletion* |

### K4–K6
| # | Score | Maljan | Source |
|---|---|---|---|
| K4.1 bot ID | partly (appendix) | `%04X%04X%04X%04X%08X%04X` in Appendix A only; no volume serial, no constant | B *Bot ID* |
| K4.2 group → FNV-1a | partly (body) | §5.2 capa row "hash data using fnv · C0030.005"; the group name `Littlehw` only in the appendix | B *Group and Group ID* |
| K4.4 two encrypted C2s | **found** | §5.7 "Additional encoded strings reference `https://titnovacrion.top/live/` and `https://skinnyjeanso.com/live/`, indicating multiple potential C2 endpoints" | B *C2 decryption* |
| K5.1 `Custom_update\Update_%x.dll` | partly (appendix) | `Custom_update`, `Update_%x`, `AppData`, `.dll` in the appendix only | B *Persistence* |
| K5.2 task `Updater`, COM, at logon | partly (body) | §5.4 "persistence mechanisms involving scheduled tasks … (`LogonTrigger`, `PT0S` …)"; T1053.005 published. The name `Updater` only in the appendix; COM not said | B *Persistence* |
| K5.3 `update_data.dat` holds new C2 URLs | partly (body) | named as a file string; purpose given as payload/update | B |
| K6.1 HTTPS POST `/live/` | **found** | §5.5 "packaged into a POST request … transmitted to the endpoint `https://skinnyjeanso.com/live/`" | B *Communications protocol* |
| K6.2 User-Agent `… Tob 1.1` | partly (appendix) | only in the appendix | B |
| K6.3 RC4 then base64 | partly (body) | §5.7 channel table "Encryption · RC4 PRGA" on the HTTP channel (right purpose this time); base64 not stated (alphabet only in the appendix); key `12345` only in the appendix | B |
| K6.4 beacon interval | missed | — | B |
| K6.5 beacon format | **found** | §5.5 quotes the base format exactly, "counter=%d&type=%d&guid=%s&os=%d&arch=%d&username=%s&group=%lu&ver=%d.%d&up=%d&direction=%s", and says the recon results populate it. The registration additions (`&computername=%s`, `&domain=%s`) are only in the appendix | B *Beacon data* |
| K6.6 beacon types 1–5 | missed | — | B |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | partly (appendix) | all four keywords in the appendix only | B *C2 instructions and commands* |

### K7–K10
- **K7 commands.** partly (body): **3** ("process lists" among the beacon data), **4** (the recon set, §5.5/§5.6, not tied to a
  C2 command), **12** and **13** ("Drops and executes additional payloads or updates, potentially using dynamically generated
  filenames and rundll32.exe"; `%s%d.exe`, `%s%d.dll`), **15** ("updates itself"), **18** (`files/bp.dat` named as a payload
  string, not as IcedID). missed: **2** (`&desklinks=[` only in the appendix), **14**, **17**, **19**, **20**. The §5.6
  "Commands" table lists the discovery commands (K8), not the C2 command IDs.
- **K8 discovery: found.** §5.5 lists `whoami /groups`, `ipconfig /all`, `systeminfo`, `nltest /domain_trusts` and
  `/all_trusts`, `net view /all` and `/all /domain`, `net group "Domain Admins" /domain`, the SecurityCenter2 WMIC query and
  (§5.6) `net config workstation`. Only the `ifconfig.me` public-IP lookup is missing.
- **K9 IOCs.** found: own hashes (exact, incl. imphash); `/live/` (in prose and the C2 table). partly (body):
  `update_data.dat`. partly (appendix): mutex `runnung`, `Custom_update\`, `Update_<hex>.dll` (`Update_%x`), task `Updater`, the
  User-Agent. None is in §9, which lists only the four hashes.
- **K10 ATT&CK.** found: T1027 (procedure now "obfuscation … to hide its malicious behavior and strings"), T1053.005
  (scheduled task), T1059.003 (cmd.exe recon). partly: T1218.011 (the parent T1218 is published for "LOLBin … rundll32"). missed:
  T1055, T1070.004.
- **Build consistency.** The two C2 domains `skinnyjeanso.com` and `titnovacrion.top` are both on B's list of 47; group
  `Littlehw` is on B's list; RC4 key `12345` is the key B expects for a March 2024 build — all three **consistent**, but the last two
  only in the appendix.
- **K11.** The one draft rule is still the hash-or-imphash YARA. None of the decoded strings (UA, `runnung`,
  `Custom_update`) made it into a rule.

## IOC recall (key K9, 8 core values)
- **Published** (the `/iocs` endpoint and §9): 1 of 8 (the sample's own hashes). The STIX bundle additionally carries two
  domain indicators, `skinnyjeanso.com` and `titnovacrion.top` (both on B's C2 list) — which the `/iocs` endpoint and §9 do
  not (a disagreement between surfaces, fixed in iteration 2).
- **Stated in the report body:** 3 of 8 (hashes, `/live/`, `update_data.dat`).
- **Present anywhere in the report, appendix included:** 8 of 8.

## Reverse direction: claims no human report supports

| Claim (quoted) | Assessment | How we know |
|---|---|---|
| "The malware exfiltrates collected data to C2 servers"; "The critical risk is unauthorized data exfiltration"; "Immediate isolation … to prevent data loss" | **unsupported as framed** | B: the recon results are command 4's answer to the C2; the sample is a loader. Nothing is exfiltrated beyond host facts |
| "attempts to evade detection by querying security products via WMI" → **T1012 Query Registry** | **contradicted** | B *Command ID 4*: the AV query is discovery (T1518.001 in the key's derived mapping); WMI is not a registry query |
| "persistence by creating scheduled tasks and modifying registry Run keys"; judge: "registry run keys, startup folder shortcuts" | **contradicted / disputed** | B, E: the `Updater` task only; P's AutoRun key is K5.4 (disputed, not scored). `Startup`, `Personal`, `Local AppData` and the Shell Folders key are E's configurable install location (K5.5), not a startup shortcut |
| "`&stiller=`" read as a scheduled-task string | **contradicted** | B: `&stiller=` is the stealer-module beacon field (command 21) |
| "RC4 encryption to hide malicious capabilities and strings" | **contradicted** (purpose) | B: the strings use a rolling XOR; RC4 (key `12345`) is the C2 traffic |
| "CRC32 hashing for data integrity or identification" | **contradicted** | B: CRC32 hashes DLL and API names |
| "T1027 (Indicator Removal from Host), specifically T1027.005 (Obfuscated Files or Information)" | **contradicted** (names swapped) | T1027 is Obfuscated Files or Information; the §8 matrix names them correctly |
| "Sysmon … processes with RC4 encryption API calls" | unsupported | RC4 is inline code |
| **Severity: Critical** | new (judgement) | no human report rates severity |
| "does not import network-related APIs … dynamically resolved" | correct but new | K3.5: wininet is loaded at run time |
| Unsigned; VT 52/75; compile time 2024-03-25 15:54:25; export name `UpdaterTag.dll`; exports at 0x3ce4 | correct but new | measured; matches the key's header facts |

**Report defects seen in this run (platform, not model):**
1. **Citations to the wrong entry pass the validator.** §4 steps 1–5, §5.2, §5.4, §5.6 and §5.7 cite **`ev_0011` (the
   VirusTotal report) for strings that are in `ev_0012` (FLOSS)**. The static analyst's own claims cite ev_0011 for the
   decoded strings; the report inherits it. The citation check at the time verified that an id exists, not that the entry
   holds the quoted fact.
2. **Truncated evidence prose printed**: §5.2 "… This suggests" and "… more suspicious tools like PowerShell di [ev_0011]"
   (claim evidence cut mid-word and printed as a sentence).
3. **The decoded C2 domains are in the STIX bundle but not in §9 or `/iocs`** (4 hash rows only, `include=all`).
4. **Two sections dropped**: `payloads` ("reached the output cap of 900 tokens … a model's reasoning counts against it")
   and `configuration` ("did not fit the schema after 1 retry") — the section that would have held the C2 pair, key
   `12345` and group `Littlehw`.
