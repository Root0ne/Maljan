# Latrodectus score: iteration 4, default model

Default model (Qwen3.6-35B-A3B on ik_llama.cpp, 32,768-token context, 1 GiB prompt cache, 8 context checkpoints per
slot), `dev` @ `1eb7312f`, default profile, **mock sandbox (nothing executed)**. Iterations 2 and 3 used 32 checkpoints,
and iteration 1 used the 8 GiB prompt-cache default. The method is exactly as on the
[benchmark page](../index.md#method) and in the [iteration-2 score](latrodectus-iteration2-default.md): 57 core items of
K1–K10 (with K1.1 split), build items as consistency checks only, chain and later items not scored.
- **partly (body)**: the body states part of the item, or states it with the wrong purpose.
- **partly (appendix)**: the value is printed only in Appendix A › Floss: strings.
- A behaviour that a string in the appendix only hints at counts as **missed**.

§9's new "Host identifiers read by the report model" table is in the body. Human sources: **B** Bitsight (names this hash), **E** Elastic, **P** Proofpoint.

## Totals (iteration 2 in brackets)

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 2 (3) | 2 (1) | 0 (0) | 1 (1) | 0 (0) |
| K2 execution flow | 6 | 0 (0) | 4 (4) | 0 (0) | 2 (2) | 0 (0) |
| K3 anti-analysis | 7 | 0 (0) | 3 (3) | 0 (0) | 4 (4) | 0 (0) |
| K4 identifiers | 3 | 1 (1) | 1 (1) | 1 (1) | 0 (0) | 0 (0) |
| K5 persistence | 3 | **1** (0) | 2 (3) | 0 (0) | 0 (0) | 0 (0) |
| K6 C2 | 7 | 3 (3) | **2** (1) | **0** (1) | 2 (2) | 0 (0) |
| K9 IOCs | 8 | **4** (3) | **3** (2) | **1** (3) | 0 (0) | 0 (0) |
| **Main (K1–K6, K9)** | **39** | **11** (10) | **17** (15) | **2** (5) | **9** (9) | **0** (0) |
| K7 commands | 11 | 0 (0) | **6** (4) | 0 (0) | 5 (7) | 0 (0) |
| K8 discovery | 1 | 1 (1) | 0 (0) | 0 (0) | 0 (0) | 0 (0) |
| K10 ATT&CK | 6 | **3** (1) | 0 (1) | 0 (0) | 3 (4) | 0 (0) |
| **Depth (K7, K8, K10)** | **18** | **4** (2) | **6** (5) | **0** (0) | **8** (11) | **0** (0) |
| **All core** | **57** | **15** (12) | **23** (20) | **2** (5) | **17** (20) | **0** (0) |

In the baseline's four columns this is **15 found / 25 partly / 17 missed / 0 wrong**. For comparison: iteration 2
scored 12 / 25 / 20 / 0, iteration 1 scored 12 / 29 / 16 / 0, and the baseline scored 3 / 7 / 46 / 1. Discounting
appendix-only items gives **15 / 23 / 19 / 0**, against 12 / 20 / 25 / 0 in both iterations 1 and 2.

## Item by item

### K1
| # | Score | Maljan (quoted) | Human source |
|---|---|---|---|
| K1.1a family | found | "**Family:** Latrodectus (moderate-to-high confidence, 0.85, stated by the judge) [ev_0011, ev_0008]" | B intro |
| K1.1b loader | **partly (body)** (it. 2: found) | "Category: Trojan/Backdoor"; §4 step 4 "Drops additional payloads (DLLs or EXEs) to disk". The word "loader" and the download-and-run purpose are missing | B intro |
| K1.2 IcedID link | missed | `files/bp.dat` appears in §5.3 and §9 only as "Local configuration or payload file" | B intro; P, E |
| K1.4 x64 DLL; arch check | partly (body) | §2 "Type · pe, x86-64, DLL". No architecture check is mentioned | B *System architecture check* |
| K1.5 four exports, one address | found | §7 "All 4 exports share one address, 0x3ce4." | E |

### K2
| # | Score | Maljan | Source |
|---|---|---|---|
| K2.1 APIs by hash | partly (body) | §5.2 capa rows "resolve function by parsing PE exports" and "hash data with CRC32"; §5.1 "imports only kernel32.dll and user32.dll … relying on dynamic behavior for its malicious functions". The report never says "by hash" | B *Windows API resolution* |
| K2.2 abort on failed check | missed | — | B *Anti analysis* |
| K2.3 mutex | missed | `CreateMutexW` appears only in the §7 imports. `runnung` is in the §9 table but described as "Unknown string, possibly part of a key or identifier" | B *Mutex* |
| K2.4 install, then persist | partly (body) | §4 step 5 "Establishes persistence by creating a scheduled task named "Updater" with a "LogonTrigger""; step 4 drops "in locations such as … AppData". There is no self-copy step | B *Persistence* |
| K2.5 register, then command loop | partly (body) | §4 step 6 "Exfiltrates collected system data … to C2 servers (https://skinnyjeanso.com/live/ or https://titnovacrion.top/live/) using HTTP POST requests". No registration and no loop | B *Communications protocol* |
| K2.6 `update_data.dat` for new C2s | partly (body) | §5.3 "Local Data Files · \update_data.dat, files/bp.dat"; §9 "Local configuration or payload file"; §4 "may write update data files". Named, but its purpose (replacement C2s) is not stated | B *The update data .dat file* |

### K3
| # | Score | Maljan | Source |
|---|---|---|---|
| K3.1 PEB BeingDebugged | partly (body) | §5.2 capa row "PEB access · B0001.019"; §7 "Debugger Detection::Process Environment Block"; §4 step 1 "accessing the PEB". §8 maps it to **T1003 OS Credential Dumping** ("accesses the PEB … to bypass sandboxing"), a wrong technique (see reverse direction) | B *Debugger check* |
| K3.2 process count | missed | — | B |
| K3.3 architecture / WOW64 | missed | — | B, E |
| K3.4 MAC check | missed | — | B |
| K3.5 PEB walk + CRC32 names | partly (body) | §5.2 "capabilities including PEB access, RC4 encryption, CRC32 hashing"; §5.1 "CRC32 hashing for data integrity or obfuscation purposes" | B |
| K3.6 string encryption | partly (body) | §5.1 "the binary employs significant obfuscation … obfuscated stackstrings … emulation recovered 81 decoded strings, indicating runtime string resolution". The scheme is given as stackstrings, not a rolling XOR | B *Strings decryption*; E |
| K3.7 self-deletion via ADS | missed | `:wtfbbq` appears only in the appendix | E *Self-deletion* |

### K4–K6
| # | Score | Maljan | Source |
|---|---|---|---|
| K4.1 bot ID | partly (appendix) | `%04X%04X%04X%04X%08X%04X` appears only in Appendix A | B *Bot ID* |
| K4.2 group → FNV-1a | partly (body) | §5.2 capa row "hash data using fnv". `Littlehw` is now in the §9 body ("Unknown string, possibly part of a key or identifier"), and `group=%lu` is in the beacon format row. The three are not linked | B *Group and Group ID* |
| K4.4 two encrypted C2s | found | §5.7 "It constructs HTTP POST requests to two distinct URLs: `https://skinnyjeanso.com/live/` and `https://titnovacrion.top/live/`"; §5.2 "Decoded strings reveal … C2 servers" | B *C2 decryption* |
| K5.1 `Custom_update\Update_%x.dll` | partly (body) | `Custom_update` is in the §9 body ("Unknown string"), and §4 and §5.4 describe drops to AppData. `Update_%x` appears only in the appendix | B *Persistence* |
| K5.2 task `Updater`, COM, at logon | **found** (it. 2: partly) | §1 "The malware establishes persistence by creating a scheduled task named 'Updater' with a LogonTrigger to execute its payload upon user login."; §5.4; §8 T1053.005 published. COM is not mentioned: the name and the trigger are stated, the mechanism is not | B *Persistence* |
| K5.3 `update_data.dat` holds new C2 URLs | partly (body) | Named in §5.3 and §9, with the purpose "Local configuration or payload file" | B |
| K6.1 HTTPS POST `/live/` | found | §5.7 channel table "HTTPS · `hxxps://skinnyjeanso[.]com/live/`; `hxxps://titnovacrion[.]top/live/`"; "constructs HTTP POST requests" | B |
| K6.2 User-Agent | found | §5.3 "User-Agent · Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)"; §5.7 | B |
| K6.3 RC4 then base64 | partly (body) | §5.7 "Network traffic is encrypted using RC4 PRGA"; the channel table says "Encryption · RC4 PRGA" (iteration 2's table said "None"). The base64 alphabet is in §9 as "Base64 alphabet" but is not tied to the traffic. `12345` is in §9 as "Likely part of a key or identifier" | B |
| K6.4 beacon interval | missed | — | B |
| K6.5 beacon format | found | §9 row `counter=%d&type=%d&guid=%s&os=%d&arch=%d&username=%s&group=%lu&ver=%d.%d&up=%d&direction=%s`, "POST parameter format for exfiltrated system info"; `&computername=%s` and `&domain=%s` are separate rows; `&mac=` is absent | B *Beacon data* |
| K6.6 beacon types 1–5 | missed | — | B |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | **partly (body)** (it. 2: appendix) | §9 rows `COMMAND` "Indicator for command execution", `CLEARURL` "Indicator for URL clearing", `ERROR` "Indicator for error state", `URLS` "Indicator for browser URL collection" (a wrong purpose; §5.3 "Browser Data Collection · URLS") | B |

### K7–K10
- **K7 commands.** partly (body): **2** (`&desklinks=[` "POST parameter for desktop links"), **3** (§5.2 "running
  processes (`proclist`)", §4 "process lists"), **4** (§5.6 `system_recon`), **12** (§4 "Drops additional payloads
  (DLLs or EXEs)", `%s%d.exe` "Pattern for dropped executable payload"), **13** (`C:\WINDOWS\SYSTEM32\rundll32.exe %s,%s`
  "Execution method for loading DLLs"; §4 step 7) and **18** (`files/bp.dat`). None of these is tied to a C2 command
  ID. missed: **14**, **15**, **17**, **19**, **20**.
- **K8 discovery: found.** §5.6 lists `ipconfig /all`, `net view /all` and `/all /domain`, `net group "Domain Admins"
  /domain`, `whoami /groups`, `nltest /domain_trusts /all_trusts`, `systeminfo`, `net config workstation` and the
  `AntiVirusProduct` WMI query. The `ifconfig.me` lookup is missing, as in iteration 2.
- **K9 IOCs.** found: own hashes; `/live/`; the User-Agent; **task `Updater`** (§1, §5.4, §10.3 and §11; iteration 2:
  appendix). partly (body): **mutex `runnung`** and **`Custom_update`** (both in the §9 table with no purpose; iteration 2:
  appendix / "routine"), `update_data.dat`. partly (appendix): `Update_%x`.
- **K10 ATT&CK.** found: **T1027** (published; RC4 and stackstrings), **T1053.005** (published, "scheduled task named
  "Updater""; iteration 2: missed), **T1218.011** (published, "uses Rundll32.exe to execute code from a DLL"; iteration
  2: partly). missed: T1055, T1070.004, T1059.003 (cmd.exe is named in §4 and §5.6, but the technique is not claimed).
- **Build consistency.** `skinnyjeanso.com` and `titnovacrion.top` are on B's list of 47. `Littlehw` is on B's group
  list, and `12345` is B's first RC4 key. Both are now in the body, but unexplained. All consistent.
- **K11.** The only draft is the hash/imphash YARA rule. The judge fell back to text extraction, so no domain indicator
  reached the export and no Suricata draft was made. Iteration 2 had two domain strings in the YARA and two DNS alerts.

## IOC recall (K9, 8 core values)
- Published (`/iocs` and the export): 1 of 8 (the sample's hashes). The two C2 domains, published in iteration 2
  (source `judge`), are **not published this time**, because the judge's bundle was cut twice and the verdict fell back
  to text extraction (`iocs.json`: 4 hashes).
- Stated in the body: **8 of 8** if a value printed without a purpose counts (`runnung`, `Custom_update`, `Updater`
  are in the new §9 host-identifier table). With a purpose, the count is 5 of 8. Iteration 2 had 5 of 8, iteration 1
  had 3.
- Present anywhere, including the appendix: 8 of 8.

## Host-identifier section
Present: 57 rows, all typed `String`, all cited to `ev_0012` (FLOSS). 56 of the 57 values are verbatim in `ev_0012`.
The 57th, `\Registry\Machine\x5c`, is `ev_0012`'s `\Registry\Machine\` with the trailing backslash written as an escape.
So every row is cited to the entry that holds it. `composer.repeated_items` found one repeat (`Updater` twice, with two
different purposes). It was recorded unresolved rather than asked: the section's one retry had gone on a
`composer.schema` question. No section was cut at its cap in this run.

## Reverse direction: claims no human report supports

| Claim (quoted) | Assessment | How we know |
|---|---|---|
| **T1003 OS Credential Dumping** published: "The malware accesses the PEB (Process Environment Block) to determine its own process characteristics or to bypass sandboxing." (0.85); summary "strong indicators of system reconnaissance and credential harvesting" | **contradicted** | The PEB access is the debugger check and the API walk (B). No report describes credential theft |
| **T1078 Valid Accounts** published: "The binary is a Trojan/Backdoor … that performs system reconnaissance and exfiltrates data" (0.95) | **unsupported** | The procedure does not describe the technique |
| **T1547.001 Registry Run Keys / Startup Folder** published: "drops additional payloads … likely in the Startup folder or AppData, to ensure persistence or lateral movement" | **contradicted** | B, E: the only persistence is the `Updater` task. The Shell Folders values are E's configurable install location (K5.5) |
| **T1005 Data from Local System**: "collects browser information and potentially steals browser-related data, indicated by the User-Agent string"; §5.3 "Browser Data Collection · URLS" | **contradicted** | `URLS` is a C2 instruction (B), and the UA is the bot's own |
| T1041 and "exfiltrates collected system data and potentially stolen files" (§1, §4, §5.6) | unsupported as framed | B: the recon results answer command 4. The sample is a loader |
| "Immediate isolation … to prevent lateral movement"; §5.4 "for persistence or lateral movement" | unsupported | No report describes lateral movement |
| §4 step 7 / T1218.011 "potentially side-loading or loading a malicious DLL from a writable directory" | unsupported (side-loading) | B, E: rundll32 runs the DLL and command 13's payloads |
| §5.2 "The binary is packed or obfuscated, indicated by a high section entropy of 6.48 in .data" | contradicted (packing) | The report's own §5.1 says "no packer signatures". `.data` 6.48 is below packed levels |
| §5.8 "The sample does not contain the string "rundll32.exe" [ev_0012]" | self-contradiction | The same paragraph quotes `C:\WINDOWS\SYSTEM32\rundll32.exe %s,%s` from ev_0012 |
| T1518.001 "attempts to disable or detect security software" | unsupported ("disable"); detection is correct (derived mapping) | B: command 4's AV query is discovery |
| Shell Folders registry read; `Content-Type: application/x-www-form-urlencoded`; T1082 | correct but new (T1082 is the key's derived mapping) | decoded strings |
| §10.3 and §11 T1204.002 User Execution | new, not claimed by any analyst | — |
| Severity High | new (judgement) | — |

**Ten contradicted or unsupported claims** (iteration 2: nine). **5 of the 10 published techniques** have no evidence
behind them (T1003, T1078, T1547.001, T1005, T1041). Iteration 2 had one (T1014). No sentence was asked about or marked:
`flagged_statements` is empty, and neither `narrative.ungrounded_capability` nor `report.rule_match_as_action` fired.
