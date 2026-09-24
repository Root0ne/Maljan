# Latrodectus score: iteration 5, default model

Default model (Qwen3.6-35B-A3B on ik_llama.cpp, 32,768-token context, 1 GiB prompt cache, 8 context checkpoints per
slot, as in iteration 4), `dev` @ `2a93b02d`, default profile, **mock sandbox (nothing executed)**. The method is
exactly as on the [benchmark page](../index.md#method) and in the [iteration-4 score](latrodectus-iteration4-default.md):
57 core items of K1–K10 (with K1.1 split), build items as consistency checks only, chain and later items not scored.

- **partly (body)**: the body states part of the item, or states it with the wrong purpose.
- **partly (appendix)**: the value is printed only in Appendix A › Floss: strings.
- A behaviour that a string in the appendix only hints at counts as **missed**.

§9's "Host identifiers read by the report model" table (73 rows) is in the body. Human sources: **B** Bitsight (names
this hash), **E** Elastic, **P** Proofpoint.

## Totals (iteration 4 in brackets)

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | **3** (2) | 1 (2) | 0 (0) | 1 (1) | 0 (0) |
| K2 execution flow | 6 | **1** (0) | 4 (4) | 0 (0) | **1** (2) | 0 (0) |
| K3 anti-analysis | 7 | 0 (0) | 3 (3) | 0 (0) | 4 (4) | 0 (0) |
| K4 identifiers | 3 | 1 (1) | **2** (1) | **0** (1) | 0 (0) | 0 (0) |
| K5 persistence | 3 | **0** (1) | 3 (2) | 0 (0) | 0 (0) | 0 (0) |
| K6 C2 | 7 | 3 (3) | 2 (2) | 0 (0) | 2 (2) | 0 (0) |
| K9 IOCs | 8 | **3** (4) | **5** (3) | **0** (1) | 0 (0) | 0 (0) |
| **Main (K1–K6, K9)** | **39** | **11** (11) | **20** (17) | **0** (2) | **8** (9) | **0** (0) |
| K7 commands | 11 | 0 (0) | **4** (6) | **1** (0) | **6** (5) | 0 (0) |
| K8 discovery | 1 | 1 (1) | 0 (0) | 0 (0) | 0 (0) | 0 (0) |
| K10 ATT&CK | 6 | **2** (3) | 0 (0) | 0 (0) | **4** (3) | 0 (0) |
| **Depth (K7, K8, K10)** | **18** | **3** (4) | **4** (6) | **1** (0) | **10** (8) | **0** (0) |
| **All core** | **57** | **14** (15) | **24** (23) | **1** (2) | **18** (17) | **0** (0) |

In the baseline's four columns this is **14 found / 25 partly / 18 missed / 0 wrong**. Iteration 4 scored
15 / 25 / 17 / 0, iteration 2 12 / 25 / 20 / 0, iteration 1 12 / 29 / 16 / 0, the baseline 3 / 7 / 46 / 1.
Discounting appendix-only items gives **14 / 24 / 19 / 0** (iteration 4: 15 / 23 / 19 / 0; iterations 1 and 2:
12 / 20 / 25 / 0).

## Item by item

### K1
| # | Score | Maljan (quoted) | Human source |
|---|---|---|---|
| K1.1a family | found | "**Family:** Latrodectus/Ulise (moderate-to-high confidence, 0.85, stated by the judge) [ev_0011, ev_0008]" | B intro |
| K1.1b loader | **found** (it. 4: partly) | §1 "It operates as a DLL loader, utilizing obfuscation and RC4 encryption …"; §5.8 "it constructs a command-line execution string for rundll32.exe to load a dynamically generated payload"; §5.4 "the sample may be a loader or dropper that constructs paths for subsequent execution" | B intro |
| K1.2 IcedID link | missed | `files/bp.dat` is in §5.3 as "File Upload Path" and in §9 as "Data file for exfiltration or storage" | B intro; P, E |
| K1.4 x64 DLL; arch check | partly (body) | §2 "Type · pe, x86-64, DLL". No architecture check | B *System architecture check* |
| K1.5 four exports, one address | found | §7 "All 4 exports share one address, 0x3ce4." | E |

### K2
| # | Score | Maljan | Source |
|---|---|---|---|
| K2.1 APIs by hash | partly (body) | §5.2 capa rows "resolve function by parsing PE exports", "hash data with CRC32"; §5.7 "network capability implemented via … dynamic resolution not captured in the static import table". Never "by hash" | B *Windows API resolution* |
| K2.2 abort on failed check | missed | — | B *Anti analysis* |
| K2.3 mutex | **found** (it. 4: missed) | §8 T1564.001 procedure (the analyst's claim) "The malware creates a mutex to ensure only one instance is running."; §9 `runnung` "Likely part of a mutex name or identifier". The technique it is filed under is wrong (see reverse direction) | B *Mutex* |
| K2.4 install, then persist | partly (body) | §1 "It attempts to establish persistence by creating scheduled tasks and modifying registry keys"; §4 step 3 "creating shortcuts in the Startup folder and potentially modifying Registry Run keys" (wrong mechanism). No self-copy | B *Persistence* |
| K2.5 register, then command loop | partly (body) | §4 step 2 "Exfiltrates the collected … data to C2 servers (https://skinnyjeanso.com/live/, https://titnovacrion.top/live/) via HTTP POST requests using RC4 encryption." No registration and no loop | B *Communications protocol* |
| K2.6 `update_data.dat` for new C2s | partly (body) | §5.3 "Update Data File · \update_data.dat"; §9 "Data file for updates or storage". Purpose not stated | B *The update data .dat file* |

### K3
| # | Score | Maljan | Source |
|---|---|---|---|
| K3.1 PEB BeingDebugged | partly (body) | §5.2 capa row "PEB access · B0001.019"; §7 "Debugger Detection::Process Environment Block". No sentence | B *Debugger check* |
| K3.2 process count | missed | — | B |
| K3.3 architecture / WOW64 | missed | — | B, E |
| K3.4 MAC check | missed | — | B |
| K3.5 PEB walk + CRC32 names | partly (body) | §5.1 "Capa analysis confirms the presence of obfuscated stackstrings, RC4 encryption (PRGA), and CRC32 hashing"; §5.2 capa rows | B |
| K3.6 string encryption | partly (body) | §5.1 "the presence of obfuscated stackstrings, which are decoded at runtime". The scheme is stackstrings, not the rolling XOR | B *Strings decryption*; E |
| K3.7 self-deletion via ADS | missed | `:wtfbbq` is now in the §9 body, but as "Likely part of a mutex name or identifier" | E *Self-deletion* |

### K4–K6
| # | Score | Maljan | Source |
|---|---|---|---|
| K4.1 bot ID | **partly (body)** (it. 4: appendix) | §5.3 "Identifier Pattern · %04X%04X%04X%04X%08X%04X"; §9 the same value as "Mutex name pattern". No derivation | B *Bot ID* |
| K4.2 group → FNV-1a | partly (body) | §5.2 capa row "hash data using fnv"; `Littlehw` in §9 ("Likely part of a mutex name or identifier"); `group=%lu` in the beacon format. Not linked | B *Group and Group ID* |
| K4.4 two encrypted C2s | found | §5.7 "The binary contains decoded strings referencing two C2 endpoints: `https://skinnyjeanso.com/live/` and `https://titnovacrion.top/live/`" | B *C2 decryption* |
| K5.1 `Custom_update\Update_%x.dll` | partly (body) | `Custom_update` and `Update_%x` both in §9 ("Likely part of a mutex name or identifier"); §5.3 "Persistence Locations · … Local AppData" | B *Persistence* |
| K5.2 task `Updater`, COM, at logon | **partly (body)** (it. 4: found) | §1 "creating scheduled tasks"; `Updater` and `LogonTrigger` in §9, each "Likely part of a mutex name or identifier". The task is never named | B *Persistence* |
| K5.3 `update_data.dat` holds new C2 URLs | partly (body) | §9 "Data file for updates or storage" | B |
| K6.1 HTTPS POST `/live/` | found | §5.7 channel row "HTTP POST exfiltration · HTTPS · `hxxps://skinnyjeanso[.]com/live/`; `hxxps://titnovacrion[.]top/live/`" | B |
| K6.2 User-Agent | found | §9 `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)` "User-Agent string for HTTP requests" | B |
| K6.3 RC4 then base64 | partly (body) | §5.7 "The sample uses RC4 encryption for data transmission"; the base64 alphabet is in §9 but not tied to the traffic; `12345` "Likely part of a mutex name or identifier" | B |
| K6.4 beacon interval | missed | — | B |
| K6.5 beacon format | found | §5.3 "Exfiltration Format"; §5.7 channel row; §9 `counter=%d&type=%d&guid=%s&os=%d&arch=%d&username=%s&group=%lu&ver=%d.%d&up=%d&direction=%s`, `&computername=%s`, `&domain=%s` | B *Beacon data* |
| K6.6 beacon types 1–5 | missed | — | B |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | partly (body) | §9 `URLS\|%d\|%s` and `URLS` "Data format for exfiltrated URLs", `COMMAND` "Data format for exfiltrated commands", `CLEARURL` "Likely part of a mutex name or identifier". `ERROR` absent. All wrong purposes | B |

### K7–K10
- **K7 commands.** partly (body): **3** (`&proclist=[` "HTTP POST parameter for process list" and the `"pid"`, `"proc"`,
  `"subproc"` rows), **4** (§5.5, §5.6 recon commands), **13** (§5.8 "constructs a command-line execution string for
  rundll32.exe to load a dynamically generated payload … `%s%d.dll`") and **18** (`files/bp.dat`). partly (appendix): **2**
  (`&desklinks=[` only in the appendix; iteration 4 had it in §9). missed: **12** (`%s%d.exe` is "EXE file name pattern" only,
  and §5.8 says "It does not drop files"), **14**, **15**, **17**, **19**, **20**. None tied to a command ID.
- **K8 discovery: found.** §5.5 and §5.6 list `ipconfig /all`, `systeminfo`, `whoami /groups`, `nltest /domain_trusts
  /all_trusts`, `net view /all /domain`, `net config workstation`, `net group "Domain Admins" /domain` and the
  `SecurityCenter2` WMI query. `ifconfig.me` is missing, as in every iteration.
- **K9 IOCs.** found: own hashes; `/live/`; the User-Agent. partly (body): mutex `runnung` ("Likely part of a mutex name
  or identifier", the label the same table gives ten other strings), `Custom_update`, **task `Updater`** (§9 row with the
  mutex label; iteration 4: found), `update_data.dat`, **`Update_%x`** (iteration 4: appendix).
- **K10 ATT&CK.** found: **T1027** (published; RC4, stackstrings), **T1218.011** (published, "uses Rundll32.exe to
  execute code"). missed: **T1053.005** (not claimed; iteration 4: found), T1055, T1070.004, T1059.003.
- **Build consistency.** `skinnyjeanso.com` and `titnovacrion.top` are on B's list of 47. `Littlehw` is on B's group
  list, and `12345` is B's first RC4 key. Both in the body, unexplained. All consistent.
- **K11.** The only draft is the hash/imphash YARA rule. The judge's verdict was stated this time, and it wrote the two
  C2 domains as indicators, but as `[url:value LIKE '%skinnyjeanso.com%']`. The platform's integrity pass drops any
  pattern without "=", so 12 of its 13 indicators were removed and no domain reached `/iocs`, STIX or a draft rule.

## IOC recall (K9, 8 core values)
- Published (`/iocs` and the export): 1 of 8 (the sample's hashes). `iocs.json` has 4 hashes. The judge wrote the two C2
  domains (and ten command-line and one registry indicator), and all were dropped as malformed (`LIKE` has no `=`).
- Stated in the body: **8 of 8** as values (all in §9; iteration 4: 8 of 8), 3 of 8 with a right purpose (iteration 4: 5).
- Present anywhere: 8 of 8.

## Host-identifier section
Present: **73 rows** (iteration 4: 57), all typed `String`, all cited to `ev_0012` (FLOSS). 70 are verbatim in
`ev_0012`. The other three are `ev_0012` values with the escaping normalised (`\\root` written `\root` twice;
`\Registry\Machine\` written `\Registry\Machine\x5c`), one of them cut with "…". So every row is cited to the entry
that holds it. `composer.repeated_items` was **asked** once and resolved (iteration 4: recorded unasked); `composer.schema`
once, resolved. No section was cut at its cap.

The purposes got worse: eleven rows (`12345`, `:wtfbbq`, `Littlehw`, `Updater`, `CLEARURL`, `runnung`, `front`,
`LogonTrigger`, `Custom_update`, `Update_%x`, `init -="%s\%s"`) carry the one label "Likely part of a mutex name or
identifier", and `%04X…` is "Mutex name pattern". Iteration 4 used "Unknown string" for the same set.

## Reverse direction: claims no human report supports

| Claim (quoted) | Assessment | How we know |
|---|---|---|
| **T1003 OS Credential Dumping** published by the judge with no claim and no procedure; §1 "strong indicators of system reconnaissance and credential harvesting capabilities" | **contradicted** | No report describes credential theft. No analyst named T1003 (`stix.credit_without_claim`); the credit was dropped, the technique published |
| **T1078 Valid Accounts** published: "The binary is a Trojan/Backdoor … that performs system reconnaissance and exfiltrates data to a C2 server." | **unsupported** | Asked (`attck.claim_does_not_describe`); the retry returned no claims, so the id stands |
| **T1564.001 Hidden Files and Directories** on "The malware creates a mutex to ensure only one instance is running." | **unsupported** (wrong technique; the mutex itself is right) | Asked, unanswered |
| **T1010 Application Window Discovery** on "collects information about the antivirus software" | **unsupported** (AV discovery is T1518.001) | Asked, unanswered |
| **T1012 Query Registry** on "checks for the presence of antivirus software and attempts to evade detection" | unsupported as framed (the Shell Folders read would carry it; the claim does not say so) | Asked, unanswered |
| **T1083 File and Directory Discovery** on "collects information about network shares and computers" | unsupported as framed (`net view` is T1135/T1018) | Asked, unanswered |
| **T1216.001 PubPrn** on "uses legitimate system binaries (LOLBin) for execution and data collection" | **unsupported** | No PubPrn string or behaviour anywhere |
| §4 step 3 "Establishes persistence by creating shortcuts in the Startup folder and potentially modifying Registry Run keys"; §10.3, §11 Run keys | **contradicted** | B, E: the only persistence is the `Updater` task. §5.4 itself says the claim "is not supported"; the Startup/Desktop/Personal values are E's configurable install locations (K5.5) |
| §5.8 "It does not drop files" | **contradicted** | B, E: commands 12, 13, 15 and 18 download and write payloads (`%s%d.exe`, `%s%d.dll`, `bp.dat`) |
| §1 "The primary risk is the exfiltration of sensitive system and domain configuration data" | unsupported as framed | B: the recon answers command 4. The sample is a loader |
| §9 purposes: eleven values "Likely part of a mutex name or identifier"; `URLS` "Data format for exfiltrated URLs"; `%04X…` "Mutex name pattern" | wrong purposes | B: install folder, task name, C2 instructions, RC4 key, group name, ADS name, bot ID |
| T1574.002, T1024, T1547.000 (invalid ids, not published) | unsupported, not published | `attck.unknown_id` ×4, unanswered |
| T1087.002 on `net group "Domain Admins" /domain`; T1018 (judge) on `net view`; T1016; T1082; T1071 | correct but new | decoded strings; the key's derived mappings |
| Severity High | new (judgement) | — |

**Eleven contradicted or unsupported claims** (iteration 4: ten; iteration 2: nine). **7 of the 15 published
techniques** have no evidence behind them as claimed (T1003, T1078, T1564.001, T1010, T1216.001, T1012, T1083;
iteration 4: 5 of 10). `flagged_statements` is empty: one `narrative.ungrounded_capability` was asked and the retry
passed, so nothing was marked.
