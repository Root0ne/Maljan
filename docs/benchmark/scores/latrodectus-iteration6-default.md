# Latrodectus score: iteration 6, default model

Default model (Qwen3.6-35B-A3B on ik_llama.cpp, 32,768-token context, 1 GiB prompt cache, 8 context checkpoints per
slot, as in iterations 4 and 5), `dev` @ `ed57265b`, default profile, **mock sandbox (nothing executed)**. The method
is exactly as on the [benchmark page](../index.md#method) and in the [iteration-5 score](latrodectus-iteration5-default.md):
57 core items of K1–K10 (with K1.1 split), build items as consistency checks only, chain and later items not scored.

- **partly (body)**: the body states part of the item, or states it with the wrong purpose.
- **partly (appendix)**: the value is printed only in Appendix A › Floss: strings.
- A behaviour that a string in the appendix only hints at counts as **missed**.

§9's "Host identifiers read by the report model" table (77 rows) is in the body. Human sources: **B** Bitsight (names
this hash), **E** Elastic, **P** Proofpoint.

## Totals (iteration 5 in brackets)

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | **2** (3) | **2** (1) | 0 (0) | 1 (1) | 0 (0) |
| K2 execution flow | 6 | **0** (1) | **5** (4) | 0 (0) | 1 (1) | 0 (0) |
| K3 anti-analysis | 7 | 0 (0) | 3 (3) | 0 (0) | 4 (4) | 0 (0) |
| K4 identifiers | 3 | 1 (1) | 2 (2) | 0 (0) | 0 (0) | 0 (0) |
| K5 persistence | 3 | 0 (0) | 3 (3) | 0 (0) | 0 (0) | 0 (0) |
| K6 C2 | 7 | 3 (3) | 2 (2) | 0 (0) | 2 (2) | 0 (0) |
| K9 IOCs | 8 | 3 (3) | 5 (5) | 0 (0) | 0 (0) | 0 (0) |
| **Main (K1–K6, K9)** | **39** | **9** (11) | **22** (20) | **0** (0) | **8** (8) | **0** (0) |
| K7 commands | 11 | 0 (0) | **5** (4) | **0** (1) | 6 (6) | 0 (0) |
| K8 discovery | 1 | 1 (1) | 0 (0) | 0 (0) | 0 (0) | 0 (0) |
| K10 ATT&CK | 6 | 2 (2) | **1** (0) | 0 (0) | **3** (4) | 0 (0) |
| **Depth (K7, K8, K10)** | **18** | **3** (3) | **6** (4) | **0** (1) | **9** (10) | **0** (0) |
| **All core** | **57** | **12** (14) | **28** (24) | **0** (1) | **17** (18) | **0** (0) |

In the baseline's four columns this is **12 found / 28 partly / 17 missed / 0 wrong**. Iteration 5 scored
14 / 25 / 18 / 0, iteration 4 15 / 25 / 17 / 0, iteration 2 12 / 25 / 20 / 0, iteration 1 12 / 29 / 16 / 0, the
baseline 3 / 7 / 46 / 1. No item is appendix-only this time, so discounting appendix-only items changes nothing: **12 / 28 /
17 / 0** (iteration 5: 14 / 24 / 19 / 0; iteration 4: 15 / 23 / 19 / 0; iterations 1 and 2: 12 / 20 / 25 / 0).

## Item by item

### K1
| # | Score | Maljan (quoted) | Human source |
|---|---|---|---|
| K1.1a family | found | "**Family:** Latrodectus (moderate-to-high confidence, 0.85, stated by the judge) [ev_0011]" | B intro |
| K1.1b loader | **partly (body)** (it. 5: found) | The sample is called a "Trojan/Backdoor" throughout; the nearest sentences are §5.6 rundll32 "potentially for persistence or payload execution" and §8 T1105 "The sample uses a custom update mechanism." Neither "loader" nor "downloads" appears | B intro |
| K1.2 IcedID link | missed | no IcedID anywhere; `files/bp.dat` is "Data file for storage" | B intro; P, E |
| K1.4 x64 DLL; arch check | partly (body) | §2 "Type · pe, x86-64, DLL". No architecture check | B |
| K1.5 four exports, one address | found | §7 "All 4 exports share one address, 0x3ce4." | E |

### K2
| # | Score | Maljan | Source |
|---|---|---|---|
| K2.1 APIs by hash | partly (body) | §5.2 capa rows "resolve function by parsing PE exports", "hash data with CRC32"; §5.1 "It uses CRC32 hashing for data integrity" (wrong purpose) | B |
| K2.2 abort on failed check | missed | — | B |
| K2.3 mutex | **partly (body)** (it. 5: found) | the analyst's claim "The sample uses a custom mutex or identifier for its operations." (§13, quoted by `attck.claim_does_not_describe`); `CreateMutexW` in §7 imports; `runnung` "Unknown string, possibly a typo or part of a key". No single-instance check | B *Mutex* |
| K2.4 install, then persist | partly (body) | §4 step 5 "Establishes persistence via Startup folder shortcuts" (wrong mechanism); `Custom_update` "Update mechanism identifier". No self-copy | B |
| K2.5 register, then command loop | partly (body) | §4 steps 3–4 build and send the POST; §5.7 "Response parsing logic is present for `URLS\|%d\|%s`, `COMMAND`, `ERROR`, and `CLEARURL` strings". No registration and no loop | B |
| K2.6 `update_data.dat` for new C2s | partly (body) | §9 `\update_data.dat` "Data file for storage"; §5.3 "Update Mechanism Strings". Purpose not stated | B |

### K3
| # | Score | Maljan | Source |
|---|---|---|---|
| K3.1 PEB BeingDebugged | partly (body) | §5.2 capa row "PEB access · B0001.019"; §7 "Debugger Detection::Process Environment Block". No sentence | B |
| K3.2 process count | missed | — | B |
| K3.3 architecture / WOW64 | missed | — | B, E |
| K3.4 MAC check | missed | — | B |
| K3.5 PEB walk + CRC32 names | partly (body) | §5.2 capa rows (PEB access, CRC32, resolve by parsing exports) | B |
| K3.6 string encryption | partly (body) | §5.1 "Capa analysis identifies the presence of obfuscated stackstrings". Not the rolling XOR | B; E |
| K3.7 self-deletion via ADS | missed | `:wtfbbq` "Unknown string, possibly a key or identifier" | E |

### K4–K6
| # | Score | Maljan | Source |
|---|---|---|---|
| K4.1 bot ID | partly (body) | §9 `%04X%04X%04X%04X%08X%04X` "Format for generating unique identifiers" (a right purpose now; it. 5 "Mutex name pattern"). No derivation | B |
| K4.2 group → FNV-1a | partly (body) | §5.2 capa row "hash data using fnv"; `Littlehw` "Unknown string, possibly part of a key or identifier"; `group=%lu` in the beacon. Not linked | B |
| K4.4 two encrypted C2s | found | §5.7 "POST requests to two URLs: `hxxps://skinnyjeanso[.]com/live/` and `hxxps://titnovacrion[.]top/live/`" | B |
| K5.1 `Custom_update\Update_%x.dll` | partly (body) | `Custom_update` "Update mechanism identifier", `Update_%x` "Update file name format", `AppData` "Folder path for data storage" | B |
| K5.2 task `Updater`, COM, at logon | partly (body) | §5.3 "Trigger Type · LogonTrigger"; §9 `LogonTrigger` "Trigger type for persistence" (right, and better than it. 5's mutex label); `Updater` "Component name for updates". The task is never named and the persistence sentences say Startup shortcuts | B |
| K5.3 `update_data.dat` holds new C2 URLs | partly (body) | §9 "Data file for storage" | B |
| K6.1 HTTPS POST `/live/` | found | §5.7 channel row "HTTP POST · HTTPS · `hxxps://skinnyjeanso[.]com/live/`; `hxxps://titnovacrion[.]top/live/`" | B |
| K6.2 User-Agent | found | §5.3 and §9 `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)` "HTTP User-Agent string for C2 requests" | B |
| K6.3 RC4 then base64 | partly (body) | §1 "uses RC4 encryption … to obfuscate its communication"; §9 base64 alphabet "Base64 alphabet" (not tied to the traffic); §5.7 channel "Encryption · TLS"; `12345` "possibly a key or identifier" | B |
| K6.4 beacon interval | missed | — (`PT0S` is "Time duration format") | B |
| K6.5 beacon format | found | §5.7 channel row and §9 `&counter=%d&type=%d&guid=%s&os=%d&arch=%d&username=%s&group=%lu&ver=%d.%d&up=%d&direction=%s`, `&computername=%s`, `&domain=%s` | B |
| K6.6 beacon types 1–5 | missed | — | B |
| K6.7 URLS/CLEARURL/COMMAND/ERROR | partly (body), **nearest yet** | §5.7 "Response parsing logic is present for `URLS\|%d\|%s`, `COMMAND`, `ERROR`, and `CLEARURL` strings"; §9 `COMMAND` "Command identifier in C2 communication", `CLEARURL` "Command to clear URLs in C2 communication", `ERROR` "Error status indicator in C2 communication", `URLS\|%d\|%s` "Data format for C2 communication". The first run to read them as the C2's response instructions with three purposes right; URLS's (store a new C2 at an index) is not stated, so partly | B |

### K7–K10
- **K7 commands.** partly (body): **2** (§4 step 3 collects "desklinks"; `&desklinks=[` "C2 communication parameter
  for shortcut creation", a wrong purpose; it. 5 appendix), **3** (`&proclist=[` "C2 communication parameter for process
  list"; the `"pid"`, `"proc"`, `"subproc"` rows), **4** (§5.5 and §5.6 recon commands), **13** (§5.6 "Executes a DLL
  function via rundll32.exe, potentially for persistence or payload execution"; `%s%d.dll` "DLL file name format") and
  **18** (`files/bp.dat` "Data file for storage"). missed: **12** (`%s%d.exe` "Executable file name format" only),
  **14**, **15** (§8's "custom update mechanism" is filed with the persistence strings, not a download-and-run
  update), **17**, **19**, **20**. None tied to a command ID.
- **K8 discovery: found.** §5.5 and §5.6 list `systeminfo`, `ipconfig /all`, `whoami /groups`, `net view /all`,
  `net view /all /domain`, `net group "Domain Admins" /domain`, `nltest /domain_trusts` (and `/all_trusts`),
  `net config workstation` and the `SecurityCenter2` WMI query. `ifconfig.me` is missing, as in every iteration.
- **K9 IOCs.** found: own hashes; `/live/`; the User-Agent. partly (body): mutex `runnung` ("Unknown string, possibly a
  typo or part of a key"), `Custom_update` ("Update mechanism identifier"), `Update_%x` ("Update file name format"),
  `update_data.dat` ("Data file for storage"), task `Updater` ("Component name for updates").
- **K10 ATT&CK.** found: **T1027** (published; RC4, stackstrings) and **T1059.003** (published, "The sample uses
  legitimate system binaries (LOLBin) to execute commands", with §4 step 1's `cmd.exe` recon; it. 5 missed).
  **partly: T1218.011** — only the parent **T1218** is published, on "likely loaded by a host process (e.g., via
  `rundll32.exe` …)" (it. 5 published T1218.011: found). missed: T1053.005, T1055, T1070.004.
- **Build consistency.** `skinnyjeanso.com` and `titnovacrion.top` are on B's list of 47; `Littlehw` is on B's group
  list; `12345` is B's first RC4 key. All consistent.
- **K11.** Drafts: the YARA rule now carries both C2 domains as strings (`2 of them`) beside the hash/imphash, and a
  Suricata DNS rule for both domains. The first network drafts on this sample since iteration 2.

## IOC recall (K9, 8 core values)
- Published (`/iocs` and the export): 1 of 8 (the sample's hashes) — plus the two C2 domains (`domain-name`, typed
  `malicious-activity`), which are build items, not K9 core values. `iocs.json`: 4 hashes + 2 domains.
- Stated in the body: **8 of 8** as values (all in §9), 3 of 8 with a right purpose (iteration 5: 3; iteration 4: 5).
- Present anywhere: 8 of 8.

## Host-identifier section
Present: **77 rows** (iteration 5: 73), all typed `String`, all cited to `ev_0012` (FLOSS). 73 are verbatim in
`ev_0012`; four are `ev_0012` values with the form normalised — `\\root` written `\root` (×2), `\Registry\Machine\`
written `\Registry\Machine\x5c`, and the beacon string given a leading `&` — and one is cut with "…". Every row is cited
to the entry that holds it. No `composer.repeated_items` this run. Two sections were cut at their cap and re-asked
(`execution_flow` 10,409 characters, 74 items begun, at most 19 distinct; `evasion_antiforensics` 12,860 characters);
`payloads` was skipped after its schema retry ("the answer was not JSON at all").

The purposes are better than iteration 5's: no single label covers the unknowns. Five rows say "Unknown string,
possibly …" (`Littlehw`, `front`, `runnung`, `:wtfbbq`, `12345`); `LogonTrigger`, `CLEARURL`, `COMMAND`, `ERROR` and
`%04X…` now carry right purposes. The largest shared label is "C2 communication parameter" on twelve beacon fields,
which is right.

## Reverse direction: claims no human report supports

| Claim (quoted) | Assessment | How we know |
|---|---|---|
| §4 step 5 "Establishes persistence via Startup folder shortcuts"; §5.4 "We assess the sample attempts to establish persistence by creating shortcuts in the Startup folder"; **T1547** published on it; §3 judge "persistence via registry/run keys (T1547)" | **contradicted** | B, E: the only persistence is the `Updater` task at logon. The Startup/Desktop/Personal values are E's configurable install locations (K5.5) |
| **T1012 Query Registry** on "The sample attempts to disable or evade antivirus detection."; §10.3 ties T1012 to the SecurityCenter2 WMI query | unsupported as framed | the AV query is WMI (T1518.001); the Shell Folders read would carry T1012, the claim does not say so. Asked (`attck.claim_does_not_describe`), unanswered (the retry was cut) |
| **T1036 Masquerading** on "The sample uses a custom file extension for its payloads or data files." | unsupported as framed | the key's derived T1036 is the `Update_*.dll` name and the `Updater` task; a file extension is not masquerading. Asked, unanswered |
| §5.1 "masquerades as a legitimate DLL" | unsupported | nothing in the evidence or the reports |
| T1047 "… and potentially for lateral movement" | unsupported (the WMI use is right) | no report describes lateral movement |
| §1 "It attempts to evade detection by querying the SecurityCenter2 WMI namespace"; §1 "Immediate isolation … to prevent further data leakage and lateral movement" | unsupported as framed | B: the AV query answers command 4 (discovery); the sample is a loader |
| Judge indicator "SHA256 6091f258…" written as `[ipv4-addr:value = '6091f258…']` | wrong (model), refused | `stix.unpublishable_endpoint`; not exported, but §9 prints it as an IPv4 row "no: not an address this run may publish" |
| T1004 (invalid id; on "uses RC4 encryption") | unsupported, not published | `attck.unknown_id`, unanswered |
| T1059.003, T1059, T1082, T1071, T1041, T1105 (on "custom update mechanism"), T1047 (WMI) | correct but new | decoded strings; the key's derived mappings (T1071.001, T1082, T1105) |
| Severity Critical | new (judgement) | — |

**Seven contradicted or unsupported claims** (iteration 5: eleven; iteration 4: ten; iteration 2: nine). **2 of the 13
published techniques** have no evidence behind them as claimed (T1547 contradicted, T1036 unsupported), and T1012 is
defensible only on a string the claim does not name (iteration 5: 7 of 15). No technique was published with no claim:
the one judge-only row is T1027.005, a capa rule match. `flagged_statements` is empty: nothing was marked.
