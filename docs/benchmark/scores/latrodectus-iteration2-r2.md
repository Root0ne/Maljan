# Latrodectus score: iteration 2, default model with the r2 disassembler

Same tree, model, profile and mock sandbox as the [default iteration-2 run](latrodectus-iteration2-default.md); the only
change is `core.static.provider = "r2"` (radare2 through r2mcp) for this job, restored afterwards. Worker: "Static
provider 'r2': 68 tools attached". Same method and grading as the [benchmark page](../index.md#method).

## What the static analyst did with a disassembler

- 39 of 40 steps (cap `steps`), 19 tool calls: `open_file`, `analyze` (level 2, 162 functions), `list_imports` ×2,
  `list_exports`, `list_strings` (count only), `list_functions` ×4 (one with the literal filter `"null"`, none returned),
  and **`decompile_function` ×9**, following the call chain from the export: `0x3ce4` → `fcn.3cb4` → `fcn.3868` (the
  start-up routine) → `fcn.ae1c` (53 callers — the API resolver) → `fcn.ae78` (121 callers — the string decoder FLOSS
  also names) → `fcn.c934`, `fcn.8820`, `fcn.6328`. It never reached the anti-analysis checks, the bot-ID derivation or
  the command dispatcher.
- The loop ended without an answer; the closing summary call (sized to the context window: 26,507 of 52,428 characters,
  1,198 s left) answered
  in 105 s, the format question was asked once (`isr.unparsed_answer`, `isr.claim_without_confidence`) and the answer
  stayed prose: **0 claims**. The prose opens with a wrong claim ("a scheduled task named \"Custom_update\" using the
  `schtasks` command") and then repeats the same list of decoded strings, cited as `.data+0x…` offsets that are
  FLOSS's code addresses, until the output ran out. No sentence from the decompiled code reached the report.
- No second loop: by design, an analyst that answered in prose has "already answered".

## Totals (default run of iteration 2 in brackets)

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 3 (3) | 1 (1) | 0 (0) | 1 (1) | 0 (0) |
| K2 execution flow | 6 | 0 (0) | 2 (4) | 1 (0) | 2 (2) | **1** (0) |
| K3 anti-analysis | 7 | 0 (0) | 3 (3) | 0 (0) | 4 (4) | 0 (0) |
| K4 identifiers | 3 | 1 (1) | 1 (1) | 1 (1) | 0 (0) | 0 (0) |
| K5 persistence | 3 | 0 (0) | 1 (3) | 2 (0) | 0 (0) | 0 (0) |
| K6 C2 | 7 | 2 (3) | 1 (1) | 2 (1) | 2 (2) | 0 (0) |
| K9 IOCs | 8 | 3 (3) | 1 (2) | 4 (3) | 0 (0) | 0 (0) |
| **Main (K1–K6, K9)** | **39** | **9** (10) | **10** (15) | **10** (5) | **9** (9) | **1** (0) |
| K7 commands | 11 | 0 (0) | 3 (4) | 0 (0) | 8 (7) | 0 (0) |
| K8 discovery | 1 | 1 (1) | 0 (0) | 0 (0) | 0 (0) | 0 (0) |
| K10 ATT&CK | 6 | 1 (1) | 1 (1) | 0 (0) | 4 (4) | 0 (0) |
| **Depth (K7, K8, K10)** | **18** | **2** (2) | **4** (5) | **0** (0) | **12** (11) | **0** (0) |
| **All core** | **57** | **11** (12) | **14** (20) | **10** (5) | **21** (20) | **1** (0) |

Four columns: **11 found / 24 partly / 21 missed / 1 wrong** (default run: 12 / 25 / 20 / 0). The control-flow items the
variant was meant to test — K2.2, K3.2–K3.4, K3.7, K4.1 derivation, K6.4, K6.6, K7 command IDs — are **all still missed**.

## Item by item (only where it differs from the default run, or needs the sentence)

| # | Score | Maljan (quoted) | Source |
|---|---|---|---|
| K1.1a, K1.1b, K1.5 | found | "Family: Latrodectus (high confidence, 0.90)"; "Category: loader"; §7 "All 4 exports share one address, 0x3ce4." | B, E |
| K1.4 | partly (body) | §2 "pe, x86-64, DLL" (§1 calls it "a … Windows PE executable") | B |
| K2.1 | partly (body) | §5.2 "imports exclusively from kernel32.dll and user32.dll … the sample's own text strings are resolved via emulation at runtime"; capa rows | B |
| K2.4 | partly (body) | §4 step 3 "creating a scheduled task named 'Updater' with a 'LogonTrigger' to execute a DLL or EXE file from the 'Startup' or 'Local AppData' folder" — no copy step | B |
| K2.5 | **wrong** | §5.7 "The sample does not implement network-based Command and Control (C2) communication … used to transmit system telemetry … rather than to receive operational commands" | B *Communications protocol*, *C2 instructions and commands* |
| K2.6 | partly (appendix) | `\update_data.dat` only in the appendix | B |
| K3.1, K3.5, K3.6 | partly (body) | §5.2 "accesses the PEB and encrypts data using RC4 PRGA"; §5.1 "stackstrings and runtime decoding routines … Emulation recovered 81 decoded strings that are not present in the static binary" | B, E |
| K4.2 | partly (body) | §5.2 capa row "hash data using fnv" | B |
| K4.4 | found | §4 step 2 names both `/live/` URLs; §5.7 "These URLs are embedded in the binary's decoded strings" | B |
| K5.1, K5.3 | partly (appendix) | `Custom_update`, `Update_%x`, `update_data.dat` only in the appendix | B |
| K5.2 | partly (body) | §4 step 3 names the task `Updater` and `LogonTrigger` — but §5.4 says "The sample does not implement persistence mechanisms … no calls to … scheduled task creation" | B, E |
| K6.1, K6.5 | found | §4 step 2; §5.7 channel table (the exact base format) | B |
| K6.2 | partly (appendix) | the UA only in the appendix | B |
| K6.3 | partly (body) | §5.7 channel "Encryption · RC4 PRGA" (right this time); base64 not stated | B |
| K6.7 | partly (appendix) | keywords only in the appendix; the body denies commands (K2.5) | B |
| K9 | 3 / 1 / 4 / 0 | found: hashes, `/live/`, task `Updater` (§4). partly (body): `runnung`, stated as "the 'Runnung' (likely 'Running') registry key under HKLM". partly (appendix): `Custom_update\`, `Update_%x`, `update_data.dat`, UA | B, E, P |
| K7 | 0 / 3 / 0 / 8 | partly (body): **3** (§4 step 2 "process list" among the POSTed data), **4** (§5.6 table of recon commands, not tied to a C2 command), **13** (§4 step 4 "Uses rundll32.exe to execute functions from a DLL, potentially for further payload delivery"). missed: 2, 12 (§5.8 "does not drop files or deliver payloads"), 14, 15, 17, 18, 19, 20 | B |
| K8 | found | §5.6 table and §5.5 list the recon commands | B |
| K10 | 1 / 1 / 0 / 4 | T1027 published (capa, judge); T1218 only in §10.3/§11; T1055, T1053.005, T1070.004, T1059.003 missed | E |

## Reverse direction: claims no human report supports

| Claim | Assessment |
|---|---|
| §5.7 "does not implement network-based Command and Control … rather than to receive operational commands" | **contradicted** (B: URLS/CLEARURL/COMMAND loop) |
| §5.4 "The sample does not implement persistence mechanisms" | **contradicted** (B, E: `Updater` task; the report's own §4) |
| §5.8 "does not drop files or deliver payloads … contains no executable code sections capable of writing to disk" | **contradicted** (B: commands 12–15, 18 download and run payloads) |
| §4 "modify the 'Runnung' (likely 'Running') registry key under HKLM" | **contradicted** (E, P: `runnung` is the mutex) |
| "strong obfuscation and credential-harvesting capabilities"; "exfiltrate the collected host profile"; "lateral movement" | unsupported (each flagged `narrative.ungrounded_capability`, 15 flags in all, left in the text) |
| §5.3 "Persistence Mechanism · Startup folder, Rundll32 execution"; judge "persistence mechanisms (scheduled tasks, shortcuts)" | contradicted (the task only) |
| T1012 for the SecurityCenter2 WMI query; T1041 in §10.3/§11 | contradicted / unsupported (discovery, command 4) |
| §5.5 cites `ev_0008` (capa) for `whoami /groups`, `ipconfig /all`, `nltest …`, which only `ev_0012` (FLOSS) holds | wrong-entry citation, not asked (the values are unquoted) |

## Verdict on the variant (n = 1)
The disassembler was available and used — nine decompiles along the real call chain, the API resolver and the string
decoder identified by their caller counts — so the control-flow gap is **not only a platform gap**. What stopped it here
is the model: 7 of its 39 steps went to listing, it spent the rest walking from the entry point without reaching the
checks, and its closing answer degenerated into a repeated string list with no confidence, which the platform correctly
refused as claims. The report written from that run is worse than the default one: four "does not" sentences
contradict the human report, one of them a K2.5 "wrong".
