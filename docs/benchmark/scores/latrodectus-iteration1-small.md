# Latrodectus score: iteration 1, small model

Small model (qwen3.8:27b on Ollama), `dev` @ `9019db82`, default profile, **mock sandbox (nothing executed)**. The
method and the "partly (body) / partly (appendix)" split are the same as in the
[default model's iteration-1 score](latrodectus-iteration1-default.md); see also the
[benchmark page](../index.md#method).

**The static analyst produced 0 claims.** Everything below comes from the triage pack (FLOSS, capa, pe_info, VT), the
judge and the report model. The analyst's 16 FLOSS searches were well aimed — its regexes name `runnung`,
`Custom_update`, `Updater`, `Littlehw`, `:wtfbbq`, `CLEARURL`, `URLS`, `12345`, `PT0S`, `%04X` — but its two syntheses
timed out (423 s and 622 s caps) and nothing it established reached the report.

## Totals

| Group | Items | Found | Partly (body) | Partly (appendix) | Missed | Wrong |
|---|---|---|---|---|---|---|
| K1 identity | 5 | 3 | 1 | 0 | 1 | 0 |
| K2 execution flow | 6 | 0 | 4 | 0 | 2 | 0 |
| K3 anti-analysis | 7 | 0 | 3 | 0 | 4 | 0 |
| K4 identifiers | 3 | 1 | 1 | 1 | 0 | 0 |
| K5 persistence | 3 | 0 | 2 | 1 | 0 | 0 |
| K6 C2 | 7 | 2 | 1 | 2 | 2 | 0 |
| K9 IOCs | 8 | 2 | 2 | 4 | 0 | 0 |
| **Main (K1–K6, K9)** | **39** | **8** | **14** | **8** | **9** | **0** |
| K7 commands | 11 | 0 | 6 | 0 | 5 | 0 |
| K8 discovery | 1 | 1 | 0 | 0 | 0 | 0 |
| K10 ATT&CK | 6 | 1 | 0 | 0 | 5 | 0 |
| **Depth (K7, K8, K10)** | **18** | **2** | **6** | **0** | **10** | **0** |
| **All core** | **57** | **10** | **20** | **8** | **19** | **0** |

In the baseline's four columns: **10 found / 28 partly / 19 missed / 0 wrong** (baseline 3/7/46/1; default model in
the same iteration 12/29/16/0).

## Item by item (only where it differs from the default model's grade or quote)

| # | Score | Maljan (quoted) | Human source |
|---|---|---|---|
| K1.1a family | found | "**Family:** Latrodectus (moderate-to-high confidence, 0.85) [ev_0011]" | B intro |
| K1.1b loader | found | "**Category:** Infostealer / Loader" (the loader half; "Infostealer" see reverse) | B intro |
| K1.4 x64 DLL | partly (body) | §2 "pe, x86-64, DLL" — but §5.2 says "a **32-bit** Windows PE executable (machine 0x8664)" | B |
| K1.5 exports | found | §7 "All 4 exports share one address, 0x3ce4." | E |
| K2.1 | partly (body) | capa rows in §5.2; prose "RC4 encryption and CRC32 hashing" as obfuscation | B |
| K2.4 | partly (body) | §4 step 7 "…to locate user directories such as 'AppData'…"; §5.4 "likely establishes persistence via registry modification or scheduled tasks" | B |
| K2.5 | partly (body) | §4 step 4 "Constructs a URL-encoded POST body … and sends it to C2 endpoints" — no loop | B |
| K2.6 / K5.3 | partly (body) | §4 step 6 "Writes or updates local files including … '\update_data.dat'" — purpose not stated | B |
| K3.1 / K3.5 | partly (body) | capa PEB / CRC32 / export-parsing rows in §5.2 | B |
| K3.6 | partly (body) | "81 decoded strings recovered via emulation"; scheme given as RC4/stackstrings | B, E |
| K4.1 | partly (appendix) | format string in Appendix A only | B |
| K4.2 | partly (body) | capa FNV row | B |
| K4.4 | **found** | "hardcoded URLs (skinnyjeanso.com, titnovacrion.top) … suggesting C2 communication"; §4 step 4 "C2 endpoints 'https://skinnyjeanso.com/live/' or 'https://titnovacrion.top/live/'" | B |
| K5.1 | partly (appendix) | `Custom_update`, `Update_%x` in the appendix only | B |
| K5.2 | partly (body) | §5.4 "command-line arguments for persistence mechanisms (e.g., "Startup", "LogonTrigger", "Updater") … likely … registry modification or scheduled tasks" — task name and logon trigger named, hedged, no COM; T1053.005 not published | B |
| K6.1 | **found** | §4 step 4 "URL-encoded POST body … to C2 endpoints 'https://skinnyjeanso.com/live/'" | B |
| K6.2 | partly (appendix) | UA in the appendix only | B |
| K6.3 | partly (body) | §4 step 5 "RC4 PRGA, CRC32 hashing, and Base64 encoding (alphabet …)" — both halves named, not tied to the C2 body | B |
| K6.5 | **found** | §4 step 4 lists the beacon fields "counter, type, guid, os, arch, username, group, ver, up, direction, computername, domain, desklinks, proclist, …" (registration fields included) | B *Beacon data* |
| K6.7 | partly (appendix) | keywords only in the appendix | B |
| K9 | 2 found (hashes; `/live/`), 2 partly (body) (`update_data.dat`; `Updater`), 4 partly (appendix) (`runnung`, `Custom_update\`, `Update_%x`, UA) | | |
| K7 | partly (body): **2** (`desklinks` among the beacon fields), **3** (`proclist`), **4** (recon set), **12** (`%s%d.exe` written; "remote execution"), **13** (rundll32 `%s,%s` pattern), **18** (`files/bp.dat`). missed: 14, 15, 17, 19, 20 | | |
| K8 | found | §4 step 3 lists all eleven cmd/wmic commands | B *Command ID 4* |
| K10 | T1027 found (capa RC4 rule, as in the baseline); T1053.005, T1059.003, T1218.011, T1055, T1070.004 missed — only the two capa techniques were published | | E |

**IOC recall (K9 core, 8):** published (`/iocs`, §9) 1 of 8 (hashes); STIX additionally carries the two C2 **URLs**
(`url:value` `https://skinnyjeanso.com/live/`, `https://titnovacrion.top/live/`); stated in the body 4 of 8; anywhere
including the appendix 8 of 8.

## Reverse direction

| Claim | Assessment | How we know |
|---|---|---|
| "a 32-bit Windows PE executable (machine 0x8664)" | **contradicted** | 0x8664 is x86-64; §2 of the same report says x86-64 |
| "high entropy in the .data section" (key finding 1) | **contradicted** | `.data` 6.48, "packer signatures none" |
| Category "Infostealer / Loader"; judge "data exfiltration preparation" | unsupported (Infostealer) | B: loader; the stealer module (command 21) is a *later* item and a separate download |
| judge: "persistence mechanisms (rundll32, registry keys)" | **contradicted** | rundll32 is not persistence; persistence is the `Updater` task (B, E) |
| "Executes via rundll32.exe using the pattern 'C:\WINDOWS\SYSTEM32\rundll32.exe %s,%s'" | misread | those format strings are command 13's (run a downloaded DLL), not how this DLL is started |
| "Static analysis identifies capabilities for execution, persistence, filesystem access, and anti-debugging [ev_0008]" | misattributed | those are the API catalogue's categories (ev_0009/ev_0013), not capa's |
| Hunting notes and recommendations all mapped to T1027/T1027.005 (e.g. "DNS queries … to skinnyjeanso.com (T1027.005)") | **contradicted** (mapping) | a DNS query is not stackstring obfuscation; only two techniques were published, and every row was pinned to them |
| "labels including Latrodectus, Trojan, and Coinminer" | correct but misleading | one engine of 52 says `Trojan.Coinminer` |
| "Accesses registry paths under '…\Explorer\Shell Folders' … to locate user directories such as 'AppData', 'Local AppData', 'Personal', and 'Desktop'" | **correct but new** | E *Setup / persistence*: the install location is configurable among exactly these folders (K5.5) |
| "credential theft" (introduction draft) | caught | recorded as unresolved `narrative.ungrounded_capability`; the sentence is not printed |
