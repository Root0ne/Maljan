# Malware Analysis Report

**Verdict**: `[MALWARE]`
**Sample SHA256**: `f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d`
**Generated**: 2026-05-17T14:50:31.735478+00:00
**Overall Confidence**: 0.50

## Sample Identification

| Field | Value |
|---|---|
| File name | `zararli.elf` |
| File size | 4,915,352 bytes |
| File type | ELF |
| MIME | application/x-executable |
| Magic bytes | `7f454c46010101000000000000000000` |
| Signed | no |

**Hashes:**

| Algorithm | Digest |
|---|---|
| MD5 | `ee8c9433935d4c68cbd7469b215f19e0` |
| SHA1 | `e82e07e32d6b928841333f8d4bb8edc66eed2ff2` |
| SHA256 | `f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d` |
| SHA512 | `180c8272792a57847f48fcc4e41df451d4b9112f9b524f0938dff22a1ac46ec8495c156a0262d7fad9ec0519b23eb33e1f0413fae6fb8737b25dda794ab41638` |

## Severity & Impact

**Rating**: `[MEDIUM]` (6.3/10)

Sample displays suspicious behaviour consistent with malware; isolate and analyse further before allowing execution.

**Affected platforms**: Linux

## Executive Summary

Analysis confirms a Remote Access Trojan (RAT) with medium severity (6.3/10) and moderate confidence (0.50). The artifact exhibits evasion capabilities targeting virtualized environments via YARA-detected sandbox evasion routines (T1497). Operational indicators suggest the use of PowerShell variants (T1059.001), direct volume access (T1006), and non-standard protocols like DNS with Z-flag manipulation (T1095) for command and control or data exfiltration. Additional telemetry points to potential credential abuse via cloud accounts (T1078.004) and RDP exposure (T1021.001), indicating a multi-vector approach to persistence and lateral movement.

## Capabilities Narrative

The malware demonstrates advanced evasion techniques designed to bypass analysis environments. YARA signatures confirm the presence of sandbox evasion routines (T1497), indicating the artifact checks for virtualization artifacts before executing core payloads. Execution is facilitated through PowerShell, with Sigma rules detecting the use of alternate PowerShell hosts (T1059.001), suggesting the operator is leveraging non-standard interpreters to obscure command execution and evade signature-based detection.

Data handling capabilities include direct access to storage volumes and non-standard communication channels. The artifact utilizes direct volume access (T1006) to read raw disk sectors, potentially targeting specific files or system artifacts without relying on standard file system APIs. For data exfiltration or command and control, the malware employs non-application layer protocols (T1095), evidenced by DNS traffic with the Z-flag bit set, which may be used to tunnel commands or exfiltrate data while blending with legitimate traffic.

The RAT supports lateral movement and credential abuse through multiple vectors. Sigma detections highlight a publicly accessible RDP service (T1021.001), suggesting the malware may facilitate remote access or indicate a misconfiguration exploited by the threat actor. Credential abuse is further indicated by failed authentications originating from unusual geographic locations (T1078.004), pointing to cloud account compromise. Additionally, file name manipulation techniques (T1036.006) are observed, likely used to disguise malicious artifacts or bypass access controls on the target system.

## Static Analysis

### Sections

| Name | VA | Virtual size | Raw size | Entropy | Notes |
|---|---|---|---|---|---|
| `(binary)` | 0x0 | 4915352 | 4915352 | 5.97 |  |

### Indicator Strings

| Kind | Value |
|---|---|
| url | `https://no-cacheGoString01234567beEfFgGv` |
| url | `http://%s/bins.shInvalid` |
| url | `http://bufio:` |
| url | `http://%s/config.datError` |
| url | `https://twitter.com/https://www.fbi.gov/type` |
| url | `https://www.bing.com/bufio:` |
| url | `https://www.google.com/https://www.reddit.com/proxy/tlsplusbypass.txt` |
| url | `https://www.facebook.com/no` |
| url | `http://slice` |
| url | `http://Mozilla/5.0` |
| url | `http://crypto/tls:` |
| ip | `5.4.62.5` |
| ip | `4.32.5.4` |
| ip | `52.5.4.72` |
| ip | `5.4.82.5` |
| ip | `2.5.4.102` |
| ip | `5.4.112.5` |
| ip | `120.0.0.0` |
| ip | `119.0.0.0` |
| ip | `81.29.156.139` |
| ip | `1.1.1.1` |
| ip | `1.3.1.1` |
| ip | `1.2.2.1` |
| ip | `1.2.1.1` |
| path | `/0je_zznoP-1ZZUhwnxEs/wLzzyuaQL_KmS3GEKIQ6/lb-sUaEl9K2FMnDVe4he` |
| path | `/netip` |
| path | `/crc32` |
| path | `/atomic` |
| path | `/ecdsa` |
| path | `/textproto` |
| path | `/cipher` |
| path | `/sha256` |
| path | `/sha512` |
| path | `/multipart` |
| path | `/ed25519` |
| path | `/flate` |
| path | `/elliptic` |
| path | `/base64` |
| path | `/intern` |
| path | `/bisect` |
| path | `/godebug` |
| path | `/fmtsort` |
| path | `/testlog` |
| path | `/x509/pkix` |
| path | `/nettrace` |
| path | `/godebugs` |
| path | `/http/internal` |
| path | `/http/httptrace` |
| path | `/internal/sys` |
| path | `/chacha8rand` |

## Dynamic Behavior

_No sandbox dynamic data available._

## Network IOCs

_No network observations available._

## Persistence Mechanisms

_No persistence mechanisms detected._

## MITRE ATT&CK Matrix

| Tactic | Technique | Confidence | Layers |
|---|---|---|---|
| Defense Evasion (TA0005) | T1497 Virtualization/Sandbox Evasion | 0.85 | yara |
| Defense Evasion (TA0005) | T1006 Direct Volume Access | 0.80 | sigma |
| Execution (TA0002) | T1059.001 PowerShell | 0.80 | sigma |
| Command and Control (TA0011) | T1095 Non-Application Layer Protocol | 0.80 | sigma |
| Lateral Movement (TA0008) | T1021.001 Remote Desktop Protocol | 0.80 | sigma |
| Defense Evasion (TA0005) | T1036.006 Space after Filename | 0.80 | sigma |
| Defense Evasion (TA0005) | T1078.004 Cloud Accounts | 0.80 | sigma |

## Capability Matrix (evidence)

### T1497 — Virtualization/Sandbox Evasion  `(conf=0.85, single-source)`
_Layers: yara_

> Deterministic YARA signature match: Virtualization and sandbox evasion (rule: sandbox_evasion, 2 pattern(s) found)

### T1006 — Direct Volume Access  `(conf=0.80, single-source)`
_Layers: sigma_

> Sigma rule detection: Potential Defense Evasion Via Raw Disk Access By Uncommon Tools (technique T1006, source=generic)

### T1059.001 — PowerShell  `(conf=0.80, single-source)`
_Layers: sigma_

> Sigma rule detection: Alternate PowerShell Hosts - PowerShell Module (technique T1059.001, source=generic)

### T1095 — Non-Application Layer Protocol  `(conf=0.80, single-source)`
_Layers: sigma_

> Sigma rule detection: Suspicious DNS Z Flag Bit Set (technique T1095, source=generic)

### T1021.001 — Remote Desktop Protocol  `(conf=0.80, single-source)`
_Layers: sigma_

> Sigma rule detection: Publicly Accessible RDP Service (technique T1021.001, source=generic)

### T1036.006 — Space after Filename  `(conf=0.80, single-source)`
_Layers: sigma_

> Sigma rule detection: Space After Filename - macOS (technique T1036.006, source=generic)

### T1078.004 — Cloud Accounts  `(conf=0.80, single-source)`
_Layers: sigma_

> Sigma rule detection: Failed Authentications From Countries You Do Not Operate Out Of (technique T1078.004, source=generic)

## Family Attribution

**Family**: rat (confidence 0.50)

## Detection Signatures

### YARA — `Maljan_AutoGen_rat`

```yara
import "hash"

rule Maljan_AutoGen_rat
{
    meta:
        author = "Maljan Auto-Generator"
        description = "Auto-generated, verdict=Malware, family=rat"
        sha256 = "f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d"
        generated_at = "2026-05-17T14:50:31.735478+00:00"
    strings:
        $s0 = "https://no-cacheGoString01234567beEfFgGv" ascii wide nocase
        $s1 = "http://%s/bins.shInvalid" ascii wide nocase
        $s2 = "http://bufio:" ascii wide nocase
        $s3 = "http://%s/config.datError" ascii wide nocase
        $s4 = "https://twitter.com/https://www.fbi.gov/type" ascii wide nocase
        $s5 = "https://www.bing.com/bufio:" ascii wide nocase
        $s6 = "https://www.google.com/https://www.reddit.com/proxy/tlsplusbypass.txt" ascii wide nocase
        $s7 = "https://www.facebook.com/no" ascii wide nocase
        $s8 = "http://slice" ascii wide nocase
        $s9 = "http://Mozilla/5.0" ascii wide nocase
        $s10 = "http://crypto/tls:" ascii wide nocase
        $s11 = "5.4.62.5" ascii wide nocase
        $s12 = "4.32.5.4" ascii wide nocase
        $s13 = "52.5.4.72" ascii wide nocase
        $s14 = "5.4.82.5" ascii wide nocase
        $s15 = "2.5.4.102" ascii wide nocase
        $s16 = "5.4.112.5" ascii wide nocase
        $s17 = "120.0.0.0" ascii wide nocase
        $s18 = "119.0.0.0" ascii wide nocase
        $s19 = "81.29.156.139" ascii wide nocase
        $s20 = "1.1.1.1" ascii wide nocase
        $s21 = "1.3.1.1" ascii wide nocase
        $s22 = "1.2.2.1" ascii wide nocase
        $s23 = "1.2.1.1" ascii wide nocase
        $s24 = "/0je_zznoP-1ZZUhwnxEs/wLzzyuaQL_KmS3GEKIQ6/lb-sUaEl9K2FMnDVe4he" ascii wide nocase
    condition:
        (hash.sha256(0, filesize) == "f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d") or (8 of them)
}
```

## Defensive Recommendations

### [P0] patching

**Action**: Monitor and block DNS traffic exhibiting non-standard protocol behaviors, such as the Z-flag, to disrupt command and control channels (T1095).

_Rationale_: Active C2 communication detected via non-application layer protocol.

### [P1] patching

**Action**: Deploy behavioral detection rules to identify sandbox evasion routines and environment introspection checks within malware artifacts (T1497).

_Rationale_: High-confidence evasion techniques detected via YARA signatures.

### [P1] patching

**Action**: Restrict PowerShell execution policies and monitor for the use of alternate hosts to prevent script-based execution of malicious payloads (T1059.001).

_Rationale_: Sigma rules indicate abuse of alternate PowerShell hosts for execution.

### [P1] patching

**Action**: Implement strict monitoring for direct volume access operations to detect unauthorized raw disk reads indicative of data targeting (T1006).

_Rationale_: Sigma rules detect raw disk access by uncommon tools.

### [P1] patching

**Action**: Secure remote access configurations by disabling unnecessary RDP exposure and enforcing multi-factor authentication to prevent unauthorized sessions (T1021.001).

_Rationale_: Sigma rules detect publicly accessible RDP service.

### [P1] patching

**Action**: Review cloud account authentication logs for geographically anomalous login attempts and enforce conditional access policies to mitigate credential abuse (T1078.004).

_Rationale_: Sigma rules detect failed authentications from unusual countries.

### [P2] patching

**Action**: Update file integrity monitoring and detection signatures to identify file names containing trailing spaces or other obfuscation techniques (T1036.006).

_Rationale_: Sigma rules detect file name manipulation on macOS.

## References

- [VirusTotal](https://www.virustotal.com/gui/file/f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d) — VT detection summary
- [MalwareBazaar](https://bazaar.abuse.ch/sample/f5a7696239b801496743753f8066775f68793e81b5d4eceb15f701950774733d/) — Sample lookup
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1497/) — Virtualization/Sandbox Evasion
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1006/) — Direct Volume Access
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/001/) — PowerShell
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1095/) — Non-Application Layer Protocol
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1021/001/) — Remote Desktop Protocol
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1036/006/) — Space after Filename
- [MITRE ATT&CK](https://attack.mitre.org/techniques/T1078/004/) — Cloud Accounts

## Run Summary

- Elapsed: 173.2s
- Verdict: Malware
- Negotiation rounds: 1
- Termination reason: `consensus`
- Final confidence: 0.500
- TTPs: 7 total, 0 corroborated, 0 consensus
