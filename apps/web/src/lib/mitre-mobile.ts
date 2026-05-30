/**
 * Wave 10 W10-TTP-02 (2026-05-30) — Mobile ATT&CK tactic resolver.
 *
 * The 2026-05-30 UI walk of the zararli.apk report (282abfe8) found
 * T1628.002 rendered as "Unknown Tactic / TA0000" because the TTPs tab
 * only knew the 14 Enterprise tactics. Sandbox analysis of Android
 * samples routinely produces Mobile ATT&CK technique IDs, so we ship a
 * curated lookup table for the techniques most commonly observed in
 * Triage-class Android sandbox reports.
 *
 * The data is sourced from https://attack.mitre.org/matrices/mobile/.
 * When a Mobile technique isn't in the table the resolver returns
 * ``null`` and the UI keeps its "Unknown Tactic" fallback — better to
 * be honest about a gap than to misclassify.
 */

export interface MitreTactic {
  id: string;
  name: string;
  matrix: "enterprise" | "mobile" | "ics";
}

/* The 14 Mobile ATT&CK tactics, ordered to mirror the official matrix. */
export const MOBILE_TACTICS: MitreTactic[] = [
  { id: "TA0027", name: "Initial Access", matrix: "mobile" },
  { id: "TA0041", name: "Execution", matrix: "mobile" },
  { id: "TA0028", name: "Persistence", matrix: "mobile" },
  { id: "TA0029", name: "Privilege Escalation", matrix: "mobile" },
  { id: "TA0030", name: "Defense Evasion", matrix: "mobile" },
  { id: "TA0031", name: "Credential Access", matrix: "mobile" },
  { id: "TA0032", name: "Discovery", matrix: "mobile" },
  { id: "TA0033", name: "Lateral Movement", matrix: "mobile" },
  { id: "TA0035", name: "Collection", matrix: "mobile" },
  { id: "TA0037", name: "Command and Control", matrix: "mobile" },
  { id: "TA0036", name: "Exfiltration", matrix: "mobile" },
  { id: "TA0034", name: "Impact", matrix: "mobile" },
  { id: "TA0038", name: "Network Effects", matrix: "mobile" },
  { id: "TA0039", name: "Remote Service Effects", matrix: "mobile" },
];

/* Curated Mobile technique → tactic map. Covers the techniques most
 * commonly produced by Triage's Android sandbox + the manual claims
 * Maljan's static / dynamic analysts emit. Subtechniques inherit their
 * parent's tactic. */
const MOBILE_TECHNIQUE_TO_TACTIC: Record<string, string> = {
  /* Initial Access */
  T1660: "TA0027", // Phishing
  T1456: "TA0027", // Drive-By Compromise
  T1474: "TA0027", // Supply Chain Compromise
  /* Execution */
  T1623: "TA0041", // Command and Scripting Interpreter
  T1603: "TA0041", // Scheduled Task/Job
  T1658: "TA0041", // Exploitation for Client Execution
  /* Persistence */
  T1624: "TA0028", // Event Triggered Execution
  T1645: "TA0028", // Compromise Client Software Binary
  T1577: "TA0028", // Compromise Application Executable
  T1541: "TA0028", // Foreground Persistence
  T1631: "TA0028", // Process Injection
  T1398: "TA0028", // Boot or Logon Initialization Scripts
  /* Privilege Escalation */
  T1626: "TA0029", // Abuse Elevation Control Mechanism
  /* Defense Evasion */
  T1628: "TA0030", // Hide Artifacts
  T1406: "TA0030", // Obfuscated Files or Information
  T1407: "TA0030", // Download New Code at Runtime
  T1633: "TA0030", // Virtualization/Sandbox Evasion
  T1655: "TA0030", // Masquerading
  T1629: "TA0030", // Impair Defenses
  T1630: "TA0030", // Indicator Removal on Host
  T1575: "TA0030", // Native API
  T1604: "TA0030", // Proxy Through Victim
  /* Credential Access */
  T1517: "TA0031", // Access Notifications
  T1414: "TA0031", // Clipboard Data
  T1634: "TA0031", // Credentials from Password Store
  T1417: "TA0031", // Input Capture
  T1635: "TA0031", // Steal Application Access Token
  T1521: "TA0031", // Encrypted Channel (also for C2 but commonly seen here)
  /* Discovery */
  T1418: "TA0032", // Software Discovery
  T1420: "TA0032", // File and Directory Discovery
  T1422: "TA0032", // System Network Configuration Discovery
  T1423: "TA0032", // Network Service Scanning
  T1424: "TA0032", // Process Discovery
  T1426: "TA0032", // System Information Discovery
  T1430: "TA0032", // Location Tracking
  T1622: "TA0032", // Debugger Evasion
  /* Lateral Movement */
  T1428: "TA0033", // Exploitation of Remote Services
  /* Collection */
  T1429: "TA0035", // Audio Capture
  T1512: "TA0035", // Video Capture
  T1513: "TA0035", // Screen Capture
  T1533: "TA0035", // Data from Local System
  T1636: "TA0035", // Protected User Data
  T1409: "TA0035", // Stored Application Data
  /* Command and Control */
  T1437: "TA0037", // Application Layer Protocol
  T1481: "TA0037", // Web Service
  T1544: "TA0037", // Remote Access Software
  T1637: "TA0037", // Dynamic Resolution
  /* Exfiltration */
  T1639: "TA0036", // Exfiltration Over Alternative Protocol
  T1646: "TA0036", // Exfiltration Over C2 Channel
  /* Impact */
  T1616: "TA0034", // Call Control
  T1471: "TA0034", // Data Encrypted for Impact
  T1641: "TA0034", // Data Manipulation
  T1642: "TA0034", // Endpoint Denial of Service
  T1643: "TA0034", // Generate Traffic from Victim
  T1582: "TA0034", // SMS Control
};

const TACTIC_LOOKUP: Record<string, MitreTactic> = Object.fromEntries(
  MOBILE_TACTICS.map((t) => [t.id, t]),
);

/**
 * Resolve a technique ID to its Mobile tactic, returning null when the
 * TID isn't covered by the curated table.
 *
 * Subtechniques (``T1628.002``) inherit their parent's tactic; the
 * resolver strips the suffix before lookup.
 */
export function resolveMobileTactic(techniqueId: string): MitreTactic | null {
  if (!techniqueId) return null;
  const parent = techniqueId.split(".")[0];
  const tacticId = MOBILE_TECHNIQUE_TO_TACTIC[parent];
  if (!tacticId) return null;
  return TACTIC_LOOKUP[tacticId] ?? null;
}

/**
 * Best-effort matrix classification.
 *
 * Mobile is detected via the curated lookup. ICS is detected by the
 * ``T0xxx`` numeric range. Everything else falls back to Enterprise —
 * the historical default and the most common case.
 */
export function classifyMatrix(
  techniqueId: string,
): "enterprise" | "mobile" | "ics" | "unknown" {
  if (!techniqueId) return "unknown";
  if (resolveMobileTactic(techniqueId)) return "mobile";
  if (/^T0\d{3}$/.test(techniqueId.split(".")[0])) return "ics";
  if (/^T\d{4}(?:\.\d{3})?$/.test(techniqueId)) return "enterprise";
  return "unknown";
}
