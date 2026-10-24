/**
 * Trimmed slices of one stored report, kept in the shapes the API served them.
 *
 * Every value here was read from a real run's `GET /reports/job/{id}` answer
 * and cut down to the rows a test needs; nothing is reshaped. The point is
 * that the console is tested against what the backend writes, not against
 * what a test author assumed it writes.
 */

import type {
  ClaimNotDiscussed,
  ConsolidatedIOC,
  EvidenceSection,
  JudgeIndicator,
} from "@/types/malware-report";

/** A table its tool cut short, which says so in its `text`. */
export const STRINGS_SECTION: EvidenceSection = {
  key: "strings",
  kind: "table",
  rows: [
    ["56943", "ascii", "J9L$N(P6R6T'VWX"],
    ["57027", "ascii", "^z`QbQd"],
    ["57166", "ascii", "g&,)$/)ul9K"],
  ],
  text: "18 more rows not shown here; the evidence endpoint carries every one under ev_0005, ev_0098.",
  items: [],
  title: "Printable strings",
  source: "tool:strings",
  columns: ["Offset", "Encoding", "Text"],
  evidence_ids: ["ev_0005", "ev_0098"],
};

/** A list that leads with a sentence counting what it lists. */
export const FUNCTIONS_EXAMINED: EvidenceSection = {
  key: "functions_examined",
  kind: "list",
  rows: [],
  text: "Function map: 51 functions visited (51 decompiled); 39 functions reach artefacts the analysis server tied to them, 25 of them visited.",
  items: [
    "function listing (list_functions)",
    "0x1360bc02200 (decompile_function)",
    "1360bc03868 (disassemble_function)",
  ],
  title: "Functions examined",
  source: "tool:list_functions",
  columns: [],
  evidence_ids: ["ev_0042", "ev_0043", "ev_0044"],
};

/** A merged table whose later rows carry a cell its columns do not name. */
export const ARTIFACT_IMPORTS: EvidenceSection = {
  key: "artifact_imports",
  kind: "table",
  rows: [
    ["dynamic", "ev_0004", "KERNEL32.dll"],
    ["dynamic", "ev_0004", "USER32.dll"],
    ["dynamic", "ev_0019, ev_0024", "kernel32.dll", "VirtualAllocEx"],
    ["dynamic", "ev_0019, ev_0024", "wininet.dll", "HttpSendRequestA"],
  ],
  text: "",
  items: [],
  title: "Imports",
  source: "artifact:dynamic",
  columns: ["Listed by", "Evidence", "Library"],
  evidence_ids: ["ev_0004", "ev_0019", "ev_0024"],
  source_server: "pipeline",
};

/** A table some of whose rows are a cell short of its columns. */
export const API_CAPABILITIES: EvidenceSection = {
  key: "tool_api_capability_capabilities",
  kind: "table",
  rows: [
    ["wsprintfW", "", "", "", "", "", "resolved at runtime from hashes"],
    ["InternetOpenW", "network", "network", "technique_id=T1071.001", "", "WinExec", "resolved at runtime from hashes"],
    ["PeekNamedPipe", "", "", "", "", ""],
  ],
  text: "",
  items: [],
  title: "Capabilities",
  source: "tool:api_capability",
  columns: ["api", "category", "behaviours", "techniques", "catalog_flags", "corroborated_by", "obtained"],
  evidence_ids: ["ev_0010", "ev_0021"],
  source_server: "pipeline",
};

/** A decompiler server's answer: one key/value row per function, each a listing. */
export const BATCH_DECOMPILE: EvidenceSection = {
  key: "tool_batch_decompile",
  kind: "kv",
  rows: [
    ["0x1360bc09040", "\nint FUN_1360bc09040(int param_1)\n\n{\n  return param_1 + 1;\n}\n\n"],
    [
      "0x1360bc03074",
      "\nundefined4 FUN_1360bc03074(void)\n\n{\n  undefined1 uVar1;\n  undefined4 uVar2;\n}\n",
    ],
  ],
  text: "",
  items: [],
  title: "Batch decompile",
  source: "tool:batch_decompile",
  columns: ["Field", "Value"],
  evidence_ids: ["ev_0063", "ev_0066"],
  source_server: "decompiler",
};

/** Two of the claims the report body leaves undiscussed, as the report stores them. */
export const UNDISCUSSED: ClaimNotDiscussed[] = [
  {
    agent: "triage",
    claim: "Init routine 0x3868 calls GetCurrentProcess, GetModuleHandleW, IsWow64Process, GetLastError and CreateMutexW through slots (ev_0024, ev_0019).",
    confidence: 0.6,
    claim_number: 25,
    missing: ["GetModuleHandleW"],
    evidence_ref: "ev_0024 (row 0x3868), ev_0019.",
  },
  {
    agent: "static",
    claim: "The file is not packed.",
    confidence: 0.85,
    claim_number: 2,
    missing: ["HasRichSignature"],
    evidence_ref:
      "ev_0138 (packed flag, matched rule, string_hits 0); ev_0134 (no special-artifact pattern); ev_0004.",
  },
];

/** The consolidated IOC table: an answered yes, an answered no, and no answer. */
export const CONSOLIDATED_IOCS: ConsolidatedIOC[] = [
  {
    kind: "hash",
    type: "SHA-256",
    value: "6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef",
    source: "identity",
    context: "the sample",
    published: "yes: the sample's own digest",
    is_network: false,
    description: "the sample",
    recovered_by: "",
  },
  {
    kind: "command",
    type: "Command line",
    value: "explorer.exe /LOADSAVEDWINDOWS",
    source: "sandbox",
    context: "pid 96",
    published: null,
    is_network: false,
    description: "pid 96",
    recovered_by: "",
  },
  {
    kind: "mutex",
    type: "Mutex",
    value: "runnung",
    source: "judge",
    context: "the judge's indicator",
    published: "yes: a second source in this run records it",
    is_network: false,
    description: "the judge's indicator",
    recovered_by: "",
  },
  {
    kind: "ip",
    type: "IPv4",
    value: "8.8.8.8",
    source: "sandbox",
    context: "public DNS resolver",
    published:
      "no: the sandbox report does not say which process made the flows to it; it is a public DNS resolver",
    is_network: true,
    description: "public DNS resolver",
    recovered_by: "",
  },
  {
    kind: "url",
    type: "URL",
    value: "https://skinnyjeanso.com/live/",
    source: "strings",
    context: "",
    published: "yes: recovered by emulation (decoded strings), ev_0018",
    is_network: true,
    description: "",
    recovered_by: "emulation, ev_0018 (decoded string, routine 0xae78, called at 0x6a1f)",
  },
];

export const JUDGE_INDICATORS: JudgeIndicator[] = [
  { kind: "url", value: "https://skinnyjeanso.com/live/", algorithm: "" },
  {
    kind: "hash",
    value: "6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef",
    algorithm: "SHA-256",
  },
  { kind: "mutex", value: "runnung", algorithm: "" },
];
