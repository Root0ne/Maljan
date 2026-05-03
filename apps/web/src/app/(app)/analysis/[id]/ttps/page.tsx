"use client";

interface Technique {
  id: string;
  name: string;
  matches: number;
  sources: string[];
}

interface Tactic {
  id: string;
  name: string;
  technique_count: number;
  techniques: Technique[];
}

const MOCK_TACTICS: Tactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    technique_count: 3,
    techniques: [
      { id: "T1566", name: "Phishing", matches: 2, sources: ["Threat Intel"] },
      { id: "T1078", name: "Valid Accounts", matches: 1, sources: ["Network"] },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    technique_count: 5,
    techniques: [
      { id: "T1059", name: "Command and Scripting Interpreter", matches: 52, sources: ["Dynamic", "Code"] },
      { id: "T1053", name: "Scheduled Task/Job", matches: 10, sources: ["Dynamic"] },
      { id: "T1204", name: "User Execution", matches: 3, sources: ["Static"] },
    ],
  },
  {
    id: "TA0003",
    name: "Persistence",
    technique_count: 4,
    techniques: [
      { id: "T1547", name: "Boot or Logon Autostart Execution", matches: 9, sources: ["Dynamic", "Static"] },
      { id: "T1053", name: "Scheduled Task/Job", matches: 10, sources: ["Dynamic"] },
      { id: "T1137", name: "Office Application Startup", matches: 3, sources: ["Static"] },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    technique_count: 3,
    techniques: [
      { id: "T1055", name: "Process Injection", matches: 47, sources: ["Dynamic", "Code"] },
      { id: "T1134", name: "Access Token Manipulation", matches: 11, sources: ["Dynamic"] },
      { id: "T1543", name: "Create or Modify System Process", matches: 5, sources: ["Dynamic"] },
    ],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    technique_count: 6,
    techniques: [
      { id: "T1027", name: "Obfuscated Files or Information", matches: 52, sources: ["Static", "Code"] },
      { id: "T1036", name: "Masquerading", matches: 63, sources: ["Static", "Dynamic"] },
      { id: "T1055", name: "Process Injection", matches: 47, sources: ["Dynamic", "Code"] },
      { id: "T1222", name: "File and Directory Permissions Modification", matches: 19, sources: ["Dynamic"] },
      { id: "T1553", name: "Subvert Trust Controls", matches: 4, sources: ["Static"] },
    ],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    technique_count: 3,
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", matches: 28, sources: ["Network"] },
      { id: "T1573", name: "Encrypted Channel", matches: 15, sources: ["Network"] },
      { id: "T1105", name: "Ingress Tool Transfer", matches: 7, sources: ["Network", "Dynamic"] },
    ],
  },
];

const SOURCE_COLORS: Record<string, string> = {
  Static: "bg-status-purple/20 text-status-purple",
  Dynamic: "bg-status-blue/20 text-status-blue",
  Network: "bg-status-orange/20 text-status-orange",
  Code: "bg-status-green/20 text-status-green",
  "Threat Intel": "bg-status-red/20 text-status-red",
};

export default function TTpsTab() {
  return (
    <div>
      {/* Controls */}
      <div className="flex items-center gap-3 mb-4">
        <div className="flex border border-border rounded overflow-hidden">
          <button className="px-3 py-1.5 text-xs bg-bg-active text-text-primary border-r border-border">
            Enterprise ({MOCK_TACTICS.reduce((s, t) => s + t.techniques.length, 0)})
          </button>
          <button className="px-3 py-1.5 text-xs text-text-muted hover:text-text-primary">
            Mobile (0)
          </button>
          <button className="px-3 py-1.5 text-xs text-text-muted hover:text-text-primary">
            ICS (0)
          </button>
        </div>
        <input
          type="text"
          placeholder="Search for technique or subtechnique"
          className="h-7 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none w-72"
        />
        <div className="ml-auto flex gap-2">
          <button className="px-3 py-1.5 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors">
            Open in MITRE Navigator
          </button>
          <button className="px-3 py-1.5 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors">
            Download TTPs
          </button>
        </div>
      </div>

      {/* Tactic Columns */}
      <div className="flex gap-3 overflow-x-auto pb-4">
        {MOCK_TACTICS.map((tactic) => (
          <div
            key={tactic.id}
            className="min-w-[200px] max-w-[220px] shrink-0"
          >
            {/* Tactic Header */}
            <div className="bg-bg-surface border border-border rounded-t px-3 py-2 border-b-0">
              <h3 className="text-xs font-medium text-text-primary">
                {tactic.name}
              </h3>
              <p className="text-xs text-text-muted">
                {tactic.id} | {tactic.technique_count} Techniques
              </p>
            </div>

            {/* Technique Cards */}
            <div className="space-y-px">
              {tactic.techniques.map((tech) => (
                <div
                  key={`${tactic.id}-${tech.id}`}
                  className="bg-bg-elevated border border-border px-3 py-2.5 hover:bg-bg-active transition-colors cursor-pointer"
                >
                  <div className="flex items-start justify-between mb-1">
                    <p className="text-xs text-text-primary font-medium leading-tight pr-2">
                      {tech.name}
                    </p>
                    <svg
                      className="w-3 h-3 text-text-muted shrink-0 mt-0.5"
                      viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
                    >
                      <path d="m6 9 6 6 6-6" />
                    </svg>
                  </div>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1">
                      <span className="text-xs text-text-muted font-mono">
                        {tech.id}
                      </span>
                      {tech.sources.map((src) => (
                        <span
                          key={src}
                          className={`inline-block w-4 h-4 rounded-full text-center text-[9px] leading-4 ${SOURCE_COLORS[src] || "bg-text-muted/20 text-text-muted"}`}
                          title={src}
                        >
                          {src[0]}
                        </span>
                      ))}
                    </div>
                    <span className="text-xs text-text-muted">
                      {tech.matches} match{tech.matches !== 1 ? "es" : ""}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
