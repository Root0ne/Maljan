"use client";

import { useState } from "react";

interface ApiKeyConfig {
  id: string;
  name: string;
  description: string;
  envVar: string;
  masked: string;
  isSet: boolean;
}

const API_KEYS: ApiKeyConfig[] = [
  { id: "gemini", name: "Google Gemini", description: "Primary LLM for malware analysis agents", envVar: "GEMINI_API_KEY", masked: "AIza...****", isSet: true },
  { id: "triage", name: "Triage (Hatching)", description: "Cloud sandbox for dynamic analysis", envVar: "TRIAGE_API_KEY", masked: "c32d...****", isSet: true },
  { id: "cape", name: "CAPEv2", description: "Local sandbox instance for behavioral analysis", envVar: "CAPE_API_URL", masked: "http://...", isSet: false },
  { id: "vt", name: "VirusTotal", description: "Threat intelligence and multi-AV scanning", envVar: "VIRUSTOTAL_API_KEY", masked: "", isSet: false },
  { id: "otx", name: "AlienVault OTX", description: "Open threat intelligence feeds", envVar: "OTX_API_KEY", masked: "", isSet: false },
];

interface AnalysisConfig {
  key: string;
  label: string;
  description: string;
  type: "number" | "toggle" | "select";
  value: number | boolean | string;
  options?: string[];
}

const ANALYSIS_CONFIGS: AnalysisConfig[] = [
  { key: "max_rounds", label: "Max Negotiation Rounds", description: "Maximum debate rounds between agents (0 = unlimited)", type: "number", value: 0 },
  { key: "confidence_threshold", label: "Confidence Threshold", description: "Minimum consensus confidence to auto-finalize verdict", type: "number", value: 80 },
  { key: "sandbox_timeout", label: "Sandbox Timeout (s)", description: "Maximum duration for dynamic analysis execution", type: "number", value: 300 },
  { key: "enable_network", label: "Network Analysis", description: "Enable PCAP capture and network traffic analysis", type: "toggle", value: true },
  { key: "enable_stix", label: "STIX Export", description: "Auto-generate STIX 2.1 bundles for each analysis", type: "toggle", value: true },
  { key: "llm_model", label: "Primary LLM Model", description: "Model used for agent reasoning", type: "select", value: "gemini-2.5-pro", options: ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash"] },
  { key: "enable_yara", label: "YARA Scanning", description: "Run YARA rules against submitted samples", type: "toggle", value: true },
  { key: "enable_sigma", label: "Sigma Detection", description: "Apply Sigma rules to behavioral logs", type: "toggle", value: true },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<"general" | "apikeys" | "analysis">("general");
  const [configs, setConfigs] = useState(ANALYSIS_CONFIGS);

  const tabs = [
    { key: "general" as const, label: "General" },
    { key: "apikeys" as const, label: "API Keys" },
    { key: "analysis" as const, label: "Analysis Config" },
  ];

  function updateConfig(key: string, value: number | boolean | string) {
    setConfigs((prev) => prev.map((c) => (c.key === key ? { ...c, value } : c)));
  }

  return (
    <div>
      <h1 className="text-lg font-semibold text-text-primary mb-4">Settings</h1>

      {/* Tab Bar */}
      <div className="flex border-b border-border mb-6">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className={`px-4 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 transition-colors ${
              activeTab === tab.key
                ? "border-accent text-accent"
                : "border-transparent text-text-secondary hover:text-text-primary"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* General Tab */}
      {activeTab === "general" && (
        <div className="space-y-4 max-w-2xl">
          <div className="bg-bg-surface border border-border rounded">
            <div className="px-4 py-3 border-b border-border">
              <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
                User Profile
              </h2>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-xs text-text-secondary mb-1.5">Full Name</label>
                <input
                  type="text"
                  defaultValue="Admin User"
                  className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-xs text-text-secondary mb-1.5">Email</label>
                <input
                  type="email"
                  defaultValue="admin@maljan.local"
                  className="w-full h-9 px-3 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                />
              </div>
              <div className="flex justify-end">
                <button className="h-8 px-4 text-xs bg-accent text-white rounded hover:bg-accent-hover transition-colors">
                  Save Changes
                </button>
              </div>
            </div>
          </div>

          <div className="bg-bg-surface border border-border rounded">
            <div className="px-4 py-3 border-b border-border">
              <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
                Application Info
              </h2>
            </div>
            <div className="p-4 space-y-2">
              {[
                ["Version", "1.0.0-beta"],
                ["Backend", "FastAPI 0.115.x"],
                ["Frontend", "Next.js 16.2.4"],
                ["Database", "PostgreSQL 16"],
                ["Queue", "ARQ + Redis"],
              ].map(([k, v]) => (
                <div key={k} className="flex items-center text-xs">
                  <span className="text-text-muted w-24">{k}</span>
                  <span className="text-text-secondary font-mono">{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* API Keys Tab */}
      {activeTab === "apikeys" && (
        <div className="space-y-3 max-w-3xl">
          {API_KEYS.map((key) => (
            <div key={key.id} className="bg-bg-surface border border-border rounded">
              <div className="flex items-center justify-between p-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm font-medium text-text-primary">{key.name}</span>
                    <span
                      className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${
                        key.isSet
                          ? "bg-status-green/10 text-status-green"
                          : "bg-status-red/10 text-status-red"
                      }`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${key.isSet ? "bg-status-green" : "bg-status-red"}`} />
                      {key.isSet ? "Configured" : "Not Set"}
                    </span>
                  </div>
                  <p className="text-xs text-text-secondary">{key.description}</p>
                  <div className="flex items-center gap-2 mt-1.5">
                    <span className="text-xs text-text-muted font-mono bg-bg-deep px-1.5 py-0.5 rounded">
                      {key.envVar}
                    </span>
                    {key.masked && (
                      <span className="text-xs text-text-muted font-mono">{key.masked}</span>
                    )}
                  </div>
                </div>
                <div className="flex gap-2 ml-4 shrink-0">
                  <button className="h-7 px-3 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors">
                    {key.isSet ? "Update" : "Configure"}
                  </button>
                  {key.isSet && (
                    <button className="h-7 px-3 text-xs text-text-secondary border border-border rounded hover:text-status-red hover:border-status-red/30 transition-colors">
                      Revoke
                    </button>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Analysis Config Tab */}
      {activeTab === "analysis" && (
        <div className="max-w-2xl">
          <div className="bg-bg-surface border border-border rounded">
            <div className="px-4 py-3 border-b border-border">
              <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
                Analysis Configuration
              </h2>
            </div>
            <div className="divide-y divide-border-light">
              {configs.map((cfg) => (
                <div key={cfg.key} className="flex items-center justify-between px-4 py-3">
                  <div className="flex-1 min-w-0 pr-4">
                    <p className="text-sm text-text-primary">{cfg.label}</p>
                    <p className="text-xs text-text-muted mt-0.5">{cfg.description}</p>
                  </div>
                  <div className="shrink-0">
                    {cfg.type === "number" && (
                      <input
                        type="number"
                        value={cfg.value as number}
                        onChange={(e) => updateConfig(cfg.key, Number(e.target.value))}
                        className="w-20 h-8 px-2 text-sm text-center bg-bg-deep border border-border rounded text-text-primary font-mono focus:border-accent focus:outline-none"
                      />
                    )}
                    {cfg.type === "toggle" && (
                      <button
                        onClick={() => updateConfig(cfg.key, !(cfg.value as boolean))}
                        className={`relative w-10 h-5 rounded-full transition-colors ${
                          cfg.value ? "bg-accent" : "bg-bg-active"
                        }`}
                      >
                        <span
                          className={`absolute top-0.5 w-4 h-4 rounded-full bg-text-primary transition-transform ${
                            cfg.value ? "left-5" : "left-0.5"
                          }`}
                        />
                      </button>
                    )}
                    {cfg.type === "select" && (
                      <select
                        value={cfg.value as string}
                        onChange={(e) => updateConfig(cfg.key, e.target.value)}
                        className="h-8 px-2 text-sm bg-bg-deep border border-border rounded text-text-primary focus:border-accent focus:outline-none"
                      >
                        {cfg.options?.map((opt) => (
                          <option key={opt} value={opt}>{opt}</option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>
              ))}
            </div>
            <div className="px-4 py-3 border-t border-border flex justify-end">
              <button className="h-8 px-4 text-xs bg-accent text-white rounded hover:bg-accent-hover transition-colors">
                Save Configuration
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
