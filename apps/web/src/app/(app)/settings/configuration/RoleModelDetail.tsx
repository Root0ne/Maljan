"use client";

import { useState } from "react";
import { Bot } from "lucide-react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { probeDetail } from "@/lib/probeDetail";
import type { ProbeResult } from "@/types/settings";
import type { AgentLLMOverride, LlmGlobalFallback } from "./AgentDefinitionsEditor";
import ModelOverrideFields from "./ModelOverrideFields";
import type { RoleEntry } from "./roleEntries";

/**
 * A role with no definition — the mediator or the function summariser — in
 * the Agents page's detail pane: what it does, its `llm.agents` entry, and a
 * Test that asks each model of that entry for one short answer, as the run
 * will. A passing Test is filed like an agent's Resolve, which is what the
 * probe gate reads when the entry is saved and when a job is submitted.
 */
export default function RoleModelDetail({
  role,
  llmAgents,
  onChangeLlmAgents,
  llmGlobal,
}: {
  role: RoleEntry;
  llmAgents: Record<string, AgentLLMOverride>;
  onChangeLlmAgents: (value: Record<string, AgentLLMOverride>) => void;
  llmGlobal: LlmGlobalFallback;
}) {
  const [result, setResult] = useState<ProbeResult | "running" | undefined>(undefined);

  const test = async () => {
    setResult("running");
    try {
      // The staged entry is what is asked about, so a model can be tested
      // before it is saved; the gate refuses saving one no probe reached.
      setResult(await api.probeAgent(role.key, { "core.llm.agents": llmAgents }));
    } catch (e) {
      setResult({
        ok: false,
        latency_ms: 0,
        detail: getErrorMessage(e),
        models: null,
        tools: null,
        details: null,
      });
    }
  };

  return (
    <section
      data-role-detail={role.key}
      aria-label={`Role ${role.key}`}
      className="min-w-0 border border-border rounded p-3 space-y-3"
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <span className="flex items-center gap-2 text-sm text-text-primary">
          <Bot size={16} aria-hidden="true" className="text-text-muted" />
          {role.label}
          <span className="text-[11px] font-mono text-text-muted">{role.key}</span>
        </span>
        <button
          type="button"
          className="text-xs text-accent-strong disabled:opacity-50"
          disabled={result === "running"}
          onClick={() => void test()}
        >
          Test model
        </button>
      </div>
      <p className="text-xs text-text-muted">{role.description}</p>
      {result === "running" && <p className="text-[11px] text-text-muted">asking…</p>}
      {result && result !== "running" && (
        <p
          className={`text-[11px] ${result.ok ? "text-status-green" : "text-status-red"}`}
          role="status"
        >
          {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {probeDetail(result.detail)}
        </p>
      )}
      <ModelOverrideFields
        agentKey={role.key}
        llmAgents={llmAgents}
        onChangeLlmAgents={onChangeLlmAgents}
        llmGlobal={llmGlobal}
        onEdited={() => setResult(undefined)}
        legend="Model (blank = the global expert model)"
      />
    </section>
  );
}
