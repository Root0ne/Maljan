"use client";

import { useState } from "react";

import { useReport } from "../layout";
import type { AgentFindingDTO } from "@/lib/api";
import type { ProcessNode } from "@/types/malware-report";
import { confidenceClass } from "@/lib/report-utils";
import Th from "@/components/ui/Th";

/** One claim of an analyst's final ISR, as the pipeline records it. */
interface AnalystClaim {
  claim?: string;
  description?: string;
  confidence?: number;
  evidence_ref?: string | string[];
}

/**
 * What the dynamic analyst concluded, whether or not the sandbox produced
 * anything.
 *
 * This tab used to render the "not detonated" notice and
 * nothing else whenever the sandbox report was empty — including on runs where
 * the dynamic analyst did execute and reasoned its way to a stated position
 * (sandbox evasion, say). That reasoning was in the API's `agent_findings` all
 * along and only the transcript ever showed it, so a run where the analyst
 * worked looked exactly like one where it never started.
 */
function dynamicClaims(findings: AgentFindingDTO[] | undefined): {
  agent: string;
  claims: AnalystClaim[];
}[] {
  return (findings ?? [])
    .filter(
      (f) =>
        f.domain?.toLowerCase() === "dynamic" ||
        f.agent_name?.toLowerCase().includes("dynamic")
    )
    .map((f) => ({ agent: f.agent_name, claims: (f.claims ?? []) as AnalystClaim[] }))
    .filter((f) => f.claims.length > 0);
}

function AnalystFindings({ findings }: { findings: ReturnType<typeof dynamicClaims> }) {
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Analyst findings
        </h2>
      </div>
      <div className="p-4 space-y-3">
        {findings.map((f) => (
          <div key={f.agent}>
            <p className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              {f.agent}
            </p>
            <ul className="space-y-2">
              {f.claims.map((c, i) => {
                const conf =
                  typeof c.confidence === "number" ? Math.round(c.confidence * 100) : null;
                const evidence = Array.isArray(c.evidence_ref)
                  ? c.evidence_ref.join(", ")
                  : c.evidence_ref;
                return (
                  <li key={i} className="border border-border-light rounded p-3">
                    <p className="text-sm text-text-primary leading-relaxed">
                      {c.claim || c.description || "(no text)"}
                    </p>
                    <div className="flex flex-wrap gap-3 mt-1.5 text-[11px] text-text-muted">
                      {conf !== null && (
                        <span className={`font-mono ${confidenceClass(conf)}`}>{conf}%</span>
                      )}
                      {evidence && (
                        <span>
                          <span className="text-text-secondary">Evidence: </span>
                          {evidence}
                        </span>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function DynamicTab() {
  const { report, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const analystFindings = dynamicClaims(report?.agent_findings);
  const dyn = report?.malware_report?.dynamic;
  // The registry exists on Windows and nowhere else. On a Linux, macOS or
  // Android sample an empty "Registry Modifications" panel reads as a sandbox
  // that found nothing rather than a concept the platform does not have, so
  // the panel is drawn only where it can be populated.
  const platform = report?.malware_report?.identity?.platform;
  const showsRegistry = platform === "windows" || !!dyn?.registry_mods.length;
  if (!dyn) {
    return (
      <div className="space-y-4">
        <div className="p-8 text-center text-sm text-text-secondary">
          No dynamic-analysis data available — the sample may not have been detonated.
        </div>
        {analystFindings.length > 0 && <AnalystFindings findings={analystFindings} />}
      </div>
    );
  }

  const sortedSignatures = [...dyn.sandbox_signatures].sort(
    (a, b) => b.severity - a.severity,
  );

  // D10: detect anti-emulation / anti-VM / anti-debug signatures so the
  // empty process-tree state can explain why the sandbox traced nothing.
  // Mirrors the regex used by the worker's degradation_reasons builder
  // (src/maljan/pipeline/nodes.py), so the banner copy and this hint
  // stay in lockstep.
  const ANTI_EMU_RE =
    /emulation|anti[\s_-]?vm|anti[\s_-]?debug|sandbox\s*detect|qemu|virtualbox|vmware|hyper[\s_-]?v/i;
  const antiEmulationHit = sortedSignatures.find(
    (s) => ANTI_EMU_RE.test(s.name) || ANTI_EMU_RE.test(s.description ?? ""),
  );

  return (
    <div className="space-y-4">
      {analystFindings.length > 0 && <AnalystFindings findings={analystFindings} />}

      {dyn.unavailable && dyn.unavailable.length > 0 && (
        <div className="text-xs text-text-muted border border-border rounded px-4 py-3 bg-bg-surface">
          Not provided by this sandbox: {dyn.unavailable.join(", ")}.
        </div>
      )}

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Process Tree ({dyn.process_tree.length} root{dyn.process_tree.length !== 1 ? "s" : ""})
          </h2>
        </div>
        <div className="p-4">
          {dyn.process_tree.length === 0 ? (
            <div className="text-xs text-text-muted">
              {antiEmulationHit ? (
                <>
                  Sandbox traced no process activity — sample employed
                  anti-emulation behaviour
                  <span className="ml-1 text-status-orange">
                    ({antiEmulationHit.name})
                  </span>
                  .
                </>
              ) : (
                <>No process activity recorded.</>
              )}
            </div>
          ) : (
            <div className="font-mono text-xs space-y-1">
              {dyn.process_tree.map((node, i) => (
                <ProcessTreeNode key={`${node.pid}-${i}`} node={node} depth={0} />
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Sandbox Signatures ({sortedSignatures.length})
          </h2>
        </div>
        {sortedSignatures.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No signatures triggered.</div>
        ) : (
          <div className="divide-y divide-border-light">
            {sortedSignatures.map((sig, i) => (
              <div key={i} className="p-4">
                <div className="flex items-start gap-3">
                  <span
                    className={`text-[11px] font-mono px-1.5 py-0.5 rounded shrink-0 ${
                      sig.severity >= 7
                        ? "bg-status-red/10 text-status-red"
                        : sig.severity >= 4
                          ? "bg-status-orange/10 text-status-orange"
                          : "bg-bg-active text-text-muted"
                    }`}
                  >
                    SEV {sig.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-text-primary">{sig.name}</div>
                    {sig.description && (
                      <div className="text-xs text-text-secondary mt-1">{sig.description}</div>
                    )}
                    {sig.technique_ids.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {sig.technique_ids.map((tid) => (
                          <span
                            key={tid}
                            className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-status-blue/10 text-status-blue"
                          >
                            {tid}
                          </span>
                        ))}
                      </div>
                    )}
                    {sig.marks.length > 0 && (
                      <details className="mt-2">
                        <summary className="text-[11px] text-text-muted cursor-pointer hover:text-text-primary">
                          {sig.marks.length} evidence mark{sig.marks.length !== 1 ? "s" : ""}
                        </summary>
                        <ul className="mt-1 ml-3 space-y-1">
                          {sig.marks.slice(0, 25).map((m, mi) => (
                            <li
                              key={mi}
                              className="text-[11px] font-mono text-text-secondary break-all"
                            >
                              {m}
                            </li>
                          ))}
                        </ul>
                      </details>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {showsRegistry && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Registry Modifications ({dyn.registry_mods.length})
            </h2>
          </div>
          {dyn.registry_mods.length === 0 ? (
            <div className="p-8 text-center text-sm text-text-muted">
              No registry activity recorded.
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <Th>Op</Th>
                  <Th>Hive</Th>
                  <Th>Key</Th>
                  <Th>Value Name</Th>
                  <Th>New Value</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-light">
                {dyn.registry_mods.slice(0, 200).map((r, i) => (
                  <tr key={i} className="hover:bg-bg-hover transition-colors">
                    <td className="px-4 py-2 text-[11px] uppercase tracking-wider text-text-muted">
                      {r.operation}
                    </td>
                    <td className="px-4 py-2 text-xs font-mono text-text-secondary">{r.hive}</td>
                    <td className="px-4 py-2 text-xs font-mono text-status-blue break-all">{r.key}</td>
                    <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                      {r.value_name || "-"}
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary break-all">
                      {r.new_value || "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {dyn.registry_mods.length > 200 && (
            <div className="px-4 py-2 text-[11px] text-text-muted border-t border-border">
              Showing first 200 of {dyn.registry_mods.length}.
            </div>
          )}
        </div>
      )}

      {dyn.notable_apis.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Notable APIs ({dyn.notable_apis.length})
            </h2>
          </div>
          <pre className="p-4 text-[11px] text-text-muted overflow-x-auto leading-relaxed">
            {JSON.stringify(dyn.notable_apis.slice(0, 50), null, 2)}
          </pre>
        </div>
      )}

      {dyn.file_operations.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              File Operations ({dyn.file_operations.length})
            </h2>
          </div>
          <pre className="p-4 text-[11px] text-text-muted overflow-x-auto leading-relaxed">
            {JSON.stringify(dyn.file_operations.slice(0, 50), null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function ProcessTreeNode({ node, depth }: { node: ProcessNode; depth: number }) {
  const [open, setOpen] = useState(depth < 2);
  const hasChildren = node.children.length > 0;

  return (
    <div>
      <div
        className="flex items-start gap-2 hover:bg-bg-hover py-0.5 px-1 rounded cursor-pointer"
        style={{ paddingLeft: depth * 16 + 4 }}
        onClick={() => hasChildren && setOpen(!open)}
      >
        <span className="text-text-muted w-3 inline-block shrink-0">
          {hasChildren ? (open ? "−" : "+") : "·"}
        </span>
        <span className="text-status-blue shrink-0">{node.pid}</span>
        <span className="text-text-muted shrink-0">/</span>
        <span className="text-text-muted shrink-0">{node.ppid || "0"}</span>
        <span className="text-text-primary shrink-0">{node.name || "(unknown)"}</span>
        {node.command_line && (
          <span className="text-text-secondary truncate" title={node.command_line}>
            {node.command_line}
          </span>
        )}
        {node.injected_into.length > 0 && (
          <span className="text-[11px] px-1 rounded bg-status-red/10 text-status-red shrink-0">
            injects→{node.injected_into.join(",")}
          </span>
        )}
      </div>
      {open && hasChildren && (
        <div>
          {node.children.map((c, i) => (
            <ProcessTreeNode key={`${c.pid}-${i}`} node={c} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}
