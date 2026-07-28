"use client";

import { useMemo, useState } from "react";

import { useReport } from "../layout";
import { entropyClass, formatBytes } from "@/lib/report-utils";
import Th from "@/components/ui/Th";
import type { StringIOC, StringIOCKind } from "@/types/malware-report";

/* Ordered by what an analyst reaches for first, not alphabetically. `secret`
 * and `crypto_wallet` sit high because a leaked credential is the one finding
 * that changes what someone does in the next five minutes. */
const STRING_KINDS: (StringIOCKind | "all")[] = [
  "all",
  "secret",
  "crypto_wallet",
  "url",
  "domain",
  "ip",
  "registry",
  "path",
  "mutex",
  "email",
  "command",
  "other",
];

export default function StaticTab() {
  const { report, loading } = useReport();
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false);
  const [stringKind, setStringKind] = useState<StringIOCKind | "all">("all");

  const staticData = report?.malware_report?.static;
  const fileType = report?.malware_report?.identity?.file_type;
  const sectionsLabel = fileType ? `${fileType} Sections` : "Sections";

  const filteredImports = useMemo(() => {
    if (!staticData) return [];
    return showSuspiciousOnly
      ? staticData.imports.filter((i) => i.is_suspicious)
      : staticData.imports;
  }, [staticData, showSuspiciousOnly]);

  const carvedPayloads = useMemo(
    () => (staticData?.embedded_resources ?? []).filter((r) => r.carved),
    [staticData],
  );
  const packerMatches = useMemo(() => staticData?.packer_matches ?? [], [staticData]);
  const techniqueHits = useMemo(
    () =>
      [...(staticData?.api_technique_hits ?? [])].sort(
        (a, b) => (b.confidence ?? 0) - (a.confidence ?? 0),
      ),
    [staticData],
  );
  const capabilityProfile = useMemo(
    () =>
      Object.entries(staticData?.api_capabilities ?? {}).sort((a, b) => b[1] - a[1]),
    [staticData],
  );

  const filteredStrings: StringIOC[] = useMemo(() => {
    if (!staticData) return [];
    return stringKind === "all"
      ? staticData.interesting_strings
      : staticData.interesting_strings.filter((s) => s.kind === stringKind);
  }, [staticData, stringKind]);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!staticData) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No static analysis data available — the sample may not be a PE/ELF
        binary, or the loader was unable to parse it.
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Carved payloads lead the page. A nested executable inside a dropper
        * is the actual malware, and it was invisible here — `embedded_resources`
        * was in the type and rendered nowhere. */}
      {carvedPayloads.length > 0 && (
        <div className="bg-bg-surface border border-status-red/40 rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-status-red uppercase tracking-wider">
              Carved payloads ({carvedPayloads.length})
            </h2>
            <p className="text-[11px] text-text-muted mt-1">
              Executables found inside the sample — appended past the last section, or
              embedded in a resource. Scanned by the signature layer separately.
            </p>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>Type</Th>
                <Th>Location</Th>
                <Th>Size</Th>
                <Th>Entropy</Th>
                <Th>SHA-256</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {carvedPayloads.map((p, i) => (
                <tr key={i} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2 text-xs font-mono text-status-red">{p.type ?? "-"}</td>
                  <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                    {p.id ?? "-"}
                    {p.source && <span className="text-text-muted"> ({p.source})</span>}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-secondary">
                    {typeof p.size === "number" ? formatBytes(p.size) : "-"}
                  </td>
                  <td
                    className={`px-4 py-2 text-xs font-mono ${
                      typeof p.entropy === "number" ? entropyClass(p.entropy) : "text-text-muted"
                    }`}
                  >
                    {typeof p.entropy === "number" ? p.entropy.toFixed(2) : "-"}
                  </td>
                  <td
                    className="px-4 py-2 text-xs font-mono text-text-muted truncate max-w-[16rem]"
                    title={p.sha256 ?? ""}
                  >
                    {p.sha256 ? `${p.sha256.slice(0, 24)}…` : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {techniqueHits.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              ATT&amp;CK from imports ({techniqueHits.length})
            </h2>
            <p className="text-[11px] text-text-muted mt-1">
              Derived from the import table alone — no sandbox, no model. This is the
              audit trail behind the capability matrix.
            </p>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>Technique</Th>
                <Th>Name</Th>
                <Th>Confidence</Th>
                <Th>Imports</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {techniqueHits.map((h, i) => (
                <tr key={i} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2 text-xs font-mono text-accent">
                    {h.technique_id ?? "-"}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-primary">{h.name ?? "-"}</td>
                  <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                    {typeof h.confidence === "number" ? h.confidence.toFixed(2) : "-"}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono text-text-muted">
                    {(h.matched_apis ?? []).slice(0, 4).join(", ")}
                    {(h.matched_apis ?? []).length > 4 &&
                      ` +${(h.matched_apis ?? []).length - 4}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(staticData.packer_hint ||
        staticData.obfuscation_indicators.length > 0 ||
        packerMatches.length > 0 ||
        capabilityProfile.length > 0) && (
        <div className="bg-bg-surface border border-border rounded p-4">
          <div className="text-[11px] text-text-muted uppercase tracking-wider mb-2">
            Packer / Obfuscation
          </div>
          {/* Ranked matches beat the bare hint: a reader needs to know whether
            * the detector saw a section name or just a string. */}
          {packerMatches.length > 0 ? (
            <div className="space-y-1 mb-2">
              {packerMatches.map((pm, i) => (
                <div key={i} className="text-sm text-text-primary">
                  {pm.name}
                  {pm.kind && <span className="text-text-muted"> ({pm.kind})</span>}
                  <span className="text-text-muted text-xs ml-2 font-mono">
                    {typeof pm.confidence === "number" ? pm.confidence.toFixed(2) : "-"}
                    {pm.method ? ` · ${pm.method}` : ""}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            staticData.packer_hint && (
              <div className="text-sm text-text-primary mb-1">
                <span className="text-text-muted">Packer hint:</span> {staticData.packer_hint}
              </div>
            )
          )}
          {capabilityProfile.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-2">
              {capabilityProfile.map(([cat, count]) => (
                <span
                  key={cat}
                  className="text-[11px] px-1.5 py-0.5 rounded bg-bg-hover text-text-secondary font-mono"
                >
                  {cat} ×{count}
                </span>
              ))}
            </div>
          )}
          {staticData.obfuscation_indicators.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-1">
              {staticData.obfuscation_indicators.map((ind) => (
                <span
                  key={ind}
                  className="text-[11px] px-1.5 py-0.5 rounded bg-status-orange/10 text-status-orange"
                >
                  {ind}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            {sectionsLabel} ({staticData.sections.length})
          </h2>
        </div>
        {staticData.sections.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No sections recorded.</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>Name</Th>
                <Th>VA</Th>
                <Th>Virtual Size</Th>
                <Th>Raw Size</Th>
                <Th>Entropy</Th>
                <Th>Characteristics</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {staticData.sections.map((s, i) => (
                <tr key={`${s.name}-${i}`} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2 text-xs font-mono text-text-primary">
                    {s.name}
                    {s.is_suspicious && (
                      <span className="ml-2 text-[11px] px-1.5 py-0.5 rounded bg-status-red/10 text-status-red">
                        SUSP
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                    {s.virtual_address}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-secondary">
                    {formatBytes(s.virtual_size)}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-secondary">
                    {formatBytes(s.raw_size)}
                  </td>
                  <td className={`px-4 py-2 text-xs font-mono ${entropyClass(s.entropy)}`}>
                    {s.entropy.toFixed(3)}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-muted font-mono truncate" title={s.characteristics}>
                    {s.characteristics || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Imports ({filteredImports.length} / {staticData.imports.length})
          </h2>
          <label className="flex items-center gap-2 text-xs text-text-secondary cursor-pointer">
            <input
              type="checkbox"
              checked={showSuspiciousOnly}
              onChange={(e) => setShowSuspiciousOnly(e.target.checked)}
              className="accent-status-red"
            />
            suspicious only
          </label>
        </div>
        {filteredImports.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No imports to show.</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>DLL</Th>
                <Th>Function</Th>
                <Th>Category</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {filteredImports.slice(0, 500).map((row, i) => (
                <tr key={i} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2 text-xs font-mono text-text-secondary">{row.dll}</td>
                  <td className="px-4 py-2 text-xs font-mono">
                    <span className={row.is_suspicious ? "text-status-red" : "text-text-primary"}>
                      {row.function}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-xs text-text-muted">
                    {row.category || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {filteredImports.length > 500 && (
          <div className="px-4 py-2 text-[11px] text-text-muted border-t border-border">
            Showing first 500 of {filteredImports.length}.
          </div>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 flex-wrap">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Interesting Strings ({filteredStrings.length})
          </h2>
          <div className="flex flex-wrap gap-1">
            {STRING_KINDS.map((k) => (
              <button
                key={k}
                onClick={() => setStringKind(k)}
                className={`text-[11px] uppercase tracking-wider px-2 py-0.5 rounded border transition-colors ${
                  stringKind === k
                    ? "border-accent text-accent"
                    : "border-border text-text-secondary hover:text-text-primary"
                }`}
              >
                {k}
              </button>
            ))}
          </div>
        </div>
        {filteredStrings.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">
            No interesting strings extracted.
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>Kind</Th>
                <Th>Value</Th>
                <Th>Notes</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {filteredStrings.slice(0, 300).map((s, i) => (
                <tr key={i} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2 text-[11px] uppercase tracking-wider text-text-muted">
                    {s.kind}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono text-status-blue break-all">
                    {s.value}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-muted">{s.notes || "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {filteredStrings.length > 300 && (
          <div className="px-4 py-2 text-[11px] text-text-muted border-t border-border">
            Showing first 300 of {filteredStrings.length}.
          </div>
        )}
      </div>

      {staticData.exports.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Exports ({staticData.exports.length})
            </h2>
          </div>
          <div className="p-4 flex flex-wrap gap-1">
            {staticData.exports.map((e) => (
              <span key={e} className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-bg-active text-text-secondary">
                {e}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
