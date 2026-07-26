"use client";

import { useState } from "react";

import { useReport } from "../layout";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import Th from "@/components/ui/Th";
import { ENRICH_STATUS_MESSAGE, ENRICH_BUTTON_LABEL } from "@/lib/enrichment";
import type { NetworkDomain, NetworkIP } from "@/types/malware-report";

export default function NetworkTab() {
  const { report, loading } = useReport();
  const [enrichBusy, setEnrichBusy] = useState(false);
  const [enrichMsg, setEnrichMsg] = useState<string | null>(null);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const mr = report?.malware_report;
  const net = mr?.network;
  // 2026-07 audit (Bulgu #4): network IOCs recovered from the PE's static
  // strings (e.g. a hard-coded C2 domain) live on ``static.interesting_strings``,
  // not on the (sandbox-only) ``network`` block. Surface them here — clearly
  // labelled as static-derived — so a domain like 888kafa.com is no longer
  // reported as "0 domains" just because the sandbox never ran.
  const staticIocs = (mr?.static?.interesting_strings ?? []).filter(
    (s) => s.kind === "domain" || s.kind === "ip" || s.kind === "url",
  );
  if (!net && staticIocs.length === 0) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No network IOCs available — the sample may not have contacted the network
        during analysis.
      </div>
    );
  }

  const reportId = report?.id;
  const triggerEnrich = async () => {
    if (!reportId || enrichBusy) return;
    setEnrichBusy(true);
    setEnrichMsg(null);
    try {
      // audit 2026-07-26 (§4): the endpoint distinguishes queued /
      // already_queued / skipped_no_network_iocs — say which one happened
      // instead of always promising a refresh.
      const res = await api.enrichReport(reportId);
      setEnrichMsg(ENRICH_STATUS_MESSAGE[res.status] ?? ENRICH_STATUS_MESSAGE.queued);
    } catch (e) {
      setEnrichMsg(`Failed to queue enrichment: ${getErrorMessage(e)}`);
    } finally {
      setEnrichBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-xs text-text-muted">
          {(net?.domains.length ?? 0) +
            staticIocs.filter((s) => s.kind === "domain").length}{" "}
          domain(s) · {(net?.ips.length ?? 0) +
            staticIocs.filter((s) => s.kind === "ip").length}{" "}
          IP(s) · {(net?.urls.length ?? 0) +
            staticIocs.filter((s) => s.kind === "url").length}{" "}
          URL(s)
          {staticIocs.length > 0 && (
            <span className="ml-1 text-text-disabled">
              ({staticIocs.length} from static strings)
            </span>
          )}
        </div>
        <button
          onClick={triggerEnrich}
          disabled={enrichBusy || !reportId}
          className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors disabled:text-text-disabled disabled:cursor-not-allowed"
        >
          {enrichBusy ? "queueing..." : ENRICH_BUTTON_LABEL}
        </button>
      </div>
      {enrichMsg && (
        <div className="text-xs text-text-secondary bg-bg-active border border-border rounded p-2">
          {enrichMsg}
        </div>
      )}

      {staticIocs.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Static-string indicators ({staticIocs.length})
            </h2>
            <p className="mt-1 text-[11px] text-text-muted">
              Extracted from the binary&apos;s strings — potential C2/network
              endpoints that were not observed on the wire during analysis.
            </p>
          </div>
          <div className="divide-y divide-border-light">
            {staticIocs.map((s, i) => (
              <div
                key={`${s.kind}-${s.value}-${i}`}
                className="px-4 py-2 flex items-center gap-3 hover:bg-bg-hover transition-colors"
              >
                <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-bg-active text-text-muted shrink-0">
                  {s.kind}
                </span>
                <code className="text-xs font-mono text-status-blue break-all">
                  {s.value}
                </code>
                <span
                  className="ml-auto text-[10px] text-text-disabled shrink-0"
                  title="Seen in static strings, not in sandbox network telemetry"
                >
                  static
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {net && (
      <>
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Domains
          </h2>
        </div>
        {net.domains.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No domains observed.</div>
        ) : (
          <div className="divide-y divide-border-light">
            {net.domains.map((d, i) => (
              <DomainCard key={`${d.fqdn}-${i}`} domain={d} />
            ))}
          </div>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            IP Endpoints
          </h2>
        </div>
        {net.ips.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No IPs observed.</div>
        ) : (
          <div className="divide-y divide-border-light">
            {net.ips.map((ip, i) => (
              <IPCard key={`${ip.address}-${i}`} ip={ip} />
            ))}
          </div>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            HTTP URLs
          </h2>
        </div>
        {net.urls.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No HTTP URLs observed.</div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <Th>Method</Th>
                <Th>Status</Th>
                <Th>URL</Th>
                <Th>User-Agent</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {net.urls.map((u, i) => (
                <tr key={i} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-2 text-[11px] uppercase tracking-wider text-text-muted">
                    {u.method}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                    {u.status ?? "-"}
                  </td>
                  <td className="px-4 py-2 text-xs font-mono text-status-blue break-all">
                    {u.url}
                  </td>
                  <td className="px-4 py-2 text-xs text-text-muted truncate" title={u.user_agent || undefined}>
                    {u.user_agent || "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            User-Agents ({net.user_agents.length})
          </h2>
        </div>
        {net.user_agents.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">No user agents observed.</div>
        ) : (
          <ul className="divide-y divide-border-light">
            {net.user_agents.map((ua, i) => (
              <li
                key={i}
                className="px-4 py-2 text-xs font-mono text-text-secondary break-all hover:bg-bg-hover transition-colors"
              >
                {ua}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            JA3 Fingerprints ({net.ja3_fingerprints.length})
          </h2>
        </div>
        {net.ja3_fingerprints.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">
            No TLS JA3 fingerprints observed.
          </div>
        ) : (
          <ul className="divide-y divide-border-light">
            {net.ja3_fingerprints.map((j, i) => (
              <li
                key={i}
                className="px-4 py-2 text-xs font-mono text-text-secondary break-all hover:bg-bg-hover transition-colors"
              >
                {typeof j === "string" ? j : JSON.stringify(j)}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            JA3S Fingerprints ({net.ja3s_fingerprints.length})
          </h2>
        </div>
        {net.ja3s_fingerprints.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">
            No TLS JA3S fingerprints observed.
          </div>
        ) : (
          <ul className="divide-y divide-border-light">
            {net.ja3s_fingerprints.map((j, i) => (
              <li
                key={i}
                className="px-4 py-2 text-xs font-mono text-text-secondary break-all hover:bg-bg-hover transition-colors"
              >
                {typeof j === "string" ? j : JSON.stringify(j)}
              </li>
            ))}
          </ul>
        )}
      </div>
      </>
      )}
    </div>
  );
}

function DomainCard({ domain }: { domain: NetworkDomain }) {
  const rep = domain.reputation as Record<string, unknown> | null;
  return (
    <div className="p-4">
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <code className="text-sm font-mono text-status-blue break-all">{domain.fqdn}</code>
            {domain.is_suspicious && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-status-red/10 text-status-red shrink-0">
                SUSP
              </span>
            )}
          </div>
          {domain.reason && (
            <div className="text-xs text-text-muted mt-1">{domain.reason}</div>
          )}
          {domain.resolved_ips.length > 0 && (
            <div className="text-xs text-text-secondary mt-1">
              <span className="text-text-muted">Resolved: </span>
              {domain.resolved_ips.join(", ")}
            </div>
          )}
        </div>
        {rep ? (
          <ReputationBadge rep={rep} />
        ) : (
          <span className="text-[11px] text-text-muted">no reputation</span>
        )}
      </div>
    </div>
  );
}

function IPCard({ ip }: { ip: NetworkIP }) {
  return (
    <div className="p-4">
      <div className="flex items-start gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <code className="text-sm font-mono text-status-blue break-all">{ip.address}</code>
            {ip.port !== null && (
              <span className="text-xs text-text-secondary">
                :{ip.port}
                {ip.transport ? `/${ip.transport}` : ""}
              </span>
            )}
            {ip.is_suspicious && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-status-red/10 text-status-red">
                SUSP
              </span>
            )}
            {ip.geo && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-secondary">
                {ip.geo}
              </span>
            )}
            {ip.asn && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-secondary font-mono">
                {ip.asn}
              </span>
            )}
          </div>
        </div>
        {ip.reputation ? (
          <ReputationBadge rep={ip.reputation as Record<string, unknown>} />
        ) : (
          <span className="text-[11px] text-text-muted">no reputation</span>
        )}
      </div>
    </div>
  );
}

function ReputationBadge({ rep }: { rep: Record<string, unknown> }) {
  const source = (rep.source as string) || "intel";
  const malicious = rep.malicious as number | undefined;
  const abuse = rep.abuse_confidence as number | undefined;
  const score =
    typeof malicious === "number"
      ? malicious
      : typeof abuse === "number"
        ? abuse
        : null;
  const cls =
    score === null
      ? "text-text-muted bg-bg-active"
      : score >= 70 || (malicious !== undefined && malicious >= 5)
        ? "text-status-red bg-status-red/10"
        : score >= 30 || (malicious !== undefined && malicious >= 1)
          ? "text-status-orange bg-status-orange/10"
          : "text-status-green bg-status-green/10";

  return (
    <span
      className={`shrink-0 text-[11px] uppercase tracking-wider px-2 py-0.5 rounded font-mono ${cls}`}
      title={JSON.stringify(rep)}
    >
      {source}
      {score !== null ? ` · ${score}` : ""}
    </span>
  );
}
