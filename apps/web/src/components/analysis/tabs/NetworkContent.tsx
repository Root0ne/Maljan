"use client";

import { useState } from "react";

import type { ReportDetailDTO } from "@/lib/api";
import Drawer from "@/components/ui/Drawer";
import Section from "@/components/ui/Section";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import Th from "@/components/ui/Th";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import { isCoveredBySection, sectionsForTab } from "@/components/analysis/reportSections";
import { endpointReputation, reputationTooltip, verdictWords } from "@/components/analysis/reputation";
import { domainFacts, ipFacts } from "@/components/analysis/networkFacts";
import {
  NETWORK_ROWS_STEP,
  hostReputation,
  hostRows,
  hostSource,
  hostSuspicious,
  sourceExplanation,
  urlHost,
  type HostRow,
} from "@/components/analysis/networkView";
import type { NetworkURL, StringIOC } from "@/types/malware-report";

type Detail =
  | { kind: "host"; row: HostRow; opener: HTMLElement }
  | { kind: "request"; url: NetworkURL; opener: HTMLElement };

/**
 * Every endpoint the run saw or read out of the sample: the hosts first, each
 * opening what is known about it and the requests it received; then the
 * HTTP requests, the DNS answers and the TLS fingerprints, each a table drawn
 * ten rows at a time; then the endpoints found only in the sample's strings.
 * A section that says the same as one of these tables is kept beside it, one
 * click away, with its citation marks.
 */
export default function NetworkContent({ report }: { report: ReportDetailDTO }) {
  const [shown, setShown] = useState<Record<string, number>>({});
  const [detail, setDetail] = useState<Detail | null>(null);
  const shownOf = (t: string) => shown[t] ?? NETWORK_ROWS_STEP;
  const show = (t: string) => (n: number) => setShown((s) => ({ ...s, [t]: n }));

  const mr = report.malware_report;
  const net = mr?.network ?? null;
  // Network IOCs recovered from the sample's static strings (a hard-coded C2
  // domain) live on `static.interesting_strings`, not on the sandbox-only
  // `network` block; they are listed here, labelled as found in the strings.
  const staticIocs: StringIOC[] = (mr?.static?.interesting_strings ?? []).filter(
    (s) => s.kind === "domain" || s.kind === "ip" || s.kind === "url",
  );
  const reportSections = mr?.sections;
  const evidenceSections = sectionsForTab(reportSections, "network", report.section_tabs);
  const covering = evidenceSections.filter((s) => s.key === "sandbox_network" || s.key === "iocs");
  const otherSections = evidenceSections.filter((s) => !covering.includes(s));
  const showsStaticIocs = staticIocs.length > 0 && !isCoveredBySection(reportSections, ["iocs"]);
  const hosts = hostRows(net);
  const urls = net?.urls ?? [];
  const domains = net?.domains ?? [];
  const tls: { kind: string; value: string }[] = [
    ...(net?.ja3_fingerprints ?? []).map((v) => ({ kind: "JA3", value: text(v) })),
    ...(net?.ja3s_fingerprints ?? []).map((v) => ({ kind: "JA3S", value: text(v) })),
  ];
  const agents = (net?.user_agents ?? []).map(text);

  return (
    <div className="space-y-4">
      <Section title="Hosts" count={hosts.length || null} empty={hosts.length === 0}>
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-light">
                <Th>Host</Th>
                <Th>Requests</Th>
                <Th>Reputation</Th>
                <Th>Seen by</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {hosts.slice(0, shownOf("hosts")).map((row) => (
                <tr key={row.key} className="hover:bg-bg-hover">
                  <td className="px-4 py-2 align-top">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <button
                        type="button"
                        onClick={(e) => setDetail({ kind: "host", row, opener: e.currentTarget })}
                        className="text-left font-mono text-xs text-status-blue break-all hover:underline"
                      >
                        {row.host}
                        {row.kind === "ip" && row.ip.port !== null && (
                          <span className="text-text-secondary">
                            :{row.ip.port}
                            {row.ip.transport ? `/${row.ip.transport}` : ""}
                          </span>
                        )}
                      </button>
                      {hostSuspicious(row) && <Flag tone="red">Suspicious</Flag>}
                      {row.kind === "domain" && row.domain.is_punycode && (
                        /* A punycode label is registered precisely so it reads
                           as a brand it is not, so the badge names the brand. */
                        <Flag tone="orange" title={row.domain.homograph_target ? `Renders like ${row.domain.homograph_target}` : undefined}>
                          {row.domain.homograph_target ? `Looks like ${row.domain.homograph_target}` : "Punycode"}
                        </Flag>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-2 align-top text-xs text-text-secondary">{row.requests.length || "-"}</td>
                  <td className="px-4 py-2 align-top">
                    <ReputationPill rep={hostReputation(row)} />
                  </td>
                  <td className="px-4 py-2 align-top">
                    <SourceWord source={hostSource(row)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ShowMoreRows shown={Math.min(shownOf("hosts"), hosts.length)} total={hosts.length} onShow={show("hosts")} step={NETWORK_ROWS_STEP} />
        </div>
      </Section>

      <Section title="HTTP requests" count={urls.length || null} empty={urls.length === 0}>
        <div className="-mx-4 -my-3 overflow-x-auto">
          <RequestTable
            urls={urls.slice(0, shownOf("http"))}
            onOpen={(url, opener) => setDetail({ kind: "request", url, opener })}
          />
          <ShowMoreRows shown={Math.min(shownOf("http"), urls.length)} total={urls.length} onShow={show("http")} step={NETWORK_ROWS_STEP} />
        </div>
      </Section>

      <Section title="DNS" count={domains.length || null} empty={domains.length === 0}>
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-light">
                <Th>Name</Th>
                <Th>Answers</Th>
                <Th>Queried by</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {domains.slice(0, shownOf("dns")).map((d, i) => (
                <tr key={`${d.fqdn}-${i}`} className="hover:bg-bg-hover">
                  <td className="px-4 py-2 align-top font-mono text-xs text-status-blue break-all">{d.fqdn}</td>
                  <td className="px-4 py-2 align-top text-xs text-text-secondary break-all">
                    {d.resolved_ips.length > 0 ? d.resolved_ips.join(", ") : "-"}
                    {d.resolved_ips_partial && (
                      <span className="block text-text-muted">
                        Some addresses withheld for size ({d.resolved_ips_withheld ?? 0} of its DNS request&apos;s answers not read).
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2 align-top font-mono text-xs text-text-secondary">
                    {d.queried_pids.length > 0 ? `PID ${d.queried_pids.join(", ")}` : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <ShowMoreRows shown={Math.min(shownOf("dns"), domains.length)} total={domains.length} onShow={show("dns")} step={NETWORK_ROWS_STEP} />
        </div>
      </Section>

      <Section title="TLS and client fingerprints" count={tls.length + agents.length || null} empty={tls.length + agents.length === 0}>
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-light">
                <Th>Kind</Th>
                <Th>Value</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {[...tls, ...agents.map((value) => ({ kind: "User agent", value }))]
                .slice(0, shownOf("tls"))
                .map((f, i) => (
                  <tr key={`${f.kind}-${i}`} className="hover:bg-bg-hover">
                    <td className="whitespace-nowrap px-4 py-2 align-top text-xs text-text-muted">{f.kind}</td>
                    <td className="px-4 py-2 align-top font-mono text-xs text-text-secondary break-all">{f.value}</td>
                  </tr>
                ))}
            </tbody>
          </table>
          <ShowMoreRows
            shown={Math.min(shownOf("tls"), tls.length + agents.length)}
            total={tls.length + agents.length}
            onShow={show("tls")}
            step={NETWORK_ROWS_STEP}
          />
        </div>
      </Section>

      <Section
        title="Endpoints in the sample's strings"
        count={showsStaticIocs ? staticIocs.length : null}
        empty={!showsStaticIocs && !covering.some((s) => s.key === "iocs")}
      >
        <div className="space-y-3">
          <p className="text-xs text-text-muted">
            Extracted from the binary&apos;s strings — potential C2 or network endpoints that were not
            observed on the wire during analysis.
          </p>
          {showsStaticIocs ? (
            <div className="-mx-4 overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-y border-border-light">
                    <Th>Kind</Th>
                    <Th>Value</Th>
                    <Th>Notes</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-light">
                  {staticIocs.slice(0, shownOf("strings")).map((s, i) => (
                    <tr key={`${s.kind}-${s.value}-${i}`} className="hover:bg-bg-hover">
                      <td className="px-4 py-2 text-xs text-text-muted">{s.kind}</td>
                      <td className="px-4 py-2 font-mono text-xs text-status-blue break-all">{s.value}</td>
                      <td className="px-4 py-2 text-xs text-text-secondary">{s.notes || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <ShowMoreRows
                shown={Math.min(shownOf("strings"), staticIocs.length)}
                total={staticIocs.length}
                onShow={show("strings")}
                step={NETWORK_ROWS_STEP}
              />
            </div>
          ) : (
            <ArtifactSections sections={covering.filter((s) => s.key === "iocs")} />
          )}
        </div>
      </Section>

      {covering.some((s) => s.key === "sandbox_network") && (
        <details>
          <summary className="cursor-pointer text-xs text-text-secondary hover:text-text-primary">
            The same traffic, as the tools returned it
          </summary>
          <div className="mt-2 space-y-3">
            <ArtifactSections sections={covering.filter((s) => s.key === "sandbox_network")} />
          </div>
        </details>
      )}

      <ArtifactSections sections={otherSections} />

      <Drawer
        open={detail !== null}
        title={detail ? (detail.kind === "host" ? detail.row.host : "HTTP request") : ""}
        onClose={() => setDetail(null)}
        returnFocusTo={detail?.opener ?? null}
      >
        {detail?.kind === "host" && <HostDetail row={detail.row} />}
        {detail?.kind === "request" && <RequestDetail url={detail.url} hosts={hosts} />}
      </Drawer>
    </div>
  );
}

function text(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function RequestTable({
  urls,
  onOpen,
}: {
  urls: NetworkURL[];
  onOpen?: (url: NetworkURL, opener: HTMLElement) => void;
}) {
  return (
    <table className="w-full">
      <thead>
        <tr className="border-b border-border-light">
          <Th>Method</Th>
          <Th>Status</Th>
          <Th>URL</Th>
          <Th>User agent</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-border-light">
        {urls.map((u, i) => (
          <tr key={i} className="hover:bg-bg-hover">
            <td className="px-4 py-2 align-top text-xs text-text-muted">{u.method ?? "-"}</td>
            <td className="px-4 py-2 align-top font-mono text-xs text-text-secondary">{u.status ?? "-"}</td>
            <td className="max-w-[28rem] px-4 py-2 align-top">
              {onOpen ? (
                <button
                  type="button"
                  onClick={(e) => onOpen(u, e.currentTarget)}
                  title={u.url}
                  className="block max-w-full truncate text-left font-mono text-xs text-status-blue hover:underline"
                >
                  {u.url}
                </button>
              ) : (
                <code className="font-mono text-xs text-status-blue break-all">{u.url}</code>
              )}
            </td>
            <td className="max-w-[14rem] truncate px-4 py-2 align-top text-xs text-text-muted" title={u.user_agent || undefined}>
              {u.user_agent || "-"}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function HostDetail({ row }: { row: HostRow }) {
  const rep = hostReputation(row);
  const source = hostSource(row);
  const facts = row.kind === "domain" ? domainFacts(row.domain) : ipFacts(row.ip);
  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <Flag tone="neutral">{row.kind === "domain" ? "Domain" : "IP address"}</Flag>
        {hostSuspicious(row) && <Flag tone="red">Suspicious</Flag>}
        <ReputationPill rep={rep} />
        <SourceWord source={source} />
      </div>
      {row.kind === "domain" ? (
        <dl className="space-y-2">
          {row.domain.reason && <Pair label="Why it stands out">{row.domain.reason}</Pair>}
          <Pair label="Resolved to">{row.domain.resolved_ips.length > 0 ? row.domain.resolved_ips.join(", ") : "Nothing recorded"}</Pair>
          {row.domain.queried_pids.length > 0 && <Pair label="Queried by PID">{row.domain.queried_pids.join(", ")}</Pair>}
          {typeof row.domain.dga_score === "number" && row.domain.dga_score > 0 && (
            <Pair label="Generated-name score">{row.domain.dga_score.toFixed(2)}</Pair>
          )}
        </dl>
      ) : (
        <dl className="space-y-2">
          {row.ip.port !== null && (
            <Pair label="Port">
              {row.ip.port}
              {row.ip.transport ? `/${row.ip.transport}` : ""}
            </Pair>
          )}
          {row.ip.geo && <Pair label="Location">{row.ip.geo}</Pair>}
          {row.ip.asn && <Pair label="Network (ASN)">{row.ip.asn}</Pair>}
        </dl>
      )}
      {facts.length > 0 && (
        <ul className="space-y-1">
          {facts.map((line) => (
            <li key={line} className="text-xs text-text-secondary">
              {line}
            </li>
          ))}
        </ul>
      )}
      {rep && (
        <div>
          <h3 className="mb-1 text-xs font-semibold text-text-secondary">Reputation record</h3>
          <pre className="whitespace-pre-wrap break-words rounded border border-border-light bg-bg-deep px-2 py-1 font-mono text-xs text-text-primary">
            {reputationTooltip(rep)}
          </pre>
        </div>
      )}
      <div>
        <h3 className="mb-1 text-xs font-semibold text-text-secondary">Requests to this host ({row.requests.length})</h3>
        {row.requests.length === 0 ? (
          <p className="text-xs text-text-muted">Not found</p>
        ) : (
          <div className="-mx-4 overflow-x-auto">
            <RequestTable urls={row.requests} />
          </div>
        )}
      </div>
    </div>
  );
}

function RequestDetail({ url, hosts }: { url: NetworkURL; hosts: HostRow[] }) {
  const host = urlHost(url.url);
  const known = hosts.find((h) => h.host.trim().toLowerCase() === host);
  return (
    <dl className="space-y-3 text-sm">
      <Pair label="URL">
        <code className="break-all font-mono text-xs">{url.url}</code>
      </Pair>
      <Pair label="Method">{url.method ?? "Not recorded"}</Pair>
      <Pair label="Response status">{url.status ?? "Not recorded"}</Pair>
      <Pair label="User agent">{url.user_agent || "Not recorded"}</Pair>
      {url.source && (
        <Pair label="Seen by">
          {url.source} — {sourceExplanation(url.source)}
        </Pair>
      )}
      <Pair label="Host">
        {host || "Not recorded"}
        {known && hostSuspicious(known) && <span className="ml-2 text-status-red">suspicious</span>}
      </Pair>
    </dl>
  );
}

function Pair({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-text-muted">{label}</dt>
      <dd className="text-text-primary">{children}</dd>
    </div>
  );
}

function Flag({ tone, title, children }: { tone: "red" | "orange" | "neutral"; title?: string; children: React.ReactNode }) {
  const cls =
    tone === "red"
      ? "bg-status-red/10 text-status-red"
      : tone === "orange"
        ? "bg-status-orange/10 text-status-orange"
        : "bg-bg-active text-text-secondary";
  return (
    <span title={title} className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] ${cls}`}>
      {children}
    </span>
  );
}

/* Where an endpoint came from. A name the sandbox watched the sample reach
 * and a run of bytes shaped like one are different claims, and only the first
 * is an observation of infrastructure; the second is held out of the export
 * until a second source knows it. */
function SourceWord({ source }: { source: string | null }) {
  if (!source) return <span className="text-xs text-text-muted">-</span>;
  return (
    <span className="text-xs text-text-muted" title={sourceExplanation(source)}>
      {source}
    </span>
  );
}

/* The enrichment record beside a host, by the figure it carries and in a
 * neutral tone: whether the source calls the endpoint malicious is its own
 * declared rule, which the row's suspicious flag already carries
 * (`endpointReputation`). A host nobody looked up says so. */
function ReputationPill({ rep }: { rep: Record<string, unknown> | null }) {
  const badge = rep ? endpointReputation(rep) : null;
  if (!rep || !badge) return <span className="text-xs text-text-muted">Not looked up</span>;
  const verdict = verdictWords(badge.verdict);
  return (
    <span
      className={`inline-flex max-w-full items-center rounded border px-1.5 py-px font-mono text-[11px] ${
        verdict?.tone === "red" ? "border-status-red/30 text-status-red" : "border-border text-text-secondary"
      }`}
      title={reputationTooltip(rep)}
    >
      {badge.source}
      {badge.figure ? ` · ${badge.figure}` : ""}
      {verdict ? ` · ${verdict.text}` : ""}
    </span>
  );
}
