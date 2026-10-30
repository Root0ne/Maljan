/**
 * What the report records about who reached an endpoint and who listed it,
 * as sentences under the row.
 *
 * The rows carried these facts and the console drew none of them: whether the
 * sample's own process tree reached an address, which other processes did,
 * the processes the sandbox's mark and the file's own tree disagree about,
 * whether the address is a public resolver, whether a name was seen only in
 * the capture's TLS names, and which analysts kept or merely mentioned the
 * value. They are the reasons a row is or is not published, so a reader
 * comparing two rows needs them.
 *
 * A fact the row does not carry is not said: an unset `sample_process_tree`
 * is "the report does not say", which is not the same as "no".
 */

import type { MalwareReport, NetworkDomain, NetworkIP } from "@/types/malware-report";

function names(values: string[] | null | undefined): string {
  return (values ?? []).filter((v) => typeof v === "string" && v.trim()).join(", ");
}

/** Who listed or mentioned the value; shared by every network kind. */
function listedBy(row: { kept_by?: string[]; mentioned_by?: string[] }): string[] {
  const lines: string[] = [];
  if (names(row.kept_by)) lines.push(`Kept as an indicator by ${names(row.kept_by)}.`);
  if (names(row.mentioned_by)) lines.push(`Mentioned without being kept by ${names(row.mentioned_by)}.`);
  return lines;
}

export function domainFacts(domain: NetworkDomain): string[] {
  const lines: string[] = [];
  if (domain.capture_only) {
    lines.push(
      "Seen only in the capture's TLS names, with no DNS or HTTP view naming it, so nothing says which process connected.",
    );
  }
  return [...lines, ...listedBy(domain)];
}

export function ipFacts(ip: NetworkIP): string[] {
  const lines: string[] = [];
  if (ip.sample_process_tree === true) {
    lines.push("The sandbox saw the sample's own process tree reach this address.");
  } else if (ip.sample_process_tree === false) {
    lines.push(
      names(ip.outside_processes)
        ? `Every flow the sandbox attributes came from outside the sample's tree: ${names(ip.outside_processes)}.`
        : "Every flow the sandbox attributes came from outside the sample's tree.",
    );
  }
  if (names(ip.marked_only_processes)) {
    lines.push(
      `Named the sample's only by ${ip.marked_by?.trim() || "the sandbox"}'s own mark: ${names(ip.marked_only_processes)}.`,
    );
  }
  if (names(ip.file_only_processes)) {
    lines.push(
      `Named the sample's only by the submitted file's process tree: ${names(ip.file_only_processes)}.`,
    );
  }
  if (ip.public_resolver) {
    lines.push("A public DNS resolver, which a sandbox guest reaches whatever the sample does.");
  }
  return [...lines, ...listedBy(ip)];
}

/**
 * How many distinct domains, addresses and URLs a run names, from the network
 * block and the sample's own strings together. A value both sources carry is
 * one endpoint, so it is counted once (names compare without case).
 */
export function endpointCounts(
  net: { domains: { fqdn: string }[]; ips: { address: string }[]; urls: { url: string }[] } | null | undefined,
  strings: { kind: string; value: string }[] | null | undefined,
): { domains: number; ips: number; urls: number } {
  const key = (value: string) => String(value ?? "").trim().toLowerCase();
  const domains = new Set((net?.domains ?? []).map((d) => key(d.fqdn)));
  const ips = new Set((net?.ips ?? []).map((i) => key(i.address)));
  const urls = new Set((net?.urls ?? []).map((u) => String(u.url ?? "").trim()));
  for (const s of strings ?? []) {
    if (s.kind === "domain") domains.add(key(s.value));
    else if (s.kind === "ip") ips.add(key(s.value));
    else if (s.kind === "url") urls.add(String(s.value ?? "").trim());
  }
  return { domains: domains.size, ips: ips.size, urls: urls.size };
}

/**
 * The counts the Network tab leads with: the endpoints the capture and the
 * binary's own strings name (a hard-coded C2 domain is not "0 domains"), and
 * how many of the capture's endpoints were found suspicious.
 */
export function networkCounts(mr: MalwareReport): {
  domains: number;
  ips: number;
  urls: number;
  suspicious: number;
} {
  const n = mr.network;
  const staticIocs = (mr.static?.interesting_strings ?? []).filter(
    (s) => s.kind === "domain" || s.kind === "ip" || s.kind === "url",
  );
  const counts = endpointCounts(n, staticIocs);
  if (!n) return { ...counts, suspicious: 0 };
  const suspicious =
    n.domains.filter((d) => d.is_suspicious).length + n.ips.filter((i) => i.is_suspicious).length;
  return { ...counts, suspicious };
}
