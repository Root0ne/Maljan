"use client";

import { useState } from "react";
import { useParams } from "next/navigation";

import { useReport } from "../layout";
import { copyToClipboard, formatBytes } from "@/lib/report-utils";
import Field from "@/components/ui/Field";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import ReputationSection from "@/components/analysis/ReputationSection";
import { readIdentitySection, type HashField } from "@/components/analysis/identitySection";
import {
  binarySectionKeys,
  isCoveredBySection,
  saysSomething,
  sectionsForTab,
} from "@/components/analysis/reportSections";
import { fileTypeLabel, platformLabel } from "@/types/malware-report";
import type { SampleIdentity } from "@/types/malware-report";

export default function IdentityTab() {
  const { report, loading } = useReport();
  const params = useParams();
  const jobId = (params.id as string) ?? "";

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const identity: SampleIdentity | undefined = report?.malware_report?.identity;
  // What the identifying tools returned, in their own shape: the `identity`
  // key/value block and the header table of whichever binary-info tool ran.
  // These lead the page; the typed block below is the report's own summary of
  // the same facts and stands down when a header section already carries them.
  const reportSections = report?.malware_report?.sections;
  /* The `identity` section is the one that overlaps this tab's own blocks: its
   * hashes are the File hashes block and its three signing rows are one fact
   * about one format. It is split rather than drawn as it arrives. */
  const tabSections = sectionsForTab(reportSections, "identity");
  const identitySection = tabSections.find((section) => section.key === "identity") ?? null;
  const {
    section: splitIdentity,
    hashes: ledgerHashes,
    signing: sectionStatesSigning,
  } = readIdentitySection(
    identitySection,
    report?.malware_report?.identity?.file_type,
  );
  const evidenceSections = tabSections.flatMap((section) =>
    section.key === "identity" ? (splitIdentity ? [splitIdentity] : []) : [section],
  );
  const showsTypedIdentity = !isCoveredBySection(reportSections, binarySectionKeys("header"));

  if (!identity) {
    return (
      <div className="space-y-4">
        <ArtifactSections sections={evidenceSections} />
        <ReputationSection jobId={jobId} enabled={!loading} />
        {evidenceSections.length === 0 && (
          <div className="p-8 text-center text-sm text-text-secondary">
            No identifying tool answered for this sample.
          </div>
        )}
      </div>
    );
  }

  const sig = identity.signing;
  const sigState = sig.is_signed
    ? sig.signature_valid === false
      ? { label: "SIGNED (INVALID)", cls: "text-status-red bg-status-red/10 border-status-red/30" }
      : { label: "SIGNED", cls: "text-status-green bg-status-green/10 border-status-green/30" }
    : { label: "UNSIGNED", cls: "text-text-muted bg-bg-active border-border" };

  const hashRows = HASH_ROWS.map(({ field, label }) => ({
    field,
    label,
    value: ledgerHashes[field] ?? identity.hashes[field as keyof typeof identity.hashes] ?? "",
  })).filter((row) => saysSomething(row.value));

  return (
    <div className="space-y-4">
      <ArtifactSections sections={evidenceSections} />

      {showsTypedIdentity && (
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Sample Identification
          </h2>
          {/* Stands down when the table above already says whether the
              sample is signed. */}
          {!sectionStatesSigning && (
            <span
              className={`text-[11px] uppercase tracking-wider font-medium px-2 py-0.5 rounded border ${sigState.cls}`}
            >
              {sigState.label}
            </span>
          )}
        </div>
        {/* A row whose value is nothing is not a row. Seven labels above
            seven "(unknown)"s said only that the extractor has seven fields. */}
        <div className="p-4 grid grid-cols-2 gap-4">
          {[
            { label: "File Name", value: identity.file_name ?? "" },
            { label: "File Type", value: identity.file_type ? fileTypeLabel(identity.file_type) : "" },
            {
              label: "Platform",
              value:
                identity.platform && identity.platform !== "unknown"
                  ? platformLabel(identity.platform)
                  : "",
            },
            {
              label: "Size",
              value: identity.file_size_bytes ? formatBytes(identity.file_size_bytes) : "",
            },
            { label: "MIME Type", value: identity.mime_type ?? "" },
            {
              label: "Compile Timestamp",
              value: identity.compile_timestamp
                ? new Date(identity.compile_timestamp).toLocaleString()
                : "",
            },
            { label: "Language / Compiler", value: identity.language_or_compiler ?? "" },
          ]
            .filter((field) => saysSomething(field.value))
            .map((field) => (
              <Field key={field.label} label={field.label} value={field.value} />
            ))}
        </div>
      </div>
      )}

      {/* Every fingerprint the run computed, in the one place that holds them.
        * The ledger's `hashes` entry leads, because it carries the ones the
        * typed model has no field for; the typed block fills in the rest. A
        * hash no tool produced is absent rather than drawn as a dash: ssdeep
        * and tlsh need an optional library and imphash needs an import table,
        * and an empty row reads as a missing value rather than an
        * inapplicable one. */}
      {hashRows.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              File Hashes
            </h2>
          </div>
          <div className="p-4 space-y-2">
            {hashRows.map((row) => (
              <HashRow key={row.field} label={row.label} value={row.value} />
            ))}
          </div>
        </div>
      )}

      <ReputationSection jobId={jobId} enabled={!loading} />

      {identity.signing.is_signed && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Code Signing
            </h2>
          </div>
          <div className="p-4 grid grid-cols-2 gap-4">
            {[
              { label: "Signer Subject", value: identity.signing.signer_subject ?? "" },
              { label: "Issuer", value: identity.signing.signer_issuer ?? "" },
              {
                label: "Signature Valid",
                value:
                  identity.signing.signature_valid === null
                    ? "unverified"
                    : identity.signing.signature_valid
                      ? "yes"
                      : "no",
              },
            ]
              .filter((field) => saysSomething(field.value))
              .map((field) => (
                <Field key={field.label} label={field.label} value={field.value} />
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

/** The hashes a reader knows by name, in the order they are usually quoted. */
const HASH_ROWS: { field: HashField; label: string }[] = [
  { field: "md5", label: "MD5" },
  { field: "sha1", label: "SHA-1" },
  { field: "sha256", label: "SHA-256" },
  { field: "sha512", label: "SHA-512" },
  { field: "imphash", label: "Imphash" },
  { field: "telfhash", label: "Telfhash" },
  { field: "ssdeep", label: "SSDeep" },
  { field: "tlsh", label: "TLSH" },
];

function HashRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="flex items-center gap-3">
      <span className="text-[11px] text-text-muted uppercase tracking-wider w-20 shrink-0">
        {label}
      </span>
      {value ? (
        <>
          <code className="flex-1 font-mono text-xs text-status-blue truncate" title={value}>
            {value}
          </code>
          <button
            onClick={async () => {
              if (await copyToClipboard(value)) {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              }
            }}
            className="text-[11px] px-2 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted"
          >
            {copied ? "copied" : "copy"}
          </button>
        </>
      ) : (
        <span className="text-xs text-text-muted">-</span>
      )}
    </div>
  );
}
